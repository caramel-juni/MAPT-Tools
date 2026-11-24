#!/usr/bin/env python3
"""Mobile application database inventory and multi-engine snapshot browser."""
import argparse, csv, json, os, re, shlex, sqlite3, subprocess, tempfile, shutil, itertools, contextlib, posixpath, importlib.util
from pathlib import Path


def adb(*args, binary=False):
    p = subprocess.run(['adb', *ADB, *args], capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.decode(errors='replace') or p.stdout.decode(errors='replace'))
    return p.stdout if binary else p.stdout.decode(errors='replace')


def classify(name, h):
    n = name.lower()
    if h.startswith(b'SQLite format 3\x00'): return 'SQLite', 'confirmed', True
    if h[:4] in (b'\x37\x7f\x06\x82', b'\x37\x7f\x06\x83'): return 'SQLite WAL', 'confirmed', False
    if h.startswith(bytes.fromhex('d9d505f920a163d7')): return 'SQLite journal', 'confirmed', False
    if h[4:8] == b'T-DB' or n.endswith('.realm'): return 'Realm candidate', 'suspected', False
    if h[12:16] in (bytes.fromhex('62310500'), bytes.fromhex('00053162'), bytes.fromhex('61150600'), bytes.fromhex('00061561')): return 'Berkeley DB', 'signature match', True
    if n.endswith(('-wal','-shm','-journal')): return 'SQLite sidecar candidate', 'suspected', False
    if n.endswith(('.ldb','.sst')) or n.startswith('manifest-'): return 'LevelDB/RocksDB candidate', 'suspected', False
    if n in ('data.mdb','lock.mdb'): return 'LMDB candidate', 'suspected', False
    if n.endswith(('.db','.db3','.sqlite','.sqlite3','.sqlcipher','.store','.sqlite-wal','.mdb','.accdb','.h2.db','.mv.db','.isar','.objectbox')): return 'Unknown database candidate (possibly encrypted)', 'suspected', False
    if n in ('data.mdb','lock.mdb'): return 'LMDB candidate', 'suspected', False
    return None


def inventory(paths, header):
    rows=[]; errors=[]
    for path in paths:
        try:
            h=header(path)
            c=classify(path.rsplit('/',1)[-1],h)
            if c: rows.append(dict(path=path, type=c[0], confidence=c[1], browsable=c[2]))
        except (OSError,RuntimeError) as e: errors.append((path,str(e)))
    return rows,errors


def group_databases(paths, rows):
    groups = {}
    for path in paths:
        groups.setdefault(posixpath.dirname(path), []).append(path)
    for directory, members in groups.items():
        names = {posixpath.basename(x) for x in members}
        kind = None
        if 'CURRENT' in names and any(n.startswith('MANIFEST-') for n in names):
            if any(n.startswith('OPTIONS-') or n == 'IDENTITY' for n in names):
                kind = 'RocksDB'
            elif any(n.endswith('.ldb') for n in names):
                kind = 'LevelDB'
            else:
                kind = 'LevelDB/RocksDB'
        elif 'data.mdb' in names:
            kind = 'LMDB'
        if kind:
            rows[:] = [r for r in rows if not (r['path'] in members and (r['type'].startswith('LevelDB') or posixpath.basename(r['path']) in ('data.mdb','lock.mdb')))]
            rows.append(dict(path=directory, type=kind, confidence='directory layout', browsable=True))
    return sorted(rows, key=lambda r:r['path'])


def copy_snapshot(src, dest, live, directory=False):
    if not live:
        if directory:
            # Do not follow symlinks or copy special files.
            dest.mkdir()
            for f in Path(src).iterdir():
                if f.is_file() and not f.is_symlink(): shutil.copyfile(f, dest/f.name)
        else: shutil.copyfile(src,dest)
        return
    if directory:
        dest.mkdir()
        files = remote('find '+shlex.quote(src)+' -maxdepth 1 -type f -print0',True)
        for raw in files.split(b'\0'):
            if not raw: continue
            f=raw.decode(errors='surrogateescape')
            if posixpath.dirname(f)!=src: raise RuntimeError('Unexpected snapshot path')
            copy_snapshot(f,dest/posixpath.basename(f),True)
    else:
        command='cat '+shlex.quote(src)
        if MODE=='root': command='su -c '+shlex.quote(command)
        elif MODE=='run-as': command='run-as '+shlex.quote(PACKAGE)+' sh -c '+shlex.quote(command)
        with dest.open('wb') as out:
            proc=subprocess.run(['adb',*ADB,'exec-out',command],stdout=out,stderr=subprocess.PIPE)
        if proc.returncode: raise RuntimeError(proc.stderr.decode(errors='replace'))


def render_bytes(value, mode):
    if not isinstance(value,bytes): return repr(value)[:2000]
    if mode=='hex': return value[:512].hex(' ')+(' ...' if len(value)>512 else '')
    if mode=='json':
        try: return json.dumps(json.loads(value),ensure_ascii=True)[:2000]
        except (ValueError,UnicodeError): pass
    return repr(value[:1024])+(' ...' if len(value)>1024 else '')


def kv_menu(iterator, getter):
    mode='text'; offset=0; needle=b''
    print('Commands: next, prev, find TEXT, get TEXT, gethex HEX, mode text|hex|json, q')
    while True:
        print(f'--- Matching records {offset+1} onward ---')
        stream=iterator()
        try:
            matches=((k,v) for k,v in stream if needle in k or needle in v)
            for k,v in itertools.islice(matches,offset,offset+20):
                print(f'KEY {render_bytes(k,mode)}  ({len(k)} bytes)\nVAL {render_bytes(v,mode)}  ({len(v)} bytes)')
        finally:
            if hasattr(stream,'close'): stream.close()
        cmd=input('kv> ').strip()
        if cmd=='q': return
        if cmd in ('','next'): offset+=20
        elif cmd=='prev': offset=max(0,offset-20)
        elif cmd.startswith('find '): needle=cmd[5:].encode(); offset=0
        elif cmd=='find': needle=b''; offset=0
        elif cmd.startswith('mode ') and cmd[5:] in ('text','hex','json'): mode=cmd[5:]
        elif cmd.startswith(('get ','gethex ')):
            try:
                key=bytes.fromhex(cmd[7:]) if cmd.startswith('gethex ') else cmd[4:].encode()
                print(render_bytes(getter(key),mode))
            except Exception as e: print(f'Lookup failed: {e}')
        else: print('Unknown command')


def browse_kv(row, live):
    kind=row['type']
    if kind=='LevelDB/RocksDB':
        choice=input('Engine ambiguous: [l] LevelDB or [r] RocksDB? ').lower()
        if choice not in ('l','r'): return
        kind='LevelDB' if choice=='l' else 'RocksDB'
    module={'LevelDB':'plyvel','RocksDB':'rocksdict','LMDB':'lmdb','Berkeley DB':'berkeleydb'}[kind]
    if importlib.util.find_spec(module) is None:
        print(f'Optional reader missing: python -m pip install {module}'); return
    with tempfile.TemporaryDirectory(prefix='mobile-kv-') as tmp:
        target=Path(tmp)/'snapshot'
        copy_snapshot(row['path'],target,live,kind!='Berkeley DB')
        print('Browsing disposable copy. Stop app activity before copying for consistency.')
        with contextlib.ExitStack() as stack:
            if kind=='LevelDB':
                import plyvel
                db=plyvel.DB(str(target),create_if_missing=False)
                stack.callback(db.close)
                def iterator():
                    with db.iterator() as it: yield from it
                getter=db.get
            elif kind=='RocksDB':
                from rocksdict import Rdict, Options, AccessType
                db=Rdict(str(target),Options(raw_mode=True),access_type=AccessType.read_only())
                stack.callback(db.close)
                print('Browsing default column family.')
                iterator=lambda: iter(db.items()); getter=db.get
            elif kind=='LMDB':
                import lmdb
                db=lmdb.open(str(target),readonly=True,lock=False,create=False,max_dbs=128)
                stack.callback(db.close)
                txn=stack.enter_context(db.begin())
                name=input('Named subdatabase (blank for main): ')
                handle=db.open_db(name.encode(),txn=txn,create=False) if name else None
                def iterator():
                    with txn.cursor(db=handle) as cur: yield from cur
                getter=lambda k: txn.get(k,db=handle)
            else:
                from berkeleydb import db as bdb
                db=bdb.DB(); stack.callback(db.close)
                name=input('Named subdatabase (blank for default): ')
                db.open(str(target),name or None,bdb.DB_UNKNOWN,bdb.DB_RDONLY)
                def iterator():
                    cur=db.cursor()
                    try:
                        record=cur.first()
                        while record is not None:
                            k,v=record
                            yield (k if isinstance(k,bytes) else str(k).encode(),v)
                            record=cur.next()
                    finally: cur.close()
                getter=db.get
            kv_menu(iterator,getter)


def local_paths(root, errors):
    for base, dirs, files in os.walk(root, followlinks=False, onerror=lambda e: errors.append((str(e.filename),str(e)))):
        for name in files:
            p=Path(base)/name
            if not p.is_symlink() and p.is_file(): yield str(p)


def local_header(p):
    with open(p,'rb') as f: return f.read(100)


def remote(command, binary=False):
    if MODE=='root': command='su -c '+shlex.quote(command)
    elif MODE=='run-as': command='run-as '+shlex.quote(PACKAGE)+' sh -c '+shlex.quote(command)
    return adb('exec-out',command,binary=binary)


def remote_header(p): return remote('head -c 100 '+shlex.quote(p),True)


def choose_package():
    packages=sorted(x.removeprefix('package:') for x in adb('shell','pm list packages -3').splitlines() if x.startswith('package:'))
    for i,p in enumerate(packages,1): print(f'{i:4} {p}')
    return packages[int(input('Package number: '))-1]


def browse(row, live):
    if not row['browsable']: print('No built-in reader for this format.'); return
    if row['type'] != 'SQLite':
        return browse_kv(row,live)
    with tempfile.TemporaryDirectory(prefix='mobile-db-') as tmp:
        target=Path(tmp)/'snapshot.db'; src=row['path']
        for suffix in ('','-wal','-shm','-journal'):
            try:
                if live:
                    data=remote('cat '+shlex.quote(src+suffix),True)
                    Path(str(target)+suffix).write_bytes(data)
                else: shutil.copyfile(src+suffix,str(target)+suffix)
            except (OSError,RuntimeError):
                if not suffix: raise
        print('Browsing temporary copy; live WAL snapshots may be inconsistent.')
        with sqlite3.connect(target.as_uri()+'?mode=ro',uri=True) as con:
            con.execute('PRAGMA query_only=ON')
            con.execute('PRAGMA trusted_schema=OFF')
            allowed={sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ,sqlite3.SQLITE_FUNCTION,sqlite3.SQLITE_RECURSIVE}
            def auth(action,a,b,c,d):
                if action==sqlite3.SQLITE_FUNCTION and (b or '').lower() in ('load_extension','writefile','readfile'): return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY
            con.set_authorizer(auth)
            tables=con.execute("SELECT name, sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name").fetchall()
            for i,(name,schema) in enumerate(tables,1): print(f'{i}. {name}\n   {schema}')
            while True:
                q=input('Table number, SELECT query, or q: ').strip()
                if q.lower()=='q': break
                if q.isdigit():
                    i=int(q)-1
                    if not 0<=i<len(tables): print('Invalid table'); continue
                    q='SELECT * FROM "'+tables[i][0].replace('"','""')+'" LIMIT 50'
                try:
                    cur=con.execute(q); print(' | '.join(x[0] for x in cur.description or []))
                    for record in cur.fetchmany(50): print(' | '.join(repr(v)[:500] for v in record))
                    print('(Maximum 50 rows displayed)')
                except sqlite3.Error as e: print(e)


def main():
    global ADB,MODE,PACKAGE
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='source',required=True)
    l=sub.add_parser('local'); l.add_argument('directory')
    a=sub.add_parser('adb'); a.add_argument('--package'); a.add_argument('--serial'); a.add_argument('--mode',choices=['root','run-as','shell'],default='root'); a.add_argument('--user',type=int,default=0); a.add_argument('--path',action='append',help='Override default roots; repeatable')
    for s in (l,a):
        s.add_argument('--json',type=Path); s.add_argument('--csv',type=Path); s.add_argument('--no-browse',action='store_true')
    args=p.parse_args(); live=args.source=='adb'; errors=[]
    if live:
        ADB=['-s',args.serial] if args.serial else []; MODE=args.mode; PACKAGE=args.package or choose_package()
        if not re.fullmatch(r'[A-Za-z0-9_.]+',PACKAGE): p.error('Invalid package')
        roots=args.path or [f'/data/user/{args.user}/{PACKAGE}',f'/data/user_de/{args.user}/{PACKAGE}',f'/storage/emulated/{args.user}/Android/data/{PACKAGE}',f'/storage/emulated/{args.user}/Android/media/{PACKAGE}']
        paths=[]
        for root in roots:
            try: paths.extend(x.decode(errors='surrogateescape') for x in remote('find '+shlex.quote(root)+' -type f -print0',True).split(b'\0') if x)
            except RuntimeError as e: errors.append((root,str(e)))
        rows,errs=inventory(dict.fromkeys(paths),remote_header)
    else:
        root=Path(args.directory).resolve()
        if not root.is_dir(): p.error('Directory does not exist')
        paths=list(local_paths(root,errors))
        rows,errs=inventory(paths,local_header)
    rows=group_databases(paths,rows)
    errors.extend(errs)
    for i,r in enumerate(rows,1): print(f'{i:4} [{r["type"]}; {r["confidence"]}] {r["path"]}')
    print(f'\n{len(rows)} candidates; {sum(r["browsable"] for r in rows)} reader-supported candidates; {len(errors)} scan errors.')
    for path,error in errors: print(f'WARNING: {path}: {error}')
    if args.json: args.json.write_text(json.dumps({'databases':rows,'errors':errors},indent=2))
    if args.csv:
        with args.csv.open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=['path','type','confidence','browsable']); w.writeheader(); w.writerows(rows)
    if not args.no_browse and rows:
        while True:
            choice=input('Database number to browse, or q: ').strip()
            if choice.lower()=='q': break
            try:
                i=int(choice)-1
                if not 0<=i<len(rows): raise ValueError('Invalid number')
                browse(rows[i],live)
            except Exception as e: print(f"Browse failed: {e}")

if __name__=='__main__':
    try: main()
    except (KeyboardInterrupt,EOFError): print('\nExiting.')
    except (RuntimeError,OSError) as e: raise SystemExit(str(e))
