#!/usr/bin/env python3
"""Android/iOS Flutter Storage Explorer: local read-only forensic browser. Python 3.10+."""
import argparse, base64, collections, datetime, hashlib, html, io, json, mimetypes, os, pathlib, plistlib, re, shutil, sqlite3, subprocess, sys, tarfile, threading, time, urllib.parse, zipfile, tempfile, secrets, copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from axml_reader import decode as decode_axml, AxmlError

MAX_READ = 2_000_000
MAX_SCAN = 8_000_000
MAX_EXPORT = 300_000_000
MAX_ENTRIES = 30000
PATTERNS = [
 ('credential field', 'HIGH', re.compile(r'(?i)(?:password|passwd|pwd|client[_-]?secret|private[_-]?key|secret[_-]?key)')),
 ('session/token field', 'HIGH', re.compile(r'(?i)(?:access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|bearer|session[_-]?id|auth[_-]?token|cookie)')),
 ('possible JWT', 'HIGH', re.compile(rb'eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}')),
 ('email address', 'MEDIUM', re.compile(rb'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')),
 ('private key marker', 'HIGH', re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
 ('payment-card-like sequence', 'MEDIUM', re.compile(rb'(?<!\d)(?:\d[ -]?){13,19}(?!\d)')),
]
SENSITIVE = re.compile(r'(?i)(password|passwd|secret|token|authorization|bearer|session|cookie|api[_-]?key|private[_-]?key|credential|email|phone|birth|address|ssn|dob)')
BINARY_EXT = {'.so','.dex','.oat','.art','.png','.jpg','.jpeg','.webp','.gif','.mp4','.mp3','.ttf','.woff','.woff2','.apk','.zip','.gz','.pdf'}


def redact(text):
    text = str(text)
    text = re.sub(r'(?i)(\b(?:authorization|access_token|refresh_token|password|client_secret|cookie|api_key)\b\s*[=:]\s*)([^,\s;]+)', r'\1[REDACTED]', text)
    text = re.sub(r'eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}', '[REDACTED JWT]', text)
    text = re.sub(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', '[REDACTED EMAIL]', text)
    return text

def category(path):
    p=path.lower().replace('\\','/')
    name=pathlib.PurePosixPath(p).name
    if 'library/preferences/' in p or p.endswith('.preferences.plist') or '/nsuserdefaults/' in p: return 'iOS UserDefaults / preferences'
    if 'library/caches/' in p or 'tmp/' in p or '/tmp/' in p: return 'iOS cache / temporary'
    if 'library/webkit/' in p or 'website data/' in p or '/webkit/' in p: return 'iOS WKWebView / website data'
    if 'library/application support/' in p: return 'iOS Application Support'
    if '/documents/' in p or p.startswith('documents/'): return 'iOS Documents'
    if 'appgroup/' in p or 'shared/appgroup' in p: return 'iOS App Group / shared container'
    if p.startswith('ipa/') or 'payload/' in p or p.startswith('frameworks/') or p.startswith('plugins/') or 'embedded.mobileprovision' in p: return 'iOS IPA / static'
    if name.endswith('.plist'): return 'Apple property list'
    if p.startswith('apk/') or '/libapp.so' in p or p.startswith('lib/') or p.startswith('assets/') or p.startswith('res/') or 'manifest' in p: return 'Android APK / static'
    if 'shared_prefs/' in p: return 'Android SharedPreferences'
    if '/datastore/' in p or p.endswith('.preferences_pb'): return 'DataStore / protobuf'
    if 'databases/' in p or p.endswith(('.db','.sqlite','.sqlite3','-wal','-shm')): return 'SQLite / database'
    if 'app_webview/' in p or 'indexeddb' in p or 'local storage' in p: return 'WebView / Chromium'
    if 'app_flutter/' in p: return 'Flutter files'
    if '/cache/' in p or p.startswith('cache/'): return 'Cache'
    if 'no_backup/' in p: return 'No-backup'
    if 'external/' in p: return 'External storage'
    if 'user_de/' in p: return 'Device-protected'
    if p.endswith(('.log','.txt')) or 'log' in name: return 'Logs / text'
    return 'Other files'

def detect(path, raw):
    hits=[]
    basename=path.lower()
    for label,sev,regex in PATTERNS:
        if isinstance(regex.pattern, str):
            if regex.search(basename): hits.append({'severity':sev,'type':label,'detail':'Sensitive-looking filename / path (needs manual review)'})
            if regex.search(raw[:MAX_SCAN].decode('utf-8',errors='ignore')): hits.append({'severity':'REVIEW' if label=='session/token field' else sev,'type':label+' in contents','detail':'Sensitive-looking term in content (may be a harmless identifier; inspect context)'})
        elif regex.search(raw):
            hits.append({'severity':sev,'type':label,'detail':'Potential match in file content (review context)'})
    if b'SQLite format 3' in raw[:20] and (b'password' in raw.lower() or b'token' in raw.lower()):
        hits.append({'severity':'REVIEW','type':'database content','detail':'SQLite file includes a sensitive-looking field name'})
    return hits

def inspect_blob(path, content, size):
    kind=category(path)
    if content.startswith(b'SQLite format 3\0'): kind='SQLite / database'
    elif path.lower().endswith(('.xml', '.json', '.properties','.plist')): kind='Structured text'
    elif path.lower().endswith(('.pb','.preferences_pb')): kind='DataStore / protobuf'
    result={'path':path,'size':size,'kind':kind,'sha256':hashlib.sha256(content).hexdigest() if size<=MAX_SCAN else None,'findings': detect(path,content),'truncated_scan':size>len(content)}
    return result

def find_contexts(data, limit=120):
    """Safely identify matching bytes with exact offsets, including inside binary blobs."""
    hits=[]
    patterns=[(name,sev,rx) for name,sev,rx in PATTERNS]
    for name,sev,pattern in patterns:
        expression=pattern if isinstance(pattern.pattern,bytes) else re.compile(pattern.pattern.encode('ascii'),pattern.flags & ~re.UNICODE)
        try:
            for match in expression.finditer(data):
                a,b=match.span()
                snippet=data[max(0,a-92):min(len(data),b+120)]
                context=''.join(chr(c) if 32<=c<=126 else ('\n' if c in (10,13) else '·') for c in snippet)
                hits.append({'type':name,'severity':sev,'offset':a,'length':b-a,'context':context[:280]})
                if len(hits)>=limit:break
        except (ValueError,re.error):continue
        if len(hits)>=limit:break
    return sorted(hits,key=lambda x:x['offset'])

def binary_strings(data, min_chars=5, max_items=600):
    """Inspect printable ASCII strings from binary data, with original offsets."""
    lines=[]
    for m in re.finditer(rb'[\x20-\x7e]{'+str(min_chars).encode()+rb',}',data):
        lines.append(f'0x{m.start():08x}  '+m.group().decode('ascii','replace')[:400])
        if len(lines)>=max_items:break
    return '\n'.join(lines)

def decode_protobuf(data, depth=0, max_fields=500):
    """Best-effort generic wire decoder, not a substitute for the actual .proto schema."""
    if depth>3 or len(data)>MAX_READ: return []
    def vi(buf,i):
        value=0; shift=0
        for _ in range(10):
            if i>=len(buf):raise ValueError('truncated varint')
            b=buf[i];i+=1;value|=(b&127)<<shift
            if not b&128:return value,i
            shift+=7
        raise ValueError('long varint')
    out=[];i=0
    try:
        while i<len(data) and len(out)<max_fields:
            tag,i=vi(data,i); field=tag>>3; wire=tag&7
            if field==0 or wire not in (0,1,2,5):raise ValueError('invalid tag')
            if wire==0:
                v,i=vi(data,i);out.append({'field':field,'value':v})
            elif wire in (1,5):
                n=8 if wire==1 else 4
                if i+n>len(data):raise ValueError('truncated fixed')
                out.append({'field':field,'hex':data[i:i+n].hex()});i+=n
            else:
                length,i=vi(data,i)
                if length>len(data)-i:raise ValueError('truncated length')
                v=data[i:i+length];i+=length
                try:
                    decoded=v.decode('utf-8')
                    if decoded.isprintable() or all(ch.isprintable() or ch in '\n\r\t' for ch in decoded):
                        out.append({'field':field,'text':decoded[:2000]});continue
                except UnicodeError:pass
                nested=decode_protobuf(v,depth+1,100) if len(v)<=50000 else []
                out.append({'field':field,'nested':nested} if nested else {'field':field,'hex':v[:160].hex(),'length':len(v)})
    except ValueError: pass
    return out

def safe_extract_tar(binary, dest):
    dest.mkdir(parents=True, exist_ok=True)
    total=0; count=0
    with tarfile.open(fileobj=io.BytesIO(binary), mode='r:*') as tf:
        for member in tf:
            count+=1
            if count>MAX_ENTRIES: raise ValueError('Too many archive entries')
            pp=pathlib.PurePosixPath(member.name)
            if pp.is_absolute() or '..' in pp.parts or member.issym() or member.islnk() or member.isdev(): continue
            if not member.isfile(): continue
            total += member.size
            if total>MAX_EXPORT: raise ValueError('Export exceeds configured size limit')
            outfile=dest.joinpath(*pp.parts)
            outfile.parent.mkdir(parents=True, exist_ok=True)
            with tf.extractfile(member) as src, open(outfile,'wb') as out: shutil.copyfileobj(src,out)
    return count

def adb_snapshot(pkg, output, mode='auto', serial=None):
    if not re.fullmatch(r'[a-zA-Z0-9_.]+', pkg): raise ValueError('Invalid package name')
    base=['adb']+(['-s',serial] if serial else [])
    choices=['run-as','su'] if mode=='auto' else [mode]
    output=pathlib.Path(output); output.mkdir(parents=True,exist_ok=True)
    succeeded=[]; errors=[]
    for choice in choices:
        if choice=='run-as': command=base+['exec-out','run-as',pkg,'tar','-C','.','-cf','-','.']
        else: command=base+['exec-out','su','-c',f'tar -C /data/user/0/{pkg} -cf - .']
        try:
            p=subprocess.run(command,capture_output=True,timeout=90)
            if p.returncode or not p.stdout: raise RuntimeError(p.stderr.decode(errors='replace')[:500])
            if len(p.stdout)>MAX_EXPORT: raise RuntimeError('Archive too large for this build')
            safe_extract_tar(p.stdout,output/'internal')
            succeeded.append('internal via '+choice)
            break
        except Exception as exc: errors.append(f'{choice}: {exc}')
    if 'su' in choices or mode=='auto':
        command=base+['exec-out','su','-c',f'tar -C /data/user_de/0/{pkg} -cf - .']
        try:
            p=subprocess.run(command,capture_output=True,timeout=40)
            if p.returncode==0 and p.stdout: safe_extract_tar(p.stdout,output/'user_de'); succeeded.append('device-protected')
        except Exception: pass
    # External scoped storage may be inaccessible; do not assume absence means no data.
    meta={'package':pkg,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'methods':succeeded,'errors':errors}
    (output/'snapshot_metadata.json').write_text(json.dumps(meta,indent=2))
    if not succeeded: raise RuntimeError('Could not access private app directory. Use a debuggable build (run-as) or rooted emulator. '+'; '.join(errors))
    return meta

class Dataset:
    def __init__(self,root,apk=None,ipa=None,ios_archive=None):
        self.root=pathlib.Path(root).resolve() if root else None
        self.archives=[]
        for label, supplied in [('APK',apk),('IPA',ipa),('iOS container',ios_archive)]:
            if supplied:
                path=pathlib.Path(supplied).resolve()
                if not zipfile.is_zipfile(path): raise ValueError(f'{label} must be a ZIP-compatible archive')
                self.archives.append((label,path))
        self.entries=[];self.findings=[]; self.catalog={}; self._scan()
    def _scan(self):
        if self.root:
            for base,dirs,files in os.walk(self.root,followlinks=False):
                dirs[:]=[d for d in dirs if not (pathlib.Path(base)/d).is_symlink()]
                for name in files:
                    fp=pathlib.Path(base)/name
                    if fp.is_symlink() or not fp.is_file():continue
                    rel=fp.relative_to(self.root).as_posix()
                    size=fp.stat().st_size
                    try:
                        with open(fp,'rb') as f: sample=f.read(MAX_SCAN)
                    except OSError:continue
                    key='dir:'+rel
                    record=inspect_blob(rel,sample,size)
                    record['id']=key; self.entries.append(record);self.catalog[key]=('file',fp)
                    self.findings += [{**f,'path':rel,'id':key} for f in record['findings']]
        for label, archive in self.archives:
            with zipfile.ZipFile(archive) as z:
                for zi in z.infolist():
                    if zi.is_dir() or len(self.entries)>=MAX_ENTRIES: continue
                    # ZIP is never extracted by the browser, and reading is capped.
                    rel=label+'/'+zi.filename
                    if zi.file_size>MAX_SCAN or zi.compress_size>MAX_SCAN:
                        sample=b''
                    else:
                        with z.open(zi) as f: sample=f.read(MAX_SCAN)
                    key=label.lower()+':'+zi.filename
                    record=inspect_blob(rel,sample,zi.file_size)
                    record['id']=key; self.entries.append(record);self.catalog[key]=('zip',archive,zi.filename)
                    self.findings += [{**f,'path':rel,'id':key} for f in record['findings']]
        self.entries.sort(key=lambda x:x['path'].lower())
    def get(self,key,limit=MAX_READ):
        if key not in self.catalog:raise KeyError('Unknown file')
        entry=self.catalog[key]
        if entry[0]=='file':
            with open(entry[1],'rb') as f:return f.read(limit)
        with zipfile.ZipFile(entry[1]) as z:
            with z.open(entry[2]) as f:return f.read(limit)
    def database_path(self,key):
        entry=self.catalog[key]
        if entry[0]!='file':raise ValueError('SQLite browsing supports extracted directories. Extract the IPA/container into a working directory to browse its DB tables.')
        ref=entry[1]
        with open(ref,'rb') as f:
            if f.read(16)!=b'SQLite format 3\x00':raise ValueError('Not a plain SQLite database (may be SQLCipher or another format)')
        return ref
    def sqlite(self,key,table=None,page=0,limit=100):
        path=self.database_path(key)
        uri=path.as_uri()+'?mode=ro'
        con=sqlite3.connect(uri,uri=True,timeout=1)
        con.row_factory=sqlite3.Row
        try:
            con.execute('PRAGMA query_only=ON')
            tables=[dict(r) for r in con.execute("SELECT name,type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            if table is None:return {'tables':tables}
            if table not in {r['name'] for r in tables}:raise ValueError('Unknown table')
            quoted='"'+table.replace('"','""')+'"'
            cols=[dict(r) for r in con.execute(f'PRAGMA table_info({quoted})')]
            rows=[{k: (('[BLOB %s bytes]'%len(v)) if isinstance(v,bytes) else v) for k,v in dict(r).items()} for r in con.execute(f'SELECT * FROM {quoted} LIMIT ? OFFSET ?', (min(max(limit,1),200), max(0,page)*min(max(limit,1),200)))]
            return {'tables':tables,'columns':cols,'rows':rows,'table':table,'page':page,'limit':limit}
        finally:con.close()

HTML = (pathlib.Path(__file__).with_name('ui.html')).read_text(encoding='utf-8')

class Workspace:
    """Mutable local session. User uploads are COPIES stored in a temporary directory."""
    def __init__(self, dataset=None):
        self.tmp=tempfile.TemporaryDirectory(prefix='flutter-explorer-')
        self.root=pathlib.Path(self.tmp.name)
        self.upload_dir=self.root/'extracted'; self.upload_dir.mkdir()
        self.uploads={};self.lock=threading.RLock()
        self.dataset=dataset if dataset is not None else Dataset(None)
        self.total_bytes=0;self.upload_count=0
        self.initial=dataset is not None
    def state(self):
        with self.lock:
            return {'entries':self.dataset.entries,'findings':self.dataset.findings,
                    'sources':[{'type':k, 'path':str(v.name)} for k,v in self.uploads.items()],
                    'imported_files':self.upload_count,'imported_bytes':self.total_bytes,'initial':self.initial, 'has_directory':any(self.upload_dir.rglob('*'))}
    def rebuild(self):
        # Archive defaults remain separate; nonarchive uploads are indexed as extracted directory.
        self.dataset=Dataset(self.upload_dir if any(self.upload_dir.rglob('*')) else None,
                             self.uploads.get('apk'),self.uploads.get('ipa'),self.uploads.get('ios-archive'))
    def upload_file(self, kind, name, source_path, size):
        """Accept a disk-backed upload; never hold the entire APK in RAM."""
        with self.lock:
            if self.total_bytes+size > MAX_EXPORT:
                raise ValueError('Session upload limit 300 MB exceeded. Use local file import or CLI --apk for larger APKs.')
            if self.upload_count>=MAX_ENTRIES:
                raise ValueError('Too many uploaded files')
            if kind in ('apk','ipa','ios-archive'):
                if not zipfile.is_zipfile(source_path):
                    raise ValueError('APK, IPA and iOS archives must be valid ZIP containers')
                suffix={'apk':'.apk','ipa':'.ipa','ios-archive':'.zip'}[kind]
                target=self.root/(kind+suffix)
                shutil.copyfile(source_path,target)
                self.uploads[kind]=target
            elif kind=='dir':
                pp=pathlib.PurePosixPath(name)
                if (not name or name.startswith('/') or '\\' in name or '..' in pp.parts or
                    len(pp.parts)>30 or any(not x or ':' in x for x in pp.parts)):
                    raise ValueError('Unsafe directory entry path')
                target=self.upload_dir.joinpath(*pp.parts)
                if target.exists(): raise ValueError('File already imported: '+name)
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source_path,target)
            else:
                raise ValueError('Unknown import type')
            self.total_bytes+=size
            self.upload_count+=1
            return {'files':self.upload_count, 'bytes':self.total_bytes}

    def import_local(self,kind,path):
        """Open a trusted, local CLI-side path without browser upload."""
        source=pathlib.Path(path).expanduser().resolve(strict=True)
        if not source.is_file():
            raise ValueError('Choose a readable APK/IPA file')
        if kind not in ('apk','ipa','ios-archive'):
            raise ValueError('Local path import supports APK, IPA and iOS ZIP')
        if not zipfile.is_zipfile(source):
            raise ValueError('Selected file is not a ZIP-compatible APK/IPA/archive')
        with self.lock:
            self.uploads[kind]=source
            self.rebuild()
            return {'ok':True,'entries':len(self.dataset.entries),'path':source.name}

    def adb_collect(self,pkg,serial=None,mode='auto'):
        # Run without lock while ADB is active, lock during result swap.
        dest=self.root/'adb-snapshot'
        if dest.exists():shutil.rmtree(dest)
        meta=adb_snapshot(pkg,dest,mode,serial)
        with self.lock:
            for fp in dest.rglob('*'):
                if fp.is_file():
                    rel=fp.relative_to(dest)
                    target=self.upload_dir/'adb-capture'/rel
                    target.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copy2(fp,target)
            self.rebuild()
        return meta


class Handler(BaseHTTPRequestHandler):
    workspace=None
    token=None
    def log_message(self,*a):
        if os.environ.get('EXPLORER_DEBUG')=='1': super().log_message(*a)
    def respond(self,body,status=200,type='application/json; charset=utf-8'):
        raw=body if isinstance(body,bytes) else (body.encode() if type.startswith('text/html') else json.dumps(body,default=str).encode())
        self.send_response(status);self.send_header('Content-Type',type);self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.send_header('X-Frame-Options','DENY');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self' 'unsafe-inline'; connect-src 'self'");self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        u=urllib.parse.urlsplit(self.path);p=urllib.parse.parse_qs(u.query)
        try:
            if u.path=='/':return self.respond(HTML.replace('__EXPLORER_TOKEN__',self.token), type='text/html; charset=utf-8')
            if u.path=='/api/index':return self.respond(self.workspace.state())
            if u.path=='/api/devices':
                try:
                    r=subprocess.run(['adb','devices','-l'],capture_output=True,text=True,timeout=8)
                    lines=[x.strip() for x in r.stdout.splitlines()[1:] if x.strip()]
                    return self.respond({'devices':lines,'error':r.stderr.strip() if r.returncode else ''})
                except Exception as ex:return self.respond({'devices':[],'error':str(ex)})
            if u.path=='/api/file':
                key=p.get('id',[''])[0];r=next((e for e in self.workspace.dataset.entries if e['id']==key),None)
                if not r:raise KeyError('File not found')
                data=self.workspace.dataset.get(key)
                if data.startswith(b'SQLite format 3\0') and self.workspace.dataset.catalog[key][0]=='file':
                    return self.respond({'sqlite':True,'matches':find_contexts(self.workspace.dataset.get(key,MAX_SCAN)),**self.workspace.dataset.sqlite(key)})
                ext=pathlib.Path(r['path']).suffix.lower()
                contexts=find_contexts(self.workspace.dataset.get(key,MAX_SCAN))
                if ext=='.xml' and len(data)>8 and data[:2]==b'\x03\x00':
                    try:return self.respond({'text':decode_axml(data),'format':'Android binary XML (decoded)','matches':contexts,'truncated':r['size']>MAX_READ})
                    except AxmlError as exc:
                        return self.respond({'text':'Binary Android XML could not be decoded: '+str(exc),'hex':data[:512].hex(' '),'format':'AXML decoding failed','matches':contexts,'truncated':r['size']>MAX_READ})
                if (b'\x00' in data[:4000] or ext in BINARY_EXT) and ext not in ('.pb','.preferences_pb','.plist'):
                    preview=' '.join(f'{c:02x}' for c in data[:512])
                    return self.respond({'text':binary_strings(data),'hex':preview,'format':'Binary strings and hex','matches':contexts,'truncated':r['size']>MAX_READ})
                txt=data.decode('utf-8',errors='replace')
                if ext in ('.pb','.preferences_pb'):
                    parsed=decode_protobuf(data)
                    return self.respond({'text':json.dumps(parsed,indent=2,ensure_ascii=False) if parsed else 'Could not decode as plain protobuf (possibly encrypted or another encoding)', 'matches':contexts,'truncated':r['size']>MAX_READ})
                if ext=='.plist' or data.startswith(b'bplist00'):
                    try:
                        obj=plistlib.loads(data)
                        def clean(v):
                            if isinstance(v,bytes):return {'binary_data_length':len(v),'hex_preview':v[:128].hex()}
                            if isinstance(v,(datetime.datetime,datetime.date)):return v.isoformat()
                            if isinstance(v,dict):return {str(k):clean(x) for k,x in v.items()}
                            if isinstance(v,list):return [clean(x) for x in v]
                            return v
                        return self.respond({'text':json.dumps(clean(obj),indent=2,ensure_ascii=False,default=str),'matches':contexts,'truncated':r['size']>MAX_READ})
                    except Exception as exc:
                        return self.respond({'text':'Could not decode plist: '+str(exc)+'\n'+data[:512].hex(),'matches':contexts,'truncated':r['size']>MAX_READ})
                if ext=='.json':
                    try:txt=json.dumps(json.loads(txt),indent=2,ensure_ascii=False)
                    except Exception:pass
                if ext=='.xml':
                    try:
                        import xml.dom.minidom
                        txt=xml.dom.minidom.parseString(data).toprettyxml()
                    except Exception:pass
                return self.respond({'text':txt,'matches':contexts,'truncated':r['size']>MAX_READ})
            if u.path=='/api/sqlite':
                return self.respond(self.workspace.dataset.sqlite(p.get('id',[''])[0],p.get('table',[''])[0],int(p.get('page',['0'])[0])))
            self.respond({'error':'not found'},404)
        except Exception as e:self.respond({'error':str(e)},400)
    def do_POST(self):
        u=urllib.parse.urlsplit(self.path)
        p=urllib.parse.parse_qs(u.query)
        try:
            if u.path not in ('/api/upload','/api/finish','/api/adb','/api/local'):
                return self.respond({'error':'not found'},404)
            # Bound requests and require same-origin custom header to mitigate drive-by cross-origin posts.
            if self.headers.get('X-Explorer-Request')!=self.token:
                return self.respond({'error':'Missing session request token'},403)
            length=int(self.headers.get('Content-Length','0'))
            if length<0 or length>MAX_EXPORT:return self.respond({'error':'Upload too large'},413)
            if u.path=='/api/upload':
                # Stream request to a temporary file rather than buffering large APKs in memory.
                with tempfile.TemporaryFile() as inp:
                    remaining=length
                    while remaining:
                        chunk=self.rfile.read(min(1024*1024,remaining))
                        if not chunk: raise ConnectionError('Browser disconnected during upload')
                        inp.write(chunk)
                        remaining-=len(chunk)
                    inp.flush()
                    inp.seek(0)
                    with tempfile.NamedTemporaryFile(dir=self.workspace.root,delete=False) as tmp:
                        temp_path=pathlib.Path(tmp.name)
                        shutil.copyfileobj(inp,tmp,1024*1024)
                try:
                    result=self.workspace.upload_file(p.get('kind',[''])[0],p.get('name',[''])[0],temp_path,length)
                finally:
                    temp_path.unlink(missing_ok=True)
                return self.respond(result)
            body=self.rfile.read(length)
            if u.path=='/api/local':
                req=json.loads(body.decode('utf-8'))
                return self.respond(self.workspace.import_local(req.get('kind',''),req.get('path','')))
            if u.path=='/api/finish':
                with self.workspace.lock:self.workspace.rebuild()
                return self.respond({'ok':True,'entries':len(self.workspace.dataset.entries)})
            if u.path=='/api/adb':
                req=json.loads(body.decode('utf-8'))
                return self.respond(self.workspace.adb_collect(req.get('package',''),req.get('serial') or None,req.get('mode','auto')))
        except Exception as ex:
            print(f'[REQUEST ERROR] {type(ex).__name__}: {ex}',file=sys.stderr,flush=True)
            try:return self.respond({'error':str(ex)},400)
            except (BrokenPipeError,ConnectionResetError):return


def main():
    ap=argparse.ArgumentParser(description='Android/iOS Flutter local storage examiner, read-only web viewer')
    sub=ap.add_subparsers(dest='cmd',required=True)
    sp=sub.add_parser('browse',help='Browse extracted data, APK, IPA and/or iOS container ZIP');sp.add_argument('--dir');sp.add_argument('--apk');sp.add_argument('--ipa');sp.add_argument('--ios-archive');sp.add_argument('--port',type=int,default=8765)
    sp=sub.add_parser('scan',help='Produce JSON file inventory and heuristic findings');sp.add_argument('--dir');sp.add_argument('--apk');sp.add_argument('--ipa');sp.add_argument('--ios-archive');sp.add_argument('--out',default='storage-report.json')
    sp=sub.add_parser('snapshot',help='Extract authorised app data over ADB');sp.add_argument('--package',required=True);sp.add_argument('--out',required=True);sp.add_argument('--mode',choices=['auto','run-as','su'],default='auto');sp.add_argument('--serial')
    sp=sub.add_parser('logcat',help='Save unfiltered device logcat for review');sp.add_argument('--out',required=True);sp.add_argument('--serial');sp.add_argument('--pid',type=int,help='Optional single PID; misses other processes/restarts')
    sp=sub.add_parser('compare',help='Compare files and SHA256 between two snapshots');sp.add_argument('before');sp.add_argument('after');sp.add_argument('--out',default='snapshot-diff.json')
    args=ap.parse_args()
    if args.cmd=='snapshot':print(json.dumps(adb_snapshot(args.package,args.out,args.mode,args.serial),indent=2));return
    if args.cmd=='logcat':
        cmd=['adb']+(['-s',args.serial] if args.serial else [])+['logcat','-v','threadtime']+(['--pid='+str(args.pid)] if args.pid else [])
        out=pathlib.Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
        print('Capturing complete logcat (or selected PID). Ctrl+C to stop. Sensitive values may be present.',flush=True)
        with open(out,'wb') as f:
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE)
            try:
                while True:
                    line=proc.stdout.readline()
                    if not line:break
                    f.write(line);f.flush()
                    s=line.decode(errors='replace')
                    if re.search(r'(?i)flutter|token|secret|authorization|sqlite|database|sharedpref|exception|otlp',s):print(redact(s.rstrip()))
            except KeyboardInterrupt:pass
            finally:proc.terminate();proc.wait(timeout=5)
        return
    if args.cmd=='compare':
        def index(path):
            root=pathlib.Path(path);ret={}
            for x in root.rglob('*'):
                if x.is_file() and not x.is_symlink():
                    h=hashlib.sha256()
                    with open(x,'rb') as f:
                        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
                    ret[x.relative_to(root).as_posix()]=h.hexdigest()
            return ret
        a=index(args.before);b=index(args.after)
        report={'added':sorted(b.keys()-a.keys()),'removed':sorted(a.keys()-b.keys()),'changed':sorted(k for k in a.keys()&b.keys() if a[k]!=b[k]),'unchanged':len([k for k in a.keys()&b.keys() if a[k]==b[k]])}
        pathlib.Path(args.out).write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));return
    if args.cmd=='scan' and not any([args.dir,args.apk,args.ipa,args.ios_archive]):ap.error('scan requires --dir, --apk, --ipa or --ios-archive')
    data=Dataset(args.dir,args.apk,args.ipa,args.ios_archive) if any([args.dir,args.apk,args.ipa,args.ios_archive]) else None
    if args.cmd=='scan':
        pathlib.Path(args.out).write_text(json.dumps({'entries':data.entries,'findings':data.findings},indent=2))
        print(f'Wrote {args.out}: {len(data.entries)} files; {len(data.findings)} leads');return
    Handler.workspace=Workspace(data)
    Handler.token=secrets.token_urlsafe(24)
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print(f'Open http://127.0.0.1:{args.port}  |  {len(Handler.workspace.dataset.entries)} files, {len(Handler.workspace.dataset.findings)} potential findings')
    print('This local viewer displays unredacted evidence. Do not expose the port to the network.')
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally: Handler.workspace.tmp.cleanup();server.server_close()

if __name__=='__main__':main()
