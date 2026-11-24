#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re, math, json, csv, collections, pathlib

RULES = [( 'Private key', r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----', 98), ('AWS access key ID',r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',90),('Google API key',r'\bAIza[\w-]{35}\b',90),('GitHub token',r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[\w]{30,})\b',95),('Stripe secret key',r'\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b',95),('Slack token',r'\bxox[baprs]-[\w-]{10,}',95),('JWT-like token',r'\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]+',90),('Credential assignment',r'(?i)(?:api[_ -]?key|client[_ -]?secret|password|refresh[_ -]?token|access[_ -]?token)\s*[=:]\s*[\"\']?[^\s\"\']{4,}',85),('Credential URL',r'\w+://[^\s:/]+:[^\s@]+@',90)]
def entropy(s):
    return -sum((n/len(s))*math.log2(n/len(s)) for n in collections.Counter(s).values()) if s else 0

def classify(s):
    for name, pattern, score in RULES:
        if re.search(pattern,s): return score,name
    if re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',s): return 25,'UUID / possible identifier'
    if re.fullmatch(r'[0-9a-fA-F]{16,}',s):
        if len(s)%2==0:
            b=bytes.fromhex(s)
            if len(b)>5 and all((y-x)%256==1 for x,y in zip(b,b[1:])): return 5,'Sequential hex'
        return 45,'Hex / possible hash or secret'
    if re.fullmatch(r'\d+',s): return 15,'Numeric constant / identifier'
    if re.search(r'^(?:_Z[NTSV]|\d+(?:function|optional|allocator)I)|(?:EEE|ERKN|ENS\d|INSt6)',s) and (len(re.findall(r'\d+[A-Za-z_]',s))>=2 or re.search(r'EEE|ERKN|ENS\d',s)): return 8,'Probable C++ symbol'
    if re.fullmatch(r'(?i)(?:null|undefined|changeme|example|placeholder|your[_-]?api[_-]?key|password|secret|token|test)',s): return 10,'Placeholder'
    if len(s)>=16 and entropy(s)>=3.8 and re.fullmatch(r'[A-Za-z0-9_+/=.-]+',s): return 60,'Opaque high-entropy candidate'
    if len(s)>=8: return 35,'Unclassified string'
    return 20,'Short string'

def load(path):
    p=pathlib.Path(path); raw=p.read_text(encoding='utf-8-sig',errors='replace')
    if p.suffix.lower()=='.json':
        obj=json.loads(raw)
        if isinstance(obj,dict):
            if 'secrets' not in obj: raise ValueError('JSON must contain a secrets array, or be an array of strings.')
            obj=obj['secrets']
        if not isinstance(obj,list) or not all(isinstance(x,str) for x in obj): raise ValueError('Expected an array of strings.')
        return obj
    if p.suffix.lower()=='.csv':
        reader=csv.DictReader(raw.splitlines()); fields=reader.fieldnames or []
        key=next((k for k in fields if k.lower() in ('secret','value','string','match')),None)
        if not key: raise ValueError('CSV needs a secret, value, string or match column.')
        return [r[key] for r in reader if r.get(key)]
    return raw.splitlines()

def records(values):
    counts=collections.Counter(s.strip() for s in values if s.strip()); out=[]
    for s,n in counts.items():
        score,kind=classify(s); out.append(dict(value=s,count=n,score=score,kind=kind,entropy=round(entropy(s),2),status='Noise' if score<=10 else 'Unreviewed'))
    return out

class App:
    def __init__(self,root):
        self.root=root; self.data=[]; root.title('Secret Triage — Offline MobSF Review'); root.geometry('1100x700'); self.query=tk.StringVar(); self.filter=tk.StringVar(value='Active'); self.reveal=tk.BooleanVar(value=True); self.regex=tk.BooleanVar(value=False)
        bar=ttk.Frame(root,padding=8); bar.pack(fill='x')
        for label,fn in [('Import',self.open),('Save review',self.save),('Load review',self.resume),('Export CSV',self.export)]: ttk.Button(bar,text=label,command=fn).pack(side='left',padx=3)
        ttk.Checkbutton(bar,text='Reveal values',variable=self.reveal,command=self.refresh).pack(side='right')
        search=ttk.Frame(root,padding=8); search.pack(fill='x'); ttk.Label(search,text='Search:').pack(side='left'); ttk.Entry(search,textvariable=self.query).pack(side='left',fill='x',expand=True); ttk.Checkbutton(search,text='Regex',variable=self.regex,command=self.refresh).pack(side='left'); ttk.Combobox(search,textvariable=self.filter,values=['Active','All','High (80+)','Medium (50–79)','Low (<50)','Noise','Confirmed','Unreviewed'],state='readonly',width=18).pack(side='left'); self.query.trace_add('write',lambda *_:self.refresh()); self.filter.trace_add('write',lambda *_:self.refresh())
        frame=ttk.Frame(root); frame.pack(fill='both',expand=True); self.tree=ttk.Treeview(frame,columns=('score','kind','count','entropy','status','value'),show='headings',selectmode='extended'); scroll=ttk.Scrollbar(frame,command=self.tree.yview); self.tree.configure(yscrollcommand=scroll.set); scroll.pack(side='right',fill='y'); self.tree.pack(fill='both',expand=True)
        for col,w in zip(self.tree['columns'],[65,220,65,70,110,500]): self.tree.heading(col,text=col.title(),command=lambda c=col:self.sort(c)); self.tree.column(col,width=w,stretch=col=='value')
        for tag,color in [('high','#ffe0e0'),('medium','#fff0cc'),('noise','#e5e5e5')]: self.tree.tag_configure(tag,background=color,foreground='#202020')
        self.detail=tk.Text(root,height=5,wrap='word'); self.detail.pack(fill='x',padx=8,pady=5); self.tree.bind('<<TreeviewSelect>>',self.inspect)
        bottom=ttk.Frame(root,padding=8); bottom.pack(fill='x');
        for status in ['Confirmed','Noise','Unreviewed']: ttk.Button(bottom,text='Mark '+status,command=lambda s=status:self.mark(s)).pack(side='left',padx=3)
        ttk.Button(bottom,text='Suppress search matches',command=self.bulk).pack(side='left'); self.info=ttk.Label(bottom); self.info.pack(side='right'); self.order='score'; self.reverse=True; self.refresh()
    def open(self):
        p=filedialog.askopenfilename(filetypes=[('Supported','*.txt *.json *.csv'),('All','*')]);
        if p:
            try: self.data=records(load(p)); self.refresh()
            except Exception as e: messagebox.showerror('Import error',str(e))
    def sort(self,c): self.reverse=not self.reverse if self.order==c else True; self.order=c; self.refresh()
    def mask(self,s): return s if self.reveal.get() else '[masked — '+str(len(s))+' chars]'
    def refresh(self):
        self.tree.delete(*self.tree.get_children()); self.detail.delete('1.0','end'); q=self.query.get(); f=self.filter.get(); self.visible=[]
        try: rx=re.compile(q,re.I) if self.regex.get() else None
        except re.error: self.info.config(text='Invalid regex'); return
        for i,r in sorted(enumerate(self.data),key=lambda x:x[1][self.order],reverse=self.reverse):
            s=r['score']; st=r['status']; hay=r['value']+' '+r['kind'];
            if q and not (rx.search(hay) if rx else q.lower() in hay.lower()): continue
            if f=='Active' and st=='Noise' or f=='High (80+)' and s<80 or f=='Medium (50–79)' and not 50<=s<80 or f=='Low (<50)' and s>=50 or f in ('Noise','Confirmed','Unreviewed') and st!=f: continue
            self.visible.append(i); self.tree.insert('', 'end',iid=str(i),values=(s,r['kind'],r['count'],r['entropy'],st,self.mask(r['value'])),tags=('noise' if st=='Noise' else 'high' if s>=80 else 'medium' if s>=50 else '',))
        self.info.config(text=f'{len(self.visible)} shown / {len(self.data)} unique / {sum(r["count"] for r in self.data)} total')
    def inspect(self,event=None):
        self.detail.delete('1.0','end'); sel=self.tree.selection();
        if sel:
            r=self.data[int(sel[0])]; self.detail.insert('end',f'{r["kind"]} | score {r["score"]} | occurrences {r["count"]}\n'+self.mask(r['value']))
    def mark(self,s):
        for i in self.tree.selection(): self.data[int(i)]['status']=s
        self.refresh()
    def bulk(self):
        if self.query.get() and messagebox.askyesno('Suppress',f'Mark all {len(self.visible)} visible search matches as noise?'):
            for i in self.visible: self.data[i]['status']='Noise'
            self.refresh()
    def save(self):
        if not messagebox.askyesno('Sensitive data','Review JSON contains original unredacted strings. Continue?'): return
        p=filedialog.asksaveasfilename(defaultextension='.json');
        if p: pathlib.Path(p).write_text(json.dumps(self.data,indent=2),encoding='utf-8')
    def resume(self):
        p=filedialog.askopenfilename();
        if p:
            try:
                data=json.loads(pathlib.Path(p).read_text()); assert isinstance(data,list) and all(set(('value','count','score','kind','entropy','status'))<=r.keys() for r in data); self.data=data; self.refresh()
            except Exception as e: messagebox.showerror('Invalid review',str(e))
    def export(self):
        raw=messagebox.askyesnocancel('Export','Export original values? Yes = unredacted; No = masked; Cancel = abort.');
        if raw is None:return
        p=filedialog.asksaveasfilename(defaultextension='.csv');
        if p:
            with open(p,'w',newline='',encoding='utf-8') as f:
                w=csv.DictWriter(f,fieldnames=['value','count','score','kind','entropy','status']); w.writeheader()
                for i in self.visible:
                    r=self.data[i].copy(); r['value']=r['value'] if raw else '[masked]'; r={k: "'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v for k,v in r.items()}; w.writerow(r)
if __name__=='__main__':
    root=tk.Tk(); App(root); root.mainloop()
