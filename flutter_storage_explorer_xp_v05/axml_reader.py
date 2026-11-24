"""Read-only Android AXML decoder for common APK manifest and res/xml files.
Pure Python, no SDK dependency. Parses chunk/string/namespace/attribute structures;
unsupported chunks are ignored rather than executed.
"""
import struct
import xml.etree.ElementTree as ET

class AxmlError(ValueError): pass

TYPE_NAMES={0x01:'reference',0x02:'attribute',0x03:'string',0x04:'float',0x05:'dimension',0x06:'fraction',0x10:'int',0x11:'hex',0x12:'boolean',0x1c:'color',0x1d:'color',0x1e:'color',0x1f:'color'}
ANDROID_URI='http://schemas.android.com/apk/res/android'

def decode(data):
    def u16(p):
        if p+2>len(data):raise AxmlError('truncated u16')
        return struct.unpack_from('<H',data,p)[0]
    def u32(p):
        if p+4>len(data):raise AxmlError('truncated u32')
        return struct.unpack_from('<I',data,p)[0]
    def len8(p):
        n=data[p];p+=1
        if n&0x80: n=((n&0x7f)<<8)|data[p];p+=1
        return n,p
    def len16(p):
        n=u16(p);p+=2
        if n&0x8000:n=((n&0x7fff)<<16)|u16(p);p+=2
        return n,p
    if len(data)<8 or u16(0)!=0x0003:raise AxmlError('not binary Android XML')
    end=u32(4)
    if end>len(data) or end<8:raise AxmlError('invalid AXML length')
    strings=[]; pos=u16(2); ns={}; stack=[]; root=None
    while pos+8<=end:
        typ=u16(pos); header=u16(pos+2); size=u32(pos+4)
        if header<8 or size<header or pos+size>end:raise AxmlError('invalid chunk boundary')
        if typ==1:
            if header<28:raise AxmlError('invalid string pool')
            count=u32(pos+8); flags=u32(pos+16); start=u32(pos+20)
            if count>200000:raise AxmlError('oversized string pool')
            for i in range(count):
                off=u32(pos+header+4*i); p=pos+start+off
                if not (pos<=p<pos+size):raise AxmlError('invalid string offset')
                if flags&0x100:
                    _,p=len8(p);n,p=len8(p);s=data[p:p+n].decode('utf-8','replace')
                else:
                    n,p=len16(p);s=data[p:p+2*n].decode('utf-16le','replace')
                strings.append(s)
        elif typ==0x100:
            if size>=24:
                prefix=u32(pos+16);uri=u32(pos+20)
                if prefix<len(strings) and uri<len(strings):ns[strings[uri]]=strings[prefix]
        elif typ==0x102:
            if header<16 or size<36:raise AxmlError('invalid start element')
            ns_id=u32(pos+16);name_id=u32(pos+20);attr_start=u16(pos+24);attr_size=u16(pos+26);attr_count=u16(pos+28)
            if name_id>=len(strings) or attr_count>10000 or attr_size<20:raise AxmlError('invalid element')
            namespace=strings[ns_id] if ns_id<len(strings) else ''
            name=('{%s}'%namespace if namespace else '')+strings[name_id]
            element=ET.Element(name)
            base=pos+16+attr_start
            for i in range(attr_count):
                p=base+i*attr_size
                if p+20>pos+size:raise AxmlError('invalid attribute boundary')
                an=u32(p);key=u32(p+4);raw=u32(p+8);vtype=data[p+15];value=u32(p+16)
                if key>=len(strings):continue
                ans=strings[an] if an<len(strings) else ''
                k=('{%s}'%ans if ans else '')+strings[key]
                if raw<len(strings):v=strings[raw]
                elif vtype==3:v=strings[value] if value<len(strings) else '<invalid string>'
                elif vtype==0x12:v='true' if value else 'false'
                elif vtype==0x10:v=str(value if value<0x80000000 else value-0x100000000)
                elif vtype==0x11:v='0x%08x'%value
                elif vtype==1:v='@0x%08x'%value
                elif vtype==2:v='?0x%08x'%value
                elif 0x1c<=vtype<=0x1f:v='#%08x'%value
                elif vtype==4:v=str(struct.unpack('<f',struct.pack('<I',value))[0])
                else:v='0x%08x (type 0x%02x)'%(value,vtype)
                element.set(k,v)
            if stack:stack[-1].append(element)
            else:root=element
            stack.append(element)
        elif typ==0x103:
            if stack:stack.pop()
        elif typ==0x104:
            if stack and size>=28:
                sid=u32(pos+16)
                if sid<len(strings):stack[-1].text=(stack[-1].text or '')+strings[sid]
        pos+=size
    if root is None:raise AxmlError('No XML root element')
    for uri,prefix in ns.items():
        try:ET.register_namespace(prefix,uri)
        except ValueError:pass
    ET.indent(root,space='  ')
    return '<?xml version="1.0" encoding="utf-8"?>\n'+ET.tostring(root,encoding='unicode')
