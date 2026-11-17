// Go linker build-info blob; supports inline and pre-1.18 pointer formats.
const MAGIC = Buffer.from('\xff Go buildinf:', 'latin1');
function extractGoBuildInfo({read, segments, mapped, max}) {
 try {
  let budget = max, skipped = false;
  for (const s of segments.filter(x => x.type === 1 && (x.flags & 2) && x.filesz)) {
   if (s.filesz > budget) { skipped = true; continue; }
   budget -= s.filesz;
   const b = read(s.offset,s.filesz);
   for (let pos = b.indexOf(MAGIC); pos >= 0; pos = b.indexOf(MAGIC,pos+1)) {
    if ((s.vaddr+pos)%16 || pos+32>b.length) continue;
    const ptrSize=b[pos+14], flags=b[pos+15]; if (![4,8].includes(ptrSize) || (flags & ~3)) continue;
    const le=!(flags&1);
    const ptr=(buf,p) => { const n=ptrSize===4 ? BigInt(le?buf.readUInt32LE(p):buf.readUInt32BE(p)) : le?buf.readBigUInt64LE(p):buf.readBigUInt64BE(p); if(n>BigInt(Number.MAX_SAFE_INTEGER)) throw Error('pointer overflow'); return Number(n); };
    const memory=(addr,n)=>read(mapped(addr,n),n);
    let version, mod;
    if (flags&2) {
     let p=pos+32;
     const string=()=>{ let n=0, mult=1, c, count=0; do { if(p>=b.length || count++>=8) throw Error('varint'); c=b[p++]; n+=(c&127)*mult; mult*=128; } while(c&128); if(!Number.isSafeInteger(n) || n>max || p+n>b.length) throw Error('string bounds'); const t=b.toString('latin1',p,p+n); p+=n; return t; };
     version=string(); mod=string();
    } else {
     const str=addr=>{ if(!addr)return ''; const hdr=memory(addr,ptrSize*2), start=ptr(hdr,0), len=ptr(hdr,ptrSize); if(len>max) throw Error('string limit'); return memory(start,len).toString('latin1'); };
     version=str(ptr(b,pos+16)); mod=str(ptr(b,pos+16+ptrSize));
    }
    if (!version.startsWith('go')) continue;
    // Module text is surrounded by 16-byte sentinels, as in debug/buildinfo.
    if (mod.length >= 33 && mod[mod.length-17] === '\n') mod=Buffer.from(mod.slice(16,-16),'latin1').toString('utf8'); else mod='';
    const modules=[],settings={}; let last=null;
    for (const line of mod.split('\n')) { const f=line.split('\t'); if ((f[0]==='mod'||f[0]==='dep') && f.length>=3) { last={kind:f[0],path:f[1],version:f[2],sum:f[3]||null}; modules.push(last); } else if(f[0]==='=>' && last && f.length>=2) last.replace={path:f[1],version:f[2] || null,sum:f[3]||null}; else if(f[0]==='build' && f.length===2) { const i=f[1].indexOf('='); if(i>0) {const key=f[1].slice(0,i),value=f[1].slice(i+1);if(/^[A-Za-z0-9_.-]{1,80}$/.test(key) && value.length<=1024) {if(Object.hasOwn(settings,key))settings[key]=null;else settings[key]=value;}} } }
    return { version, modules, settings };
   }
  }
  if (skipped) return {status:'unavailable',reason:'Go build information search exceeded metadata limit'};
 } catch { return {status:'unavailable',reason:'Malformed Go build information'}; }
 return null;
}
module.exports={extractGoBuildInfo};
