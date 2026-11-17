'use strict';
// Read-only RPM database storage adapters. On-disk structures are based on
// rpm/lib/backend/ndb/rpmpkg.c and Berkeley DB dbinc/db_page.h.
const fs = require('node:fs');
const DEFAULT_LIMITS = Object.freeze({ maxDatabaseBytes: 8 * 1024 ** 3, maxHeaderBytes: 64 * 1024 ** 2, maxPackages: 1000000, maxPages: 2000000 });
const DIRS = ['/usr/lib/sysimage/rpm', '/var/lib/rpm'];
function adler32(buffer) { let a=1,b=0; for(let i=0;i<buffer.length;i++) {a=(a+buffer[i])%65521;b=(b+a)%65521;} return ((b<<16)|a)>>>0; }
function read(fd, start, length, size) {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length) || start < 0 || length < 0 || start+length > size) throw Error('truncated RPM database');
  const b=Buffer.alloc(length);let at=0;while(at<length){const n=fs.readSync(fd,b,at,length-at,start+at);if(!n)throw Error('truncated RPM database');at+=n;}return b;
}
function readNdb(file, { limits, onBlob }) {
  const fd=fs.openSync(file,'r'); try {
    const size=fs.fstatSync(fd).size;if(size>limits.maxDatabaseBytes || size%16)throw Error('invalid or oversized RPM NDB');
    const head=read(fd,0,32,size);if(head.toString('ascii',0,4)!=='RpmP' || head.readUInt32LE(4)!==0)throw Error('unsupported RPM NDB header');
    const pages=head.readUInt32LE(12);if(!pages || pages>limits.maxPages || pages*4096>size)throw Error('invalid RPM NDB slot pages');
    const slots=[],ids=new Set();
    for(let page=0;page<pages;page++) {
      const b=read(fd,page*4096,4096,size);
      for(let off=page===0?32:0;off<4096;off+=16) {
        if(b.toString('ascii',off,off+4)!=='Slot')throw Error('invalid RPM NDB slot');
        const id=b.readUInt32LE(off+4),start=b.readUInt32LE(off+8),count=b.readUInt32LE(off+12);if(!start)continue;
        if(!id||!count||start<pages*256||(start+count)*16>size||ids.has(id))throw Error('invalid RPM NDB slot bounds');
        ids.add(id);slots.push({id,start,count});if(slots.length>limits.maxPackages)throw Error('RPM package count limit exceeded');
      }
    }
    const ordered=[...slots].sort((a,b)=>a.start-b.start);for(let i=1;i<ordered.length;i++)if(ordered[i].start<ordered[i-1].start+ordered[i-1].count)throw Error('overlapping RPM NDB blobs');
    for(const slot of slots) {
      const len=slot.count*16;if(len>limits.maxHeaderBytes+32)throw Error('RPM header exceeds configured limit');
      const b=read(fd,slot.start*16,len,size),bodySize=b.readUInt32LE(12),tail=len-12;
      if(b.toString('ascii',0,4)!=='BlbS'||b.readUInt32LE(4)!==slot.id||Math.ceil((16+bodySize+12)/16)!==slot.count||b.toString('ascii',tail+8,tail+12)!=='BlbE'||b.readUInt32LE(tail+4)!==bodySize||b.readUInt32LE(tail)!==adler32(b.subarray(0,tail)))throw Error('invalid RPM NDB blob or checksum');
      onBlob(b.subarray(16,16+bodySize));
    }
  } finally {fs.closeSync(fd);}
}
function readBdb(file, { limits, onBlob }) {
  const fd=fs.openSync(file,'r');try {
    const size=fs.fstatSync(fd).size;if(size>limits.maxDatabaseBytes)throw Error('RPM Berkeley DB exceeds configured limit');
    const meta=read(fd,0,512,size);let le;
    if(meta.readUInt32LE(12)===0x00061561)le=true;else if(meta.readUInt32BE(12)===0x00061561)le=false;else throw Error('unsupported RPM Berkeley DB format');
    const u32=(b,o)=>le?b.readUInt32LE(o):b.readUInt32BE(o),u16=(b,o)=>le?b.readUInt16LE(o):b.readUInt16BE(o);
    const version=u32(meta,16),pageSize=u32(meta,20),last=u32(meta,32);
    if(meta[24] || meta[25]!==8 || version<7 || version>9 || pageSize<512 || pageSize>65536 || (pageSize&(pageSize-1)) || last>=limits.maxPages || (last+1)*pageSize>size)throw Error('unsupported or invalid RPM Berkeley DB metadata');
    const page=n=>{if(n>last)throw Error('RPM Berkeley DB page out of bounds');return read(fd,n*pageSize,pageSize,size);};
    let seen=0;
    for(let n=1;n<=last;n++) {
      const b=page(n),type=b[25];if(type!==2 && type!==13)continue;
      const count=u16(b,20);if(count%2 || 26+count*2>pageSize)throw Error('invalid RPM Berkeley DB hash page');
      const offsets=[];for(let i=0;i<count;i++){const o=u16(b,26+i*2);if(o<26+count*2||o>=pageSize)throw Error('invalid RPM Berkeley DB item offset');offsets.push(o);}
      for(let i=1;i<count;i+=2){
        // RPM reserves integer key zero for its next-header-number counter.
        const key=offsets[i-1];
        if(b[key]===1 && key+5<=pageSize && u32(b,key+1)===0) continue;
        const off=offsets[i],kind=b[off];let data;
        if(kind===3){
          if(off+12>pageSize)throw Error('invalid RPM Berkeley DB overflow item');let next=u32(b,off+4);const length=u32(b,off+8),parts=[];let actual=0;const visited=new Set();
          if(length>limits.maxHeaderBytes)throw Error('RPM header exceeds configured limit');
          while(next){if(visited.has(next)||visited.size>=limits.maxPages)throw Error('RPM Berkeley DB overflow cycle');visited.add(next);const part=page(next);if(part[25]!==7)throw Error('invalid RPM Berkeley DB overflow page');const nextPage=u32(part,16),available=nextPage?pageSize-26:u16(part,22);if(available>pageSize-26 || actual+available>length)throw Error('invalid RPM Berkeley DB overflow length');parts.push(part.subarray(26,26+available));actual+=available;next=nextPage;}
          if(actual!==length)throw Error('truncated RPM Berkeley DB overflow item');data=Buffer.concat(parts,actual);
        } else if(kind===1){
          const end=Math.min(pageSize,...offsets.filter(x=>x>off));data=b.subarray(off+1,end);if(data.length>limits.maxHeaderBytes)throw Error('RPM header exceeds configured limit');
        } else throw Error(`unsupported RPM Berkeley DB item type ${kind}`);
        if(++seen>limits.maxPackages)throw Error('RPM package count limit exceeded');onBlob(data);
      }
    }
  }finally{fs.closeSync(fd);}
}
const adapters = [
  {id:'sqlite', filename:'rpmdb.sqlite', read(file,ctx,onBlob) {if(fs.statSync(file).size>ctx.limits.maxDatabaseBytes)throw Error('RPM SQLite exceeds configured limit');const db=ctx.openSqlite(file,{readonly:true});try{const stmt=db.prepare(`SELECT blob FROM Packages LIMIT ${ctx.limits.maxPackages + 1}`), rows=typeof stmt.iterate==='function'?stmt.iterate():stmt.all();let n=0;for(const row of rows){if(++n>ctx.limits.maxPackages||row.blob.length>ctx.limits.maxHeaderBytes)throw Error('RPM SQLite resource limit exceeded');onBlob(row.blob);}}finally{db.close();}}},
  {id:'ndb', filename:'Packages.db', read(file,ctx,onBlob) {readNdb(file,{limits:ctx.limits,onBlob});}},
  {id:'bdb', filename:'Packages', read(file,ctx,onBlob) {readBdb(file,{limits:ctx.limits,onBlob});}},
];
async function readRpmStorage(root, options) {
  const limits={...DEFAULT_LIMITS,...options.limits};for(const [k,v] of Object.entries(limits))if(!Number.isSafeInteger(v)||v<1)throw Error(`invalid RPM storage limit ${k}`);
  const ctx={...options,limits}, available=options.rpmStorageAdapters || adapters, ids=new Set();
  for(const a of available){if(!a||!a.id||ids.has(a.id)||typeof a.read!=='function'||(!a.filename&&typeof a.probe!=='function'))throw Error('invalid RPM storage adapter');ids.add(a.id);}
  for(const dir of DIRS)for(const adapter of available){
    const manifestPath=adapter.filename ? `${dir}/${adapter.filename}` : null;
    const file=adapter.probe ? await adapter.probe(root,ctx,dir) : options.safeFile(root,manifestPath);if(!file)continue;
    const packages=[],warnings=[];let reason;
    try {await adapter.read(file,ctx,blob=>{try{const header=options.rpmHeader(blob);packages.push({...header,manifestPath});if(header.ownershipIncomplete)warnings.push(`RPM ${adapter.id}: package file ownership incomplete`);}catch(e){warnings.push(`RPM header: ${e.message}`);}});}catch(e){reason=e.message;warnings.push(`RPM ${adapter.id}: ${e.message}`);}
    return {packages,coverage:{collector:'rpm',backend:adapter.id,status:reason||warnings.length?'incomplete':'complete',count:packages.length,...(reason?{reason}: {})},warnings};
  }
  return null;
}
module.exports={readRpmStorage,readNdb,readBdb,adapters,DEFAULT_LIMITS};
