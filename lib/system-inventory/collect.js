'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {openSqlite} = require('../sqlite-driver');

function safeFile(root, name) {
 const base = fs.realpathSync(root), candidate = path.join(base, name.replace(/^\/+/, ''));
 try { const real = fs.realpathSync(candidate); return real === base || real.startsWith(base + path.sep) ? real : null; }
 catch { return null; }
}
function read(root, name, opts={}) { const limit=opts.maxSystemMetadataBytes ?? 64*1024*1024; if(!Number.isSafeInteger(limit)||limit<1)throw Error('invalid system metadata size limit');const file=safeFile(root,name);if(!file)return null;const st=fs.statSync(file);if(!st.isFile()||st.size>limit)throw Error(`system metadata is not a bounded regular file: ${name}`);return fs.readFileSync(file,'utf8'); }
function osRelease(text) {
 const out = {};
 for (const line of (text || '').split(/\r?\n/)) {
  const m = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/); if (!m) continue;
  let v=m[2].trim();
  if (v.startsWith('"') && v.endsWith('"')) v=v.slice(1,-1).replace(/\\([\\"$`])/g,'$1');
  else if (v.startsWith("'") && v.endsWith("'")) v=v.slice(1,-1);
  out[m[1]]=v;
 }
 return {id:out.ID || null, versionId:out.VERSION_ID || null, codename:out.VERSION_CODENAME || null, idLike:out.ID_LIKE || null, name:out.PRETTY_NAME || out.NAME || null};
}
function fields(text) {
 const out={}; let key;
 for(const line of text.split(/\r?\n/)) {
  if (/^[ \t]/.test(line) && key) {out[key]+='\n'+line.slice(1); continue;}
  const m=line.match(/^([^:]+):\s*(.*)$/); if(m) {key=m[1];out[key]=m[2];}
 }
 return out;
}
function base(name,version,architecture,manager,manifestPath,extra={}) {return {name,version,architecture:architecture || null,manager,manifestPath,ecosystem:'system',provenance:'installed',...extra};}
const dpkg={id:'dpkg', async collect(root,opts={}) {
 const p='/var/lib/dpkg/status', text=read(root,p,opts); if(text===null)return null;
 const packages=[], warnings=[];
 for(const stanza of text.split(/\r?\n\r?\n/)) {
  if(!stanza.trim())continue;const f=fields(stanza);
  if(!f.Package || !/^(unknown|install|hold|deinstall|purge) (ok|reinstreq) (not-installed|config-files|half-installed|unpacked|half-configured|triggers-awaited|triggers-pending|installed)$/.test(f.Status || '') || (!f.Version && /\binstalled$/.test(f.Status))){warnings.push('Malformed dpkg status record');continue;}
  if(!/^\S+\s+\S+\s+installed$/.test(f.Status))continue;
  const s=(f.Source || '').match(/^([^\s(]+)(?:\s*\(([^)]+)\))?$/);
  if(f.Source && !s)warnings.push('Malformed dpkg source identity');
  const binaryRebuild=/\+b\d+$/.test(f.Version);
  const infoName=/^[a-z0-9][a-z0-9+.-]*$/.test(f.Package) ? f.Package : null;
  let list=null;try{if(infoName)list=read(root,`/var/lib/dpkg/info/${infoName}:${f.Architecture}.list`,opts) ?? read(root,`/var/lib/dpkg/info/${infoName}.list`,opts);}catch(e){warnings.push('dpkg file ownership: '+e.message);}
  const ownedPaths=list ? list.split(/\r?\n/).filter(line=>line.startsWith('/') && !line.split('/').includes('..')) : [];
  packages.push(base(f.Package,f.Version,f.Architecture,'dpkg',p,{sourceName:f.Source ? s?.[1] || null : f.Package,sourceVersion:f.Source && !s ? null : s?.[2] || (binaryRebuild ? null : f.Version),ownedPaths,packageMetadata:{origin:f.Origin||null,maintainer:f.Maintainer||null,homepage:f.Homepage||null}}));
 }
 return {packages,coverage:{collector:'dpkg',status:warnings.length?'incomplete':'complete',count:packages.length},warnings};
}};
const apk={id:'apk', async collect(root,opts={}) {
 const p='/lib/apk/db/installed', text=read(root,p,opts); if(text===null)return null;
 const packages=[],warnings=[];
 for(const stanza of text.split(/\r?\n\r?\n/)) {
  if(!stanza.trim())continue;const f=fields(stanza); if(!f.P || !f.V){warnings.push('Malformed APK installed record');continue;}
  let dir='';const ownedPaths=[];
  for(const line of stanza.split(/\r?\n/)){if(line.startsWith('F:'))dir=line.slice(2);else if(line.startsWith('R:')){const name=line.slice(2),fp='/'+[dir,name].filter(Boolean).join('/');if(!fp.split('/').includes('..'))ownedPaths.push(fp);}}
  packages.push(base(f.P,f.V,f.A,'apk',p,{sourceName:f.o || f.P,sourceVersion:f.V,ownedPaths,packageMetadata:{maintainer:f.m||null,homepage:f.U||null}}));
 }
 return {packages,coverage:{collector:'apk',status:warnings.length?'incomplete':'complete',count:packages.length},warnings};
}};
// RPM database blobs consist of header index count, data length, entries and data;
// some producers include the 8-byte header magic while database blobs omit it.
function rpmHeader(input) {
 const b=Buffer.from(input); let start=0;
 if(b.length>=8 && b.subarray(0,4).equals(Buffer.from([0x8e,0xad,0xe8,1])))start=8;
 if(b.length<start+8)throw Error('truncated RPM header');
 const n=b.readUInt32BE(start), size=b.readUInt32BE(start+4), data=start+8+n*16;
 if(n>100000 || size>64*1024*1024 || data+size>b.length)throw Error('invalid RPM header bounds');
 const tags={};
 for(let i=0;i<n;i++) {
  const pos=start+8+i*16, tag=b.readUInt32BE(pos), type=b.readUInt32BE(pos+4), off=b.readUInt32BE(pos+8), count=b.readUInt32BE(pos+12);
  if(![1000,1001,1002,1003,1022,1044,1116,1117,1118].includes(tag))continue;
  if(off>=size)throw Error('invalid RPM tag offset');
  if(count>1000000)throw Error('RPM tag count limit exceeded');
  if(type===6 || type===8 || type===9) {
   let cursor=data+off;const values=[];const total=type===6?1:count;
   for(let j=0;j<total;j++){const end=b.indexOf(0,cursor);if(end<0 || end>=data+size)throw Error('invalid RPM string');values.push(b.toString('utf8',cursor,end));cursor=end+1;}
   tags[tag]=type===6?values[0]:values;
  } else if(type===4 && count>0 && off+count*4<=size) {
   const values=[];for(let j=0;j<count;j++)values.push(b.readUInt32BE(data+off+j*4));
   tags[tag]=tag===1116?values:values[0];
  } else throw Error('unsupported or invalid RPM tag type');
 }
 if(!tags[1000] || !tags[1001] || !tags[1002])throw Error('RPM header lacks NEVR');
 const version=(tags[1003] ? tags[1003]+':' : '')+tags[1001]+'-'+tags[1002];
 const source=tags[1044]?.match(/^(.*)-([^-]+)-([^-]+)\.src\.rpm$/);
 const ownedPaths=[];let ownershipIncomplete=false;
 if(tags[1116] || tags[1117] || tags[1118]) {
  if(!Array.isArray(tags[1116]) || !Array.isArray(tags[1117]) || !Array.isArray(tags[1118]) || tags[1116].length!==tags[1117].length)throw Error('invalid RPM file list');
  for(let i=0;i<tags[1117].length;i++){
   const dir=tags[1118][tags[1116][i]],name=tags[1117][i];
   if(dir==='/' && name===''){ownedPaths.push('/');continue;}
   if(typeof dir!=='string' || !dir.startsWith('/') || !name || name.includes('/') || dir.split('/').includes('..')){ownershipIncomplete=true;continue;}
   ownedPaths.push(path.posix.join(dir,name));
  }
 }
 return {name:tags[1000],version,architecture:tags[1022] || null,sourceName:source?.[1] || null,sourceVersion:source && !tags[1003] ? source[2]+'-'+source[3] : null,ownedPaths,...(ownershipIncomplete?{ownershipIncomplete:true}:{})};
}
const rpm={id:'rpm',async collect(root,opts={}) {
 const result=await require('./rpm-storage').readRpmStorage(root,{safeFile,openSqlite,rpmHeader,rpmStorageAdapters:opts.rpmStorageAdapters,limits:opts.rpmStorageLimits});
 if(!result)return null;
 return {...result,packages:result.packages.map(h=>base(h.name,h.version,h.architecture,'rpm',h.manifestPath,h))};
}};

async function collectSystemInventory(root,opts={}) {
 const packages=[],coverage=[],warnings=[];let distribution;
 try {const text=read(root,'/etc/os-release',opts) || read(root,'/usr/lib/os-release',opts);distribution=osRelease(text);if(!distribution.id || !distribution.versionId){coverage.push({collector:'os-release',status:'incomplete',reason:'missing distribution ID or version'});warnings.push('Distribution identity is missing or incomplete');}}
 catch(e){distribution=osRelease(null);coverage.push({collector:'os-release',status:'incomplete',reason:e.message});warnings.push('Distribution identity: '+e.message);}
 const active=opts.collectors || [dpkg,apk,rpm], ids=new Set();
 if(!Array.isArray(active))throw Error('invalid system collector registry');
 for(const c of active){if(!c || typeof c.id!=='string' || !c.id || ids.has(c.id) || typeof c.collect!=='function')throw Error('invalid system collector registry');ids.add(c.id);}
 for(const collector of active) {
  try {const result=await collector.collect(root,opts);if(!result)continue;coverage.push(result.coverage);warnings.push(...(result.warnings||[]));packages.push(...result.packages.map(p=>({...p,distribution})));}
  catch(e){coverage.push({collector:collector.id,status:'incomplete',reason:e.message});warnings.push(`${collector.id}: ${e.message}`);}
 }
 if(!coverage.some(c=>c.collector!=='os-release'))coverage.push({collector:'system',status:'unknown',reason:'no supported package database found'});
 return {packages,distribution,coverage,warnings};
}
module.exports={collectSystemInventory,osRelease,rpmHeader,collectors:[dpkg,apk,rpm],safeFile};
