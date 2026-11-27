'use strict';

const crypto = require('node:crypto');
const {gunzipSync} = require('node:zlib');
const {getResource,hasHostedProxy,resourceOrigin} = require('../providers');
const {debian,apk:compareApk} = require('../system-inventory/versions');
const {build} = require('../providers/package-releases');
const {responseFetchedAt} = require('../providers/common');
const {fresh} = require('../cache-policy');
const maxBytes = 192 * 1024 ** 2;
const namespace = 'package-release-catalogue-v1';

async function readResource(repo, opts, provider, type, params, parse, revision='') {
  const key = JSON.stringify([provider,type,params]);
  const saved = repo.get(namespace,key);
  const usable = saved && saved.metadata.revision === revision && (opts.offline || !hasHostedProxy() || saved.metadata.origin===resourceOrigin());
  if (usable && (opts.offline || revision || fresh(saved.fetchedAt))) return saved;
  if (opts.offline) return null;
  try {
    const timeout=AbortSignal.timeout(25000);
    const signal=opts.signal ? AbortSignal.any([timeout,opts.signal]) : timeout;
    const response = await getResource(provider,type,params,{fetcher:opts.fetcher,signal});
    if (!response.ok) { await response.body?.cancel(); return null; }
    const value = await parse(response);
    if (value == null) return null;
    const fetchedAt = responseFetchedAt(response);
    repo.put(namespace,key,value,{fetchedAt,metadata:{revision,origin:resourceOrigin()}});
    return {value,fetchedAt};
  } catch (error) { if(opts.signal?.aborted)throw error; return usable ? saved : null; }
}

async function readBytes(response,limit) {
  if(Number(response.headers.get('content-length'))>limit) {
    await response.body?.cancel();
    throw Error('Package index exceeds its size limit');
  }
  const chunks=[];
  let size=0;
  for await(const chunk of response.body) {
    size+=chunk.length;
    if(size>limit)throw Error('Package index exceeds its size limit');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks,size);
}

function manifest(text,arch) {
  const sha = /^SHA256:\n((?: [^\n]+\n)+)/m.exec(text)?.[1];
  if (!sha) return null;
  const files = new Map(), expanded = new Map();
  for (const line of sha.trim().split('\n')) {
    const [hash,n,file] = line.trim().split(/\s+/);
    const match = /^(\w[\w-]*)\/binary-([\w]+)\/Packages(?:\.(gz|xz))?$/.exec(file);
    if (!match || match[2]!==arch || !/^[a-f0-9]{64}$/.test(hash)) continue;
    const [section,ext] = [match[1],match[3]];
    if (!ext) expanded.set(section,Number(n));
    else if (ext==='gz' || !files.has(section)) files.set(section,{file,hash,size:Number(n),ext,section});
  }
  return [...files.values()].map(f=>({...f,expanded:expanded.get(f.section) ?? null}));
}

async function unpack(buffer,file) {
  if (file.ext==='gz') return gunzipSync(buffer,{maxOutputLength:maxBytes});
  // XZ-only pockets exist on Debian. The standalone CLI already embeds 7-Zip.
  const wasm = process.versions.bun ? (await import('./disk-wasm.mjs')).default : require.resolve('7z-wasm/7zz.wasm');
  const z = await require('7z-wasm')({wasmBinary:require('node:fs').readFileSync(wasm),print:()=>{},printErr:()=>{}});
  z.FS.writeFile('/Packages.xz',buffer);
  // Allow expansion only within the uncompressed size published in Release.
  if (file.expanded == null || file.expanded > maxBytes) throw Error('Unbounded package index');
  if (z.callMain(['e','-y','-txz','/Packages.xz','-o/'])!==0 || z.FS.stat('/Packages').size!==file.expanded) throw Error('Invalid XZ index');
  return Buffer.from(z.FS.readFile('/Packages'));
}

function packageIndex(text,arch,apk=false) {
  const packages = Object.create(null);
  const compare = apk ? compareApk : debian;
  for (const stanza of text.split('\n\n')) {
    const name=(apk ? /^P:(.+)$/m : /^Package: (.+)$/m).exec(stanza)?.[1];
    const version=(apk ? /^V:(.+)$/m : /^Version: (.+)$/m).exec(stanza)?.[1];
    const architecture=(apk ? /^A:(.+)$/m : /^Architecture: (.+)$/m).exec(stanza)?.[1];
    if (!name || !version || ![arch,apk?'noarch':'all'].includes(architecture)) continue;
    const source=(apk ? /^o:(\S+)/m : /^Source: (\S+)/m).exec(stanza)?.[1] || name;
    const key=[name,source,architecture].join('/');
    if (!packages[key] || compare(version,packages[key])>0) packages[key]=version;
  }
  return packages;
}

async function aptPocket(repo,opts,p,arch) {
  const load=(type,params,parse,rev)=>readResource(repo,opts,'package-releases',type,params,parse,rev);
  const release=await load('release',p,async r=>(await readBytes(r,8*1024**2)).toString());
  if (!release) return null;
  const entries=manifest(release.value,arch);
  if (!entries?.length) return null;
  const result=[];
  for (const f of entries) {
    const params={...p,file:f.file};
    const entry=await load('index',params,async response=>{
      if(f.size>48*1024**2 || f.expanded>maxBytes) return null;
      const buffer=await readBytes(response,f.size);
      if(buffer.length!==f.size || crypto.createHash('sha256').update(buffer).digest('hex')!==f.hash)return null;
      return packageIndex((await unpack(buffer,f)).toString(),arch);
    },f.hash);
    if (!entry) return null;
    result.push({packages:entry.value,source:p.suite+'/'+f.section,url:build('index',params).url,asOf:release.fetchedAt});
  }
  return result;
}

async function apkIndex(response,arch) {
  const extract=require('tar-stream').extract();
  let packages=null;
  extract.on('entry',(header,stream,next)=>{
    if(header.name!=='APKINDEX') {stream.on('end',next);stream.resume();return;}
    require('node:stream/consumers').text(stream).then(text=>{packages=packageIndex(text,arch,true);next();}).catch(error=>extract.destroy(error));
  });
  const data=gunzipSync(await readBytes(response,32*1024**2),{maxOutputLength:maxBytes});
  await require('node:stream/promises').pipeline(require('node:stream').Readable.from([data]),extract);
  return packages;
}

async function distroCatalogues(repo,opts,d,arch) {
  if(d?.id==='alpine') {
    const series=/^(\d+\.\d+)(?:\.\d+)?$/.exec(d.versionId)?.[1];
    if (!series) return [];
    const out=[];
    for(const section of ['main','community']) {
      const p={series:'v'+series,arch,section};
      const e=await readResource(repo,opts,'package-releases','apk',p,r=>apkIndex(r,arch));
      if(!e)return [];
      out.push({packages:e.value,source:p.series+'/'+section,url:build('apk',p).url,asOf:e.fetchedAt});
    }
    return out;
  }
  if(!['ubuntu','debian'].includes(d?.id) || !/^[a-z]{2,24}$/.test(d.codename || ''))return [];
  const series=d.codename, deb=d.id==='debian';
  const mirror=deb?'debian':['i386','amd64'].includes(arch)?'ubuntu':'ubuntu-ports';
  const archived=deb?'debian-archive':'ubuntu-archive';
  let archive=mirror, base=await aptPocket(repo,opts,{archive,suite:series},arch);
  if (!base) {archive=archived;base=await aptPocket(repo,opts,{archive,suite:series},arch);}
  if (!base)return [];
  const security=deb?archive+'-security':archive==='ubuntu'?'ubuntu-security':archive;
  const oldSecurity=deb && /^\d+$/.test(d.versionId) && Number(d.versionId)<11;
  const patches=await aptPocket(repo,opts,{archive:security,suite:series+(oldSecurity?'/updates':'-security')},arch);
  const updates=await aptPocket(repo,opts,{archive,suite:series+'-updates'},arch);
  if(!patches || !updates)return [];
  return [...base,...updates,...patches];
}
module.exports={readResource,distroCatalogues};
