'use strict';

// Optional compact NVD enrichment snapshots. The traditional per-CVE cache is
// still read and written separately. Each immutable generation is sharded so
// one lookup does not parse the entire mirror.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const shardName = id => hash(id).slice(0, 2) + '.json';
const cached = new Map();
const MAX_CACHED_SHARDS = 4;
const MAX_SHARD_BYTES = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 128 * 1024;

function shard(root, generation, manifest, name) {
 const expected = manifest.shards?.[name];
 if (typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected)) return null;
 const file = path.join(root, generation, name), cacheKey = file + ':' + expected;
 if (cached.has(cacheKey)) { const item = cached.get(cacheKey); cached.delete(cacheKey); cached.set(cacheKey,item); return item; }
 try {
  if (fs.statSync(file).size > MAX_SHARD_BYTES) return null;
  const bytes = fs.readFileSync(file);
  if (hash(bytes) !== expected) return null;
  const data = JSON.parse(bytes.toString('utf8'));
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  cached.set(cacheKey,data);
  while (cached.size > MAX_CACHED_SHARDS) cached.delete(cached.keys().next().value);
  return data;
 } catch { return null; }
}

function readBulk(cacheDir, id) {
 if (!/^CVE-\d{4}-\d{4,}$/i.test(id)) return null;
 const root = path.join(cacheDir, '_bulk'); let names;
 try { names = fs.readdirSync(root).filter(x => /^\d{10,16}-[a-f0-9]{64}$/.test(x)).sort().reverse(); }
 catch { return null; }
 for (const name of names) {
  try {
   const manifestFile=path.join(root,name,'manifest.json');
   if (fs.statSync(manifestFile).size > MAX_MANIFEST_BYTES) continue;
   const bytes = fs.readFileSync(manifestFile);
   if (hash(bytes) !== name.split('-')[1]) continue;
   const meta = JSON.parse(bytes.toString('utf8'));
   if (meta.schema !== 1 || !Number.isSafeInteger(meta.fetchedAt) || meta.fetchedAt <= 0 || meta.fetchedAt > Date.now()+300000 || String(meta.fetchedAt) !== name.split('-')[0]) continue;
   const data = shard(root,name,meta,shardName(id)), body = data?.[id];
   if (body && typeof body === 'object' && !Array.isArray(body) && body.id === id) return {_schema:1,_fetchedAt:meta.fetchedAt,body};
  } catch { /* Invalid generation cannot establish a cache hit. */ }
 }
 return null;
}

// Validate metadata without loading record shards. The generation name is
// content-addressed; an explicit name is needed for staged atomic imports.
function readManifest(dir, generationName = path.basename(dir)) {
 if (!/^\d{10,16}-[a-f0-9]{64}$/.test(generationName)) throw new Error('invalid compact NVD generation name');
 const manifestFile=path.join(dir,'manifest.json');
 if (!fs.statSync(dir).isDirectory() || fs.statSync(manifestFile).size > MAX_MANIFEST_BYTES) throw new Error('invalid compact NVD manifest');
 const bytes=fs.readFileSync(manifestFile);
 if (hash(bytes)!==generationName.split('-')[1]) throw new Error('compact NVD manifest checksum mismatch');
 const meta=JSON.parse(bytes.toString('utf8'));
 if (meta?.schema!==1 || !Number.isSafeInteger(meta.fetchedAt) || meta.fetchedAt<=0 || meta.fetchedAt>Date.now()+300000 || String(meta.fetchedAt)!==generationName.split('-')[0] || !Number.isSafeInteger(meta.count) || meta.count<0 || !meta.shards || typeof meta.shards!=='object' || Array.isArray(meta.shards)) throw new Error('invalid compact NVD manifest');
 const names=Object.keys(meta.shards);
 if(names.length>256 || names.some(k=>!/^[a-f0-9]{2}\.json$/.test(k) || !/^[a-f0-9]{64}$/.test(meta.shards[k]))) throw new Error('invalid compact NVD shard list');
 return meta;
}

function validateGeneration(dir, generationName = path.basename(dir)) {
 const meta=readManifest(dir,generationName),names=Object.keys(meta.shards),actual=fs.readdirSync(dir);
 if(actual.length!==names.length+1 || actual.some(k=>k!=='manifest.json' && !Object.hasOwn(meta.shards,k))) throw new Error('unexpected compact NVD snapshot file');
 let total=0;
 for(const shardFile of names) {
  const file=path.join(dir,shardFile);
  if(!fs.statSync(file).isFile() || fs.statSync(file).size>MAX_SHARD_BYTES)throw new Error('invalid compact NVD shard');
  const raw=fs.readFileSync(file);
  if(hash(raw)!==meta.shards[shardFile]) throw new Error('compact NVD shard checksum mismatch');
  const entries=JSON.parse(raw.toString('utf8'));
  if(!entries || typeof entries!=='object' || Array.isArray(entries)) throw new Error('invalid compact NVD shard');
  for(const [id,body] of Object.entries(entries)) {
   if(!/^CVE-\d{4}-\d{4,}$/.test(id) || shardName(id)!==shardFile || !body || typeof body!=='object' || Array.isArray(body) || body.id!==id) throw new Error('invalid compact NVD record');
   total++;
  }
 }
 if(total!==meta.count) throw new Error('compact NVD record count mismatch');
 return {records:total,fetchedAt:meta.fetchedAt};
}

// Validate every input before an archive import can modify its target cache.
// This is intentionally independent of the lazy read cache.
function validateAll(cacheDir) {
 const root=path.join(cacheDir,'_bulk');
 if (!fs.existsSync(root)) return {generations:0,records:0};
 if (!fs.statSync(root).isDirectory()) throw new Error('invalid compact NVD snapshot directory');
 let generations=0, records=0;
 for (const name of fs.readdirSync(root)) { const entry=validateGeneration(path.join(root,name),name); generations++;records+=entry.records; }
 return {generations,records};
}

// This summary establishes only timestamp/count from valid metadata; lookup
// verifies the corresponding shard checksum before trusting any advisory.
function snapshotSummary(cacheDir) {
 const root=path.join(cacheDir,'_bulk');let names;
 try { names=fs.readdirSync(root); } catch {return null;}
 let count=0,oldestFetchedAt=Infinity,newestFetchedAt=0,newestRecordCount=0;
 for(const name of names) try {
  const meta=readManifest(path.join(root,name),name);count++;
  oldestFetchedAt=Math.min(oldestFetchedAt,meta.fetchedAt);
  if(meta.fetchedAt>newestFetchedAt){newestFetchedAt=meta.fetchedAt;newestRecordCount=meta.count;}
 } catch { /* Invalid metadata is not a source observation. */ }
 return count ? {count,oldestFetchedAt,newestFetchedAt,newestRecordCount} : null;
}

// Writer is used by the server export job. The generation name incorporates
// the manifest hash, making it immutable and safe to merge with older seeds.
function createWriter(cacheDir, fetchedAt) {
 if (!Number.isSafeInteger(fetchedAt) || fetchedAt <= 0 || fetchedAt > Date.now()+300000) throw new Error('invalid NVD snapshot time');
 const root = path.join(cacheDir,'_bulk'); fs.mkdirSync(root,{recursive:true});
 const tmp = fs.mkdtempSync(path.join(root,'.build-'));
 const writers = new Map(); let count=0, finished=false;
 return {
  add(id, body) {
   if (finished || !/^CVE-\d{4}-\d{4,}$/.test(id) || !body || body.id !== id) throw new Error('invalid NVD snapshot record');
   const name = shardName(id); let item = writers.get(name);
   if (!item) { item = {fd:fs.openSync(path.join(tmp,name),'wx',0o600),first:true,bytes:1}; writers.set(name,item); fs.writeFileSync(item.fd,'{'); }
   const line=(item.first?'':',') + JSON.stringify(id) + ':' + JSON.stringify(body);
   item.bytes+=Buffer.byteLength(line);
   if (item.bytes + 1 > MAX_SHARD_BYTES) throw new Error('NVD snapshot shard exceeds size limit');
   fs.writeFileSync(item.fd,line); item.first=false; count++;
  },
  finish() {
   if (finished) throw new Error('NVD snapshot already finished'); finished=true;
   try {
    const shards={};
    for (const [name,item] of writers) { fs.writeFileSync(item.fd,'}'); fs.closeSync(item.fd); item.fd=null; shards[name]=hash(fs.readFileSync(path.join(tmp,name))); }
    const bytes=Buffer.from(JSON.stringify({schema:1,fetchedAt,count,shards}));
    fs.writeFileSync(path.join(tmp,'manifest.json'),bytes,{flag:'wx',mode:0o600});
    const generation = `${fetchedAt}-${hash(bytes)}`, dest=path.join(root,generation);
    if (fs.existsSync(dest)) fs.rmSync(tmp,{recursive:true,force:true}); else fs.renameSync(tmp,dest);
    return {generation,count};
   } catch (error) { for(const item of writers.values()) if(item.fd!==null)try{fs.closeSync(item.fd)}catch{} fs.rmSync(tmp,{recursive:true,force:true}); throw error; }
  },
  abort() { if(finished)return; finished=true; for(const item of writers.values())try{fs.closeSync(item.fd)}catch{} fs.rmSync(tmp,{recursive:true,force:true}); }
 };
}
module.exports = {readBulk,createWriter,shardName,validateAll,validateGeneration,snapshotSummary};
