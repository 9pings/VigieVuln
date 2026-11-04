'use strict';

const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const {Readable}=require('node:stream');
const {getCacheDb}=require('../cache-db');
const CHUNK=1024*1024;
const DEFAULT_CACHE_DIR=()=>require('../cache-directory').getProxyCacheDir();
const preparedDefaults=new Set();

function location(dir){
 const name=path.basename(dir),parent=path.basename(path.dirname(dir));
 if(name==='resource-cache')return {root:path.dirname(dir),prefix:'resource-cache:'};
 if(parent==='hosted-resources')return {root:path.dirname(path.dirname(dir)),prefix:`hosted:${name}:`};
 return {root:dir,prefix:'serve-cache:'};
}

function createCacheStore(dir=DEFAULT_CACHE_DIR()){
 if(dir===DEFAULT_CACHE_DIR()&&!preparedDefaults.has(dir)){
  require('../cache-startup').prepareServeCache();
  preparedDefaults.add(dir);
 }
 const {root,prefix}=location(dir),db=getCacheDb(root),pinned=new Map(),pending=new Set();
 const full=key=>prefix+key;
 let maxStoreBytes=Infinity,maxEntries=Infinity;
 const resource=db.prepare('SELECT r.*,b.bytes FROM resources r JOIN resource_bodies b USING(body_id) WHERE r.key=?');
 const count=()=>db.prepare('SELECT COUNT(*) n FROM resources WHERE key LIKE ?').get(prefix+'%').n;
 const total=()=>db.prepare('SELECT COALESCE(SUM(b.bytes),0) n FROM resources r JOIN resource_bodies b USING(body_id) WHERE r.key LIKE ?').get(prefix+'%').n;
 const removeBody=id=>{
  if((pinned.get(id)||0)>0){pending.add(id);return}
  db.prepare('DELETE FROM resource_bodies WHERE body_id=? AND NOT EXISTS (SELECT 1 FROM resources WHERE body_id=?)').run(id,id);
  pending.delete(id);
 };
 const evict=key=>{const old=resource.get(key);if(!old)return false;db.prepare('DELETE FROM resources WHERE key=?').run(key);removeBody(old.body_id);return true};
 const makeRoom=(extra=0,keepKey=null,adding=false)=>{
  if(extra>maxStoreBytes)throw Error('proxy store quota exceeded');
  while(total()+extra>maxStoreBytes||count()+(adding?1:0)>maxEntries){
   const rows=db.prepare('SELECT key,body_id FROM resources WHERE key LIKE ? ORDER BY fetched_at LIMIT 100').all(prefix+'%');
   const victim=rows.find(row=>row.key!==keepKey && !(pinned.get(row.body_id)||0));
   if(!victim)throw Error('proxy store quota exceeded (active readers are pinned)');
   evict(victim.key);
  }
 };
 function publish(key,body,meta){
  const id=crypto.createHash('sha256').update(body).digest('hex'),fullKey=full(key),old=resource.get(fullKey);
  makeRoom(body.length,fullKey,!old);
  db.transaction(()=>{
   db.prepare('INSERT OR IGNORE INTO resource_bodies(body_id,bytes,sha256) VALUES (?,?,?)').run(id,body.length,id);
   if(!db.prepare('SELECT 1 FROM resource_chunks WHERE body_id=? LIMIT 1').get(id)){
    const put=db.prepare('INSERT INTO resource_chunks(body_id,ordinal,data) VALUES (?,?,?)');
    for(let i=0;i<body.length;i+=CHUNK)put.run(id,i/CHUNK,body.subarray(i,i+CHUNK));
   }
   db.prepare(`INSERT INTO resources(key,body_id,fetched_at,ttl_ms,content_type,response_headers_json,metadata_json)
    VALUES (?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET body_id=excluded.body_id,fetched_at=excluded.fetched_at,
    ttl_ms=excluded.ttl_ms,content_type=excluded.content_type,response_headers_json=excluded.response_headers_json,
    metadata_json=excluded.metadata_json`).run(fullKey,id,meta.fetchedAt,meta.ttlMs,meta.contentType||null,
     JSON.stringify(meta.responseHeaders||{}),JSON.stringify({url:key}));
  });
  if(old&&old.body_id!==id)removeBody(old.body_id);
 }
 return {
  dir,kind:'sqlite',maxEntryBytes:256*1024*1024,
  configureLimits(bytes,entries){maxStoreBytes=bytes;maxEntries=entries;makeRoom()},
  claimOwner(){return ()=>{}},
  get(key){const row=resource.get(full(key));if(!row)return null;return {url:key,bodyId:row.body_id,fetchedAt:row.fetched_at,
   ttlMs:row.ttl_ms,contentType:row.content_type,responseHeaders:JSON.parse(row.response_headers_json),bytes:row.bytes}},
  touch(key,entry,meta){
   const r=db.prepare('UPDATE resources SET fetched_at=?,ttl_ms=?,response_headers_json=? WHERE key=? AND body_id=? AND fetched_at=?')
    .run(meta.fetchedAt,meta.ttlMs,JSON.stringify(meta.responseHeaders||{}),full(key),entry.bodyId,entry.fetchedAt);
   return r.changes>0;
  },
  acquire(entry){if(!entry.bodyId)return ()=>{};const id=entry.bodyId;pinned.set(id,(pinned.get(id)||0)+1);let done=false;
   return ()=>{if(done)return;done=true;const n=pinned.get(id)-1;if(n)pinned.set(id,n);else{pinned.delete(id);if(pending.has(id))removeBody(id)}}},
  openBody(entry){if(entry.bodyPath)return fs.createReadStream(entry.bodyPath);
   const getChunk=db.prepare('SELECT data FROM resource_chunks WHERE body_id=? AND ordinal=?');
   return Readable.from((function*(){for(let ordinal=0;;ordinal++){
    const row=getChunk.get(entry.bodyId,ordinal);if(!row)return;yield Buffer.from(row.data);
   }})())},
  readBody(entry){if(entry.bodyPath)return fs.readFileSync(entry.bodyPath);
   return Buffer.concat(db.prepare('SELECT data FROM resource_chunks WHERE body_id=? ORDER BY ordinal').all(entry.bodyId).map(row=>Buffer.from(row.data)))},
  createWriter(){const file=path.join(os.tmpdir(),'vigievuln-resource-'+crypto.randomBytes(12).toString('hex'));
   return {account(){},sink(){return fs.createWriteStream(file,{flags:'wx',mode:0o600})},bytes(){return fs.statSync(file).size},
    read(){return fs.readFileSync(file)},commit(key,meta){try{publish(key,fs.readFileSync(file),meta)}finally{fs.rmSync(file,{force:true})}},
    detach(meta){const timer=setTimeout(()=>fs.rmSync(file,{force:true}),30000);timer.unref?.();return {...meta,bodyPath:file}},
    abort(){fs.rmSync(file,{force:true})}}},
  put(key,body,meta){publish(key,Buffer.from(body),meta)},
  purge(key){return evict(full(key))},
  clear(){let n=0;for(const row of db.prepare('SELECT key FROM resources WHERE key LIKE ?').all(prefix+'%'))if(evict(row.key))n++;return n},
  size:count,bodyBytes:total,diskBytes:total,
 };
}

module.exports={createCacheStore,DEFAULT_CACHE_DIR};
