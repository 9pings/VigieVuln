'use strict';
// Shared bounded source snapshots stay on the relay. Each caller receives only
// its projection, with the original observation time and full source hash.
const {gzipSync,gunzipSync}=require('node:zlib');
const {createHash}=require('node:crypto');
function createSnapshotProjection({store,load,validate,project,ttlMs,allowStale,stats,maxEntries=1000,maxSourceBytes=128*1024*1024,maxResponseBytes=32*1024*1024,now=Date.now}){
 const flights=new Map(),failures=new Map();let memo=null;
 async function source(key,request){
  if(flights.has(key)){stats.coalesced++;return flights.get(key);}
  const work=(async()=>{
   let previous=null;const entry=await store.get(key);
   if(entry && entry.fetchedAt>0 && entry.fetchedAt<=now() && entry.bytes<=maxSourceBytes){
    const release=store.acquire(entry);try{
     if(memo?.key===key && memo.fetchedAt===entry.fetchedAt && memo.bytes===entry.bytes)previous=memo;
     else{const body=gunzipSync(await store.readBody(entry),{maxOutputLength:maxSourceBytes});await validate(body,request);previous=memo={key,body,fetchedAt:entry.fetchedAt,bytes:entry.bytes,sha256:createHash('sha256').update(body).digest('hex')};}
    }catch{/* corrupt cached snapshots are never projected */}finally{release();}
   }
   if(previous && now()-previous.fetchedAt<Math.min(ttlMs,entry.ttlMs)){stats.hits++;return {...previous,stale:false};}
   const failed=failures.get(key);
   if(failed?.until>now()){if(previous&&allowStale){stats.stale++;return {...previous,stale:true,failure:failed.error};}throw failed.error;}
   try{
    stats.misses++;const body=await load(request,maxSourceBytes);
    if(!Buffer.isBuffer(body)||!body.length||body.length>maxSourceBytes)throw Error('Invalid source snapshot size');
    await validate(body,request);const compressed=gzipSync(body),fetchedAt=now();
    if(compressed.length>Math.min(store.maxEntryBytes||maxSourceBytes,maxSourceBytes))throw Error('Source snapshot exceeds cache storage limit');
    await store.put(key,compressed,{fetchedAt,ttlMs,contentType:'application/gzip',bytes:compressed.length});
    memo={key,body,fetchedAt,bytes:compressed.length,sha256:createHash('sha256').update(body).digest('hex')};failures.delete(key);return {...memo,stale:false};
   }catch(error){stats.errors++;for(const [k,v] of failures)if(v.until<=now())failures.delete(k);if(failures.size>=maxEntries)failures.delete(failures.keys().next().value);const delay=Number.isFinite(error.retryAfterS)?Math.max(1000,Math.min(604800000,error.retryAfterS*1000)):30000;failures.set(key,{until:now()+delay,error});if(previous&&allowStale){stats.stale++;return {...previous,stale:true,failure:error};}throw error;}
  })();flights.set(key,work);try{return await work;}finally{flights.delete(key);}
 }
 return async(key,request,params)=>{const snapshot=await source(key,request),body=Buffer.from(await project(snapshot.body,params));if(body.length>maxResponseBytes)throw Error('Projected source response exceeds limit');return {body,fetchedAt:snapshot.fetchedAt,stale:snapshot.stale,sha256:snapshot.sha256,failure:snapshot.failure};};
}
module.exports={createSnapshotProjection};
