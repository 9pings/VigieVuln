'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),fs=require('node:fs');
// These are real-server integration checks, like the distro pathway tests.
// A standalone CLI checkout does not include the independently released server.
// Skip only when that checkout is absent; an available but broken server fails.
const serverAvailable=fs.existsSync(path.resolve(__dirname,'../../server-main/lib/server.js'));
const integration={skip:serverAvailable?false:'sibling server-main checkout not available (hosted integration)'};
test('hosted force update bypasses local EUVD mirror and preserves authenticated upstream result',integration,async()=>{
 const fadFile=require.resolve('../../server-main/lib/fad'),old=require.cache[fadFile];require.cache[fadFile]={id:fadFile,filename:fadFile,loaded:true,exports:{fad:rel=>require(path.join(__dirname,'../lib',rel)),fadData:file=>require(path.join(__dirname,'../data',file))}};
 const {open}=require('../../server-main/test/helpers/db'),{createServiceServer}=require('../../server-main/lib/server');const s=await open(),key=await s.tokens.add({role:'client',label:'force test'});let calls=0;
 const id='EUVD-2024-48936';await s.assets.upsert(require('../../server-main/lib/jobs/euvd-details').asset({id,description:'mirror'},Date.now()-1000));
 const server=createServiceServer({...s,swr:false,fetcher:async()=>{calls++;return Response.json({id,description:'upstream'});}});await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
 const ask=flag=>fetch(`http://127.0.0.1:${server.address().port}/v1/resource`,{method:'POST',headers:{'content-type':'application/json','x-fad-proxy-token':key.token},body:JSON.stringify({provider:'euvd',type:'vulnerability',params:{id},...(flag?{revalidate:true}:{})})});
 try{assert.equal((await (await ask(false)).json()).description,'mirror');assert.equal(calls,0);assert.equal((await (await ask(true)).json()).description,'upstream');assert.equal(calls,1);assert.equal((await (await ask(true)).json()).description,'upstream');assert.equal(calls,2);}
 finally{await new Promise(ok=>server.close(ok));await s.driver.close();if(old)require.cache[fadFile]=old;else delete require.cache[fadFile];}
});

test('forced EUVD refresh retains mirror-only record on upstream 503 or 429',integration,async()=>{
 const fadFile=require.resolve('../../server-main/lib/fad'),old=require.cache[fadFile];require.cache[fadFile]={id:fadFile,filename:fadFile,loaded:true,exports:{fad:rel=>require(path.join(__dirname,'../lib',rel)),fadData:file=>require(path.join(__dirname,'../data',file))}};
 const {open}=require('../../server-main/test/helpers/db'),{createServiceServer}=require('../../server-main/lib/server');
 try{for(const status of [503,429]){
  const s=await open(),key=await s.tokens.add({role:'client',label:'fallback test'}),id='EUVD-2024-48936',observedAt=Date.now()-60000;let calls=0;
  const original={id,description:'mirror-only'};await s.assets.upsert(require('../../server-main/lib/jobs/euvd-details').asset(original,observedAt));
  const server=createServiceServer({...s,swr:false,fetcher:async()=>{calls++;return new Response('',{status,headers:{'retry-after':'30'}})}});await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
  try{const res=await fetch(`http://127.0.0.1:${server.address().port}/v1/resource`,{method:'POST',headers:{'content-type':'application/json','x-fad-proxy-token':key.token},body:JSON.stringify({provider:'euvd',type:'vulnerability',params:{id},revalidate:true})});assert.equal(res.status,200);assert.deepEqual(await res.json(),original);assert.equal(res.headers.get('x-fad-proxy'),'stale');assert.equal(res.headers.get('x-fad-proxy-reason'),'refresh-failed');assert.equal(res.headers.get('x-fad-proxy-refresh-status'),String(status));assert.equal(res.headers.get('x-fad-proxy-refresh-cause'),status===429?'rate-limit':'upstream-http');if(status===429)assert.equal(res.headers.get('retry-after'),'30');assert.equal(Date.parse(res.headers.get('x-fad-proxy-fetched-at')),observedAt);assert.match(res.headers.get('x-fad-proxy-scope'),/search-record/);assert.equal(calls,1);}
  finally{await new Promise(ok=>server.close(ok));await s.driver.close();}
 }}finally{if(old)require.cache[fadFile]=old;else delete require.cache[fadFile];}
});
