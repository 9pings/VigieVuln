'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {createCacheStore,startProxyCacheServer}=require('../lib/proxy-cache');
const {configureResourceRoute,getResource}=require('../lib/providers');
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));

test('direct client revalidates an expired representation without downloading it',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-conditional-client-'));t.after(()=>{ require('../lib/cache-db').closeCacheDbs(); fs.rmSync(dir,{recursive:true,force:true}); });
 const store=createCacheStore(dir),seen=[];
 const fetcher=async(_url,init)=>{const headers=new Headers(init.headers);seen.push(headers.get('if-none-match'));return seen.length===1?Response.json({name:'fixture'},{headers:{etag:'"version-1"'}}):new Response(null,{status:304,headers:{etag:'"version-1"'}})};
 configureResourceRoute({proxyUrl:null,hosted:false,store,health:null,fetcher});
 try{
  assert.deepEqual(await (await getResource('npm','package',{name:'fixture'})).json(),{name:'fixture'});
  const response=await getResource('npm','package',{name:'fixture'},{forceRefresh:true});
  assert.equal(response.headers.get('x-fad-proxy'),'revalidated');assert.deepEqual(await response.json(),{name:'fixture'});
  assert.deepEqual(seen,[null,'"version-1"']);
 }finally{configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,fetcher:null})}
});

test('direct client uses Last-Modified and replaces a changed representation',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-conditional-modified-'));t.after(()=>{ require('../lib/cache-db').closeCacheDbs(); fs.rmSync(dir,{recursive:true,force:true}); });
 const store=createCacheStore(dir),seen=[],date='Wed, 21 Oct 2015 07:28:00 GMT';
 const fetcher=async(_url,init)=>{seen.push(new Headers(init.headers).get('if-modified-since'));return Response.json({name:'fixture',revision:seen.length},{headers:{'last-modified':date}})};
 configureResourceRoute({proxyUrl:null,hosted:false,store,health:null,fetcher});
 try{
  await getResource('npm','package',{name:'fixture'});
  assert.deepEqual(await (await getResource('npm','package',{name:'fixture'},{forceRefresh:true})).json(),{name:'fixture',revision:2});
  assert.deepEqual(seen,[null,date]);
 }finally{configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,fetcher:null})}
});

test('proxy revalidates upstream using ETag and keeps its existing cached body',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-conditional-proxy-'));t.after(()=>{ require('../lib/cache-db').closeCacheDbs(); fs.rmSync(dir,{recursive:true,force:true}); });
 const seen=[];const fetcher=async(_url,init)=>{seen.push(init.headers['if-none-match']||null);return seen.length===1?Response.json({totalResults:0,vulnerabilities:[]},{headers:{etag:'"upstream-v1"'}}):new Response(null,{status:304,headers:{etag:'"upstream-v1"'}})};
 const proxy=await startProxyCacheServer({port:0,host:'127.0.0.1',store:createCacheStore(dir),fetcher,overrideTtlMs:30,swr:false});
 try{
  const call=()=>fetch(proxy.url+'/v1/resource',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({provider:'nvd',type:'cve',params:{id:'CVE-2024-31210'}})});
  assert.deepEqual(await (await call()).json(),{totalResults:0,vulnerabilities:[]});
  await wait(60);const second=await call();assert.equal(second.status,200);assert.equal(second.headers.get('x-fad-proxy'),'revalidated');assert.equal(second.headers.get('etag'),null);assert.deepEqual(await second.json(),{totalResults:0,vulnerabilities:[]});
  assert.deepEqual(seen,[null,'"upstream-v1"']);
 }finally{await new Promise(resolve=>proxy.server.close(resolve))}
});
