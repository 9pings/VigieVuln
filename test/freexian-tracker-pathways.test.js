'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {startProxyCacheServer,createCacheStore}=require('../lib/proxy-cache');
const {configureResourceRoute}=require('../lib/providers'),{closeCacheDbs}=require('../lib/cache-db');
const {exportCache,importCache}=require('../lib/cache-archive-sqlite');
const {assessFreexianTracker}=require('../lib/system-inventory/freexian-tracker');
// Small structure adapted from the publisher's Debian ELTS tracker.
const data={apt:{'CVE-2026-109518':{description:'APT acquisition retry issue',releases:{bullseye:{status:'resolved',fixed_version:'2.2.5',repositories:{bullseye:'2.2.5','bullseye-lts':'2.2.5'}}}}},unrelated:{'CVE-2026-1234':{releases:{bullseye:{status:'open'}}}}};
const inventory={distribution:{id:'debian',versionId:'11',codename:'bullseye'},packages:[{name:'apt',sourceName:'apt',sourceVersion:'2.2.4',version:'2.2.4',manager:'dpkg'}]};
const reset=()=>configureResourceRoute({proxyUrl:null,hosted:false,store:null,hostedStore:null,token:null,fetcher:null});
const origin='https://deb.freexian.com/extended-lts/tracker/data/json';
function upstream(counter){return async url=>{counter.n++;assert.equal(String(url),origin);const text=JSON.stringify(data);return new Response(text,{headers:{'content-type':'application/json','content-length':String(Buffer.byteLength(text))}})}}
async function assess(dir,extra={}){const r=await assessFreexianTracker(inventory,{cacheDir:dir,...extra});assert.equal(r.matches.length,1,JSON.stringify({warnings:r.warnings,coverage:r.coverage}));assert.equal(r.matches[0].cve.id,'CVE-2026-109518');assert.equal(r.assessments[0].status,'affected');return r;}
test('direct source projects requested packages and SQL export/import replays offline',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-freexian-direct-')),counter={n:0};try{reset();const source=path.join(root,'source'),target=path.join(root,'target');const a=await assess(source,{fetcher:upstream(counter)});assert.equal(counter.n,1);await exportCache(path.join(root,'cache.tar.gz'),{sourceDir:source});await importCache(path.join(root,'cache.tar.gz'),{targetDir:target});const b=await assess(target,{offline:true,fetcher:()=>assert.fail('offline network')});assert.deepEqual(b.assessments,a.assessments);}finally{reset();closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}});
test('fleet projects source on proxy and client replays its cache offline',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-freexian-fleet-')),counter={n:0};let server;try{const x=await startProxyCacheServer({host:'127.0.0.1',port:0,store:createCacheStore(path.join(root,'relay')),fetcher:upstream(counter)});server=x.server;configureResourceRoute({proxyUrl:x.url,hosted:false,store:null,hostedStore:null,fetcher:(url,init)=>{assert.ok(String(url).startsWith(x.url+'/'));return fetch(url,init)}});const dir=path.join(root,'client');const a=await assess(dir);assert.equal(counter.n,1);const target=path.join(root,'offline');await exportCache(path.join(root,'cache.tar.gz'),{sourceDir:dir,proxyOrigin:x.url});await importCache(path.join(root,'cache.tar.gz'),{targetDir:target,proxyOrigin:x.url});reset();const b=await assess(target,{offline:true,fetcher:()=>assert.fail('offline network')});assert.deepEqual(b.assessments,a.assessments);}finally{reset();if(server)await new Promise(ok=>server.close(ok));closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}});
test('hosted server projects source through typed resource',async t=>{
 const serviceFile=path.resolve(__dirname,'../../server-main/lib/server.js'),fadFile=path.resolve(__dirname,'../../server-main/lib/fad.js');if(!fs.existsSync(serviceFile)){t.skip('sibling server-main unavailable');return;}
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-freexian-hosted-')),counter={n:0},old=require.cache[fadFile];let server;require.cache[fadFile]={id:fadFile,filename:fadFile,loaded:true,exports:{fad:rel=>require(path.resolve(__dirname,'../lib',rel)),fadData:file=>require(path.resolve(__dirname,'../data',file))}};
 try{server=require(serviceFile).createServiceServer({store:createCacheStore(path.join(root,'relay')),tokens:{verify:()=>null},allowAnonymousProxy:true,localAnswers:false,ratePerMinute:0,publicRatePerMinute:0,fetcher:upstream(counter)});await new Promise(ok=>server.listen(0,'127.0.0.1',ok));const base=`http://127.0.0.1:${server.address().port}`;configureResourceRoute({proxyUrl:base,hosted:true,store:null,hostedStore:null,fetcher:(url,init)=>{assert.ok(String(url).startsWith(base+'/'));return fetch(url,init)}});await assess(path.join(root,'client'));assert.equal(counter.n,1);}finally{reset();if(server)await new Promise(ok=>server.close(ok));if(old)require.cache[fadFile]=old;else delete require.cache[fadFile];closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}});
test('regional profile includes EU Freexian and excludes it from US without consultation',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-freexian-region-'));let calls=0;
 try {const {adapters,assessDistributionSources}=require('../lib/system-inventory/distribution-sources'),adapter=adapters.find(a=>a.id==='freexian-tracker');assert.ok(adapter);const shared={cacheDir:root,distributionSourceAdapters:[adapter],fetchResource:async()=>{calls++;return Response.json(data)}};
  const us=await assessDistributionSources(inventory,{...shared,distributionSourceRegion:'us'});assert.equal(calls,0);assert.equal(us.coverage[0].result,'not-consulted');
  const eu=await assessDistributionSources(inventory,{...shared,distributionSourceRegion:'eu'});assert.equal(calls,1);assert.equal(eu.matches.length,1);
 }finally{reset();closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}
});
test('failed refresh retains last actual snapshot with explicit partial coverage',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-freexian-stale-'));try{
  const initial=await assess(root,{fetchResource:async()=>Response.json(data)});
  const replay=await assess(root,{forceUpdate:true,fetchResource:async()=>{throw Error('timeout')}});
  assert.deepEqual(replay.assessments,initial.assessments);assert.equal(replay.coverage[0].execution,'partial');assert.match(replay.warnings[0].message,/timeout/);
 }finally{reset();closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}
});
test('shared fleet snapshot isolates two package projections and coalesces upstream download',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-freexian-scope-')),counter={n:0};let server;
 try{const x=await startProxyCacheServer({host:'127.0.0.1',port:0,store:createCacheStore(path.join(root,'relay')),fetcher:upstream(counter)});server=x.server;
  const ask=async packages=>{const r=await fetch(x.url+'/v1/resource',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({provider:'freexian',type:'tracker',params:{packages}})});assert.equal(r.status,200);return r.json()};
  const [a,b]=await Promise.all([ask(['apt']),ask(['unrelated'])]);assert.deepEqual(Object.keys(a.packages),['apt']);assert.deepEqual(Object.keys(b.packages),['unrelated']);assert.equal(counter.n,1);
 }finally{reset();if(server)await new Promise(ok=>server.close(ok));closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}
});
test('proxy bounds projected response and never returns an incomplete body',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-freexian-limit-'));let server;
 try{const x=await startProxyCacheServer({host:'127.0.0.1',port:0,maxBodyBytes:32,store:createCacheStore(path.join(root,'relay')),fetcher:upstream({n:0})});server=x.server;
  const r=await fetch(x.url+'/v1/resource',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({provider:'freexian',type:'tracker',params:{packages:['apt']}})});assert.notEqual(r.status,200);assert.ok(!(await r.text()).includes('CVE-2026-109518'));
 }finally{reset();if(server)await new Promise(ok=>server.close(ok));closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}
});
test('proxy serves a retained snapshot with real refresh failure provenance',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-freexian-relay-stale-'));let server,calls=0;
 try{const x=await startProxyCacheServer({host:'127.0.0.1',port:0,overrideTtlMs:1,allowStale:true,store:createCacheStore(path.join(root,'relay')),fetcher:async()=>{calls++;return calls===1?Response.json(data):new Response('',{status:503,headers:{'retry-after':'10'}})}});server=x.server;
  const ask=()=>fetch(x.url+'/v1/resource',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({provider:'freexian',type:'tracker',params:{packages:['apt']}})});
  const a=await ask();assert.equal(a.status,200);const observed=a.headers.get('x-fad-proxy-fetched-at');await a.text();await new Promise(ok=>setTimeout(ok,10));const b=await ask();assert.equal(b.status,200);assert.equal(b.headers.get('x-fad-proxy'),'stale');assert.equal(b.headers.get('x-fad-proxy-refresh-status'),'503');assert.equal(b.headers.get('x-fad-proxy-fetched-at'),observed);assert.ok((await b.json()).packages.apt);assert.equal(calls,2);
 }finally{reset();if(server)await new Promise(ok=>server.close(ok));closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}
});
