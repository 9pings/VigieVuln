'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {assessAlpineTracker}=require('../lib/system-inventory/alpine-tracker');
test('regional source profiles select classified operators independently and honor explicit exclusion',async()=>{
 const {applySourceProfile}=require('../lib/source-profile'),{assessDistributionSources}=require('../lib/system-inventory/distribution-sources');
 for(const sourceProfile of ['eu','us']){
  const called=[],adapters=[{id:'unknown'},{id:'europe',operatorRegion:'eu'},{id:'american',operatorRegion:'us'}].map(a=>({...a,supports:()=>true,assess:async()=>{called.push(a.id);return {}}}));
  const options={...applySourceProfile({sourceProfile}).options,distributionSourceAdapters:adapters};
  const r=await assessDistributionSources({distribution:{id:'alpine'},packages:[]},options);assert.deepEqual(called,[sourceProfile==='eu'?'europe':'american']);assert.equal(r.coverage.length,2);assert.equal(r.warnings.length,0);
  await assessDistributionSources({distribution:{id:'alpine'},packages:[]},{...options,distroAdvisories:false});assert.equal(called.length,1);
 }
});
test('Alpine tracker fleet HTTP and SQL cache archive replay offline without direct requests',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-alpine-paths-')),source=path.join(root,'source'),dest=path.join(root,'dest'),archive=path.join(root,'cache.tar.gz');
 const {startProxyCacheServer,createCacheStore}=require('../lib/proxy-cache'),store=createCacheStore(path.join(root,'fleet')),origin='https://security.alpinelinux.org',sourceUrl=`${origin}/srcpkg/zlib`,vuln=`${origin}/vuln/CVE-2026-27171`;let upstream=0;
 const {server,url}=await startProxyCacheServer({port:0,host:'127.0.0.1',store,fetcher:async u=>{upstream++;assert.ok(String(u).startsWith(origin));return Response.json(String(u)===sourceUrl?{id:sourceUrl,cpeMatch:[{package:sourceUrl,vuln}]}:{id:vuln,state:[{packageVersion:`${sourceUrl}/1.3.1-r0`,repo:'3.19-main',fixed:false}]});}});
 t.after(async()=>{require('../lib/providers').configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});await new Promise(r=>server.close(r));store.close?.();require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const providers=require('../lib/providers');providers.configureResourceRoute({proxyUrl:url,hosted:false,fetcher:global.fetch,store:null,hostedStore:null});
 const p=[{manager:'apk',name:'zlib',sourceName:'zlib',sourceVersion:'1.3.1-r0'}],d={id:'alpine',versionId:'3.19.1'},fetcher=(u,o)=>{assert.ok(String(u).startsWith(url+'/'));return fetch(u,o)};
 const online=await assessAlpineTracker(p,d,{cacheDir:source,fetcher});assert.equal(online.observations[0].status,'possible');assert.equal(upstream,2);
 await require('../lib/cache-archive-sqlite').exportCache(archive,{sourceDir:source,proxyOrigin:url});await require('../lib/cache-archive-sqlite').importCache(archive,{targetDir:dest,proxyOrigin:url});
 providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});const offline=await assessAlpineTracker(p,d,{cacheDir:dest,offline:true,fetcher:()=>assert.fail('offline network')});assert.deepEqual(offline,online);
});
