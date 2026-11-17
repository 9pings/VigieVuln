'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {assessAlpineTracker}=require('../lib/system-inventory/alpine-tracker');
test('Alpine tracker preserves exact possible and unknown source-package states and replays offline',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-alpine-tracker-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const origin='https://security.alpinelinux.org',id='CVE-2026-27171',busy='CVE-2025-60876',calls=[];
 const fetcher=async url=>{calls.push(url);const name=url.endsWith('/zlib')?'zlib':'busybox';if(url.includes('/srcpkg/'))return Response.json({id:url,cpeMatch:[{package:url,vuln:`${origin}/vuln/${name==='zlib'?id:busy}`}]});const isZlib=url.endsWith(id);return Response.json({id:url,state:isZlib?[{packageVersion:`${origin}/srcpkg/zlib/1.3.1-r0`,repo:'3.19-main',fixed:false}]:[{packageVersion:`${origin}/srcpkg/busybox/1.36.1-r16`,repo:'3.19-main',fixed:false}]});};
 const packages=[{manager:'apk',name:'zlib',sourceName:'zlib',sourceVersion:'1.3.1-r0'},...['busybox','busybox-binsh','ssl_client'].map(name=>({manager:'apk',name,sourceName:'busybox',sourceVersion:'1.36.1-r15'}))],distro={id:'alpine',versionId:'3.19.1'};
 const online=await assessAlpineTracker(packages,distro,{cacheDir,fetcher});assert.equal(online.coverage.execution,'completed');assert.equal(calls.length,4);
 const z=online.observations.find(x=>x.id===id),b=online.observations.find(x=>x.id===busy);assert.equal(z.status,'possible');assert.equal(z.repositoryVerified,false);assert.equal(z.advisoryVerdict,false);assert.equal(b.status,'unknown');assert.deepEqual(b.packages,['busybox','busybox-binsh','ssl_client']);
 const offline=await assessAlpineTracker(packages,distro,{cacheDir,offline:true,fetcher:()=>assert.fail('network')});assert.deepEqual(offline,online);
});
test('missing cache and provider failure do not claim absence or a fixed package',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-alpine-tracker-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const p=[{manager:'apk',name:'zlib',sourceName:'zlib',sourceVersion:'1.3.1-r0'}],d={id:'alpine',versionId:'3.19'};
 const offline=await assessAlpineTracker(p,d,{cacheDir,offline:true});assert.equal(offline.coverage.execution,'partial');assert.equal(offline.diagnostics[0].code,'cache-missing');assert.deepEqual(offline.observations,[]);
 const online=await assessAlpineTracker(p,d,{cacheDir,fetcher:async()=>new Response('',{status:403})});assert.equal(online.coverage.execution,'partial');assert.match(online.diagnostics[0].reason,/HTTP 403/);
});
test('only exact source version, release and optional repository determine tracker state',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-alpine-scope-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const origin='https://security.alpinelinux.org',source=`${origin}/srcpkg/zlib`,url=`${origin}/vuln/CVE-2026-27171`;
 const fetcher=async u=>u===source?Response.json({id:u,cpeMatch:[{package:source,vuln:url}]}):Response.json({id:url,state:[{packageVersion:`${source}/1.3.1-r0`,repo:'3.19-main',fixed:false},{packageVersion:`${source}/1.3.1-r0`,repo:'3.19-community',fixed:true},{packageVersion:`${source}/1.3.2-r0`,repo:'3.19-main',fixed:true},{packageVersion:`${source}/1.3.1-r0`,repo:'3.20-main',fixed:true}]});
 const p=[{manager:'apk',name:'zlib',sourceName:'zlib',sourceVersion:'1.3.1-r0'}],d={id:'alpine',versionId:'3.19.1'};
 const mixed=await assessAlpineTracker(p,d,{cacheDir,fetcher});assert.equal(mixed.observations[0].status,'unknown');
 const main=await assessAlpineTracker(p,d,{cacheDir,offline:true,alpineRepository:'main'});assert.equal(main.observations[0].status,'possible');assert.equal(main.observations[0].repositoryVerified,true);
 const community=await assessAlpineTracker(p,d,{cacheDir,offline:true,alpineRepository:'community'});assert.equal(community.observations[0].status,'fixed');
});
test('Alpine tracker uses configured proxy, preserves stale evidence, and never caches invalid payload',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-alpine-proxy-')),providers=require('../lib/providers');t.after(()=>{providers.configureResourceRoute({proxyUrl:null,fetcher:null,hosted:false});require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const p=[{manager:'apk',name:'zlib',sourceName:'zlib',sourceVersion:'1.3.1-r0'}],d={id:'alpine',versionId:'3.19'},origin='https://security.alpinelinux.org',source=`${origin}/srcpkg/zlib`,url=`${origin}/vuln/CVE-2026-27171`,at='2026-01-01T00:00:00.000Z';let invalid=true,calls=0;
 const fetcher=async(u,opts)=>{assert.equal(u,'https://fleet.invalid/v1/resource');calls++;const r=JSON.parse(opts.body);assert.equal(r.provider,'alpine');return Response.json(r.type==='package'?(invalid?{id:'wrong',cpeMatch:[]}:{id:source,cpeMatch:[{package:source,vuln:url}]}):{id:url,state:[{packageVersion:`${source}/1.3.1-r0`,repo:'3.19-main',fixed:false}]},{headers:{'x-fad-proxy-fetched-at':at,'x-fad-proxy':'stale'}})};
 providers.configureResourceRoute({proxyUrl:'https://fleet.invalid',hosted:false,fetcher,store:null,hostedStore:null});let result=await assessAlpineTracker(p,d,{cacheDir,fetcher});assert.equal(result.coverage.execution,'partial');assert.match(result.diagnostics[0].reason,/invalid/);
 invalid=false;result=await assessAlpineTracker(p,d,{cacheDir,fetcher});assert.equal(result.observations[0].status,'possible');assert.equal(result.observations[0].stale,true);assert.equal(result.observations[0].observedAt,at);assert.ok(calls>=3);
 providers.configureResourceRoute({proxyUrl:null,fetcher:null});result=await assessAlpineTracker(p,d,{cacheDir,offline:true,fetcher:()=>assert.fail('network')});assert.equal(result.observations[0].status,'possible');assert.equal(result.observations[0].stale,true);
});
