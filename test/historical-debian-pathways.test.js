'use strict';
// Synthetic transport fixture: the tracker syntax follows Debian's real lists.
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {startProxyCacheServer,createCacheStore}=require('../lib/cache/proxy-cache');
const {configureResourceRoute}=require('../lib/providers');
const {exportCache,importCache}=require('../lib/cache/archive');
const {closeCacheDbs}=require('../lib/cache/db');
const h=require('../lib/providers/debian/historical');
const commit='b'.repeat(40),d={id:'debian',versionId:'11',codename:'bullseye'};
const lists={CVE:'CVE-2024-2511 (OpenSSL issue)\n\t- openssl 3.2.2-1\n\t[bullseye] - openssl 1.1.1w-0+deb11u2\nCVE-2024-9988 (unrelated)\n\t[bullseye] - unrelated 2.0-1\n',DSA:'[01 Sep 2024] DSA-1234-1 unrelated - update\n\t{CVE-2024-9988}\n\t[bullseye] - unrelated 2.0-1\n',DLA:'[01 Sep 2024] DLA-3942-1 openssl - update\n\t{CVE-2024-2511}\n\t[bullseye] - openssl 1.1.1w-0+deb11u2\n'};
const dep={name:'libssl1.1',sourceName:'openssl',sourceVersion:'1.1.1w-0+deb11u1',version:'1.1.1w-0+deb11u1'};
test('fleet HTTP projects private source snapshots and replays scoped cache offline after transfer',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-history-pathways-')),source=path.join(dir,'source'),target=path.join(dir,'target'),archive=path.join(dir,'cache.tar.gz');let directClient=0,upstream=[];
 const store=createCacheStore(path.join(dir,'relay'));
 const {server,url}=await startProxyCacheServer({host:'127.0.0.1',port:0,store,fetcher:async url=>{upstream.push(url);if(url.includes('sources.debian.org'))return new Response(JSON.stringify({package:'openssl',version:'1.1.1w-0+deb11u1',pkg_infos:{suites:['bullseye']}}));if(url.includes('endoflife.date'))return new Response(JSON.stringify([{cycle:'11',codename:'Bullseye',eol:'2026-08-31'}]));if(url.includes('/repository/commits?'))return new Response(JSON.stringify([{id:commit,committed_date:'2026-08-31T12:00:00Z'}]));const m=url.match(/\/data\/(CVE|DSA|DLA)\/list$/);if(m)return new Response(lists[m[1]]);throw Error('unexpected upstream');}});
 try{
  configureResourceRoute({proxyUrl:url,hosted:false,store:null,hostedStore:null,token:null,fetcher:async (u,init)=>{if(!String(u).startsWith(url+'/')){directClient++;throw Error('client direct network forbidden');}return fetch(u,init)}});
  await h.syncHistoricalDebian(d,{cacheDir:source,packages:['openssl']});await h.syncDebianPackageOrigins([{name:'openssl',version:'1.1.1w-0+deb11u1'}],{cacheDir:source});assert.equal(directClient,0);assert.equal(upstream.length,6);
  const snapshot=require('../lib/cache/repository').createCacheRepository(source).getSnapshot(h.namespace(d));assert.deepEqual(snapshot.metadata.queriedPackages,['openssl']);assert.equal(snapshot.metadata.commit,commit);assert.match(snapshot.metadata.sourceHashes.CVE,/^[a-f0-9]{64}$/);
  const scoped=h.assessHistoricalDebian({distribution:d,packages:[dep,{...dep,name:'other',sourceName:'unrelated'}]},{cacheDir:source});assert.equal(scoped.matches.length,1);assert.ok(scoped.coverage[0].unknown>=1);
  const wholeDir=path.join(dir,'whole');await h.importHistoricalDebian(lists,{distribution:d,commit,cutoff:'2026-08-31',cacheDir:wholeDir});const full=h.assessHistoricalDebian({distribution:d,packages:[dep]},{cacheDir:wholeDir});assert.deepEqual(scoped.matches.map(m=>m.cve.id),full.matches.map(m=>m.cve.id));
  await exportCache(archive,{sourceDir:source});await importCache(archive,{targetDir:target});
  configureResourceRoute({proxyUrl:null,hosted:false,store:null,hostedStore:null,fetcher:()=>{throw Error('offline network forbidden')}});
  const replay=h.assessHistoricalDebian({distribution:d,packages:[dep]},{cacheDir:target,offline:true});assert.deepEqual(replay.matches.map(m=>m.cve.id),['CVE-2024-2511']);assert.equal(replay.matches[0].cve.historicalEvidence.originStatus,'corroborated');assert.equal(replay.coverage[0].commit,commit);
 }finally{configureResourceRoute({proxyUrl:null,hosted:false,store:null,hostedStore:null,token:null,fetcher:null});await new Promise(ok=>server.close(ok));closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}
});

test('actual hosted server projects Debian resources without exposing full source lists',async t=>{
 const serviceFile=path.resolve(__dirname,'../../server-main/lib/server.js'),fadFile=path.resolve(__dirname,'../../server-main/lib/fad.js');
 if(!fs.existsSync(serviceFile)){t.skip('sibling server-main checkout not available');return;}
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-history-hosted-')),cacheDir=path.join(dir,'client'),upstream=[];
 const old=require.cache[fadFile];require.cache[fadFile]={id:fadFile,filename:fadFile,loaded:true,exports:{fad:rel=>require('vigievuln/lib/'+rel),fadData:file=>require(path.resolve(__dirname,'../data',file))}};
 let server;
 try{
  const {createServiceServer}=require(serviceFile),store=createCacheStore(path.join(dir,'relay'));
  server=createServiceServer({store,tokens:{verify:()=>null},allowAnonymousProxy:true,localAnswers:false,ratePerMinute:0,publicRatePerMinute:0,fetcher:async url=>{upstream.push(url);if(url.includes('endoflife.date'))return new Response(JSON.stringify([{cycle:'11',codename:'Bullseye',eol:'2026-08-31'}]));if(url.includes('/repository/commits?'))return new Response(JSON.stringify([{id:commit,committed_date:'2026-08-31T12:00:00Z'}]));const m=url.match(/\/data\/(CVE|DSA|DLA)\/list$/);if(m)return new Response(lists[m[1]]);throw Error('unexpected upstream');}});
  await new Promise(ok=>server.listen(0,'127.0.0.1',ok));const base=`http://127.0.0.1:${server.address().port}`;
  configureResourceRoute({proxyUrl:base,hosted:true,store:null,hostedStore:null,token:null,fetcher:async (url,init)=>{if(!String(url).startsWith(base+'/'))throw Error('direct client access prohibited');return fetch(url,init)}});
  await h.syncHistoricalDebian(d,{cacheDir,packages:['openssl']});
  const repo=require('../lib/cache/repository').createCacheRepository(cacheDir),snap=repo.getSnapshot(h.namespace(d));assert.equal(snap.metadata.commit,commit);assert.deepEqual(snap.metadata.queriedPackages,['openssl']);assert.ok(snap.metadata.sourceHashes.CVE);assert.equal(repo.get(h.namespace(d),'unrelated'),null);
  assert.deepEqual(h.assessHistoricalDebian({distribution:d,packages:[dep]},{cacheDir,offline:true}).matches.map(x=>x.cve.id),['CVE-2024-2511']);assert.equal(upstream.length,5);
 }finally{configureResourceRoute({proxyUrl:null,hosted:false,store:null,hostedStore:null,token:null,fetcher:null});if(server)await new Promise(ok=>server.close(ok));if(old)require.cache[fadFile]=old;else delete require.cache[fadFile];closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}
});
