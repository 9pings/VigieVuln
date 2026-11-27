'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const {acquireInventories,assessInventories,incompleteCapabilities}=require('../lib/artifacts/scan');
const {importSystemAdvisories}=require('../lib/system-inventory');
test('non-blocking record enrichment does not hide true image coverage gaps',()=>{
 const result={artifacts:[{id:'image',coverage:[{capability:'inventory',execution:'completed'},{capability:'advisories',execution:'completed'},{capability:'inventory',execution:'partial',affectsCompleteness:false}]}],warnings:[{type:'source-unavailable',artifactTargetId:'image',affectsCompleteness:false}]};
 assert.deepEqual(incompleteCapabilities(result),[]);
 result.warnings.push({type:'source-unavailable',artifactTargetId:'image',message:'OSV discovery failed'});
 assert.deepEqual(incompleteCapabilities(result),[{target:'image',capability:'sources'}]);
});
function write(root,p,body){const file=path.join(root,p);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,body);}
test('rootfs uses offline scoped advisory snapshots and package ownership',async t=>{
 const work=fs.mkdtempSync(path.join(os.tmpdir(),'vv-image-scan-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(work,{recursive:true,force:true});});const root=path.join(work,'root'),cacheDir=path.join(work,'cache');
 write(root,'etc/os-release','ID=debian\nVERSION_ID=12.4\n');
 write(root,'var/lib/dpkg/status','Package: libfoo\nStatus: install ok installed\nVersion: 1.0-1\nArchitecture: amd64\nSource: foo (1.0-1)\n');
 write(root,'var/lib/dpkg/info/libfoo.list','/usr/lib/node_modules/foo/package.json\n');
 write(root,'usr/lib/node_modules/foo/package.json',JSON.stringify({name:'foo',version:'1.0.0'}));
 const distribution={id:'debian',versionId:'12'};const record={id:'DEBIAN-CVE-X',aliases:['CVE-2024-12345'],affected:[{package:{ecosystem:'Debian:12',name:'foo',purl:'pkg:deb/debian/foo?arch=source'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1.0-2'}]}]}]};
 await importSystemAdvisories([record],{distribution,cacheDir,complete:true});
 const targets=await acquireInventories(root,{offline:true});
 const npm=targets[0].deps.find(x=>x.ecosystem==='npm');assert.equal(npm.osPackageOwners[0].name,'libfoo');assert.equal(JSON.stringify(targets).includes(root),false);
 const result=await assessInventories(targets,{offline:true,cacheDir,fetcher:()=>{throw Error('network called');}});
 assert.equal(result.cveMatches.length,1);const match=result.cveMatches[0];assert.equal(match.cve.id,'CVE-2024-12345');assert.ok(result.resolvedDeps.has(match.dep.coordKey));assert.equal(match.dep.manager,'dpkg');
 const repeated=await assessInventories([targets[0],{...targets[0],id:'second-image'}],{offline:true,cacheDir,fetcher:()=>{throw Error('network called');}});
 const summaries=repeated.warnings.filter(w=>w.type==='cve-enrichment-summary');assert.equal(summaries.length,1);assert.equal(summaries[0].records.length,1);assert.equal(summaries[0].affectsCompleteness,false);
 assert.ok(repeated.artifacts.every(a=>a.coverage.filter(c=>['nvd','euvd','euvd-details'].includes(c.collector)).every(c=>c.affectsCompleteness===false)));
 assert.ok(!repeated.warnings.some(w=>['nvd','euvd','euvd-details'].includes(w.source)));
 const missing=await assessInventories(targets,{offline:true,cacheDir:path.join(work,'empty')});assert.ok(incompleteCapabilities(missing).some(x=>x.capability==='advisories'));assert.ok(missing.warnings.some(x=>/No offline system advisory/.test(x.message)));
});
test('system package coordinates retain distinct architectures and versions',()=>{
 const {systemDep}=require('../lib/artifacts/scan'),distribution={id:'debian',versionId:'12'},pkg={name:'libfoo',manager:'dpkg',version:'1-1',architecture:'amd64',manifestPath:'/var/lib/dpkg/status'};
 const one=systemDep(pkg,'target',distribution),two=systemDep({...pkg,architecture:'arm64'},'target',distribution),three=systemDep({...pkg,version:'2-1'},'target',distribution);
 assert.equal(new Set([one.coordKey,two.coordKey,three.coordKey]).size,3);
});
test('merged usr directory aliases preserve ownership but leaf symlinks do not transfer it',async t=>{
 const work=fs.mkdtempSync(path.join(os.tmpdir(),'vv-merged-usr-'));t.after(()=>fs.rmSync(work,{recursive:true,force:true}));const root=path.join(work,'root');
 write(root,'etc/os-release','ID=debian\nVERSION_ID=12\n');
 write(root,'var/lib/dpkg/status','Package: owner\nStatus: install ok installed\nVersion: 1-1\nArchitecture: amd64\n');
 write(root,'var/lib/dpkg/info/owner.list','/lib/node_modules/owned/package.json\n/lib/node_modules/link/package.json\n');
 write(root,'usr/lib/node_modules/owned/package.json',JSON.stringify({name:'owned',version:'1.0.0'}));
 write(root,'usr/lib/node_modules/target/package.json',JSON.stringify({name:'target',version:'1.0.0'}));
 fs.mkdirSync(path.join(root,'usr/lib/node_modules/link'));fs.symlinkSync('../target/package.json',path.join(root,'usr/lib/node_modules/link/package.json'));
 fs.symlinkSync('usr/lib',path.join(root,'lib'));
 const [inventory]=await acquireInventories(root,{offline:true});
 assert.equal(inventory.deps.find(x=>x.ecosystem==='npm' && x.name==='owned').osPackageOwners[0].name,'owner');
 assert.equal(inventory.deps.find(x=>x.ecosystem==='npm' && x.name==='target').osPackageOwners,undefined);
});
test('artifact inventory prepares transferable offline advisories through a fleet proxy',async t=>{
 const {zipSync,strToU8}=require('fflate'),{createSnapshot}=require('../lib/artifacts/scan');const {startProxyCacheServer,createCacheStore}=require('../lib/proxy-cache');
 const work=fs.mkdtempSync(path.join(os.tmpdir(),'vv-prep-image-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(work,{recursive:true,force:true});});
 const root=path.join(work,'root');write(root,'etc/os-release','ID=alpine\nVERSION_ID=3.20\n');write(root,'lib/apk/db/installed','P:foo\nV:1-r0\nA:x86_64\no:foo\n\n');
 const targets=await acquireInventories(root,{offline:true}),inventory=path.join(work,'inventory.json');fs.writeFileSync(inventory,JSON.stringify(createSnapshot(targets)));
 const rec={id:'ALPINE-X',affected:[{package:{ecosystem:'Alpine:v3.20',name:'foo'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-r0'}]}]}]};const zip=zipSync({'v.json':strToU8(JSON.stringify(rec))});
 const pack=require('tar-stream').pack(), packed=require('node:stream/consumers').buffer(pack);
 pack.entry({name:'APKINDEX'},'P:foo\nV:3-r0\nA:x86_64\no:foo\n\n');pack.finalize();
 const apkIndex=require('node:zlib').gzipSync(await packed);
 const store=createCacheStore(path.join(work,'server'));let advisories=0, catalogues=0;
 const {server,url}=await startProxyCacheServer({port:0,host:'127.0.0.1',store,fetcher:async source=>{
  if(String(source).endsWith('/APKINDEX.tar.gz')) {catalogues++;return new Response(apkIndex,{headers:{'content-type':'application/gzip'}});}
  advisories++;return new Response(zip,{headers:{'content-type':'application/zip'}});
 }});
 const bundle=path.join(work,'cache.tar.gz'),source=path.join(work,'source'),dest=path.join(work,'dest');const originalExit=process.exitCode;
 try {
  const route=require('../lib/cli-command-routing').routeArguments(['cache','prepare',inventory,'--retries','0','--output',bundle,'--cache-dir',source,'--source-profile','proxy','--proxy-cache',url,'--allow-insecure-http','--no-gcve','--no-distro-advisories','--enrich','none']);
  assert.deepEqual(route.args.slice(0,2),['system','scan']);const result=await require('../lib/cli-image').run(route.args.slice(2));assert.equal(result.exitCode,0);assert.equal(advisories,2);assert.equal(catalogues,2);assert.ok(fs.existsSync(bundle));
  await require('../lib/cache-archive-sqlite').importCache(bundle,{targetDir:dest,proxyOrigin:url});
  const offline=await assessInventories(targets,{cacheDir:dest,offline:true,enrich:[],fetcher:()=>{throw Error('network')}});assert.equal(offline.cveMatches.length,1);
  assert.equal(offline.artifacts[0].components.find(c=>c.name==='foo').releaseVersions.distribution.version,'3-r0');
 } finally {process.exitCode=originalExit;await new Promise(resolve=>server.close(resolve));store.close?.();}
});
test('online system OSV refresh respects complete fresh snapshots, expiry, incompleteness and exclusion',async t=>{
 const {zipSync,strToU8}=require('fflate'),{createCacheRepository}=require('../lib/cache-repository'),{systemDep}=require('../lib/artifacts/scan');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-osv-freshness-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const distribution={id:'alpine',versionId:'3.20'},pkg={manager:'apk',name:'foo',version:'1-r0',sourceName:'foo',sourceVersion:'1-r0',architecture:'x86_64',manifestPath:'/status'},target={id:'image',kind:'rootfs',metadata:{},distribution,packages:[pkg],deps:[systemDep(pkg,'image',distribution)],coverage:[],warnings:[]};
 const rec={id:'ALPINE-X',affected:[{package:{ecosystem:'Alpine:v3.20',name:'foo'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-r0'}]}]}]},zip=zipSync({'x.json':strToU8(JSON.stringify(rec))});
 for(const scenario of ['fresh','expired','incomplete','disabled']){
  const cacheDir=path.join(root,scenario);await importSystemAdvisories([rec],{distribution,cacheDir,complete:scenario!=='incomplete'});
  if(scenario==='expired'){const repo=createCacheRepository(cacheDir),snapshot=repo.getSnapshot('system-osv:Alpine:v3.20');repo.putSnapshot('system-osv:Alpine:v3.20',{...snapshot,fetchedAt:Date.now()-7*3600000});}
  let calls=0;const result=await assessInventories([target],{cacheDir,allLibs:false,osv:scenario!=='disabled',distroAdvisories:false,disableGcve:true,disableCveProject:true,enrich:[],fetcher:async()=>{calls++;return new Response(zip,{headers:{'content-type':'application/zip'}})}});
  assert.equal(calls,['expired','incomplete'].includes(scenario)?1:0,scenario);if(scenario==='disabled')assert.equal(result.artifacts[0].coverage.find(c=>c.collector==='system-osv').execution,'not-applicable');
 }
});
