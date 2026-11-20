'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {assessNginxAdvisories,parseNginxAdvisories}=require('../lib/system-inventory/nginx-advisories');
const xml=`<!DOCTYPE article SYSTEM "../../dtd/article.dtd"><article><section><security><item name="HTTP/2 issue when configured" severity="major" cve="2024-12345" good="1.24.1+, 1.25.2+" vulnerable="1.20.0-1.24.0" advisory="https://nginx.org/advisory"/><item name="Windows only" cve="2024-44444" vulnerable="nginx/Windows 1.0.0-1.24.0"/></security></section></article>`;
test('vendor declared package yields upstream range evidence without configuration or signature assertions',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-nginx-advisories-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const vendor={manager:'dpkg',name:'nginx',sourceName:'nginx',sourceVersion:'1.24.0-1~bullseye',packageMetadata:{maintainer:'NGINX Packaging <nginx-packaging@f5.com>'}},generic={...vendor,packageMetadata:{maintainer:'Debian Nginx Maintainers <pkg-nginx@lists.alioth.debian.org>'}},fetcher=async()=>new Response(xml,{headers:{'content-type':'application/xml'}});
 const result=await assessNginxAdvisories([vendor,generic],{cacheDir,fetcher});assert.equal(result.matches.length,1);assert.equal(result.matches[0].cve.id,'CVE-2024-12345');assert.equal(result.matches[0].cve.fixVersion,'1.24.1');assert.equal(result.matches[0].dep.packageOrigin.status,'third-party');assert.equal(result.matches[0].cve.vendorEvidence.signatureVerified,false);assert.equal(result.matches[0].cve.vendorEvidence.configurationApplicability,'unknown');assert.ok(result.observations.some(o=>o.dep===generic));assert.ok(result.observations.some(o=>o.cveId==='CVE-2024-44444'));
 const offline=await assessNginxAdvisories([vendor,generic],{cacheDir,offline:true,fetcher:()=>assert.fail('network')});assert.deepEqual(offline,result);
});
test('external XML entities rejected and unsupported ranges stay unknown',async()=>{
 await assert.rejects(parseNginxAdvisories('<!DOCTYPE article [<!ENTITY x SYSTEM "file:///etc/passwd">]><article/>'),/entity/i);
 const valid=await parseNginxAdvisories(xml);assert.equal(valid.records.length,2);assert.match(valid.sha256,/^[a-f0-9]{64}$/);
});
test('missing or failed source is incomplete and stale cached positives survive refresh failure',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-nginx-advisories-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const p=[{manager:'dpkg',sourceName:'nginx',sourceVersion:'1.24.0-1',packageMetadata:{maintainer:'NGINX Packaging <nginx-packaging@f5.com>'}}];
 const missing=await assessNginxAdvisories(p,{cacheDir,offline:true});assert.equal(missing.coverage[0].execution,'partial');assert.equal(missing.matches.length,0);
 await assessNginxAdvisories(p,{cacheDir,fetcher:async()=>new Response(xml)});const repo=require('../lib/cache-repository').createCacheRepository(cacheDir),cached=repo.get('catalogue','nginx-advisories').value;cached.observedAt=1;repo.put('catalogue','nginx-advisories',cached);
 const failed=await assessNginxAdvisories(p,{cacheDir,fetcher:async()=>new Response('',{status:403})});assert.equal(failed.matches.length,1);assert.equal(failed.coverage[0].execution,'partial');assert.match(failed.warnings[0].message,/403/);
});
test('image assessment consults vendor independently of OSV and excludes its packages from Debian ranges',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-nginx-scan-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const distribution={id:'debian',versionId:'11',codename:'bullseye'},vendor={manager:'dpkg',name:'nginx',sourceName:'nginx',version:'1.24.0-1~bullseye',sourceVersion:'1.24.0-1~bullseye',architecture:'amd64',manifestPath:'/status',packageMetadata:{maintainer:'NGINX Packaging <nginx-packaging@f5.com>'}},debian={manager:'dpkg',name:'curl',sourceName:'curl',version:'1-1',sourceVersion:'1-1',architecture:'amd64',manifestPath:'/status'};
 await require('../lib/system-inventory/nginx-advisories').syncNginxAdvisories({cacheDir,fetcher:async()=>new Response(xml)});
 const osvRecords=['nginx','curl'].map(name=>({id:`OSV-${name}`,aliases:[name==='nginx'?'CVE-2024-99991':'CVE-2024-99992'],affected:[{package:{ecosystem:'Debian:11',name},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'9-1'}]}]}]}));await require('../lib/system-inventory').importSystemAdvisories(osvRecords,{cacheDir,distribution,complete:true});
 const {assessInventories,systemDep}=require('../lib/artifacts/scan'),target={id:'img',kind:'rootfs',metadata:{},distribution,packages:[vendor,debian],deps:[systemDep(vendor,'img',distribution),systemDep(debian,'img',distribution)],coverage:[],warnings:[]},opts={cacheDir,offline:true,disableCveProject:true,disableGcve:true,enrich:[]};
 const independent=await assessInventories([target],{...opts,osv:false});assert.ok(independent.cveMatches.some(m=>m.cve.id==='CVE-2024-12345'&&m.source==='nginx-vendor-advisories'));assert.ok(independent.artifacts[0].coverage.some(c=>c.collector==='nginx-vendor-advisories'));
 const combined=await assessInventories([target],opts);assert.ok(combined.cveMatches.some(m=>m.cve.id==='CVE-2024-99992'));assert.ok(!combined.cveMatches.some(m=>m.cve.id==='CVE-2024-99991'));
 const excluded=await assessInventories([target],{...opts,osv:false,distroAdvisories:false});assert.ok(!excluded.cveMatches.some(m=>m.source==='nginx-vendor-advisories'));
});
test('vendor XML travels through fleet HTTP and survives archive transfer offline',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-nginx-fleet-')),source=path.join(root,'source'),dest=path.join(root,'dest'),archive=path.join(root,'cache.tar.gz'),providers=require('../lib/providers'),{createCacheStore,startProxyCacheServer}=require('../lib/proxy-cache'),store=createCacheStore(path.join(root,'fleet'));let count=0;
 const {server,url}=await startProxyCacheServer({host:'127.0.0.1',port:0,store,fetcher:async u=>{count++;assert.match(String(u),/raw\.githubusercontent\.com\/nginx\/nginx.org/);return new Response(xml,{headers:{'content-type':'application/xml'}});}});
 t.after(async()=>{providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});await new Promise(r=>server.close(r));store.close?.();require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 providers.configureResourceRoute({proxyUrl:url,hosted:false,fetcher:global.fetch,store:null,hostedStore:null});const p=[{manager:'dpkg',name:'nginx',sourceName:'nginx',sourceVersion:'1.24.0-1',packageMetadata:{maintainer:'NGINX Packaging <nginx-packaging@f5.com>'}}],fetcher=(u,o)=>{assert.ok(String(u).startsWith(url+'/'));return fetch(u,o)};
 const online=await assessNginxAdvisories(p,{cacheDir:source,fetcher});assert.equal(online.matches.length,1);assert.equal(count,1);
 await require('../lib/cache-archive-sqlite').exportCache(archive,{sourceDir:source,proxyOrigin:url});await require('../lib/cache-archive-sqlite').importCache(archive,{targetDir:dest,proxyOrigin:url});providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});
 const offline=await assessNginxAdvisories(p,{cacheDir:dest,offline:true,fetcher:()=>assert.fail('network')});assert.deepEqual(offline,online);
});
test('vendor adapter applies to dpkg on Ubuntu without assuming distro ownership',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-nginx-ubuntu-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 await require('../lib/system-inventory/nginx-advisories').syncNginxAdvisories({cacheDir,fetcher:async()=>new Response(xml)});
 const p={manager:'dpkg',name:'nginx',sourceName:'nginx',sourceVersion:'1.24.0-1',packageMetadata:{maintainer:'NGINX Packaging <nginx-packaging@f5.com>'}};
 const result=await require('../lib/system-inventory/distribution-sources').assessDistributionSources({distribution:{id:'ubuntu',versionId:'22.04'},packages:[p]},{cacheDir,offline:true});assert.equal(result.matches[0].source,'nginx-vendor-advisories');
});
test('origin classifiers are injectable and conflicting evidence is indeterminate',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-origin-hooks-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const {identifyPackageOrigin}=require('../lib/system-inventory/distribution-sources'),a={id:'one',identifyPackageOrigin:()=>({status:'third-party',declared:'vendor-a'})},b={id:'two',identifyPackageOrigin:()=>({status:'distribution',declared:'vendor-b'})},pkg={manager:'dpkg',name:'custom',sourceName:'custom',version:'1',sourceVersion:'1',manifestPath:'/status'};
 assert.equal(identifyPackageOrigin(pkg,{distributionSourceAdapters:[a]}).status,'third-party');assert.equal(identifyPackageOrigin(pkg,{distributionSourceAdapters:[a,b]}).status,'ambiguous');
 const distribution={id:'debian',versionId:'11'},rec={id:'OSV-custom',aliases:['CVE-2024-99991'],affected:[{package:{ecosystem:'Debian:11',name:'custom'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'9-1'}]}]}]};await require('../lib/system-inventory').importSystemAdvisories([rec],{distribution,cacheDir,complete:true});
 const {assessInventories,systemDep}=require('../lib/artifacts/scan'),target={id:'img',kind:'rootfs',metadata:{},distribution,packages:[pkg],deps:[systemDep(pkg,'img',distribution)],coverage:[],warnings:[]};
 const adapters=[a,b].map(x=>({...x,supports:()=>false,assess:async()=>({})})),result=await assessInventories([target],{cacheDir,offline:true,disableCveProject:true,disableGcve:true,enrich:[],distributionSourceAdapters:adapters});
 assert.ok(!result.cveMatches.some(m=>m.cve.id==='CVE-2024-99991'));assert.equal(result.artifacts[0].components[0].packageOrigin.status,'ambiguous');
});

const recentXml='<article><section><security><item name="HTTP/2 flow control" cve="2026-123007" vulnerable="1.9.5-1.31.8" good="1.31.9+, 1.30.7+"/><item name="HTTP/3" cve="CVE-2026-121810" vulnerable="1.25.0-1.31.8" good="1.31.9+, 1.30.7+"/></security></section></article>';
test('stable fixed exceptions do not suppress vulnerable mainline versions, for APK and dpkg',async()=>{
 const snapshot={...await parseNginxAdvisories(recentXml),observedAt:Date.now()},cacheRepository={get:()=>({value:snapshot})};
 assert.deepEqual(snapshot.records.map(r=>r.id),['CVE-2026-123007','CVE-2026-121810']);
 for(const manager of ['apk','dpkg'])for(const [version,affected,fix] of [['1.30.6',true,'1.30.7'],['1.30.7',false],['1.30.8',false],['1.31.8',true,'1.31.9'],['1.31.9',false],['1.29.9',true,null]]){
  const pkg={manager,name:'nginx',sourceName:'nginx',sourceVersion:version+(manager==='apk'?'-r1':'-1~bookworm'),packageMetadata:{maintainer:'NGINX Packaging <nginx-packaging@f5.com>'}};
  const result=await assessNginxAdvisories([pkg],{offline:true,cacheRepository});
  assert.equal(result.matches.length,affected?2:0,`${manager} ${version}`);
  assert.equal(result.coverage[0].execution,'completed');
  if(affected){assert.equal(result.matches[0].cve.fixVersion,fix);assert.equal(result.matches[0].dep.packageOrigin.source,`${manager}-maintainer`);}
 }
});
test('APK collection retains vendor identity, but source package origin alone never establishes the vendor',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-nginx-apk-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 fs.mkdirSync(path.join(root,'lib/apk/db'),{recursive:true});fs.mkdirSync(path.join(root,'etc'));
 fs.writeFileSync(path.join(root,'etc/os-release'),'ID=alpine\nVERSION_ID=3.24.4\n');
 fs.writeFileSync(path.join(root,'lib/apk/db/installed'),'P:nginx\nV:1.30.6-r1\nA:x86_64\no:nginx\nm:NGINX Packaging <nginx-packaging@f5.com>\nU:https://nginx.org/\n\n');
 const inventory=await require('../lib/system-inventory').collectSystemInventory(root),pkg=inventory.packages[0];
 assert.equal(pkg.packageMetadata.maintainer,'NGINX Packaging <nginx-packaging@f5.com>');
 const snapshot={...await parseNginxAdvisories(recentXml),observedAt:Date.now()},cacheRepository={get:()=>({value:snapshot})};
 const result=await require('../lib/system-inventory/distribution-sources').assessDistributionSources(inventory,{cacheDir:path.join(root,'cache'),cacheRepository,offline:true});
 assert.equal(result.matches.filter(m=>m.source==='nginx-vendor-advisories').length,2);
 for(const packageMetadata of [{origin:'nginx',maintainer:'Alpine Maintainer <dev@alpinelinux.org>'},{origin:'nginx'},{maintainer:'NGINX <packaging@f5.com.evil.test>'}]){
  const generic={...pkg,packageMetadata};assert.equal(require('../lib/system-inventory/nginx-advisories').nginxPackageOrigin(generic),null);
  const result=await assessNginxAdvisories([generic],{offline:true,cacheRepository});assert.equal(result.matches.length,0);assert.equal(result.observations.length,2);
 }
 const ambiguous=await assessNginxAdvisories([{...pkg,packageOrigin:{status:'ambiguous'}}],{offline:true,cacheRepository});assert.equal(ambiguous.matches.length,0);
});
test('old parsed catalogues refresh online and remain explicitly incomplete offline',async()=>{
 const snapshot={...await parseNginxAdvisories(recentXml),observedAt:Date.now()};delete snapshot.parserVersion;snapshot.records=snapshot.records.slice(0,1);
 let saved,calls=0;const cacheRepository={get:()=>({value:snapshot}),put:(_namespace,_key,value)=>{saved=value;}};
 const pkg={manager:'apk',sourceName:'nginx',sourceVersion:'1.30.6-r1',packageMetadata:{maintainer:'NGINX <packaging@nginx.org>'}};
 const offline=await assessNginxAdvisories([pkg],{offline:true,cacheRepository});assert.equal(offline.coverage[0].execution,'partial');assert.equal(offline.matches.length,1);
 const online=await assessNginxAdvisories([pkg],{cacheRepository,fetcher:async()=>{calls++;return new Response(recentXml);}});
 assert.equal(calls,1);assert.equal(online.matches.length,2);assert.equal(online.coverage[0].execution,'completed');assert.equal(saved.parserVersion,2);
});

test('full Alpine assessment keeps vendor ranges separate from distribution backports',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-nginx-alpine-assess-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true});});
 const distribution={id:'alpine',versionId:'3.24.4'},vendor={manager:'apk',name:'nginx',sourceName:'nginx',version:'1.30.6-r1',sourceVersion:'1.30.6-r1',architecture:'x86_64',manifestPath:'/lib/apk/db/installed',packageMetadata:{maintainer:'NGINX Packaging <nginx-packaging@f5.com>'}};
 await require('../lib/system-inventory/nginx-advisories').syncNginxAdvisories({cacheDir,fetcher:async()=>new Response(recentXml)});
 await require('../lib/system-inventory').importSystemAdvisories([{id:'ALPINE-CVE-fixture',aliases:['CVE-2026-99999'],affected:[{package:{ecosystem:'Alpine:v3.24',name:'nginx'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1.31.0-r0'}]}]}]}],{cacheDir,distribution,complete:true});
 const {assessInventories,systemDep}=require('../lib/artifacts/scan');
 for(const official of [true,false]){
  const pkg=official?vendor:{...vendor,packageMetadata:{maintainer:'Alpine Maintainer <dev@alpinelinux.org>'}};
  const target={id:'img',kind:'rootfs',metadata:{},distribution,packages:[pkg],deps:[systemDep(pkg,'img',distribution)],coverage:[],warnings:[]};
  const result=await assessInventories([target],{cacheDir,offline:true,disableCveProject:true,disableGcve:true,enrich:[]});
  assert.equal(result.cveMatches.some(m=>m.cve.id==='CVE-2026-123007'),official);
  assert.equal(result.cveMatches.some(m=>m.cve.id==='CVE-2026-99999'),!official);
 }
});
