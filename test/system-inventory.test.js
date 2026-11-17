'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {zipSync,strToU8}=require('fflate');
const {collectSystemInventory,assessSystemInventory,importSystemAdvisories,syncSystemAdvisories,rpmHeader,versions}=require('../lib/system-inventory');
const {closeCacheDbs}=require('../lib/cache-db');
function root(t){const p=fs.mkdtempSync(path.join(os.tmpdir(),'vv-system-'));t.after(()=>{closeCacheDbs();fs.rmSync(p,{recursive:true,force:true});});return p;}
function put(dir,file,text){const p=path.join(dir,file);fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,text);}
test('installed dpkg records preserve source identity and reject host symlinks',async t=>{
 const dir=root(t);put(dir,'etc/os-release','ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n');
 put(dir,'var/lib/dpkg/status','Package: libone\nStatus: install ok installed\nVersion: 1:2.0-1+b2\nArchitecture: amd64\nSource: one (1:2.0-1)\n\nPackage: absent\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: b\nStatus: install ok installed\nVersion: 1+b1\n');
 const inv=await collectSystemInventory(dir);assert.equal(inv.packages.length,2);assert.equal(inv.packages[0].sourceName,'one');assert.equal(inv.packages[0].sourceVersion,'1:2.0-1');assert.equal(inv.packages[1].sourceVersion,null);assert.equal(inv.distribution.versionId,'12');
 fs.rmSync(path.join(dir,'var/lib/dpkg/status'));fs.symlinkSync('/etc/passwd',path.join(dir,'var/lib/dpkg/status'));assert.equal((await collectSystemInventory(dir)).packages.length,0);
});
test('APK installed db and unsupported RPM backend are visible',async t=>{
 const dir=root(t);put(dir,'etc/os-release','ID=alpine\nVERSION_ID=3.20\n');put(dir,'lib/apk/db/installed','P:libfoo\nV:1.2-r1\nA:x86_64\no:foo\n\n');put(dir,'var/lib/rpm/Packages.db','ndb');
 const inv=await collectSystemInventory(dir);assert.equal(inv.packages[0].sourceName,'foo');assert.equal(inv.coverage.find(x=>x.collector==='rpm').status,'incomplete');
});
test('native version order handles epoch, release, prerelease and RPM caret',()=>{
 assert.equal(versions.debian('1:1.0-1','2.0-1'),1);assert.equal(versions.debian('1.0~rc1-1','1.0-1'),-1);assert.equal(versions.debian('1.0-1','1.0-2'),-1);
 assert.equal(versions.rpm('1.0^2020-1','1.0-1'),1);assert.equal(versions.rpm('1.0^2020-1','1.0.1-1'),-1);assert.equal(versions.rpm('1.0~rc1-1','1.0-1'),-1);
 assert.equal(versions.apk('1.0_rc1-r0','1.0-r0'),-1);assert.equal(versions.apk('1.0-r1','1.0-r2'),-1);assert.equal(versions.apk('???','1'),null);
});
test('offline source and release scoped advisory matches with unknown coverage',async t=>{
 const dir=root(t), distribution={id:'debian',versionId:'12'}, dep={name:'libfoo',sourceName:'foo',sourceVersion:'1.0-1',version:'1.0-1',manager:'dpkg'};
 const records=[{id:'DEBIAN-CVE-1',aliases:['CVE-2024-12345'],affected:[{package:{ecosystem:'Debian:12',name:'foo',purl:'pkg:deb/debian/foo?arch=source'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1.0-2'}]}]}]}];
 await importSystemAdvisories(records,{distribution,cacheDir:dir,complete:true});
 let result=await assessSystemInventory({distribution,packages:[dep]},{cacheDir:dir});assert.equal(result.matches.length,1);assert.equal(result.matches[0].cve.id,'CVE-2024-12345');assert.equal(result.coverage[0].status,'complete');
 result=await assessSystemInventory({distribution,packages:[{...dep,sourceVersion:'1.0-2'}]},{cacheDir:dir});assert.equal(result.matches.length,0);
 result=await assessSystemInventory({distribution,packages:[{...dep,sourceVersion:null}]},{cacheDir:dir});assert.equal(result.coverage[0].unknown,1);
 result=await assessSystemInventory({distribution:{id:'debian',versionId:'13'},packages:[dep]},{cacheDir:dir});assert.equal(result.coverage[0].status,'missing');
});
test('online preparation imports an OSV zip and offline sync forbids network',async t=>{
 const dir=root(t),distribution={id:'alpine',versionId:'3.20'};
 const record={id:'ALPINE-CVE-1',affected:[{package:{ecosystem:'Alpine:v3.20',name:'foo'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0-r0'}]}]}]};
 const zip=zipSync({'one.json':strToU8(JSON.stringify(record))});let called=0;
 await syncSystemAdvisories(distribution,{cacheDir:dir,fetcher:async()=>{called++;return {ok:true,arrayBuffer:async()=>zip};}});
 await assert.rejects(syncSystemAdvisories(distribution,{offline:true,cacheDir:dir,fetcher:()=>{throw Error('network');}}),/offline/);assert.equal(called,1);
 const result=await assessSystemInventory({distribution,packages:[{name:'foo',version:'1.0-r0'}]},{cacheDir:dir});assert.equal(result.matches.length,1);
});
test('malformed RPM headers are rejected',()=>assert.throws(()=>rpmHeader(Buffer.alloc(8)),/lacks|bounds/));
test('RPM SQLite package headers are decoded without invoking rpm',async t=>{
 const dir=root(t);put(dir,'etc/os-release','ID=rocky\nVERSION_ID=9\n');
 const values=[[1000,6,'libfoo'],[1001,6,'1.2'],[1002,6,'3.el9'],[1022,6,'x86_64'],[1044,6,'foo-1.2-3.el9.src.rpm']];
 let size=0;const chunks=[];for(const item of values){const b=Buffer.from(item[2]+'\0');chunks.push(b);item.push(size);size+=b.length;}
 const blob=Buffer.alloc(8+values.length*16+size);blob.writeUInt32BE(values.length);blob.writeUInt32BE(size,4);
 for(let i=0;i<values.length;i++){const [tag,type,,offset]=values[i],p=8+i*16;blob.writeUInt32BE(tag,p);blob.writeUInt32BE(type,p+4);blob.writeUInt32BE(offset,p+8);blob.writeUInt32BE(1,p+12);}Buffer.concat(chunks).copy(blob,8+values.length*16);
 const dbfile=path.join(dir,'usr/lib/sysimage/rpm/rpmdb.sqlite');fs.mkdirSync(path.dirname(dbfile),{recursive:true});const db=require('../lib/sqlite-driver').openSqlite(dbfile);db.exec('CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)');db.prepare('INSERT INTO Packages VALUES (?,?)').run(1,blob);db.close();
 const inventory=await collectSystemInventory(dir);assert.equal(inventory.packages.length,1);assert.equal(inventory.packages[0].sourceName,'foo');assert.equal(inventory.packages[0].version,'1.2-3.el9');assert.equal(inventory.coverage[0].status,'complete');
});
test('advisory adapters are injectable and preserve snapshot coverage',async t=>{
 const dir=root(t),distribution={id:'custom',versionId:'1'};
 const adapters=[{resolveScope:d=>d.id==='custom'?{base:'Custom',ecosystem:'Custom:1',compare:versions.debian}:null}];
 const rec={id:'CUSTOM-1',affected:[{package:{ecosystem:'Custom:1',name:'foo'},ranges:[{type:'ECOSYSTEM',events:[{fixed:'2-1'},{introduced:'0'}]}]}]};
 await importSystemAdvisories([rec],{distribution,adapters,cacheDir:dir,complete:true});
 const result=await assessSystemInventory({distribution,packages:[{name:'foo',version:'1-1',sourceName:'foo',sourceVersion:'1-1'}]},{adapters,cacheDir:dir});assert.equal(result.matches.length,1);
 await assert.rejects(importSystemAdvisories([rec],{distribution,adapters,cacheDir:dir}),/partial snapshot/);
 await assert.rejects(importSystemAdvisories([rec],{distribution:{id:'debian',versionId:'12'},cacheDir:dir,complete:true}),/no records/);
});
test('malformed advisory ranges remain unknown and Alpine releases normalize',async t=>{
 const dir=root(t),distribution={id:'alpine',versionId:'3.20.9'};
 const record={id:'ALPINE-X',affected:[{package:{ecosystem:'Alpine:v3.20',name:'foo'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'1.0',fixed:'2.0'}]}]}]};
 await importSystemAdvisories([record],{distribution,cacheDir:dir,complete:true});
 const result=await assessSystemInventory({distribution,packages:[{name:'foo',sourceName:'foo',sourceVersion:'1.5'}]},{cacheDir:dir});assert.equal(result.coverage[0].status,'incomplete');assert.equal(result.matches.length,0);
 assert.equal(versions.apk('1.01','1.1'),-1);assert.equal(versions.apk('1.0','1.0-r0'),-1);assert.equal(versions.apk('1.0_rc1','1.0'),-1);
});
test('explicit RHEL repository scope is identity bound and mirror credentials are never persisted',async t=>{
 const dir=root(t),distribution={id:'rhel',versionId:'9.6'},advisoryConfig={distribution,base:'Red Hat',ecosystem:'Red Hat:rhel_eus:9.6::appstream',versionScheme:'rpm',sourceUrl:'https://mirror.example/db.zip?token=secret'};
 const record={id:'RHSA-X',affected:[{package:{ecosystem:advisoryConfig.ecosystem,name:'pkg'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}]}]};
 const zip=zipSync({'one.json':strToU8(JSON.stringify(record))});await syncSystemAdvisories(distribution,{advisoryConfig,cacheDir:dir,fetcher:async()=>({ok:true,arrayBuffer:async()=>zip})});
 const snapshot=require('../lib/cache-repository').createCacheRepository(dir).getSnapshot('system-osv:'+advisoryConfig.ecosystem);assert.equal(snapshot.metadata.source,'https://mirror.example/db.zip');
 const result=await assessSystemInventory({distribution,packages:[{name:'pkg',version:'1-1'}]},{advisoryConfig,cacheDir:dir});assert.equal(result.matches.length,1);
 const different=await assessSystemInventory({distribution:{id:'rhel',versionId:'9.7'},packages:[]},{advisoryConfig,cacheDir:dir});assert.equal(different.coverage[0].status,'unknown');
 await assert.rejects(syncSystemAdvisories(distribution,{advisoryConfig:{...advisoryConfig,sourceUrl:'http://example.com/db'},cacheDir:dir}),/HTTPS/);
});
test('RPM file lists link files to owners without executing package tools',()=>{
 const values=[[1000,6,['pkg']],[1001,6,['1']],[1002,6,['1']],[1116,4,[0,1]],[1117,8,['one','two']],[1118,8,['/usr/bin/','/etc/']]];
 const chunks=[],offsets=[];let len=0;for(const [,type,items] of values){const b=type===4?Buffer.concat(items.map(x=>{const v=Buffer.alloc(4);v.writeUInt32BE(x);return v;})):Buffer.from(items.join('\0')+'\0');offsets.push(len);chunks.push(b);len+=b.length;}
 const blob=Buffer.alloc(8+values.length*16+len);blob.writeUInt32BE(values.length);blob.writeUInt32BE(len,4);values.forEach(([tag,type,items],i)=>{const p=8+i*16;blob.writeUInt32BE(tag,p);blob.writeUInt32BE(type,p+4);blob.writeUInt32BE(offsets[i],p+8);blob.writeUInt32BE(items.length,p+12);});Buffer.concat(chunks).copy(blob,8+values.length*16);
 assert.deepEqual(rpmHeader(blob).ownedPaths,['/usr/bin/one','/etc/two']);
});
test('offline system snapshots survive cache bundle transfer',async t=>{
 const dir=root(t),source=path.join(dir,'source'),target=path.join(dir,'target'),archive=path.join(dir,'cache.tar.gz'),distribution={id:'debian',versionId:'12'};
 const record={id:'DEBIAN-X',affected:[{package:{ecosystem:'Debian:12',name:'foo'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}]}]};
 await importSystemAdvisories([record],{distribution,cacheDir:source,complete:true});const {exportCache,importCache}=require('../lib/cache-archive-sqlite');
 await exportCache(archive,{sourceDir:source});await importCache(archive,{targetDir:target});
 const result=await assessSystemInventory({distribution,packages:[{name:'foo',sourceName:'foo',version:'1-1',sourceVersion:'1-1'}]},{cacheDir:target,offline:true});assert.equal(result.matches.length,1);assert.equal(result.coverage[0].status,'complete');
});
test('metadata limits and malformed records yield incomplete coverage',async t=>{
 const dir=root(t);put(dir,'etc/os-release','ID=debian\nVERSION_ID=12\n');put(dir,'var/lib/dpkg/status','Package: broken\nStatus: install ok installed\n\nPackage: valid\nStatus: install ok installed\nVersion: 1-1\n');put(dir,'lib/apk/db/installed','P:broken\n\n');
 const result=await collectSystemInventory(dir);assert.equal(result.packages.length,1);assert.equal(result.coverage.find(x=>x.collector==='dpkg').status,'incomplete');assert.equal(result.coverage.find(x=>x.collector==='apk').status,'incomplete');
 const bounded=await collectSystemInventory(dir,{maxSystemMetadataBytes:8});assert.ok(bounded.coverage.some(x=>x.status==='incomplete'));await assert.rejects(collectSystemInventory(dir,{collectors:[{id:'x'},{id:'x'}]}),/collector registry/);
});
test('SUSE product and service-pack identity cannot be inferred from a major release',async t=>{
 const dir=root(t);
 for(const distribution of [{id:'opensuse-leap',versionId:'15.6'},{id:'opensuse',versionId:'15.6'},{id:'sles',versionId:'15.6'}]) {
  const result=await assessSystemInventory({distribution,packages:[]},{cacheDir:dir});assert.equal(result.coverage[0].status,'unknown');
 }
 const distribution={id:'opensuse-leap',versionId:'16.0'},advisoryConfig={distribution,base:'openSUSE',ecosystem:'openSUSE:Leap 16.0',versionScheme:'rpm'};
 const record={id:'openSUSE-X',affected:[{package:{ecosystem:advisoryConfig.ecosystem,name:'pkg'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}]}]};
 await importSystemAdvisories([record],{distribution,advisoryConfig,cacheDir:dir,complete:true});
 const result=await assessSystemInventory({distribution,packages:[{name:'pkg',version:'1-1',sourceName:'pkg'}]},{cacheDir:dir,advisoryConfig});assert.equal(result.matches.length,1);
});
test('OSV upstream CVE relationships survive offline assessment and JSON export',async()=>{
 const distribution={id:'debian',versionId:'12'};
 const records=[{id:'DEBIAN-CVE-2009-1300',upstream:['CVE-2009-1300','CVE-2024-12345'],aliases:[],affected:[{package:{ecosystem:'Debian:12',name:'apt'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}]}]}];
 const assessed=await assessSystemInventory({distribution,packages:[{name:'apt',sourceName:'apt',version:'1-1',sourceVersion:'1-1'}]},{records,complete:true});
 assert.equal(assessed.matches.length,1);const cve=assessed.matches[0].cve;assert.equal(cve.id,'DEBIAN-CVE-2009-1300');assert.deepEqual(cve.aliases,[]);assert.deepEqual(cve.upstream,['CVE-2009-1300','CVE-2024-12345']);
 const result=require('../lib/json-export').buildFindings({cveMatches:assessed.matches});assert.deepEqual(result.cve[0].upstream,cve.upstream);
});
test('fleet proxy serves and caches typed OSV distro archive without direct client access',async t=>{
 const dir=root(t),record={id:'ALPINE-X',affected:[{package:{ecosystem:'Alpine:v3.20',name:'foo'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-r0'}]}]}]};
 const zip=zipSync({'one.json':strToU8(JSON.stringify(record))});let hits=0;
 const {startProxyCacheServer,createCacheStore}=require('../lib/proxy-cache');
 const store=createCacheStore(path.join(dir,'proxy'));const {server,url}=await startProxyCacheServer({port:0,host:'127.0.0.1',store,fetcher:async target=>{hits++;assert.match(target,/\/Alpine\/all\.zip$/);return new Response(zip,{status:200,headers:{'content-type':'application/zip'}});}});
 const routing=require('../lib/providers');routing.configureResourceRoute({proxyUrl:url,hosted:false,token:null,fetcher:null,store:null});
 try {
  const distribution={id:'alpine',versionId:'3.20'};
  await syncSystemAdvisories(distribution,{cacheDir:path.join(dir,'client-a')});
  await syncSystemAdvisories(distribution,{cacheDir:path.join(dir,'client-b')});assert.equal(hits,1);
  const result=await assessSystemInventory({distribution,packages:[{name:'foo',sourceName:'foo',version:'1-r0'}]},{cacheDir:path.join(dir,'client-b'),offline:true});assert.equal(result.matches.length,1);
 } finally {routing.configureResourceRoute({proxyUrl:null,hosted:false,token:null,fetcher:null,store:null});await new Promise(resolve=>server.close(resolve));store.close?.();}
});
test('targeted distro queries follow pages and remain usable offline for exactly consulted versions',async t=>{
 const dir=root(t),distribution={id:'debian',versionId:'12'},dep={manager:'dpkg',name:'libx',sourceName:'x',sourceVersion:'1-1',version:'1-1'},inv={distribution,packages:[dep]};
 const record={id:'DEBIAN-X',upstream:['CVE-2024-12345'],affected:[{package:{ecosystem:'Debian:12',name:'x',purl:'pkg:deb/debian/x?arch=source'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}]}]};let pages=0;
 const fetcher=async(url,init)=>{if(String(url).endsWith('/querybatch')){const request=JSON.parse(init.body);assert.equal(request.queries[0].package.ecosystem,'Debian:12');pages++;return Response.json({results:[pages===1?{next_page_token:'next'}:{vulns:[{id:'DEBIAN-X'}]}]});}if(String(url).endsWith('/DEBIAN-X'))return Response.json(record);throw Error('unexpected endpoint');};
 const {assessTargetedSystemInventory}=require('../lib/system-inventory');let result=await assessTargetedSystemInventory(inv,{cacheDir:dir,fetcher});assert.equal(pages,2);assert.equal(result.matches.length,1);assert.equal(result.coverage[0].scope,'consulted-package-versions');
 result=await assessTargetedSystemInventory(inv,{cacheDir:dir,offline:true,fetcher:()=>{throw Error('network')}});assert.equal(result.matches.length,1);assert.equal(result.coverage[0].status,'complete');
 result=await assessTargetedSystemInventory({distribution,packages:[{...dep,sourceVersion:'1-2'}]},{cacheDir:dir,offline:true});assert.equal(result.coverage[0].status,'incomplete');
});
test('targeted distro consultation fails closed for incomplete pages and missing source versions',async t=>{
 const dir=root(t),distribution={id:'debian',versionId:'12'},dep={manager:'dpkg',name:'x',sourceName:'x',sourceVersion:'1-1',version:'1-1'};
 const {assessTargetedSystemInventory}=require('../lib/system-inventory');
 const result=await assessTargetedSystemInventory({distribution,packages:[dep,{...dep,sourceVersion:null}]},{cacheDir:dir,fetcher:async()=>Response.json({results:[]})});assert.equal(result.coverage[0].status,'incomplete');assert.equal(result.matches.length,0);assert.ok(result.coverage[0].unknown>=2);
});
test('hosted-style proxy performs distro package consultations and offline cache replay',async t=>{
 const dir=root(t),distribution={id:'debian',versionId:'12'},inv={distribution,packages:[{manager:'dpkg',name:'libfoo',sourceName:'foo',sourceVersion:'1-1',version:'1-1'}]};
 const record={id:'DEBIAN-ONE',affected:[{package:{ecosystem:'Debian:12',name:'foo',purl:'pkg:deb/debian/foo?arch=source'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}]}]};
 const {startProxyCacheServer,createCacheStore}=require('../lib/proxy-cache');const store=createCacheStore(path.join(dir,'proxy'));let calls=0;
 const {server,url}=await startProxyCacheServer({port:0,host:'127.0.0.1',store,fetcher:async(target,init)=>{calls++;if(String(target).endsWith('/querybatch')){assert.equal(JSON.parse(init.body).queries[0].package.ecosystem,'Debian:12');return Response.json({results:[{vulns:[{id:'DEBIAN-ONE'}]}]});}if(String(target).endsWith('/DEBIAN-ONE'))return Response.json(record);throw Error('unexpected source');}});
 const routing=require('../lib/providers');routing.configureResourceRoute({proxyUrl:url,hosted:true,token:null,fetcher:null,store:null,hostedStore:null});
 try {const {assessTargetedSystemInventory}=require('../lib/system-inventory');const online=await assessTargetedSystemInventory(inv,{cacheDir:path.join(dir,'client')});assert.equal(online.matches.length,1);assert.equal(online.coverage[0].status,'complete');assert.equal(calls,2);routing.configureResourceRoute({proxyUrl:null,hosted:false});const offline=await assessTargetedSystemInventory(inv,{cacheDir:path.join(dir,'client'),offline:true,fetcher:()=>{throw Error('network')}});assert.equal(offline.matches.length,1);}finally{routing.configureResourceRoute({proxyUrl:null,hosted:false,token:null,fetcher:null,store:null});await new Promise(resolve=>server.close(resolve));store.close?.();}
});
test('targeted per-version consultations transfer through cache bundles',async t=>{
 const dir=root(t),source=path.join(dir,'source'),target=path.join(dir,'target'),archive=path.join(dir,'targeted.tar.gz'),distribution={id:'alpine',versionId:'3.20'};
 const inv={distribution,packages:[{manager:'apk',name:'foo',sourceName:'foo',sourceVersion:'1-r0',version:'1-r0'}]};
 const {assessTargetedSystemInventory}=require('../lib/system-inventory');const online=await assessTargetedSystemInventory(inv,{cacheDir:source,fetcher:async()=>Response.json({results:[{}]})});assert.equal(online.coverage[0].status,'complete');
 const {exportCache,importCache}=require('../lib/cache-archive-sqlite');await exportCache(archive,{sourceDir:source});await importCache(archive,{targetDir:target});
 const result=await assessTargetedSystemInventory(inv,{cacheDir:target,offline:true,fetcher:()=>{throw Error('network')}});assert.equal(result.coverage[0].status,'complete');assert.equal(result.matches.length,0);
});
test('Debian advisory keeps dated upstream and related evidence distinct from aliases',async()=>{
 const distribution={id:'debian',versionId:'11'},dep={name:'curl',sourceName:'curl',sourceVersion:'1-1',version:'1-1',manager:'dpkg'};
 const record={id:'DLA-3951-1',summary:'curl - security update',published:'2024-11-14T00:00:00Z',modified:'2026-03-09T01:21:26Z',upstream:['CVE-2024-8096','CVE-2024-9999'],related:['DEBIAN-CVE-2024-8096'],affected:[{package:{name:'curl',ecosystem:'Debian:11',purl:'pkg:deb/debian/curl?arch=source'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}],database_specific:{source:'https://storage.googleapis.com/debian-osv/dla-osv/DLA-3951-1.json'}}]};
 const out=await assessSystemInventory({distribution,packages:[dep]},{records:[record],complete:true});assert.equal(out.matches.length,1);const cve=out.matches[0].cve;
 assert.equal(cve.id,'DLA-3951-1');assert.deepEqual(cve.aliases,[]);assert.deepEqual(cve.upstream,['CVE-2024-8096','CVE-2024-9999']);assert.deepEqual(cve.related,['DEBIAN-CVE-2024-8096']);assert.equal(cve.severity,'UNKNOWN');assert.equal(cve.published,record.published);assert.equal(cve.modified,record.modified);assert.equal(cve.summary,record.summary);assert.equal(cve.advisorySource,record.affected[0].database_specific.source);
});
