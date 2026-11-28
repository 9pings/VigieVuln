'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {zipSync,strToU8}=require('fflate');
const {collectSystemInventory,assessSystemInventory,importSystemAdvisories,syncSystemAdvisories,rpmHeader,versions}=require('../lib/system-inventory');
const {closeCacheDbs}=require('../lib/cache/db');
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
 const dbfile=path.join(dir,'usr/lib/sysimage/rpm/rpmdb.sqlite');fs.mkdirSync(path.dirname(dbfile),{recursive:true});const db=require('../lib/cache/sqlite-driver').openSqlite(dbfile);db.exec('CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)');db.prepare('INSERT INTO Packages VALUES (?,?)').run(1,blob);db.close();
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
 const snapshot=require('../lib/cache/repository').createCacheRepository(dir).getSnapshot('system-osv:'+advisoryConfig.ecosystem);assert.equal(snapshot.metadata.source,'https://mirror.example/db.zip');
 const result=await assessSystemInventory({distribution,packages:[{name:'pkg',version:'1-1'}]},{advisoryConfig,cacheDir:dir});assert.equal(result.matches.length,1);
 // The explicit scope is bound to the release it names: another release gets its own, automatic, scope.
 const different=await assessSystemInventory({distribution:{id:'rhel',versionId:'9.7'},packages:[]},{advisoryConfig,cacheDir:dir});assert.deepEqual([different.coverage[0].status,different.coverage[0].ecosystem],['missing','Red Hat:enterprise_linux:9']);
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
 await importSystemAdvisories([record],{distribution,cacheDir:source,complete:true});const {exportCache,importCache}=require('../lib/cache/archive');
 await exportCache(archive,{sourceDir:source});await importCache(archive,{targetDir:target});
 const result=await assessSystemInventory({distribution,packages:[{name:'foo',sourceName:'foo',version:'1-1',sourceVersion:'1-1'}]},{cacheDir:target,offline:true});assert.equal(result.matches.length,1);assert.equal(result.coverage[0].status,'complete');
});
test('metadata limits and malformed records yield incomplete coverage',async t=>{
 const dir=root(t);put(dir,'etc/os-release','ID=debian\nVERSION_ID=12\n');put(dir,'var/lib/dpkg/status','Package: broken\nStatus: install ok installed\n\nPackage: valid\nStatus: install ok installed\nVersion: 1-1\n');put(dir,'lib/apk/db/installed','P:broken\n\n');
 const result=await collectSystemInventory(dir);assert.equal(result.packages.length,1);assert.equal(result.coverage.find(x=>x.collector==='dpkg').status,'incomplete');assert.equal(result.coverage.find(x=>x.collector==='apk').status,'incomplete');
 const bounded=await collectSystemInventory(dir,{maxSystemMetadataBytes:8});assert.ok(bounded.coverage.some(x=>x.status==='incomplete'));await assert.rejects(collectSystemInventory(dir,{collectors:[{id:'x'},{id:'x'}]}),/collector registry/);
});
test('SUSE releases are assessed from their os-release identity; an explicit scope still overrides it',async t=>{
 const dir=root(t);
 // The release and service pack are in os-release: no declaration is needed. Only the advisory data is missing here.
 for(const [distribution,ecosystem] of [[{id:'opensuse-leap',versionId:'15.6'},'openSUSE:Leap 15.6'],[{id:'sles',versionId:'15.6'},'SUSE:Linux Enterprise 15 SP6']]) {
  const result=await assessSystemInventory({distribution,packages:[]},{cacheDir:dir});assert.deepEqual([result.coverage[0].status,result.coverage[0].ecosystem],['missing',ecosystem]);
 }
 const unknown=await assessSystemInventory({distribution:{id:'opensuse',versionId:'15.6'},packages:[]},{cacheDir:dir});assert.equal(unknown.coverage[0].status,'unknown');
 const distribution={id:'opensuse-leap',versionId:'16.0'},advisoryConfig={distribution,base:'openSUSE',ecosystem:'openSUSE:Leap 16.0',versionScheme:'rpm'};
 const record={id:'openSUSE-X',affected:[{package:{ecosystem:advisoryConfig.ecosystem,name:'pkg'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}]}]};
 await importSystemAdvisories([record],{distribution,advisoryConfig,cacheDir:dir,complete:true});
 const result=await assessSystemInventory({distribution,packages:[{name:'pkg',version:'1-1',sourceName:'pkg'}]},{cacheDir:dir,advisoryConfig});assert.equal(result.matches.length,1);
});
test('OSV upstream CVE relationships survive offline assessment and JSON export',async()=>{
 const distribution={id:'debian',versionId:'12'};
 const records=[{id:'DEBIAN-CVE-2009-1300',upstream:['CVE-2009-1300','CVE-2024-12345'],aliases:[],affected:[{package:{ecosystem:'Debian:12',name:'apt'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}]}]}];
 const assessed=await assessSystemInventory({distribution,packages:[{name:'apt',sourceName:'apt',version:'1-1',sourceVersion:'1-1'}]},{records,complete:true});
 assert.equal(assessed.matches.length,1);const cve=assessed.matches[0].cve;assert.equal(cve.id,'CVE-2009-1300','a per-CVE distribution record is shown under its CVE id');assert.equal(cve.sourceAdvisoryId,'DEBIAN-CVE-2009-1300');assert.deepEqual(cve.aliases,[]);assert.deepEqual(cve.upstream,['CVE-2009-1300','CVE-2024-12345']);
 const result=require('../lib/reports/json-export').buildFindings({cveMatches:assessed.matches});assert.deepEqual(result.cve[0].upstream,cve.upstream);
});
test('fleet proxy serves and caches typed OSV distro archive without direct client access',async t=>{
 const dir=root(t),record={id:'ALPINE-X',affected:[{package:{ecosystem:'Alpine:v3.20',name:'foo'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-r0'}]}]}]};
 const zip=zipSync({'one.json':strToU8(JSON.stringify(record))});let hits=0;
 const {startProxyCacheServer,createCacheStore}=require('../lib/cache/proxy-cache');
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
 const {startProxyCacheServer,createCacheStore}=require('../lib/cache/proxy-cache');const store=createCacheStore(path.join(dir,'proxy'));let calls=0;
 const {server,url}=await startProxyCacheServer({port:0,host:'127.0.0.1',store,fetcher:async(target,init)=>{calls++;if(String(target).endsWith('/querybatch')){assert.equal(JSON.parse(init.body).queries[0].package.ecosystem,'Debian:12');return Response.json({results:[{vulns:[{id:'DEBIAN-ONE'}]}]});}if(String(target).endsWith('/DEBIAN-ONE'))return Response.json(record);throw Error('unexpected source');}});
 const routing=require('../lib/providers');routing.configureResourceRoute({proxyUrl:url,hosted:true,token:null,fetcher:null,store:null,hostedStore:null});
 try {const {assessTargetedSystemInventory}=require('../lib/system-inventory');const online=await assessTargetedSystemInventory(inv,{cacheDir:path.join(dir,'client')});assert.equal(online.matches.length,1);assert.equal(online.coverage[0].status,'complete');assert.equal(calls,2);routing.configureResourceRoute({proxyUrl:null,hosted:false});const offline=await assessTargetedSystemInventory(inv,{cacheDir:path.join(dir,'client'),offline:true,fetcher:()=>{throw Error('network')}});assert.equal(offline.matches.length,1);}finally{routing.configureResourceRoute({proxyUrl:null,hosted:false,token:null,fetcher:null,store:null});await new Promise(resolve=>server.close(resolve));store.close?.();}
});
test('targeted per-version consultations transfer through cache bundles',async t=>{
 const dir=root(t),source=path.join(dir,'source'),target=path.join(dir,'target'),archive=path.join(dir,'targeted.tar.gz'),distribution={id:'alpine',versionId:'3.20'};
 const inv={distribution,packages:[{manager:'apk',name:'foo',sourceName:'foo',sourceVersion:'1-r0',version:'1-r0'}]};
 const {assessTargetedSystemInventory}=require('../lib/system-inventory');const online=await assessTargetedSystemInventory(inv,{cacheDir:source,fetcher:async()=>Response.json({results:[{}]})});assert.equal(online.coverage[0].status,'complete');
 const {exportCache,importCache}=require('../lib/cache/archive');await exportCache(archive,{sourceDir:source});await importCache(archive,{targetDir:target});
 const result=await assessTargetedSystemInventory(inv,{cacheDir:target,offline:true,fetcher:()=>{throw Error('network')}});assert.equal(result.coverage[0].status,'complete');assert.equal(result.matches.length,0);
});
test('Debian advisory keeps dated upstream and related evidence distinct from aliases',async()=>{
 const distribution={id:'debian',versionId:'11'},dep={name:'curl',sourceName:'curl',sourceVersion:'1-1',version:'1-1',manager:'dpkg'};
 const record={id:'DLA-3951-1',summary:'curl - security update',published:'2024-11-14T00:00:00Z',modified:'2026-03-09T01:21:26Z',upstream:['CVE-2024-8096','CVE-2024-9999'],related:['DEBIAN-CVE-2024-8096'],affected:[{package:{name:'curl',ecosystem:'Debian:11',purl:'pkg:deb/debian/curl?arch=source'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2-1'}]}],database_specific:{source:'https://storage.googleapis.com/debian-osv/dla-osv/DLA-3951-1.json'}}]};
 const out=await assessSystemInventory({distribution,packages:[dep]},{records:[record],complete:true});assert.equal(out.matches.length,1);const cve=out.matches[0].cve;
 assert.equal(cve.id,'DLA-3951-1');assert.deepEqual(cve.aliases,[]);assert.deepEqual(cve.upstream,['CVE-2024-8096','CVE-2024-9999']);assert.deepEqual(cve.related,['DEBIAN-CVE-2024-8096']);assert.equal(cve.severity,'UNKNOWN');assert.equal(cve.published,record.published);assert.equal(cve.modified,record.modified);assert.equal(cve.summary,record.summary);assert.equal(cve.advisorySource,record.affected[0].database_specific.source);
});
test('OSV versions[] counts even when ranges exist (B5)',()=>{
 const {verdict}=require('../lib/system-inventory/advisories');
 const a={ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1.0-2'}]}],versions:['1.0-1','1.1-1']};
 assert.equal(verdict('1.1-1',a,versions.debian),true);
 // compared by the distribution scheme, not by string: an explicit zero epoch is the same version
 assert.equal(verdict('0:1.1-1',a,versions.debian),true);
 assert.equal(verdict('1:1.1-1',a,versions.debian),false);
 assert.equal(verdict('1.0-1',a,versions.debian),true);assert.equal(verdict('1.2-1',a,versions.debian),false);
 // an undecidable range still leaves an unlisted version unknown, a listed one is affected
 const u={ranges:[{type:'GIT',events:[{introduced:'abc'}]}],versions:['1.1-1']};
 assert.equal(verdict('1.1-1',u,versions.debian),true);assert.equal(verdict('1.2-1',u,versions.debian),null);
});
test('distroless dpkg status.d control files are installed packages; md5sums are ignored',async t=>{
 const dir=root(t);put(dir,'etc/os-release','ID=debian\nVERSION_ID=12\n');
 put(dir,'var/lib/dpkg/status.d/libssl3','Package: libssl3\nVersion: 3.0.11-1~deb12u2\nArchitecture: amd64\nSource: openssl\n');
 put(dir,'var/lib/dpkg/status.d/libssl3.md5sums','0123456789abcdef0123456789abcdef  usr/lib/x86_64-linux-gnu/libssl.so.3\n');
 put(dir,'var/lib/dpkg/status.d/tzdata','Package: tzdata\nVersion: 2024a-0+deb12u1\nArchitecture: all\n');
 put(dir,'var/lib/dpkg/status.d/removed','Package: removed\nStatus: deinstall ok config-files\nVersion: 1\n');
 let inv=await collectSystemInventory(dir);const dpkg=inv.coverage.find(c=>c.collector==='dpkg');
 assert.deepEqual(inv.packages.map(p=>[p.name,p.version,p.sourceName,p.sourceVersion,p.manifestPath]),[['libssl3','3.0.11-1~deb12u2','openssl','3.0.11-1~deb12u2','/var/lib/dpkg/status.d/libssl3'],['tzdata','2024a-0+deb12u1','tzdata','2024a-0+deb12u1','/var/lib/dpkg/status.d/tzdata']]);
 assert.deepEqual(dpkg,{collector:'dpkg',status:'complete',count:2});assert.deepEqual(inv.warnings,[]);
 put(dir,'var/lib/dpkg/status','Package: libssl3\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\nArchitecture: amd64\nSource: openssl\n\nPackage: base-files\nStatus: install ok installed\nVersion: 12.4\nArchitecture: amd64\n');
 put(dir,'var/lib/dpkg/status.d/broken','Package: broken\n');
 inv=await collectSystemInventory(dir);
 assert.deepEqual(inv.packages.map(p=>[p.name,p.manifestPath]),[['libssl3','/var/lib/dpkg/status'],['base-files','/var/lib/dpkg/status'],['tzdata','/var/lib/dpkg/status.d/tzdata']]);
 assert.equal(inv.coverage.find(c=>c.collector==='dpkg').status,'incomplete');
});

test('RPM source version keeps the epoch of a same-build package; module label and signed kernel source are read',async t=>{
 const header=values=>{let size=0;const chunks=[];for(const item of values){const b=Buffer.from(item[2]+'\0');chunks.push(b);item.push(size);size+=b.length;}
  const blob=Buffer.alloc(8+values.length*16+size);blob.writeUInt32BE(values.length);blob.writeUInt32BE(size,4);
  for(let i=0;i<values.length;i++){const [tag,type,,offset]=values[i],p=8+i*16;blob.writeUInt32BE(tag,p);blob.writeUInt32BE(type,p+4);blob.writeUInt32BE(offset,p+8);blob.writeUInt32BE(1,p+12);}
  Buffer.concat(chunks).copy(blob,8+values.length*16);return rpmHeader(blob);};
 const epoch=n=>{const b=Buffer.alloc(4);b.writeUInt32BE(n);return b;};
 // Epoch is an INT32 tag: build it by hand next to the string tags.
 const withEpoch=(name,version,release,source,label)=>{
  const strings=[[1000,name],[1001,version],[1002,release],[1044,source],...(label?[[5096,label]]:[])];
  let size=0;const chunks=[],index=[];
  for(const [tag,value] of strings){const b=Buffer.from(value+'\0');index.push([tag,6,size,1]);chunks.push(b);size+=b.length;}
  while(size%4){chunks.push(Buffer.alloc(1));size++;}
  index.push([1003,4,size,1]);chunks.push(epoch(1));size+=4;
  const blob=Buffer.alloc(8+index.length*16+size);blob.writeUInt32BE(index.length);blob.writeUInt32BE(size,4);
  index.forEach(([tag,type,offset,count],i)=>{const p=8+i*16;blob.writeUInt32BE(tag,p);blob.writeUInt32BE(type,p+4);blob.writeUInt32BE(offset,p+8);blob.writeUInt32BE(count,p+12);});
  Buffer.concat(chunks).copy(blob,8+index.length*16);return rpmHeader(blob);};
 const dbus=withEpoch('dbus-libs','1.12.8','18.el8','dbus-1.12.8-18.el8.src.rpm');
 assert.equal(dbus.version,'1:1.12.8-18.el8');assert.equal(dbus.sourceVersion,'1:1.12.8-18.el8','same build: the source shares the epoch');
 const own=withEpoch('perl-Encode','2.97','3.el8','perl-5.26.3-421.el8.src.rpm');
 assert.equal(own.sourceVersion,'5.26.3-421.el8');assert.equal(own.sourceEpochUnknown,true,'a subpackage with its own version does not reveal the source epoch');
 const plain=header([[1000,6,'perl-Errno'],[1001,6,'1.28'],[1002,6,'421.el8'],[1044,6,'perl-5.26.3-421.el8.src.rpm']]);
 assert.equal(plain.sourceVersion,'5.26.3-421.el8');assert.equal(plain.sourceEpochUnknown,true);
 assert.equal(dbus.sourceEpochUnknown,undefined);
 const php=withEpoch('php-cli','7.2.24','1.module+el8.4.0+413+c9202dda','php-7.2.24-1.module+el8.4.0+413+c9202dda.src.rpm','php:7.2:8040020210421:76554e01');
 assert.equal(php.modularityLabel,'php:7.2:8040020210421:76554e01');
 const dir=root(t);put(dir,'etc/os-release','ID=debian\nVERSION_ID=12\n');
 put(dir,'var/lib/dpkg/status','Package: linux-image-6.1.0-17-amd64\nStatus: install ok installed\nArchitecture: amd64\nSource: linux-signed-amd64 (6.1.69+1)\nVersion: 6.1.69-1\n\nPackage: linux-image-amd64\nStatus: install ok installed\nArchitecture: amd64\nSource: linux-signed-amd64 (6.1.69+1)\nVersion: 6.1.69-1\n');
 const kernel=(await collectSystemInventory(dir)).packages;
 assert.deepEqual(kernel.map(p=>[p.name,p.sourceName,p.sourceVersion]),[['linux-image-6.1.0-17-amd64','linux','6.1.69-1'],['linux-image-amd64','linux-signed-amd64','6.1.69+1']]);
});

test('an RPM module-stream erratum applies only to packages of that stream',async t=>{
 const dir=root(t),distribution={id:'rocky',versionId:'8.6'};
 const erratum=(id,summary,name,fixed)=>({id,summary,aliases:['CVE-2099-'+id.slice(-4)],affected:[{package:{ecosystem:'Rocky Linux:8',name},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed}]}]}]});
 await importSystemAdvisories([
  erratum('RLSA-2099:0001','Moderate: perl:5.32 security update','perl-Carp','0:1.50-439.module+el8.10.0+1616+0d20cc68'),
  erratum('RLSA-2099:0002','Moderate: php:7.4 security update','php','0:7.4.33-1.module+el8.10.0+1604+6558efc7'),
  erratum('RLSA-2099:0003','Important: dbus security update','dbus','1:1.12.8-23.el8_7.1'),
 ],{distribution,cacheDir:dir,complete:true});
 const pkg=(name,version,sourceName,extra={})=>({name,version,architecture:'x86_64',manager:'rpm',ecosystem:'system',sourceName,sourceVersion:version,...extra});
 const ids=async packages=>(await assessSystemInventory({distribution,packages},{cacheDir:dir})).matches.map(m=>m.cve.sourceAdvisoryId).sort();
 assert.deepEqual(await ids([pkg('perl-Carp','1.42-396.el8','perl-Carp')]),[],'a non-modular package is not described by a module erratum');
 assert.deepEqual(await ids([pkg('php-cli','7.2.24-1.module+el8.4.0+413+c9202dda','php',{modularityLabel:'php:7.2:8040020210421:76554e01'})]),[],'another stream of the module');
 assert.deepEqual(await ids([pkg('php-cli','7.4.19-1.module+el8.6.0+789+2130c178','php',{modularityLabel:'php:7.4:8060020220527:9a7fc3ab'})]),['RLSA-2099:0002'],'the same stream below its fix');
 assert.deepEqual(await ids([pkg('php-cli','7.4.19-1.module+el8.6.0+789+2130c178','php')]),['RLSA-2099:0002'],'without a module label the range decides');
 assert.deepEqual(await ids([pkg('dbus-libs','1:1.12.8-18.el8','dbus')]),['RLSA-2099:0003'],'epoch-qualified source version is matched');
 // A subpackage with its own version borrows the source epoch from the advisory bounds.
 await importSystemAdvisories([erratum('RLSA-2099:0004','Moderate: perl security update','perl','4:5.26.3-419.el8')],{distribution,cacheDir:dir,complete:true});
 const errno=version=>({...pkg('perl-Errno','1.28-421.el8','perl'),sourceVersion:version,sourceEpochUnknown:true});
 assert.deepEqual(await ids([errno('5.26.3-421.el8')]),[],'4:5.26.3-421 is past the fix 4:5.26.3-419');
 assert.deepEqual(await ids([errno('5.26.3-416.el8')]),['RLSA-2099:0004'],'4:5.26.3-416 is before the fix');
});
