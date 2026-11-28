'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {resolveGoMainIdentities}=require('../lib/artifacts/go-main-identity');
const rev='0c8778639a3cade0cf73aa26f56f822a4fb835e8',moduleName='github.com/traefik/traefik/v2',version='v2.11.0';
function fixture(){return {metadata:{configDigest:'sha256:'+'a'.repeat(64),platform:{os:'linux',architecture:'amd64'},imageConfig:{labels:{'org.opencontainers.image.source':'https://github.com/traefik/traefik','org.opencontainers.image.version':version}}},deps:[{ecosystem:'binary',artifactPath:'usr/local/bin/traefik',hashes:{sha256:'b'.repeat(64)},binaryMetadata:{go:{version:'go1.22.0',modules:[{kind:'mod',path:moduleName,version:'(devel)'}],settings:{vcs:'git','vcs.revision':rev,'vcs.modified':'false',GOOS:'linux',GOARCH:'amd64'}}}}]};}
function info(){return {Version:version,Time:'2024-02-12T15:14:04Z',Origin:{VCS:'git',URL:'https://github.com/traefik/traefik',Ref:`refs/tags/${version}`,Hash:rev}};}
function dir(t){const p=fs.mkdtempSync(path.join(os.tmpdir(),'vv-go-main-'));t.after(()=>{require('../lib/cache/db').closeCacheDbs();fs.rmSync(p,{recursive:true,force:true});});return p;}
test('clean Go revision corroborates publisher label using version-specific Go proxy evidence and replays offline',async t=>{const cacheDir=dir(t),target=fixture();let calls=0;const out=await resolveGoMainIdentities(target,{cacheDir,lookup:async(m,v)=>{calls++;assert.equal(m,moduleName);assert.equal(v,version);return {info:info(),observedAt:1700000000000};}});assert.equal(out.deps.length,1);assert.equal(out.deps[0].name,moduleName);assert.equal(out.deps[0].version,version);assert.equal(out.deps[0].binaryEvidence.revision,rev);assert.equal(out.deps[0].binaryEvidence.observedAt,1700000000000);const offline=await resolveGoMainIdentities(target,{cacheDir,offline:true,lookup:()=>{throw Error('network used')}});assert.equal(offline.deps.length,1);assert.equal(calls,1);});
test('conflicting source, tag, revision, modification and platform cannot establish a version',async t=>{const cacheDir=dir(t);for(const change of [x=>x.Origin.Hash='f'.repeat(40),x=>x.Origin.Ref='refs/tags/v2.11.1',x=>x.Origin.URL='https://example.org/other',x=>x.Version='v2.11.1']){let x=info();change(x);const r=await resolveGoMainIdentities(fixture(),{cacheDir,lookup:async()=>x});assert.equal(r.deps.length,0);assert.equal(r.coverage.result,'conflicting-evidence');}for(const change of [x=>x.metadata.imageConfig.labels['org.opencontainers.image.source']='https://github.com/spoofed/repo',x=>x.metadata.imageConfig.labels['org.opencontainers.image.version']='v2.11.1',x=>x.deps[0].binaryMetadata.go.settings['vcs.modified']='true',x=>x.deps[0].binaryMetadata.go.settings.GOARCH='arm64']){let x=fixture();change(x);assert.equal((await resolveGoMainIdentities(x,{cacheDir,lookup:async()=>info()})).deps.length,0);}});
test('multiple binaries are independently verified and missing offline evidence never contacts network',async t=>{let x=fixture(),other=structuredClone(x.deps[0]);other.artifactPath='usr/local/bin/other';other.hashes.sha256='c'.repeat(64);other.binaryMetadata.go.settings['vcs.revision']='e'.repeat(40);x.deps.push(other);const cacheDir=dir(t),r=await resolveGoMainIdentities(x,{cacheDir,lookup:async()=>info()});assert.equal(r.deps.length,1);assert.equal(r.deps[0].binaryEvidence.binaryPath,'usr/local/bin/traefik');assert.equal(r.coverage.conflicts,1);const cold=await resolveGoMainIdentities(x,{cacheDir:dir(t),offline:true,lookup:()=>{throw Error('network used')}});assert.equal(cold.deps.length,0);assert.equal(cold.coverage.execution,'partial');});
test('Go proxy module-info provider validates and encodes module version',()=>{const p=require('../lib/providers/go');assert.equal(p.build('module-info',{module:'github.com/!alice/!thing/v2',version:'v2.1.0-RC1'}).url,'https://proxy.golang.org/github.com/!alice/!thing/v2/@v/v2.1.0-!r!c1.info');assert.throws(()=>p.build('module-info',{module:'../x',version:'v1.0.0'}));assert.throws(()=>p.build('module-info',{module:'example.org/x',version:'../../x'}));});
test('evidence survives cache export and import for offline use',async t=>{const source=dir(t),target=dir(t),archive=path.join(dir(t),'cache.tar.gz'),image=fixture();await resolveGoMainIdentities(image,{cacheDir:source,lookup:async()=>info()});const {exportCache,importCache}=require('../lib/cache/archive');await exportCache(archive,{sourceDir:source});await importCache(archive,{targetDir:target});const replay=await resolveGoMainIdentities(image,{cacheDir:target,offline:true,lookup:()=>{throw Error('network used')}});assert.equal(replay.deps.length,1);});
test('submodule tags preserve the repository-relative tag prefix',async t=>{const x=fixture(),main=x.deps[0].binaryMetadata.go.modules[0];main.path='github.com/traefik/traefik/sub/v2';const i=info();i.Origin.Ref='refs/tags/sub/v2.11.0';const out=await resolveGoMainIdentities(x,{cacheDir:dir(t),lookup:async()=>i});assert.equal(out.deps.length,1);});
test('a contradictory fresh version response invalidates earlier matching cached evidence',async t=>{const cacheDir=dir(t),target=fixture();assert.equal((await resolveGoMainIdentities(target,{cacheDir,lookup:async()=>info()})).deps.length,1);const altered=info();altered.Origin.Hash='f'.repeat(40);assert.equal((await resolveGoMainIdentities(target,{cacheDir,lookup:async()=>altered})).deps.length,0);assert.equal((await resolveGoMainIdentities(target,{cacheDir,offline:true})).deps.length,0);});
test('offline image assessment matches a versioned Go main module after cache transfer',async t=>{
 const source=dir(t),targetCache=dir(t),archive=path.join(dir(t),'cache.tar.gz'),target={...fixture(),id:'image-a',kind:'image',evidence:'content-inventory',distribution:null,packages:[],coverage:[],warnings:[]};
 target.deps[0].artifactTargetId='image-a';target.deps[0].coordKey='artifact:image-a:binary:usr/local/bin/traefik';
 await resolveGoMainIdentities(target,{cacheDir:source,lookup:async()=>info()});
 const {openAdvisoryStore}=require('../lib/advisories/store'),s=openAdvisoryStore({cacheDir:source}),now=Date.now(),id='GO-2024-9999';
 try{s.commit({records:[{source:'osv',document:{id,affected:[{package:{ecosystem:'Go',name:moduleName},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'2.12.0'}]}]}]},fetchedAt:now}],queries:[{source:'osv',ecosystem:'Go',name:moduleName,version,ids:[id],fetchedAt:now,complete:true}]});}finally{s.close();}
 const {exportCache,importCache}=require('../lib/cache/archive');await exportCache(archive,{sourceDir:source});await importCache(archive,{targetDir:targetCache});
 const result=await require('../lib/artifacts/scan').assessInventories([target],{cacheDir:targetCache,offline:true,enrich:[],fetcher:()=>{throw Error('network forbidden')}});
 const hit=result.cveMatches.find(m=>m.cve.id===id);assert.ok(hit);assert.equal(hit.dep.artifactTargetId,'image-a');assert.equal(hit.dep.binaryEvidence.source,'go-vcs-and-module-proxy');assert.equal(hit.dep.version,version);
});
test('online lookup failure preserves cached version as explicitly stale, including offline replay',async t=>{const cacheDir=dir(t),target=fixture(),at=Date.now()-10000;await resolveGoMainIdentities(target,{cacheDir,lookup:async()=>({info:info(),observedAt:at})});const out=await resolveGoMainIdentities(target,{cacheDir,lookup:async()=>{throw Error('temporary outage')}});assert.equal(out.deps.length,1);assert.equal(out.deps[0].binaryEvidence.observedAt,at);assert.equal(out.deps[0].binaryEvidence.stale,true);assert.equal(out.coverage.execution,'partial');assert.match(out.warnings[0].message,/refresh failed.*temporary outage/);const replay=await resolveGoMainIdentities(target,{cacheDir,offline:true});assert.equal(replay.deps[0].binaryEvidence.stale,true);assert.equal(replay.coverage.execution,'partial');});
test('fleet proxy observation preserves its actual timestamp and stale status',async t=>{const providers=require('../lib/providers'),cacheDir=dir(t),at=Date.now()-60000;providers.configureResourceRoute({proxyUrl:'https://fleet.example',hosted:false,store:null,hostedStore:null});try{let calls=0;const out=await resolveGoMainIdentities(fixture(),{cacheDir,fetcher:async(url,opts)=>{calls++;assert.equal(url,'https://fleet.example/v1/resource');assert.equal(JSON.parse(opts.body).type,'module-info');return Response.json(info(),{headers:{'x-fad-proxy-fetched-at':new Date(at).toISOString(),'x-fad-proxy':'stale'}});}});assert.equal(calls,1);assert.equal(out.deps[0].binaryEvidence.observedAt,at);assert.equal(out.deps[0].binaryEvidence.stale,true);assert.equal(out.coverage.execution,'partial');assert.match(out.warnings[0].message,/stale/);}finally{providers.configureResourceRoute({proxyUrl:null,hosted:false,store:null,hostedStore:null});}});

// Gitea 1.23.8 as published: vanity module path, version label without "v", version in the linker flags.
function vanity(){
 const x=fixture(),rev2='cccd54999a6c3b9f2573d2ba20d83d7c4cac77c3';
 x.metadata.imageConfig.labels={'org.opencontainers.image.source':'https://github.com/go-gitea/gitea','org.opencontainers.image.version':'1.23.8'};
 const go=x.deps[0].binaryMetadata.go;go.modules[0].path='code.gitea.io/gitea';
 go.settings={...go.settings,'vcs.revision':rev2,'-ldflags':'"-s -w  -X \\"main.MakeVersion=GNU Make 4.4.1\\" -X \\"main.Version=1.23.8\\" -X \\"main.Tags=bindata sqlite\\""'};
 return {target:x,info:{Version:'v1.23.8',Time:'2025-05-12T22:01:45Z',Origin:{VCS:'git',URL:'https://github.com/go-gitea/gitea',Hash:rev2,Ref:'refs/tags/v1.23.8'}}};
}
test('linker flags propose the application version and exclude the toolchain versions',()=>{
 const {linkerVersions,moduleVersion}=require('../lib/artifacts/go-main-identity');
 assert.deepEqual(linkerVersions(vanity().target.deps[0].binaryMetadata.go.settings),['v1.23.8']);
 assert.deepEqual(linkerVersions({'-ldflags':'-X main.GoVersion=1.22.0 -X github.com/a/b/version.Version=v2.1.0 -X main.gitVersion=v2.1.0 -X main.version=dev'}),['v2.1.0']);
 assert.deepEqual(linkerVersions({}),[]);
 assert.equal(moduleVersion('1.23.8'),'v1.23.8');assert.equal(moduleVersion('latest'),null);
});
test('a vanity-path module is versioned from its linker flag once the proxy records the same revision',async t=>{
 const cacheDir=dir(t),{target,info:i}=vanity();const asked=[];
 const out=await resolveGoMainIdentities(target,{cacheDir,lookup:async(m,v)=>{asked.push(`${m}@${v}`);return {info:i,observedAt:1700000000000};}});
 assert.deepEqual(asked,['code.gitea.io/gitea@v1.23.8']);
 assert.equal(out.deps.length,1);assert.equal(out.deps[0].name,'code.gitea.io/gitea');assert.equal(out.deps[0].version,'v1.23.8');
 assert.equal(out.deps[0].binaryEvidence.versionProposedBy,'linker-flag');assert.deepEqual(out.warnings,[]);
 // The same binary on a plain filesystem, without any image label.
 const bare=vanity().target;bare.metadata={};
 assert.equal((await resolveGoMainIdentities(bare,{cacheDir:dir(t),lookup:async()=>i})).deps.length,1);
 const offline=await resolveGoMainIdentities(vanity().target,{cacheDir,offline:true,lookup:()=>{throw Error('network used');}});
 assert.equal(offline.deps.length,1);
});
test('a linker flag alone never binds a version',async t=>{
 const cacheDir=dir(t);
 // Another revision than the tagged one: a fork or a later commit carrying the same version string.
 const moved=vanity();moved.info.Origin.Hash='f'.repeat(40);
 let out=await resolveGoMainIdentities(moved.target,{cacheDir,lookup:async()=>moved.info});
 assert.equal(out.deps.length,0);assert.equal(out.coverage.result,'conflicting-evidence');
 // A version the proxy does not know is a wrong proposal, not an unavailable source.
 out=await resolveGoMainIdentities(vanity().target,{cacheDir,lookup:async()=>{throw Object.assign(Error('Go proxy HTTP 404'),{status:404});}});
 assert.equal(out.deps.length,0);assert.deepEqual(out.warnings,[]);
 // A real outage is reported.
 out=await resolveGoMainIdentities(vanity().target,{cacheDir,lookup:async()=>{throw Object.assign(Error('Go proxy HTTP 503'),{status:503});}});
 assert.equal(out.deps.length,0);assert.equal(out.coverage.result,'unavailable');assert.equal(out.warnings.length,1);
 // Modified or unstamped checkouts offer nothing to verify.
 for(const change of [s=>s['vcs.modified']='true',s=>{delete s.vcs;delete s['vcs.revision'];}]){
  const x=vanity();change(x.target.deps[0].binaryMetadata.go.settings);
  out=await resolveGoMainIdentities(x.target,{cacheDir,lookup:()=>{throw Error('must not be asked');}});
  assert.equal(out.deps.length,0);assert.equal(out.coverage.result,'no-candidate');assert.deepEqual(out.warnings,[]);
 }
});
test('a version label without the v prefix is the same module version',async t=>{
 const x=fixture();x.metadata.imageConfig.labels['org.opencontainers.image.version']='2.11.0';
 const out=await resolveGoMainIdentities(x,{cacheDir:dir(t),lookup:async()=>info()});
 assert.equal(out.deps.length,1);assert.equal(out.deps[0].version,'v2.11.0');assert.equal(out.deps[0].binaryEvidence.versionProposedBy,'oci-label');
});
