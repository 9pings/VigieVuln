'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {openAdvisoryStore}=require('../lib/advisories/store');const {gcveEnvelope,cveEnvelope,matchNativePackages}=require('../lib/advisories/native');
function fixture(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-native-packages-'));const store=openAdvisoryStore({cacheDir:dir});t.after(()=>{store.close();require('../lib/cache/db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true})});return store;}
function gcve(affected){const raw={cveMetadata:{vulnId:'GCVE-1-native-test',state:'PUBLISHED',dateUpdated:'2025-01-01T00:00:00Z'},containers:{cna:{descriptions:[{lang:'en',value:'Independent European advisory'}],affected,x_gcve:[{vulnId:'GCVE-1-native-test',recordType:'advisory'}]}}};return gcveEnvelope({raw,gna:1,collectedAt:new Date().toISOString(),sourceUrl:'https://example.test/advisories'});}
test('GCVE native SQL matches distro package and independent application without OSV or NVD',t=>{
 const store=fixture(t),record=gcve([{packageURL:'pkg:deb/debian/curl?distro=debian-12&arch=source',versions:[{version:'0',lessThan:'2:7.90-2',versionType:'deb',status:'affected'}]},{packageURL:'pkg:npm/demo',versions:[{version:'1.2.3',status:'affected'}]}]);store.commit({records:[record]});
 const system={ecosystem:'system',manager:'dpkg',name:'curl',version:'1:7.88-1+b1',sourceName:'curl',sourceVersion:'1:7.88-1',architecture:'amd64',distribution:{id:'debian',versionId:'12'},coordKey:'system'},app={ecosystem:'npm',name:'demo',version:'1.2.3',coordKey:'app'};
 const result=matchNativePackages(new Map([[system.coordKey,system],[app.coordKey,app]]),store);assert.equal(result.matches.length,2);assert.ok(result.matches.every(m=>m.source==='GCVE:GNA-1' && m.cve.id==='GCVE-1-native-test'));assert.equal(result.matches[0].cve.gcveSource,'https://example.test/advisories');assert.equal(result.coverage.status,'partial');
});
test('distro identity, source version and architecture are required and wrong schemes remain unknown',t=>{
 const store=fixture(t),record=gcve([{packageURL:'pkg:deb/debian/curl?distro=debian-12&arch=amd64',versions:[{version:'0',lessThan:'2.0',versionType:'custom',status:'affected'}]}]);store.commit({records:[record]});
 const base={ecosystem:'system',manager:'dpkg',name:'curl',version:'1.0',architecture:'amd64',distribution:{id:'debian',versionId:'12'},coordKey:'sys'};
 let result=matchNativePackages([base],store);assert.equal(result.matches.length,0);assert.equal(result.unknown.length,1);
 result=matchNativePackages([{...base,distribution:{id:'ubuntu',versionId:'12'}}],store);assert.equal(result.matches.length,0);
 result=matchNativePackages([{...base,architecture:'arm64'}],store);assert.equal(result.matches.length,0);assert.equal(result.unknown.length,0);
 result=matchNativePackages([{...base,architecture:null}],store);assert.equal(result.unknown.length,1);
});
test('native CVEProject application PURLs and old unindexed envelopes are still consulted',t=>{
 const store=fixture(t),raw={cveMetadata:{cveId:'CVE-2024-12345',state:'PUBLISHED'},containers:{cna:{affected:[{packageURL:'pkg:golang/example.com/demo',versions:[{version:'1.0.0',lessThan:'2.0.0',versionType:'semver',status:'affected'}]}]}}};
 const envelope=cveEnvelope(raw,{fetchedAt:Date.now()});assert.equal(envelope.packages.some(p=>p.ecosystem==='Go'),true);
 // Simulate an older envelope whose historical index did not contain Go.
 store.commit({records:[{...envelope,packages:[]}]});const dep={ecosystem:'go',name:'example.com/demo',version:'1.2.0',coordKey:'go'};
 const result=matchNativePackages([dep],store);assert.equal(result.matches.length,1);assert.equal(result.matches[0].cve.id,'CVE-2024-12345');
});
test('Debian-wide native source identity requires official collection or typed PURL and dpkg bounds',t=>{
 const store=fixture(t),base={packageName:'apt',collectionURL:'https://packages.debian.org/',versions:[{version:'2.2.0',lessThan:'2.2.5',versionType:'dpkg',status:'affected'}]},raw=a=>({cveMetadata:{cveId:'CVE-2026-109518',state:'PUBLISHED'},containers:{cna:{affected:[a]}}});
 store.commit({records:[cveEnvelope(raw(base),{fetchedAt:Date.now()})]});const dep={ecosystem:'system',manager:'dpkg',name:'apt',sourceName:'apt',sourceVersion:'2.2.4',version:'2.2.4',architecture:'amd64',distribution:{id:'debian',versionId:'11'},coordKey:'apt'};
 assert.equal(matchNativePackages([dep],store).matches.length,1);assert.equal(matchNativePackages([{...dep,distribution:{id:'ubuntu',versionId:'22.04'}}],store).matches.length,0);assert.equal(matchNativePackages([{...dep,packageOrigin:{status:'third-party'}}],store).matches.length,0);
 const {systemPackage}=require('../lib/advisories/native-package-match');assert.ok(systemPackage({...base,packageName:undefined,collectionURL:undefined,packageURL:'pkg:deb/debian/apt'}));assert.equal(systemPackage({...base,collectionURL:'https://evil.invalid/'}),null);assert.equal(systemPackage({...base,versions:[{...base.versions[0],versionType:'semver'}]}),null);
});
test('CNA Debian source assertion requires authoritative provider, vendor and dpkg bounds',t=>{
 const store=fixture(t),org='79363d38-fa19-49d1-9214-5f28da3f3ac5',affected={vendor:'Debian',packageName:'apt',versions:[{version:'2.2.0',lessThan:'2.2.5',versionType:'dpkg',status:'affected'}]},raw={cveMetadata:{cveId:'CVE-2026-109518',state:'PUBLISHED',assignerOrgId:org},containers:{cna:{providerMetadata:{orgId:org},affected:[affected]}}},dep={ecosystem:'system',manager:'dpkg',name:'apt',sourceName:'apt',sourceVersion:'2.2.4',version:'2.2.4',architecture:'amd64',distribution:{id:'debian',versionId:'11'},coordKey:'apt'};
 const envelope=cveEnvelope(raw,{fetchedAt:Date.now()});assert.ok(envelope.packages.some(p=>p.ecosystem==='system:deb:debian:*'&&p.name==='apt'));store.commit({records:[envelope]});assert.equal(matchNativePackages([dep],store).matches.length,1);
 const {explicitNativePackage}=require('../lib/advisories/native-package-match'),context={source:'cveproject',record:raw,container:raw.containers.cna};assert.equal(explicitNativePackage({...affected,vendor:'Ubuntu'},context),null);assert.equal(explicitNativePackage(affected,{...context,source:'gcve'}),null);assert.equal(explicitNativePackage(affected,{...context,record:{...raw,cveMetadata:{...raw.cveMetadata,assignerOrgId:'other'}}}),null);assert.equal(explicitNativePackage(affected,{...context,container:{...raw.containers.cna}}),null);
});
test('native matcher respects newer per-GNA absence proof and CVEProject rejections',t=>{
 const store=fixture(t),now=Date.now(),record=gcve([{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status:'affected'}]}]);record.fetchedAt=now-2000;
 store.commit({records:[record]});const dep={ecosystem:'npm',name:'demo',version:'1.0.0',coordKey:'demo'};assert.equal(matchNativePackages([dep],store).matches.length,1);
 store.commit({records:[{source:'gcve-snapshot',id:'gna:1',fetchedAt:now-1000,document:{id:'gna:1',gna:1,ids:[]},provenance:{gna:1,sourceUrl:'https://example.test/advisories'}}]});assert.equal(matchNativePackages([dep],store).matches.length,0);
 const raw={cveMetadata:{cveId:'CVE-2024-22222',state:'PUBLISHED',dateUpdated:'2025-01-01T00:00:00Z'},containers:{cna:{affected:[{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status:'affected'}]}]}}};
 store.commit({records:[cveEnvelope(raw,{fetchedAt:now-500})]});assert.equal(matchNativePackages([dep],store).matches.length,1);
 store.commit({records:[cveEnvelope({cveMetadata:{cveId:'CVE-2024-22222',state:'REJECTED',dateUpdated:'2026-01-01T00:00:00Z'},containers:{cna:{}}},{fetchedAt:now})]});assert.equal(matchNativePackages([dep],store).matches.length,0);
});
test('contradictory CNA and ADP statements remain unknown per occurrence',t=>{
 const store=fixture(t),raw={cveMetadata:{cveId:'CVE-2024-33333',state:'PUBLISHED'},containers:{cna:{affected:[{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status:'affected'}]}]},adp:[{affected:[{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status:'unaffected'}]}]}]}};
 store.commit({records:[cveEnvelope(raw,{fetchedAt:Date.now()})]});const result=matchNativePackages([{ecosystem:'npm',name:'demo',version:'1.0.0',coordKey:'demo'}],store);assert.equal(result.matches.length,0);assert.equal(result.unknown.length,1);
});
test('independent versions and artifact occurrences are not collapsed',t=>{
 const store=fixture(t),record=gcve([{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',versionType:'semver',status:'affected'},{version:'2.0.0',versionType:'semver',status:'affected'}]}]);store.commit({records:[record]});
 const deps=[{ecosystem:'npm',name:'demo',version:'1.0.0',versions:['1.0.0','2.0.0'],artifactTargetId:'image-a',manifestPath:'/app/package.json'},{ecosystem:'npm',name:'demo',version:'1.0.0',artifactTargetId:'image-b',manifestPath:'/app/package.json'}];
 const result=matchNativePackages(deps,store);assert.equal(result.matches.length,3);assert.deepEqual(result.matches.map(m=>[m.dep.artifactTargetId,m.dep.version]).sort(),[['image-a','1.0.0'],['image-a','2.0.0'],['image-b','1.0.0']]);
});
test('image scan detects independent EU advisory when OSV and NVD are disabled or fail',async t=>{
 const store=fixture(t),cacheDir=store.cacheDir,record=gcve([{packageURL:'pkg:deb/debian/curl?distro=debian-12&arch=source',versions:[{version:'0',lessThan:'2.0-1',versionType:'deb',status:'affected'}]}]);store.commit({records:[record]});
 const {systemDep,assessInventories}=require('../lib/artifacts/scan'),distribution={id:'debian',versionId:'12'},pkg={manager:'dpkg',name:'curl',sourceName:'curl',sourceVersion:'1.0-1',version:'1.0-1',architecture:'amd64',manifestPath:'/var/lib/dpkg/status'},id='image-eu';
 const target={id,kind:'rootfs',metadata:{},distribution,packages:[pkg],deps:[systemDep(pkg,id,distribution)],coverage:[],warnings:[]};
 const result=await assessInventories([target],{cacheDir,offline:true,osv:false,nvd:false,disableCveProject:true,enrich:[],fetcher:()=>{throw Error('offline network')}});
 assert.equal(result.cveMatches.length,1);assert.equal(result.cveMatches[0].cve.id,'GCVE-1-native-test');assert.ok(result.artifacts[0].coverage.some(c=>c.collector==='native-gcve' && c.execution==='completed' && c.complete===false));
 const failed=await assessInventories([target],{cacheDir,offline:true,nvd:false,disableCveProject:true,enrich:[],repository:{getSnapshot(){throw Error('simulated OSV failure')}},fetcher:()=>{throw Error('offline network')}});
 assert.equal(failed.cveMatches.length,1);assert.equal(failed.cveMatches[0].cve.id,'GCVE-1-native-test');assert.ok(failed.warnings.some(w=>/System OSV assessment failed/.test(w.message)));
});
test('native source preparation honors offline, disable flags and retains cache on refresh failure',async t=>{
 const store=fixture(t),record=gcve([{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status:'affected'}]}]);store.commit({records:[record]});let calls=0;
 const {prepareNativeSources}=require('../lib/advisories/native-source-prepare');const deps=new Map([['demo',{ecosystem:'npm',name:'demo',version:'1.0.0',coordKey:'demo'}]]);
 let prep=await prepareNativeSources(deps,{store,offline:true,disableCveProject:true,nativeSourceAdapters:{gcve:async()=>{calls++;throw Error('must not fetch')}}});assert.equal(calls,0);assert.deepEqual(prep.sources,['gcve']);assert.equal(matchNativePackages(deps,store,{sources:prep.sources}).matches.length,1);
 prep=await prepareNativeSources(deps,{store,disableCveProject:true,nativeSourceAdapters:{gcve:async()=>{calls++;throw Error('unavailable')}}});assert.equal(calls,1);assert.match(prep.warnings[0].message,/unavailable/);assert.equal(prep.warnings[0].code,'source-request-failed');assert.equal(matchNativePackages(deps,store,{sources:prep.sources}).matches.length,1);
});
test('real signed GCVE preparation and native CVE import stay in the requested cache',async t=>{
 const crypto=require('node:crypto'),root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-source-isolation-')),target=path.join(root,'target'),other=path.join(root,'other'),rawDir=path.join(root,'cves');
 t.after(()=>{require('../lib/cache/db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});fs.mkdirSync(rawDir);
 const {publicKey,privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});const directory=Buffer.from(JSON.stringify([{id:1,gcve_pull_api:'https://trusted.example/'}]));const signature=crypto.sign('RSA-SHA512',directory,privateKey).toString('base64');
 const doc=gcve([{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status:'affected'}]}]).document;
 const fetcher=async url=>{if(url.endsWith('/gcve.json'))return new Response(directory);if(url.endsWith('/gcve.json.sigsha512'))return new Response(signature);if(url==='https://trusted.example/dumps/gna-1.ndjson')return new Response(JSON.stringify(doc)+'\n');throw Error('unexpected network');};
 const deps=new Map([['demo',{ecosystem:'npm',name:'demo',version:'1.0.0',coordKey:'demo'}]]),{prepareNativeSources}=require('../lib/advisories/native-source-prepare');
 const prep=await prepareNativeSources(deps,{cacheDir:target,nativeSources:['gcve'],fetcher,gcveOptions:{allowedOrigins:['https://trusted.example'],trustedKey:publicKey}});assert.deepEqual(prep.sources,['gcve']);assert.equal(prep.warnings.length,0);
 const local=openAdvisoryStore({cacheDir:target}),elsewhere=openAdvisoryStore({cacheDir:other});try{assert.ok(local.getRecord('gcve','GCVE-1-native-test'));assert.equal(elsewhere.getRecord('gcve','GCVE-1-native-test'),null);}finally{local.close();elsewhere.close();}
 const raw={cveMetadata:{cveId:'CVE-2024-55555',state:'PUBLISHED'},containers:{cna:{affected:[{packageURL:'pkg:golang/example.com/demo',versions:[{version:'1.0.0',status:'affected'}]}]}}};fs.writeFileSync(path.join(rawDir,'CVE-2024-55555.json'),JSON.stringify(raw));
 await require('../lib/providers/cveproject/download').buildCveIndex(rawDir,{cacheDir:target});const local2=openAdvisoryStore({cacheDir:target}),elsewhere2=openAdvisoryStore({cacheDir:other});try{assert.ok(local2.getRecord('cveproject','CVE-2024-55555'));assert.equal(elsewhere2.getRecord('cveproject','CVE-2024-55555'),null);}finally{local2.close();elsewhere2.close();}
});
test('CVE semver open lower bound zero supports bounded ranges without guessing other types',()=>{
 const {versionVerdict}=require('../lib/advisories/native-package-match');
 const a={defaultStatus:'unaffected',versions:[{version:'0',status:'affected',versionType:'semver',lessThan:'2.11.55'},{version:'2.11.55',status:'unaffected',versionType:'semver'}]};
 assert.equal(versionVerdict('v2.11.0',a,'Go'),true);assert.equal(versionVerdict('v2.11.55',a,'Go'),false);assert.equal(versionVerdict('v2.12.0',a,'Go'),false);
 assert.equal(versionVerdict('v2.11.0',{...a,versions:[{...a.versions[0],versionType:'custom'}]},'Go'),null);
});

test('native advisory platform restrictions do not exclude a matching package version',t=>{
 const store=fixture(t);
 store.commit({records:[gcve([{packageURL:'pkg:npm/demo',platforms:['Windows','arm64'],versions:[{version:'1.2.3',status:'affected'}]}])]});
 const dep={ecosystem:'npm',name:'demo',version:'1.2.3',coordKey:'demo'};
 const found=matchNativePackages(new Map([[dep.coordKey,dep]]),store);
 assert.equal(found.matches.length,1);assert.deepEqual(found.unknown,[]);
 assert.equal(matchNativePackages(new Map([[dep.coordKey,{...dep,version:'2.0.0'}]]),store).matches.length,0);
});
