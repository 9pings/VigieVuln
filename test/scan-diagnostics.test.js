'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {assessInventories,systemDep,incompleteCapabilities}=require('../lib/artifacts/scan');
const {prepareNativeSources}=require('../lib/native-source-prepare');
function fixture(t){
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-diagnostics-'));
 const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir});
 t.after(()=>{store.close();require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 return {cacheDir,store};
}
const deps=()=>new Map([['demo',{ecosystem:'npm',name:'demo',version:'1.0.0',coordKey:'demo'}]]);
test('consulted native records do not require a globally complete catalogue or an offline refresh',async t=>{
 const {store}=fixture(t),at=Date.now()-86400000;
 store.commit({records:[require('../lib/native-advisories').cveEnvelope({cveMetadata:{cveId:'CVE-2025-12345',state:'PUBLISHED'},containers:{cna:{affected:[]}}},{fetchedAt:at})],coverages:[{source:'cveproject',ecosystem:'*',fetchedAt:at,complete:false}]});
 const result=await prepareNativeSources(deps(),{store,offline:true,nativeSources:['cveproject']});
 assert.deepEqual(result.warnings,[]);assert.equal(result.coverage[0].execution,'completed');
 assert.equal(result.coverage[0].complete,false);assert.equal(result.coverage[0].issue,null);assert.equal(result.coverage[0].freshness,'expired');
 const failed=await prepareNativeSources(deps(),{store,nativeSources:['cveproject'],nativeSourceAdapters:{cveproject:async()=>{throw Error('fixture refresh failed')}}});
 assert.equal(failed.coverage[0].execution,'partial');assert.equal(failed.coverage[0].issue,'refresh-failed');assert.match(failed.warnings[0].message,/refresh failed/);assert.equal(failed.warnings[0].source,'cveproject');
});
test('native absence observations count as consultations; an unprepared source remains a real gap',async t=>{
 const {store}=fixture(t),opts={store,offline:true,nativeSources:['cveproject']};
 assert.equal((await prepareNativeSources(deps(),opts)).coverage[0].issue,'missing-source');
 store.commit({queries:[{source:'cveproject',ecosystem:'npm',name:'demo',version:'*',ids:[],complete:true,fetchedAt:Date.now()-86400000}]});
 const result=await prepareNativeSources(deps(),opts);
 assert.equal(result.coverage[0].execution,'completed');assert.equal(result.coverage[0].scope,'consulted-packages');assert.equal(result.coverage[0].issue,null);
});
test('undecidable native comparison remains incomplete coverage and informational context',async t=>{
 const {store,cacheDir}=fixture(t),raw={cveMetadata:{cveId:'CVE-2024-33333',state:'PUBLISHED'},containers:{cna:{affected:[{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status:'affected'}]}]},adp:[{affected:[{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status:'unaffected'}]}]}]}};
 store.commit({records:[require('../lib/native-advisories').cveEnvelope(raw,{fetchedAt:Date.now()})]});
 const dep={ecosystem:'npm',name:'demo',version:'1.0.0',coordKey:'demo',artifactTargetId:'image'},target={id:'image',kind:'rootfs',metadata:{},distribution:null,packages:[],deps:[dep],warnings:[],coverage:[]};
 const result=await assessInventories([target],{cacheDir,offline:true,osv:false,disableGcve:true,enrich:[]});
 assert.equal(result.artifacts[0].coverage.find(c=>c.collector==='native-comparisons').result,'indeterminate');
 assert.ok(result.notices.some(w=>/undecidable/.test(w.message)));assert.ok(!result.warnings.some(w=>/undecidable|native-comparisons/.test(w.message)));
});
test('explicitly excluded image advisory sources produce neither alerts nor failed coverage gates',async t=>{
 const {cacheDir}=fixture(t),distribution={id:'debian',versionId:'12'},pkg={manager:'dpkg',name:'demo',version:'1-1',sourceName:'demo',sourceVersion:'1-1',architecture:'amd64'};
 const target={id:'image',kind:'rootfs',metadata:{},distribution,packages:[pkg],deps:[systemDep(pkg,'image',distribution)],warnings:[],coverage:[]};
 const result=await assessInventories([target],{cacheDir,offline:true,osv:false,disableCveProject:true,disableGcve:true,enrich:[]});
 assert.deepEqual(result.warnings,[]);assert.deepEqual(incompleteCapabilities(result,['advisories','sources']),[]);
 assert.equal(result.artifacts[0].coverage.find(c=>c.collector==='system-osv').execution,'not-applicable');
});
test('OS-owned archive notice leaves alerts only after its installed package was assessed',async t=>{
 const {cacheDir}=fixture(t),distribution={id:'debian',versionId:'12'},pkg={manager:'dpkg',name:'demo',version:'1-1',sourceName:'demo',sourceVersion:'1-1',architecture:'amd64',ownedPaths:['/usr/share/java/demo.jar']};
 const warning={type:'dependency-coverage',capability:'inventory',reason:'installed-metadata-error',manifestPath:'/usr/share/java/demo.jar',message:'installed metadata incomplete: archive has no complete Maven coordinate'};
 const target={id:'image',kind:'rootfs',metadata:{},distribution,packages:[pkg],deps:[systemDep(pkg,'image',distribution)],warnings:[warning],coverage:[{collector:'installed-applications',capability:'inventory',execution:'partial',result:'indeterminate'}]};
 const opts={cacheDir,offline:true,disableCveProject:true,disableGcve:true,enrich:[]};
 const unprepared=await assessInventories([target],opts);assert.ok(unprepared.warnings.some(w=>w.manifestPath===warning.manifestPath));
 await require('../lib/system-inventory').importSystemAdvisories([{id:'TEST-unrelated',affected:[{package:{ecosystem:'Debian:12',name:'unrelated'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1-1'}]}]}]}],{cacheDir,distribution,complete:true});
 const assessed=await assessInventories([target],opts);
 assert.deepEqual(assessed.warnings,[]);assert.equal(assessed.notices[0].type,'os-owned-component');
 assert.equal(assessed.artifacts[0].coverage.find(c=>c.collector==='installed-applications').execution,'completed');
 const broken=await assessInventories([{...target,warnings:[{...warning,message:'invalid ZIP archive'}]}],opts);
 assert.ok(broken.warnings.some(w=>w.message==='invalid ZIP archive'));assert.equal(broken.notices.length,0);
});
