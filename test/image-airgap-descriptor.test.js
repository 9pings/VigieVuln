'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {serializeDeps,deserializeDeps}=require('../lib/deps-descriptor');
const {buildProjectDescriptor}=require('../lib/project-descriptor');
const {buildProjectScope}=require('../lib/airgap-project');
const hash=x=>crypto.createHash('sha256').update(JSON.stringify(x)).digest('hex');
const refs=[{reference:'private.example/team/app:1.2',platform:'linux/amd64',role:'deployment',path:'/secret/project/compose.yml',declared:'PRIVATE=x',token:'secret'}, {reference:'nginx:1.24',role:'base',classification:'registry'}, {reference:'localbuild:latest',localBuild:true}, {reference:'${PRIVATE_IMAGE}',classification:'unresolved'}, {reference:'https://u:p@example.test/x'}, {reference:'example.test/x?token=secret'}, {reference:'nginx:1.24',platform:'/secret/path'}];
test('airgap descriptors retain reviewed registry identities without paths, variables, credentials or build inputs',()=>{
 const d=serializeDeps(new Map(),{imageReferences:refs,generatedAt:'2026-01-01T00:00:00.000Z'}),out=deserializeDeps(d);
 assert.equal(out.imageReferences.length,2);assert.deepEqual(Object.keys(out.imageReferences[1]).sort(),['platform','reference']);
 const raw=JSON.stringify(d);assert.doesNotMatch(raw,/\/secret|PRIVATE_IMAGE|token|localbuild|u:p/);assert.match(d.note,/image references/);
 assert.deepEqual(deserializeDeps(d,{images:false}).imageReferences,[]);assert.equal(serializeDeps(new Map(),{imageReferences:refs,images:false}).imageReferences,undefined);
 const v2=buildProjectDescriptor(new Map(),{imageReferences:refs});assert.deepEqual(v2.imageReferences,out.imageReferences);assert.equal(buildProjectDescriptor(new Map(),{imageReferences:refs,images:false}).imageReferences,undefined);
 assert.deepEqual(deserializeDeps({schema:'fad-deps/1',deps:[]}).imageReferences,[]);
});
test('image-only scoped cache archive keeps only reviewed canonical/legacy inventory keys',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-airgap-image-')),source=path.join(root,'source'),target=path.join(root,'target');const {createCacheRepository}=require('../lib/cache-repository'),{exportCache,importCache}=require('../lib/cache-archive-sqlite'),{closeCacheDbs}=require('../lib/cache-db');
 try{const repo=createCacheRepository(source),chosen=refs[0],canonical='private.example/team/app@1.2',good=hash([canonical,'linux/amd64',false]),legacy=hash([chosen.reference,'linux/amd64',false]),other=hash(['private.example/other@2','linux/amd64',false]);
  const snapshot=require('../lib/artifacts/scan').createSnapshot([{id:'fixture',metadata:{},deps:[],packages:[],coverage:[],warnings:[]}]);
  repo.put('image-inventory',good,snapshot);repo.put('image-inventory',legacy,snapshot);repo.put('image-inventory',other,{schema:'test',value:'private-other'});
  const registryKey=x=>'image-tags-'+crypto.createHash('sha256').update(x).digest('hex'),selectedTag=registryKey('private.example/team/app'),otherTag=registryKey('private.example/other/secret');
  repo.put('catalogue',selectedTag,{registry:'private.example',repository:'team/app',tags:['1.2']});repo.put('catalogue',otherTag,{registry:'private.example',repository:'other/secret',tags:['1']});
  const scope=buildProjectScope(new Map(),{imageReferences:[chosen]});assert.equal(scope.packages.length,0);assert.equal(scope.imageReferences.length,1);assert.equal(scope.retainAllNvd,true);
  await exportCache(path.join(root,'cache.tar.gz'),{sourceDir:source,project:scope});await importCache(path.join(root,'cache.tar.gz'),{targetDir:target});
  const imported=createCacheRepository(target);assert.deepEqual(imported.get('image-inventory',good).value,snapshot);assert.deepEqual(imported.get('image-inventory',legacy).value,snapshot);assert.equal(imported.get('image-inventory',other),null);
  assert.equal(imported.get('catalogue',selectedTag).value.repository,'team/app');assert.equal(imported.get('catalogue',otherTag),null);
 }finally{closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}
});

test('image readiness rejects missing, wrong-platform and corrupt inventories',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-image-readiness-'));const {createCacheRepository}=require('../lib/cache-repository'),{validateImageSnapshotCompleteness,imageInventoryKeys}=require('../lib/airgap-project');
 try{const repo=createCacheRepository(root),scope=buildProjectScope(new Map(),{imageReferences:[refs[0]]});assert.throws(()=>validateImageSnapshotCompleteness(scope,repo),/missing/);
  const item=scope.imageReferences[0];repo.put('image-inventory',imageInventoryKeys({...item,platform:'linux/arm64'})[0],{schema:'invalid'});assert.throws(()=>validateImageSnapshotCompleteness(scope,repo),/missing/);
  repo.put('image-inventory',imageInventoryKeys(item)[0],{schema:'invalid'});assert.throws(()=>validateImageSnapshotCompleteness(scope,repo),/invalid/);
 }finally{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}
});
test('reviewed image descriptor survives cache transfer and offline acquisition by canonical identity',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-image-roundtrip-')),source=path.join(root,'source'),target=path.join(root,'target');const {createCacheRepository}=require('../lib/cache-repository'),{exportCache,importCache}=require('../lib/cache-archive-sqlite'),{closeCacheDbs}=require('../lib/cache-db'),{createSnapshot,acquireInventories}=require('../lib/artifacts/scan');
 try {
  const reviewed=deserializeDeps(serializeDeps(new Map(),{imageReferences:[{reference:'nginx:1.24',platform:'linux/amd64',role:'deployment',path:'/private/compose.yml'}]})).imageReferences;
  const snapshot=createSnapshot([{id:'sha256:fixture',metadata:{platform:{os:'linux',architecture:'amd64'}},deps:[],packages:[],coverage:[],warnings:[]}]);
  const scope=buildProjectScope(new Map(),{imageReferences:reviewed}),key=require('../lib/airgap-project').imageInventoryKeys(reviewed[0])[0];
  createCacheRepository(source).put('image-inventory',key,snapshot);await exportCache(path.join(root,'cache.tar.gz'),{sourceDir:source,project:scope});await importCache(path.join(root,'cache.tar.gz'),{targetDir:target});
  const found=await acquireInventories('docker.io/library/nginx:1.24',{registry:true,offline:true,platform:'linux/amd64',cacheDir:target,fetcher:()=>assert.fail('offline network')});assert.equal(found[0].id,'sha256:fixture');assert.equal(found[0].evidence,'cached-inventory');
 }finally{closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})}
});

test('package-only project export retains no unrelated registry tag observations',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-package-registry-scope-')),source=path.join(root,'source'),target=path.join(root,'target');const {createCacheRepository}=require('../lib/cache-repository'),{buildProjectSnapshot}=require('../lib/airgap-project');
 try{const key='image-tags-'+crypto.createHash('sha256').update('private.example/secret/app').digest('hex');createCacheRepository(source).put('catalogue',key,{registry:'private.example',repository:'secret/app',tags:['1']});buildProjectSnapshot(source,target,{schema:1,packages:[{ecosystem:'npm',name:'public-example'}],cves:[],imageReferences:[]});assert.equal(createCacheRepository(target).get('catalogue',key),null);}
 finally{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});}
});
