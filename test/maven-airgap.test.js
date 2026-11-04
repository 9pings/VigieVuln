'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const core=require('../lib/core');
const {collectResolvedDeps,settleManagedOnly}=require('../lib/cve-match');
const {resolveReactor}=require('../lib/maven-reactor');
const {buildReactorHints,restoreReactorHints}=require('../lib/maven-airgap');
const {serializeDeps,deserializeDeps}=require('../lib/deps-descriptor');
const {G,upstream,writeLocal,run,versionsOf}=require('./helpers/maven-scenario');

test('airgap descriptor retains independent Maven module management without paths or secrets',async()=>{
 const dir=writeLocal({
  'a/pom.xml':{g:'local',a:'a',v:'1',props:{'x.version':'1.0','api.token':'secret-value'},depMgmt:[{a:'X',v:'${x.version}'}],deps:[{a:'X'},{g:'private.internal',a:'secret',v:'1'}]},
  'b/pom.xml':{g:'local',a:'b',v:'1',depMgmt:[{a:'X',v:'2.0'}],deps:[{a:'X'}]},
 });
 const store=core.newMetadataStore();for(const p of core.findPomFiles(dir))await core.parsePom(p,store);
 const propsByPom={};for(const p of Object.keys(store.byPath))await core.getAllInheritedProps(p,store,propsByPom);
 const hints=buildReactorHints({store,propsByPom},{exclude:/^private\./,versionPropertyNames:['x.version']});
 const json=JSON.stringify(hints);assert.ok(!json.includes(dir));assert.ok(!json.includes('secret-value'));assert.ok(!json.includes('private.internal'));
 const {store:restored,propsByPom:restoredProps}=restoreReactorHints(hints);
 const resolved=collectResolvedDeps(store,propsByPom,{deps2Exclude:/^private\./});
 const imported=deserializeDeps(serializeDeps(resolved,{reactor:hints}));
 const R=upstream([{g:G,a:'X',v:'1.0'},{g:G,a:'X',v:'2.0'}]);
 const fetcher=async url=>R[url]?{ok:true,status:200,text:async()=>R[url]}:{ok:false,status:404,text:async()=>''};
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-reactor-'));
 await resolveReactor(imported.resolved,restored,restoredProps,{fetcher,cacheDir,includeTestDeps:true,transitive:true});settleManagedOnly(imported.resolved);
 assert.deepEqual(versionsOf(imported.resolved,'X'),['1.0','2.0']);
 require('../lib/cache-db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});fs.rmSync(cacheDir,{recursive:true,force:true});
});

test('invalid Maven reactor descriptors fail closed',()=>{
 assert.throws(()=>restoreReactorHints({schema:1,modules:[{dependencies:[{groupId:'../../private',artifactId:'x'}],management:[],overrides:{}}]}),/invalid/);
});

test('descriptor resolution discovers transitives before consultation and replays the same graph offline',async t=>{
 const dir=writeLocal({'pom.xml':{g:'local',a:'app',v:'1',deps:[{a:'direct',v:'1.0'}]}});
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-reactor-replay-'));
 t.after(()=>{require('../lib/cache-db').closeCacheDbs(); fs.rmSync(dir,{recursive:true,force:true});fs.rmSync(cacheDir,{recursive:true,force:true})});
 const store=core.newMetadataStore();for(const p of core.findPomFiles(dir))await core.parsePom(p,store);
 const props={};for(const p of Object.keys(store.byPath))await core.getAllInheritedProps(p,store,props);
 const hints=buildReactorHints({store,propsByPom:props});
 const descriptor=serializeDeps(collectResolvedDeps(store,props),{reactor:hints});
 const R=upstream([{a:'direct',v:'1.0',deps:[{a:'transitive',v:'2.0'}]},{a:'transitive',v:'2.0'}]);
 const fetcher=async url=>R[url]?{ok:true,status:200,text:async()=>R[url]}:{ok:false,status:404,text:async()=>''};
 const online=deserializeDeps(descriptor);
 await resolveReactor(online.resolved,online.reactor.store,online.reactor.propsByPom,{fetcher,cacheDir,transitive:true});
 settleManagedOnly(online.resolved);
 assert.deepEqual(versionsOf(online.resolved,'transitive'),['2.0']);
 const offline=deserializeDeps(descriptor);
 await resolveReactor(offline.resolved,offline.reactor.store,offline.reactor.propsByPom,{offline:true,fetcher:()=>assert.fail('offline network'),cacheDir,transitive:true});
 settleManagedOnly(offline.resolved);
 assert.deepEqual(versionsOf(offline.resolved,'transitive'),versionsOf(online.resolved,'transitive'));
});

test('separate module versions keep their own transitive dependencies in a transferred reactor',async t=>{
 const dir=writeLocal({
  'a/pom.xml':{g:'local',a:'a',v:'1',deps:[{a:'shared',v:'1.0'}]},
  'b/pom.xml':{g:'local',a:'b',v:'1',deps:[{a:'shared',v:'2.0'}]},
 });
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-reactor-branches-'));
 t.after(()=>{require('../lib/cache-db').closeCacheDbs(); fs.rmSync(dir,{recursive:true,force:true});fs.rmSync(cacheDir,{recursive:true,force:true})});
 const store=core.newMetadataStore();for(const p of core.findPomFiles(dir))await core.parsePom(p,store);
 const props={};for(const p of Object.keys(store.byPath))await core.getAllInheritedProps(p,store,props);
 const descriptor=serializeDeps(collectResolvedDeps(store,props),{reactor:buildReactorHints({store,propsByPom:props})});
 const R=upstream([
  {a:'shared',v:'1.0',deps:[{a:'old-branch',v:'1.0'}]},
  {a:'shared',v:'2.0',deps:[{a:'new-branch',v:'2.0'}]},
  {a:'old-branch',v:'1.0'},{a:'new-branch',v:'2.0'},
 ]);
 const fetcher=async url=>R[url]?{ok:true,status:200,text:async()=>R[url]}:{ok:false,status:404,text:async()=>''};
 for(const offline of [false,true]){
  const restored=deserializeDeps(descriptor);
  await resolveReactor(restored.resolved,restored.reactor.store,restored.reactor.propsByPom,{fetcher:offline?()=>assert.fail('offline network'):fetcher,offline,cacheDir,transitive:true});
  settleManagedOnly(restored.resolved);
  assert.deepEqual(versionsOf(restored.resolved,'old-branch'),['1.0']);
  assert.deepEqual(versionsOf(restored.resolved,'new-branch'),['2.0']);
 }
});
