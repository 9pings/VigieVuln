'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {resolveTransitiveDeps}=require('../lib/transitive');

test('missing offline POMs are reported even when a negative result is memoized',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-transitive-coverage-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const missing=[],effCache=new Map(),deps=[{groupId:'example',artifactId:'library',version:'1.0'}];
 const options={offline:true,cacheDir:dir,repos:[{central:false}],effCache,onMissingPom:p=>missing.push(p)};
 assert.equal((await resolveTransitiveDeps(deps,options)).size,0);
 assert.equal((await resolveTransitiveDeps(deps,options)).size,0);
 assert.deepEqual(missing,[{groupId:'example',artifactId:'library',version:'1.0'},{groupId:'example',artifactId:'library',version:'1.0'}]);
});

test('depth-limited traversal reports uninspected dependency nodes',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-transitive-depth-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const xml='<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>root</artifactId><version>1.0</version><dependencies><dependency><groupId>example</groupId><artifactId>child</artifactId><version>1.0</version></dependency></dependencies></project>';
 let stopped=0;
 const deps=await resolveTransitiveDeps([{groupId:'example',artifactId:'root',version:'1.0'}],{cacheDir:dir,maxDepth:1,fetcher:async()=>({ok:true,status:200,text:async()=>xml}),onDepthLimit:n=>{stopped+=n;}});
 assert.equal(deps.size,1);assert.equal(stopped,1);
});

test('unexpected effective-POM failure signals incomplete resolution', async () => {
 const {resolveTransitiveDeps}=require('../lib/transitive');let failures=0;
 const result=await resolveTransitiveDeps([{groupId:'org.example',artifactId:'root',version:'1',scope:'compile'}],{
  offline:true,effCache:{has(){throw new Error('broken cache');}},onResolutionError:()=>failures++,
 });
 assert.equal(result.size,0);assert.equal(failures,1);
});
