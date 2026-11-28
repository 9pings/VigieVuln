'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {createSnapshot,readSnapshot,writeSnapshot,acquireInventories}=require('../lib/artifacts/scan');
const {applyComponentScope}=require('../lib/artifacts/inventory-scope');
const {IMAGE_COMPONENT_SCOPE}=require('../lib/artifacts/component-scope');
const {closeCacheDbs}=require('../lib/cache/db');
function fixture() {
 const id='image-a';
 const row=(name,ecosystem,artifactPath,other={})=>({name,ecosystem,coordKey:`artifact:${id}:${name}`,artifactTargetId:id,artifactPath,...other});
 const npm=(name,p)=>row(name,'npm',p,{provenance:'installed',installEvidence:{source:'npm',path:p}});
 return {id,kind:'image',metadata:{acquisition:{indexDigest:'sha256:'+'a'.repeat(64)}},evidence:'content-inventory',packages:[],coverage:[{collector:'installed-applications',execution:'completed',result:'indeterminate',artifactTargetId:id}],warnings:[
  {reason:'installed-metadata-error',manifestPath:'app/node_modules/tool/dist/mjs/package.json',message:'invalid fragment'},
  {reason:'installed-metadata-error',manifestPath:'app/node_modules/tool/package.json',message:'real error'}
 ],deps:[npm('root','app/package.json'),npm('tool','app/node_modules/tool/package.json'),npm('nested-cli','app/node_modules/tool/node_modules/cli/package.json'),npm('scoped','app/node_modules/@org/pkg/package.json'),npm('fragment','app/node_modules/tool/dist/mjs/package.json'),npm('windows-fragment','C:\\app\\node_modules\\tool\\dist\\mjs\\package.json'),
 row('runtime','go','bin/tool',{provenance:'binary-module',binaryEvidence:{source:'go-buildinfo',original:{kind:'dep'}}}),row('nested.jar','maven','app/tool.jar!/lib/nested.jar',{installEvidence:{source:'jar',path:'app/tool.jar!/lib/nested.jar'}}),row('nuget-lib','nuget','app/app.deps.json',{installEvidence:{source:'nuget',path:'app/app.deps.json'}}),row('os-pkg','system','var/lib/dpkg/status')]};
}
function tmp(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-image-scope-'));t.after(()=>{closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});return root;}
test('legacy image retains physical dependencies and drops only npm package fragments',()=>{
 const old=fixture(),result=applyComponentScope(old);
 assert.deepEqual(result.deps.map(d=>d.name),['root','tool','nested-cli','scoped','runtime','nested.jar','nuget-lib','os-pkg']);
 assert.equal(old.deps.length,10,'original snapshot remains unchanged');
 assert.equal(result.coverage[0].execution,'partial');assert.equal(result.warnings.filter(w=>w.reason==='image-inventory-scope-outdated').length,1);
 assert.equal(result.deps.find(d=>d.name==='root').imageRole,'direct');assert.equal(result.deps.find(d=>d.name==='root').scope,'runtime');
 assert.equal(result.deps.find(d=>d.name==='nested-cli').imageRole,'transitive');assert.equal(result.deps.find(d=>d.name==='nested-cli').scope,'transitive');
 assert.ok(result.warnings.some(w=>w.message==='real error'));assert.ok(!result.warnings.some(w=>w.message==='invalid fragment'));
 assert.deepEqual(applyComponentScope(result),result,'repeated application is idempotent');
});
test('direct assessment can filter without inventing a legacy cache warning',()=>{
 const result=applyComponentScope(fixture(),{checkPolicy:false});
 assert.equal(result.deps.some(d=>d.name==='fragment'),false);
 assert.equal(result.coverage[0].execution,'completed');assert.ok(!result.warnings.some(w=>w.reason==='image-inventory-scope-outdated'));
 const saved=applyComponentScope(fixture());assert.equal(applyComponentScope(saved,{checkPolicy:false}).coverage[0].execution,'partial');
});
test('publisher SBOMs stay unchanged regardless of paths or legacy marker',()=>{
 const target={...fixture(),kind:'sbom'};assert.deepEqual(applyComponentScope(target),target);
});
test('snapshot integrity is validated before filtering and legacy partial survives re-export',async t=>{
 const root=tmp(t),file=path.join(root,'old.json'),after=path.join(root,'new.json');
 const doc=createSnapshot([fixture()]);fs.writeFileSync(file,JSON.stringify(doc));
 const [result]=readSnapshot(file);assert.equal(result.deps.some(d=>d.name==='nested-cli'),true);assert.equal(result.coverage[0].execution,'partial');
 await writeSnapshot(after,[result]);assert.equal(readSnapshot(after)[0].coverage[0].execution,'partial');
 doc.targets[0].deps.pop();fs.writeFileSync(file,JSON.stringify(doc));assert.throws(()=>readSnapshot(file),/integrity/);
});
test('offline registry reuse filters old scope without any network call',async t=>{
 const root=tmp(t),input='example.invalid/team/app:latest';
 const key=crypto.createHash('sha256').update(JSON.stringify([input,null,false])).digest('hex');
 require('../lib/cache/repository').createCacheRepository(root).put('image-inventory',key,createSnapshot([fixture()]));
 const [result]=await acquireInventories(input,{registry:true,offline:true,cacheDir:root,fetcher:()=>assert.fail('offline network')});
 assert.equal(result.deps.some(d=>d.name==='fragment'),false);assert.equal(result.deps.some(d=>d.name==='nested-cli'),true);
 assert.equal(result.coverage[0].execution,'partial');assert.equal(result.metadata.componentScope,undefined);
});
test('legacy image inventory survives airgap cache transfer with partial scope and without npm fragments',async t=>{
 const root=tmp(t),source=path.join(root,'source'),destination=path.join(root,'destination'),input='example.invalid/team/app:latest';
 const key=crypto.createHash('sha256').update(JSON.stringify([input,null,false])).digest('hex');
 require('../lib/cache/repository').createCacheRepository(source).put('image-inventory',key,createSnapshot([fixture()]));
 const archive=path.join(root,'cache.tar.gz'),{exportCache,importCache}=require('../lib/cache/archive');
 await exportCache(archive,{sourceDir:source});await importCache(archive,{targetDir:destination});
 const [result]=await acquireInventories(input,{registry:true,offline:true,cacheDir:destination,fetcher:()=>assert.fail('offline network')});
 assert.equal(result.deps.some(d=>d.name==='fragment'),false);assert.equal(result.deps.some(d=>d.name==='nested-cli'),true);
 assert.equal(result.coverage[0].execution,'partial');assert.ok(result.warnings.some(w=>w.reason==='image-inventory-scope-outdated'));
});
test('online registry reacquires old scoped inventory even when the image digest is unchanged',async t=>{
 const root=tmp(t),cacheDir=path.join(root,'cache'),input='example.invalid/team/app:latest',fsroot=path.join(root,'rootfs');
 fs.mkdirSync(path.join(fsroot,'etc'),{recursive:true});fs.writeFileSync(path.join(fsroot,'etc','os-release'),'ID=alpine\nVERSION_ID=3.20\n');
 const repo=require('../lib/cache/repository').createCacheRepository(cacheDir),key=crypto.createHash('sha256').update(JSON.stringify([input,null,false])).digest('hex');
 repo.put('image-inventory',key,createSnapshot([fixture()]));
 const registry=require('../lib/images/registry'),oldImage=registry.fetchRegistryImage,oldDigest=registry.fetchRegistryDigest;let images=0,digests=0;
 registry.fetchRegistryImage=async()=>{images++;return {path:fsroot,metadata:{digest:'sha256:'+'a'.repeat(64)},cleanup:async()=>{}}};
 registry.fetchRegistryDigest=async()=>{digests++;return 'sha256:'+'a'.repeat(64)};
 try {
  const fresh=await acquireInventories(input,{registry:true,cacheDir});assert.equal(images,1);assert.equal(fresh[0].metadata.componentScope,IMAGE_COMPONENT_SCOPE);
  const cached=await acquireInventories(input,{registry:true,cacheDir});assert.equal(images,1);assert.equal(digests,1);assert.equal(cached[0].evidence,'cached-inventory');
  const canonicalKey=crypto.createHash('sha256').update(JSON.stringify(['example.invalid/team/app@latest',null,false])).digest('hex');
  const contaminated=structuredClone(repo.get('image-inventory',canonicalKey).value.targets);
  contaminated[0].deps.push({name:'fragment',ecosystem:'npm',coordKey:'fragment',artifactTargetId:contaminated[0].id,artifactPath:'app/node_modules/tool/dist/package.json',installEvidence:{source:'npm',path:'app/node_modules/tool/dist/package.json'}});
  repo.put('image-inventory',canonicalKey,createSnapshot(contaminated));
  await acquireInventories(input,{registry:true,cacheDir});assert.equal(images,2,'inconsistent scope marker requires a fresh inventory');
 } finally {registry.fetchRegistryImage=oldImage;registry.fetchRegistryDigest=oldDigest;}
});
