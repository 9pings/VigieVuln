'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {acquireInventories,assessInventories,writeSnapshot}=require('../lib/artifacts/scan');
function setup(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-image-retire-')),root=path.join(dir,'root'),cacheDir=path.join(dir,'cache');
 fs.mkdirSync(root);t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const cache=require('../lib/cache-repository').createCacheRepository(cacheDir);
 const put=(name,text)=>{const f=path.join(root,name);fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,text);};
 const signatures=(fixed='2.0.0')=>cache.put('auxiliary','retire-signatures',JSON.stringify({jquery:{extractors:{filename:['jquery-(§§version§§)\\.js'],filecontent:['jQuery v(§§version§§)']},vulnerabilities:[{below:fixed,severity:'high',identifiers:{CVE:['CVE-2025-12345'],summary:'Fixture'},info:['https://example.test/advisory']}]}}));
 const options={offline:true,imageRetire:true,cacheDir,osv:false,distroAdvisories:false,publisherAdvisories:false,disableCveProject:true,disableGcve:true,enrich:[],fetcher:()=>assert.fail('network')};
 return {dir,root,cacheDir,put,signatures,options};
}
test('image RetireJS scans deployed assets, excludes package stores and symlinks, and reassesses snapshots',async t=>{
 const f=setup(t);f.signatures();
 f.put('app/dist/jquery-1.0.0.js','fixture');f.put('app/build/bundle.js','/*! jQuery v1.1.0 */');
 for(const dir of ['node_modules/pkg','vendor/pkg','site-packages/pkg','.npm','usr/share/nodejs/pkg'])f.put(`${dir}/jquery-1.0.0.js`,'fixture');
 const outside=path.join(f.dir,'outside');fs.mkdirSync(outside);fs.writeFileSync(path.join(outside,'jquery-0.1.0.js'),'fixture');
 fs.symlinkSync(outside,path.join(f.root,'linked'));fs.symlinkSync(path.join(outside,'jquery-0.1.0.js'),path.join(f.root,'jquery-0.1.0.js'));
 const targets=await acquireInventories(f.root,f.options);
 assert.deepEqual(targets[0].deps.filter(d=>d.installEvidence?.source==='retire').map(d=>d.artifactPath).sort(),['app/build/bundle.js','app/dist/jquery-1.0.0.js']);
 const assessed=await assessInventories(targets,f.options);
 assert.equal(assessed.cveMatches.length,2);assert.ok(assessed.cveMatches.every(m=>m.source==='retire' && m.dep.artifactTargetId===targets[0].id && m.dep.imageSource.category==='vendored'));
 const snapshot=path.join(f.dir,'inventory.json');await writeSnapshot(snapshot,targets);
 f.signatures('0.5.0');
 const replay=await assessInventories(await acquireInventories(snapshot,{...f.options,inventory:true}),f.options);
 assert.equal(replay.cveMatches.length,0,'stored findings must not override updated signatures');
 assert.equal(replay.artifacts[0].coverage.find(c=>c.collector==='image-retire'&&c.capability==='advisories').result,'no-match');
});
test('missing signatures and bounded scans cannot become clean image results',async t=>{
 const f=setup(t);f.put('app/jquery-1.0.0.js','fixture');
 const targets=await acquireInventories(f.root,f.options);
 assert.ok(targets[0].warnings.some(w=>w.reason==='image-retire-incomplete'));
 const assessed=await assessInventories(targets,f.options);
 assert.equal(assessed.artifacts[0].coverage.find(c=>c.collector==='image-retire'&&c.capability==='advisories').result,'indeterminate');
 f.signatures();
 const [limited]=await acquireInventories(f.root,{...f.options,maxImageJsFileBytes:1});
 assert.equal(limited.coverage.find(c=>c.collector==='image-retire').execution,'partial');
 const plain=await acquireInventories(f.root,{...f.options,imageRetire:false});
 const missing=await assessInventories(plain,f.options);
 assert.ok(missing.warnings.some(w=>/reacquire image contents/.test(w.message)));
});
test('OS-owned JavaScript uses distribution verdicts, including previously collected identities',async t=>{
 const f=setup(t);f.signatures();f.put('usr/share/javascript/jquery-1.0.0.js','fixture');
 const {collectImageJs,assessImageJs}=require('../lib/artifacts/retire');
 const collected=await collectImageJs(f.root,f.options,['/usr/share/javascript/jquery-1.0.0.js']);
 assert.equal(collected.deps.length,0);assert.equal(collected.coverage.excludedOwnedFiles,1);
 const [target]=await acquireInventories(f.root,f.options);
 for(const d of target.deps)d.osPackageOwners=[{manager:'dpkg',name:'libjs-jquery',version:'1.0.0-2'}];
 const result=await assessImageJs(target,f.options);assert.equal(result.matches.length,0);
});
