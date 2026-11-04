'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-npm-airgap-'));
require('../lib/cache-directory').setActiveCacheDir(root);
const {checkNpmRegistryDeps}=require('../lib/codecs/npm/registry');
const {makeDepRecord}=require('../lib/dep-record');
test('offline registry absence survives a different resolved version, without overriding positive evidence',async t=>{
 t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});
 const dep=makeDepRecord({ecosystem:'npm',name:'offline-fixture',version:'2.0.0'}),resolved=new Map([[dep.coordKey,dep]]);
 const save=entries=>require('../lib/json-cache').save(root,'npm-registry',{meta:{fetchedAt:Date.now()},entries});
 save({'offline-fixture@1.0.0':{error:'HTTP 404',absent:true}});
 assert.equal((await checkNpmRegistryDeps(resolved,{offline:true})).private.length,1);
 save({'offline-fixture@1.0.0':{error:'HTTP 404',absent:true},'offline-fixture@1.5.0':{latest:'1.5.0'}});
 assert.equal((await checkNpmRegistryDeps(resolved,{offline:true})).private.length,0);
});
