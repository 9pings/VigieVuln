'use strict';
require('./helpers/isolated-cache')('maven-case-identity');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {openAdvisoryStore}=require('../lib/advisory-store');
const {newOsvIndex,addOsvRecord,matchOsvDbDeps,matchOsvDbRecords}=require('../lib/osv-db');
const {makeDepRecord}=require('../lib/dep-record');

test('Maven advisory and query identities preserve case in warm and streamed offline matching',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-maven-case-'));
 const store=openAdvisoryStore({cacheDir:dir}),now=Date.now();t.after(()=>{store.close();require('../lib/cache-db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const advisory={id:'GHSA-case',affected:[{package:{ecosystem:'Maven',name:'org.example:Widget'},versions:['1.0.0']}]};
 const upper={source:'osv',ecosystem:'Maven',name:'org.example:Widget',version:'1.0.0'};
 const lower={...upper,name:'org.example:widget'};
 store.commit({records:[{source:'osv',document:advisory,fetchedAt:now,provenance:{transport:'direct'}}],queries:[{...upper,ids:['GHSA-case'],complete:true,fetchedAt:now,provenance:{transport:'direct'}}]});
 assert.deepEqual(store.getQuery(upper).ids,['GHSA-case']);assert.equal(store.getQuery(lower),null);
 store.commit({queries:[{...lower,ids:[],complete:true,fetchedAt:now+1,provenance:{transport:'direct'}}]});
 assert.deepEqual(store.getQuery(upper).ids,['GHSA-case']);assert.deepEqual(store.getQuery(lower).ids,[]);
 const deps=name=>{const dep=makeDepRecord({ecosystem:'maven',namespace:'org.example',name,version:'1.0.0'});return new Map([[dep.coordKey,dep]]);};
 const index=newOsvIndex('Maven');addOsvRecord(index,advisory);
 assert.equal(matchOsvDbDeps(deps('Widget'),index).length,1);assert.equal(matchOsvDbDeps(deps('widget'),index).length,0);
 const text=JSON.stringify(advisory)+'\n',file=path.join(dir,'seed.jsonl');fs.writeFileSync(file,text);
 const seed={ecosystem:'Maven',recordsFile:file,recordCount:1,sha256:crypto.createHash('sha256').update(text).digest('hex')};
 assert.equal((await matchOsvDbRecords(deps('Widget'),seed)).length,1);assert.equal((await matchOsvDbRecords(deps('widget'),seed)).length,0);
});
