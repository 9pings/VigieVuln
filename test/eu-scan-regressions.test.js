'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {createCacheRepository}=require('../lib/cache-repository');
const {enrichArtifactFindings}=require('../lib/artifacts/enrichment');
const {projectImageCves}=require('../lib/artifacts/cve-view');
function tmp(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'eu-review-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true})});return dir;}
test('EU context survives offline with OSV and NVD disabled and remains tied to each upstream CVE',async t=>{
 const cacheDir=tmp(t),repo=createCacheRepository(cacheDir),now=Date.now(),a='CVE-2024-12345',b='CVE-2024-56789';
 repo.put('catalogue','euvd',{_fetchedAt:now,body:{byCve:{[a]:'EUVD-2024-55'},exploited:{[a]:'2024-03-01'}}});
 repo.put('catalogue','certfr',{meta:{fetchedAt:now},entries:{'CERTFR-2024-AVI-001':{kind:'avis',title:'Example',cves:[b]}}});
 const matches=[{dep:{artifactTargetId:'image-a',ecosystem:'system',name:'demo',version:'1',coordKey:'image-a/demo'},cve:{id:'DLA-2024-1',upstream:[a,b],severity:'UNKNOWN'},source:'GCVE:GNA-1'}];let calls=0;
 const r=await enrichArtifactFindings(matches,{offline:true,osv:false,nvd:false,cacheDir,enrich:['gcve','euvd','certfr'],fetcher:()=>{calls++;throw Error('network')}});
 assert.equal(calls,0);for(const id of ['gcve','euvd','certfr'])assert.equal(r.coverage.find(c=>c.collector===id).execution,'completed');assert.equal(r.coverage.find(c=>c.collector==='euvd-details').execution,'partial');assert.equal(matches[0].cve.euvd,undefined);assert.equal(matches[0].cve.certfr,undefined);assert.equal(matches[0].cve.kev,undefined);
 const rows=projectImageCves(matches),one=rows.find(m=>m.cve.id===a),two=rows.find(m=>m.cve.id===b);assert.equal(one.cve.euvd.id,'EUVD-2024-55');assert.equal(one.cve.certfr,undefined);assert.equal(two.cve.certfr[0].ref,'CERTFR-2024-AVI-001');assert.equal(two.cve.euvd,undefined);assert.equal(one.cve.kev,undefined);
});
test('an excluded source is not consulted even if its cache has matching evidence',async t=>{
 const cacheDir=tmp(t),repo=createCacheRepository(cacheDir),id='CVE-2024-12345';repo.put('catalogue','euvd',{_fetchedAt:Date.now(),body:{byCve:{[id]:'EUVD-2024-1'},exploited:{}}});const matches=[{cve:{id}}];
 const r=await enrichArtifactFindings(matches,{cacheDir,offline:true,euvd:false,enrich:['gcve','euvd'],fetcher:()=>{throw Error('network')}});assert.equal(matches[0].cve.euvd,undefined);assert.equal(r.coverage.find(c=>c.collector==='euvd').result,'not-consulted');assert.equal(matches[0].cve.gcve,'GCVE-0-2024-12345');
});
