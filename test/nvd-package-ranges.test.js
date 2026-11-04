'use strict';
const isolated=require('./helpers/isolated-cache')('nvd-package-ranges');
const {test}=require('node:test'),assert=require('node:assert/strict');
const {matchBoundNvdRanges,collectPackageNvdBindings}=require('../lib/nvd-package-ranges');
const {makeDepRecord}=require('../lib/dep-record');
const record=require('./fixtures/cve-maven-matching/nvd-jackson-11113.json');
const dep=version=>makeDepRecord({ecosystem:'maven',namespace:'com.fasterxml.jackson.core',name:'jackson-databind',version});
const existing=()=>[{dep:dep('2.9.5'),source:'osv+nvd',cve:{...structuredClone(record),fixVersion:'2.9.10.4'}}];
const osv=require('./fixtures/cve-maven-matching/osv-jackson-11113.json');
test('an isolated older release reuses stored package identity even when OSV excludes its version',async t=>{
 const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir:isolated});t.after(()=>store.close());
 store.commit({records:[{source:'osv',document:osv,fetchedAt:Date.now()}]});
 const d=dep('2.5.2'),deps=new Map([[d.coordKey,d]]);
 assert.equal(require('../lib/osv-db').vulnVerdict(d.version,osv,'Maven'),false);
 const bindings=collectPackageNvdBindings(deps,store);
 assert.equal(bindings.length,1);
 assert.deepEqual(matchBoundNvdRanges(deps,bindings),[],'binding alone is not a finding');
 require('../lib/nvd').writeCache(record.id,record);
 await require('../lib/nvd').enrichMatches(bindings,{offline:true});
 const found=matchBoundNvdRanges(deps,bindings);
 assert.equal(found.length,1);assert.equal(found[0].dep.version,'2.5.2');assert.equal(found[0].source,'nvd');
 assert.deepEqual(matchBoundNvdRanges(deps,[...found,...bindings]),[],'actual findings still deduplicate');
 const fixed=dep('2.9.10.4');assert.deepEqual(matchBoundNvdRanges(new Map([[fixed.coordKey,fixed]]),bindings),[]);
});
test('withdrawals, other packages, aggregate CVEs and non-Maven data cannot provide package bindings',()=>{
 const d=dep('2.5.2'),deps=new Map([[d.coordKey,d]]);
 for(const change of [r=>r.document.withdrawn='2026-01-01T00:00:00Z',r=>r.withdrawnAt='2026-01-01T00:00:00Z',r=>r.source='cveproject',r=>r.document.aliases.push('CVE-2020-99999'),r=>r.document.affected.forEach(a=>a.package.ecosystem='npm'),r=>r.document.affected.forEach(a=>a.package.name='com.fasterxml.jackson.core:Jackson-databind')]) {
  const r={source:'osv',document:structuredClone(osv)};change(r);
  assert.deepEqual(collectPackageNvdBindings(deps,{getPackageRecords:()=>[r]}),[]);
 }
});
test('NVD extends an existing exact OSV binding to an affected older branch, without copying its fix',()=>{
 const deps=new Map(['2.5.2','2.9.5','2.9.10.4'].map(v=>[v,dep(v)]));
 const r=matchBoundNvdRanges(deps,existing());
 assert.deepEqual(r.map(m=>m.dep.version),['2.5.2']);
 assert.equal(r[0].source,'nvd');assert.equal(r[0].cve.fixVersion,null);
});
test('a generic product, absent OSV binding, AND or deployment qualifier cannot add findings',()=>{
 const d=dep('2.5.2'),deps=new Map([[d.coordKey,d]]);
 assert.deepEqual(matchBoundNvdRanges(deps,[]),[]);
 const m=existing();m[0].source='CVEProject+nvd';assert.deepEqual(matchBoundNvdRanges(deps,m),[]);
 const config={operator:'OR',nodes:[{operator:'OR',cpeMatch:[{vulnerable:true,criteria:'cpe:2.3:a:fasterxml:jackson-databind:*:*:*:*:*:*:*:*',versionEndExcluding:'3.0'}]}]};
 for(const change of [c=>c.operator='AND',c=>c.negate=true,c=>c.nodes[0].operator='AND',c=>c.nodes[0].cpeMatch[0].criteria='cpe:2.3:a:fasterxml:jackson:*:*:*:*:*:*:*:*',c=>c.nodes[0].cpeMatch[0].criteria='cpe:2.3:a:fasterxml:jackson-databind:*:*:*:*:*:windows:*:*']){
  const c=structuredClone(config);change(c);const m=existing();m[0].cve.configurations=[c];assert.deepEqual(matchBoundNvdRanges(deps,m),[]);
 }
 assert.deepEqual(matchBoundNvdRanges(deps,existing(),{byVendorProduct:{'fasterxml:jackson-databind':['com.fasterxml.jackson.core:jackson-databind','com.fasterxml.jackson.core:jackson-core']}}),[]);
 const invalid=existing();invalid[0].cve.configurations=[structuredClone(config)];invalid[0].cve.configurations[0].nodes[0].cpeMatch[0].vulnerable='false';
 assert.deepEqual(matchBoundNvdRanges(deps,invalid),[]);
});
