'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {vulnVerdict}=require('../lib/osv-db');
const {makeDepRecord}=require('../lib/dep-record');
const {queryBatch}=require('../lib/osv');
const {openAdvisoryStore}=require('../lib/advisory-store');

const affected={package:{ecosystem:'Maven',name:'org.example:widget'},versions:['1.0','1.1'],ranges:[],database_specific:{vigievuln_partial_versions:true,unaffected_versions:['2.0']}};
const record={id:'vv:CVE-2026-1234:test',aliases:['CVE-2026-1234'],affected:[affected],curation:{method:'AI-assisted reconciliation'}};

test('reviewed partial versions distinguish affected, known unaffected, unknown and conflicting evidence',()=>{
 const evaluate=v=>vulnVerdict(v,record,'Maven',{source:'vigievuln'});
 assert.equal(evaluate('1.0'),true);
 assert.equal(evaluate('1.0.0'),true, 'equivalent Maven versions match');
 assert.equal(evaluate('2.0'),false);
 assert.equal(evaluate('1.5'),null);
 const contradictory={...record,affected:[{...affected,database_specific:{...affected.database_specific,unaffected_versions:['1.0']}}]};
 assert.equal(vulnVerdict('1.0',contradictory,'Maven',{source:'vigievuln'}),null);
 const unknownRange={...record,affected:[{...affected,ranges:[{type:'GIT',events:[{introduced:'0'}]}]}]};
 assert.equal(vulnVerdict('2.0',unknownRange,'Maven',{source:'vigievuln'}),null);
});

test('external OSV records do not use VigieVuln-only partial metadata',()=>{
 assert.equal(vulnVerdict('1.5',record,'Maven'),false);
 assert.equal(vulnVerdict('2.0',record,'Maven',{source:'osv'}),false);
 const contradictory={...record,affected:[{...affected,database_specific:{...affected.database_specific,unaffected_versions:['1.0']}}]};
 assert.equal(vulnVerdict('1.0',contradictory,'Maven',{source:'osv'}),true);
});

test('offline reviewed evidence reports a match or a partial-coverage warning',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-partial-'));
 const store=openAdvisoryStore({cacheDir:root}),at=Date.now();t.after(()=>{store.close();require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});
 store.commit({records:[{source:'vigievuln',document:record,packages:[affected.package],fetchedAt:at,provenance:{transport:'test'}}],coverages:[{source:'osv',ecosystem:'Maven',complete:true,fetchedAt:at}]});
 const dep=version=>makeDepRecord({ecosystem:'maven',namespace:'org.example',name:'widget',version});
 const warnings=[];const result=await queryBatch([dep('1.0'),dep('1.5'),dep('2.0')],{offline:true,store,cacheDir:root,onWarning:w=>warnings.push(w)});
 assert.equal(result.length,1);assert.equal(result[0].source,'vigievuln');assert.equal(result[0].dep.version,'1.0');
 const partial=warnings.filter(w=>w.message.includes('partial version evidence'));
 assert.equal(partial.length,1);assert.match(partial[0].message,/@1\.5/);
});

test('reviewed npm evidence matches only its package and ecosystem, offline',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-npm-reviewed-'));
 const store=openAdvisoryStore({cacheDir:root}),at=Date.now();t.after(()=>{store.close();require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});
 const npm={package:{ecosystem:'npm',name:'uri-js'},versions:['4.4.0','4.4.1'],ranges:[],database_specific:{vigievuln_partial_versions:true}};
 const advisory={id:'vv:CVE-2026-103387:test',aliases:['CVE-2026-103387'],affected:[npm],curation:{method:'AI-assisted reconciliation'}};
 store.commit({records:[{source:'vigievuln',document:advisory,packages:[npm.package],fetchedAt:at,provenance:{transport:'test'}}],coverages:[{source:'osv',ecosystem:'npm',complete:true,fetchedAt:at},{source:'osv',ecosystem:'PyPI',complete:true,fetchedAt:at}]});
 const dep=(ecosystem,name,version)=>makeDepRecord({ecosystem,name,version});
 const warnings=[];const results=await queryBatch([dep('npm','uri-js','4.4.1'),dep('npm','uri-js','4.4.2'),dep('npm','uri-js-other','4.4.1'),dep('pypi','uri-js','4.4.1')],{offline:true,store,cacheDir:root,onWarning:w=>warnings.push(w)});
 assert.equal(results.length,1);assert.equal(results[0].source,'vigievuln');assert.equal(results[0].dep.name,'uri-js');assert.equal(results[0].dep.version,'4.4.1');assert.equal(results[0].cve.curation.method,'AI-assisted reconciliation');
 assert.ok(warnings.some(w=>w.message.includes('partial version evidence') && w.message.includes('uri-js@4.4.2')));
 assert.ok(!warnings.some(w=>w.message.includes('uri-js-other') && w.message.includes('partial version evidence')));
});
