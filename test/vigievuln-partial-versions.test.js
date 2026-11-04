'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {vulnVerdict}=require('../lib/osv-db');
const {makeDepRecord}=require('../lib/dep-record');
const {queryBatch,queryReviewedForDeps,vulnToMatch}=require('../lib/osv');
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
 assert.equal(result[0].cve.fixVersion,'2.0');assert.equal(result[0].cve.fixEvidence,'explicit-unaffected-version');
 const standalone=queryReviewedForDeps(new Map([[dep('1.0').coordKey,dep('1.0')]]),{store,cacheDir:root});
 assert.equal(standalone.length,1);assert.equal(standalone[0].cve.fixVersion,'2.0');assert.equal(standalone[0].cve.fixEvidence,'explicit-unaffected-version');
 const partial=warnings.filter(w=>w.message.includes('partial version evidence'));
 assert.equal(partial.length,1);assert.match(partial[0].message,/@1\.5/);
});

test('only VV explicit safe releases can become advisory candidates, with every applicable entry checked',()=>{
 const dep=makeDepRecord({ecosystem:'maven',namespace:'org.example',name:'widget',version:'1.0'});
 const vv=v=>vulnToMatch(dep,v,{source:'vigievuln'}).cve;
 assert.equal(vulnToMatch(dep,record).cve.fixVersion,null,'external OSV must ignore VV metadata');
 assert.equal(vv(record).fixVersion,'2.0');
 assert.equal(vv({...record,affected:[affected,{...affected,versions:['2.0'],database_specific:{vigievuln_partial_versions:true,unaffected_versions:['3.0']}}]}).fixVersion,null,'conflicting applicable entry blocks candidate');
 assert.equal(vv({...record,affected:[affected,{...affected,versions:['1.0'],database_specific:{vigievuln_partial_versions:true,unaffected_versions:['3.0']}}]}).fixVersion,null,'candidate unknown in another entry');
 assert.equal(vv({...record,affected:[affected,{...affected,package:{ecosystem:'Maven',name:'org.other:widget'},versions:['2.0']}]}).fixVersion,'2.0','other package does not interfere');
 assert.equal(vv({...record,affected:[{...affected,database_specific:{vigievuln_partial_versions:true,unaffected_versions:['1.0','0.9']}}]}).fixVersion,null,'same or older version is not an upgrade');
 assert.equal(vv({...record,affected:[{...affected,ranges:[{type:'GIT',events:[{introduced:'0'}]}]}]}).fixVersion,null,'unknown range blocks candidate');
});

test('VV candidate survives enrichment, but conflicting or unverified advisory fixes suppress it',()=>{
 const {mergeBySource}=require('../lib/merge-sources');
 const {buildFindings}=require('../lib/json-export');
 const {generateHtmlReport}=require('../lib/cve-report');
 const dep=makeDepRecord({ecosystem:'maven',namespace:'org.example',name:'widget',version:'1.0'});
 const vv=vulnToMatch(dep,record,{source:'vigievuln'});vv.source='vigievuln';
 const nvd={dep,source:'nvd',cve:{id:'CVE-2026-1234',description:'NVD enrichment'}};
 for(const order of [[vv,nvd],[nvd,vv]]){
  const merged=mergeBySource([],order);assert.equal(merged.length,1);assert.equal(merged[0].cve.fixVersion,'2.0');assert.equal(merged[0].cve.fixEvidence,'explicit-unaffected-version');
  const json=buildFindings({cveMatches:merged,projectInfo:{name:'fixture'}});assert.equal(json.cve[0].fixVersion,'2.0');assert.equal(json.cve[0].fixEvidence,'explicit-unaffected-version');assert.equal(json.cve[0].packageFixVerified,false);
  const html=generateHtmlReport({cveMatches:merged,projectInfo:{name:'fixture'},warnings:[],locale:'fr'});assert.match(html,/Cette version précise a été vérifiée comme non affectée/);assert.match(html,/L’absence d’autres vulnérabilités/);
 }
 for(const other of [
  {dep,source:'osv',cve:{id:'CVE-2026-1234',fixVersion:'3.0',fixEvaluation:'verified'}},
  {dep,source:'CVEProject',cve:{id:'CVE-2026-1234',fixVersion:null,fixEvaluation:'unknown'}},
  {dep,source:'nvd',cve:{id:'CVE-2026-1234',fixVersion:null,fixEvaluation:'unknown'}}
 ]) for(const order of [[vv,other],[other,vv]]){
  const merged=mergeBySource([],order)[0];assert.equal(merged.cve.fixVersion,null);assert.equal(merged.cve.fixEvidence,undefined);assert.ok(merged.cve.fixConflict);
 }
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
