'use strict';
require('./helpers/isolated-cache')('nvd-affected');
const {test}=require('node:test'),assert=require('node:assert/strict');
const nvd=require('../lib/nvd');
const {matchNvdAffected,collectPackageNvdBindings}=require('../lib/nvd-package-ranges');
const {makeDepRecord}=require('../lib/dep-record');
const raw=require('./fixtures/cve-maven-matching/nvd-logback-13006.json');
const jackson=require('./fixtures/cve-maven-matching/nvd-jackson-18401.json');
const dep=(coord,version)=>{const [namespace,name]=coord.split(':');return makeDepRecord({ecosystem:'maven',namespace,name,version});};
const candidates=r=>[{bindingOnly:true,cve:{...nvd.extractFromNvdRecord(r),nvdAffected:r.affected,nvdVulnStatus:r.vulnStatus}}];
function match(r,coord,version){const d=dep(coord,version);return matchNvdAffected(new Map([[d.coordKey,d]]),candidates(r));}

test('real NVD native ranges work without CPEs, including inclusive and unaffected boundaries',()=>{
 assert.equal(raw.configurations,undefined);
 for(const [v,want] of [['0.9.19',false],['0.9.20',true],['1.2.2',true],['1.5.36',true],['1.5.37',false]])
  assert.equal(match(raw,'ch.qos.logback:logback-core',v).length>0,want,v);
 assert.equal(match(raw,'ch.qos.logback:logback-classic','1.2.2').length,0);
 assert.equal(match(raw,'wrong.vendor:logback-core','1.2.2').length,0);
 const m=match(raw,'ch.qos.logback:logback-core','1.2.2')[0];
 assert.equal(m.source,'nvd');assert.equal(m.cve.affectedProviders[0].name,'vulnerability@ncsc.ch');
});
test('real native package identity and separate Jackson release branches survive normalization',()=>{
 for(const [v,want] of [['2.8.4',false],['2.18.5',true],['2.18.6',false],['2.20.0',true],['2.21.1',false]])
  assert.equal(match(jackson,'com.fasterxml.jackson.core:jackson-core',v).length>0,want,v);
 assert.equal(match(jackson,'com.fasterxml.jackson.core:jackson-databind','2.20.0').length,0);
 assert.equal(match(jackson,'tools.jackson.core:jackson-core','3.0.0').length,1);
 assert.equal(match(jackson,'tools.jackson.core:jackson-core','3.1.0').length,0);
});
test('platform restrictions, rejected records and provider conflicts cannot become findings',()=>{
 for(const change of [
  r=>r.affected[0].affectedData[0].platforms=['Windows'],
  r=>r.vulnStatus='Rejected',
  r=>{const other=structuredClone(r.affected[0]);other.source='another-cna';other.affectedData[0].versions=[{version:'1.2.2',status:'unaffected',versionType:'maven'}];r.affected.push(other);}
 ]){const r=structuredClone(raw);change(r);assert.equal(match(r,'ch.qos.logback:logback-core','1.2.2').length,0);}
});
test('version status changes and explicit exclusions use the same native evaluator',()=>{
 const r=structuredClone(raw),a=r.affected[0].affectedData[0];
 a.versions=[{version:'1.0',lessThan:'2.0',versionType:'maven',status:'affected',changes:[{at:'1.2',status:'unaffected'},{at:'1.4',status:'affected'}]}];
 for(const [v,want] of [['1.1',true],['1.2',false],['1.3',false],['1.4',true],['2.0',false]])assert.equal(match(r,'ch.qos.logback:logback-core',v).length>0,want,v);
});
test('live fetch, persistent cache and offline enrichment retain full native data',async()=>{
 let calls=0;
 const record=await nvd.fetchOne(raw.id,{fetcher:async()=>{calls++;return Response.json({vulnerabilities:[{cve:raw}]});},mirror:false});
 assert.deepEqual(record.affected,raw.affected);
 assert.deepEqual(nvd.readCache(raw.id).affected,raw.affected);
 const bindings=[{bindingOnly:true,source:'osv',cve:{id:raw.id}}];
 await nvd.enrichMatches(bindings,{offline:true,fetcher:()=>{throw Error('offline network');}});
 const d=dep('ch.qos.logback:logback-core','1.2.2');
 assert.equal(matchNvdAffected(new Map([[d.coordKey,d]]),bindings).length,1);assert.equal(calls,1);
 const bulk=require('../lib/nvd-bulk'),writer=bulk.createWriter(nvd.NVD_CACHE_DIR,Date.now());
 writer.add(raw.id,record);writer.finish();
 assert.deepEqual(bulk.readBulk(nvd.NVD_CACHE_DIR,raw.id).body.affected,raw.affected);
});
test('an exact stored package binding needs no curated CPE entry for native NVD lookup',()=>{
 const d=dep('example:unmapped','1.0');
 const store={getPackageRecords:()=>[{source:'osv',document:{id:'GHSA-aaaa-bbbb-cccc',aliases:[raw.id],affected:[{package:{ecosystem:'Maven',name:'example:unmapped'}}]}}]};
 assert.equal(collectPackageNvdBindings(new Map([[d.coordKey,d]]),store).length,1);
});
