'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {assessDistributionSources}=require('../lib/system-inventory/distribution-sources');

// A workstation with 3 300 packages produced several hundred thousand tracker assessments:
// appending them with a spread call overflowed the stack and the whole source was lost.
test('a distribution source returning several hundred thousand assessments is kept',async()=>{
 const dep={name:'linux-image',version:'6.1',sourceName:'linux',sourceVersion:'6.1',manager:'dpkg'};
 const assessments=Array.from({length:400000},(_,n)=>({dep,cveId:`CVE-2024-${100000+n}`,source:'bulk',status:'fixed',evidence:{}}));
 const adapter={id:'bulk',supports:()=>true,assess:async()=>({matches:[],observations:[],coverage:[{source:'bulk',execution:'completed',result:'consulted'}],warnings:[],assessments})};
 const result=await assessDistributionSources({distribution:{id:'debian',versionId:'13',codename:'trixie'},packages:[dep]},{distributionSourceAdapters:[adapter]});
 assert.deepEqual(result.warnings,[]);
 assert.equal(result.coverage.find(c=>c.source==='bulk').execution,'completed');
});
