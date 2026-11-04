'use strict';
const {test}=require('node:test'), assert=require('node:assert/strict');
const {needsMavenReview}=require('../lib/coverage-diagnostics');
const dep={groupId:'org.example',artifactId:'demo',version:'3.0.0'};
const candidate=evidence=>({dep,cve:{id:'CVE-2026-12345',coordinateEvidence:evidence}});
const doc=(fixed='2.0.0')=>({id:'GHSA-test',aliases:['CVE-2026-12345'],affected:[{package:{ecosystem:'Maven',name:'org.example:demo'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed}]}]}]});
const store=(fresh,records)=>({getQuery:()=>fresh?{fresh:true}:null,getPackageRecords:()=>records.map(document=>({document}))});
test('only exact Maven candidates without a fresh independent OSV verdict require review',()=>{
 assert.equal(needsMavenReview(candidate('unknown'),store(false,[])),false);
 assert.equal(needsMavenReview(candidate('curated-product'),store(false,[])),false);
 assert.equal(needsMavenReview(candidate('explicit-coordinate'),store(false,[doc()])),true);
 assert.equal(needsMavenReview(candidate('explicit-coordinate'),store(true,[])),true);
 assert.equal(needsMavenReview(candidate('explicit-coordinate'),store(true,[doc()])),false);
 assert.equal(needsMavenReview(candidate('curated-module'),store(true,[doc('4.0.0')])),false);
 assert.equal(needsMavenReview(candidate('explicit-coordinate'),store(true,[doc(),doc('4.0.0')])),true);
 const other={...doc(),aliases:['CVE-2026-99999']};
 assert.equal(needsMavenReview(candidate('explicit-coordinate'),store(true,[other])),true);
});
