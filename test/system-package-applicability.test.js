'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {sourceOnlyReason,reconcileSystemFindings}=require('../lib/system-inventory/package-applicability');
const dep={ecosystem:'system',manager:'dpkg',packageType:'deb',name:'linux-libc-dev',sourceName:'linux',sourceVersion:'4.19.67-2+deb10u2',version:'4.19.67-2+deb10u2',distribution:{id:'debian',versionId:'10',codename:'buster'}};
const match={dep,source:'debian-security-tracker-history',cve:{id:'CVE-2021-3493',historicalEvidence:{scope:'inherited-source-note'}}};
const ubuntu={cveMetadata:{state:'PUBLISHED'},containers:{cna:{affected:[{vendor:'Ubuntu',product:'linux kernel',versions:[]}]}}};
test('Ubuntu-specific source inference cannot certify a Debian binary as vulnerable',()=>{
 assert.equal(sourceOnlyReason({...match,dep:{...dep,name:'linux-image-4.19.0'}},ubuntu).code,'different-package-distribution');
 assert.equal(sourceOnlyReason({...match,dep:{...dep,name:'linux-image-4.19.0'},cve:{historicalEvidence:{scope:'release-specific'}}},ubuntu),null);
});
test('kernel header source association does not claim the installed kernel is vulnerable',()=>{
 assert.equal(sourceOnlyReason(match,null).code,'kernel-headers-source-association');
 assert.equal(sourceOnlyReason({...match,dep:{...dep,name:'linux-image-4.19.0'}},null),null);
 const explicit={cveMetadata:{state:'PUBLISHED'},containers:{cna:{affected:[{product:'linux-libc-dev'}]}}};
 assert.equal(sourceOnlyReason(match,explicit),null);
 assert.equal(sourceOnlyReason({...match,dep:{...dep,name:'libssl3',sourceName:'openssl'}},null),null);
});
test('source-level evidence is retained outside confirmed binary findings',()=>{
 const result=reconcileSystemFindings([match],{getRecord:()=>({document:ubuntu})});
 assert.deepEqual(result.matches,[]);assert.equal(result.observations[0].cveId,match.cve.id);
 assert.equal(result.observations[0].status,'source-package-only');
});
