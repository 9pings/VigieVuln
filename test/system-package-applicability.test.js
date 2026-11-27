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
test('the installed distribution\'s own advisory is not withdrawn by a CNA record naming another vendor',()=>{
 // CVE-2026-3497: the CNA (Canonical) lists Ubuntu's OpenSSH builds; Debian tracks the same patch for bookworm.
 const openssh={...dep,name:'openssh-server',sourceName:'openssh',sourceVersion:'1:9.2p1-2+deb12u2',version:'1:9.2p1-2+deb12u2',distribution:{id:'debian',versionId:'12',codename:'bookworm'}};
 const own={dep:openssh,source:'osv',cve:{id:'CVE-2026-3497',sourceAdvisoryId:'DEBIAN-CVE-2026-3497',distributionAdvisory:{source:'Debian',release:'Debian:12'}}};
 assert.equal(sourceOnlyReason(own,ubuntu),null);
 assert.equal(reconcileSystemFindings([own],{getRecord:()=>({document:ubuntu})}).matches.length,1);
 const inferred={dep:openssh,source:'cveproject',cve:{id:'CVE-2026-3497'}};
 assert.equal(sourceOnlyReason(inferred,ubuntu).code,'different-package-distribution','without the distribution\'s own statement the vendor scope still holds');
});
