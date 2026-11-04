'use strict';

// A product-name candidate does not establish package identity. An exact Maven
// candidate is actionable unless a fresh, independently identified OSV record
// gives a definite, consistent answer for that same CVE and package/version.
function needsMavenReview(candidate, store, {ttlMs} = {}) {
 const evidence=candidate?.cve?.coordinateEvidence;
 if (!['explicit-coordinate','curated-module'].includes(evidence)) return false;
 const dep=candidate.dep || {}, name=`${dep.groupId}:${dep.artifactId}`;
 const id=candidate.cve?.id,version=String(dep.version || '');
 if(!id || !dep.groupId || !dep.artifactId || !version) return true;
 const query=store.getQuery({source:'osv',ecosystem:'Maven',name,version},{ttlMs});
 if(!query?.fresh) return true;
 const records=store.getPackageRecords('Maven',name,{source:'osv'}).filter(r=>{
  const d=r.document;
  return !r.withdrawnAt && !d?.withdrawn && [d?.id,...(d?.aliases || [])].includes(id);
 });
 if(!records.length) return true;
 const {vulnVerdict}=require('./osv-db');
 const verdicts=records.map(({document})=>{
  const affected=(document.affected || []).filter(a=>a?.package?.ecosystem==='Maven' && a.package.name===name);
  return affected.length ? vulnVerdict(version,{...document,affected},'Maven') : null;
 });
 return verdicts.some(v=>v===null) || verdicts.some(v=>v!==verdicts[0]);
}
module.exports={needsMavenReview};
