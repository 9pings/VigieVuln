'use strict';
// A related upstream CVE is evidence about that CVE, not an alias or a
// package-level applicability assertion for every issue in an advisory.
function relatedRisk(cve, sourceField) {
 return cve?.riskEvidence?.relationship === 'upstream' && cve?.[sourceField] === cve.riskEvidence.source;
}
function relatedSignal(cve, field) {
 const evidence=cve?.[field+'Evidence'];
 if(evidence?.relationship)return evidence.relationship==='upstream';
 const own=[cve?.id,...(cve?.aliases||[])].some(id=>typeof id==='string' && /^CVE-\d{4}-\d{4,}$/i.test(id));
 return !own && (cve?.upstream||[]).some(id=>typeof id==='string' && /^CVE-\d{4}-\d{4,}$/i.test(id));
}
function evidenceObject(cve) {
 return { ...(cve?.riskEvidence?{risk:cve.riskEvidence}:{}),...(cve?.nvdEvidence?.records?.length?{nvd:cve.nvdEvidence.records}:{}),
  ...(cve?.cveEvidence?.length?{cves:cve.cveEvidence}:{}),...(cve?.euvdDetails?{euvd:cve.euvdDetails}:{}),...(cve?.kevEvidence?{kev:cve.kevEvidence}:{}),...(cve?.epssEvidence?{epss:cve.epssEvidence}:{}),
  ...(cve?.upstream?.length?{upstream:cve.upstream}:{}),...(cve?.related?.length?{related:cve.related}:{}) };
}
module.exports={relatedRisk,relatedSignal,evidenceObject};
