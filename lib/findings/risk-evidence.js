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
// Exported with every vulnerability (SBOM property, SARIF result, CSAF note): it carries the
// identifiers and scores that justify a rating, not the advisory texts. Descriptions,
// reference lists and CWE names stay on the vulnerability entry itself; embedding them here
// again made one kernel announcement weigh 5 MB in a CycloneDX document.
const brief=record=>{if(!record||typeof record!=='object')return record;const {description,references,cwes,...rest}=record;return rest;};
const withoutDescription=record=>{if(!record||typeof record!=='object')return record;const {description,...rest}=record;return rest;};
function evidenceObject(cve) {
 return { ...(cve?.riskEvidence?{risk:cve.riskEvidence}:{}),...(cve?.nvdEvidence?.records?.length?{nvd:cve.nvdEvidence.records.map(brief)}:{}),
  ...(cve?.cveEvidence?.length?{cves:cve.cveEvidence.map(e=>e?{...e,...(e.euvdDetails?{euvdDetails:brief(e.euvdDetails)}:{}),...(Array.isArray(e.certfr)?{certfr:e.certfr.map(a=>a?.ref||a)}:{})}:e)}:{}),...(cve?.euvdDetails?{euvd:withoutDescription(cve.euvdDetails)}:{}),...(cve?.kevEvidence?{kev:cve.kevEvidence}:{}),...(cve?.epssEvidence?{epss:cve.epssEvidence}:{}),
  ...(cve?.upstream?.length?{upstream:cve.upstream}:{}),...(cve?.related?.length?{related:cve.related}:{}) };
}
module.exports={relatedRisk,relatedSignal,evidenceObject};
