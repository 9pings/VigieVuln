'use strict';

const headerPackages = {
 deb:/^linux-(?:libc-dev|headers(?:-|$))/,
 apk:/^linux-headers$/,
 rpm:/^kernel-(?:headers|devel)(?:-|$)/,
};
const distributions = new Map([
 ['ubuntu','ubuntu'],['debian','debian'],['alpine linux','alpine'],
 ['red hat enterprise linux','rhel'],['suse linux enterprise','sles'],
]);

function sourceOnlyReason(match, record) {
 const dep=match.dep,manager=dep?.packageType || ({dpkg:'deb',apk:'apk',rpm:'rpm'})[dep?.manager];
 if(dep?.ecosystem!=='system')return null;
 const affected=record?.cveMetadata?.state==='PUBLISHED' ? record.containers?.cna?.affected || [] : [];
 // Distribution identity describes the package implementation and its patches.
 // It is independent of the runtime prerequisites assumed by the CPE policy.
 const declared=affected.map(a=>distributions.get(String(a.vendor||'').toLowerCase()));
 const installed=dep.distribution?.id;
 const releaseProof=match.cve?.historicalEvidence?.scope==='release-specific' || match.cve?.vendorEvidence;
 if(installed && declared.length && declared.every(Boolean) && !declared.includes(installed) && !releaseProof)
  return {code:'different-package-distribution',message:'The advisory identifies '+[...new Set(declared)].join(', ')+' packages; the installed package is from '+installed+'.'};
 if(!headerPackages[manager]?.test(dep.name||''))return null;
 const explicit=affected.some(a=>[a.packageName,a.product].includes(dep.name));
 if(explicit)return null;
 return {code:'kernel-headers-source-association',message:'The installed package supplies kernel development headers. A source-package kernel advisory alone does not identify vulnerable executable code in these headers.'};
}

function reconcileSystemFindings(matches,store) {
 const accepted=[],observations=[],records=new Map();
 for(const match of matches){
  if(match.dep?.ecosystem!=='system'){accepted.push(match);continue;}
  const ids=[...new Set([match.cve?.id,...(match.cve?.upstream||[]),...(match.cve?.aliases||[])].filter(id=>/^CVE-\d{4}-\d+$/.test(id||'')))];
  let reason;
  if(ids.length===1){
   const id=ids[0];
   if(!records.has(id))records.set(id,store.getRecord('cveproject',id)?.document);
   reason=sourceOnlyReason(match,records.get(id));
  }else reason=sourceOnlyReason(match,null);
  if(!reason){accepted.push(match);continue;}
  observations.push({dep:match.dep,cveId:match.cve.id,source:match.source,status:'source-package-only',reason:reason.message,
   evidence:{code:reason.code,distribution:match.dep.distribution,sourceName:match.dep.sourceName,sourceVersion:match.dep.sourceVersion,
    historicalEvidence:match.cve.historicalEvidence || null,sourceAdvisoryId:match.cve.sourceAdvisoryId || match.advisoryId || null}});
 }
 return {matches:accepted,observations};
}
module.exports={sourceOnlyReason,reconcileSystemFindings};
