'use strict';

// Informational observations describe the chosen scan context, not failed work.
// Keep them available for provenance without counting them as alerts or gaps.
const isInformational = diagnostic => diagnostic?.severity === 'info' || (!diagnostic?.severity &&
 (diagnostic?.informational === true || diagnostic?.reason === 'image-content-unverified'));
function partitionDiagnostics(diagnostics = []) {
 const warnings = [], notices = [];
 for (const diagnostic of diagnostics) (isInformational(diagnostic) ? notices : warnings).push(diagnostic);
 return {warnings, notices};
}
// A comparison can be indeterminate even after every requested record arrived.
// Keep the candidates for review without describing this as a retrieval failure.
function advisoryEvidenceDiagnostic(values = []) {
 const records = new Map();
 for (const value of values) {
  const name=value.package || value.name || '', key=JSON.stringify([value.artifactTargetId||'',value.id||'',name,value.version||'']);
  if(!records.has(key))records.set(key,{...value,name});
 }
 const items=[...records.values()].map(v=>({id:[v.id,v.name && `${v.name}@${v.version||'?'}`].filter(Boolean).join(' · '),
  ...(v.artifactTargetId?{artifactTargetId:v.artifactTargetId}:{}),detail:v.reason || 'Available advisory data does not establish whether this version is affected.'}));
 return {type:'advisory-evidence',severity:'info',affectsCompleteness:false,affectsAssessment:true,count:items.length,items,
  message:`${items.length} advisory package/version comparison(s) remain undecidable with the available data; no affected or unaffected verdict is inferred.`};
}
module.exports = {isInformational, partitionDiagnostics, advisoryEvidenceDiagnostic};
