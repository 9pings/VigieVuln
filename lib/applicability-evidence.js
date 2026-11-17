'use strict';
// Preserve independent applicability proofs when sources describe one finding.
function applicabilityEvidence(...records){
 const proofs=new Map();
 for(const c of records){
  for(const item of [...(c?.applicabilityEvidence||[]),...['historical','vendor','publisher'].flatMap(kind=>c?.[kind+'Evidence']?[{kind,evidence:c[kind+'Evidence']}]:[])]){
   if(item && typeof item.kind==='string' && item.evidence && typeof item.evidence==='object')proofs.set(JSON.stringify(item),item);
  }
 }
 return [...proofs.values()];
}
module.exports={applicabilityEvidence};
