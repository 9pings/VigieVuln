'use strict';
// Scan registry images referenced by source definitions without executing them.
// This layer reuses the existing OCI acquisition and inventory cache; source
// declarations are attached only after acquisition so cached inventories
// never acquire another project's paths.
const {parseReference}=require('./registry');
const {acquireInventories,assessInventories}=require('../artifacts/scan');

function declaration(ref,digest){return {id:ref.id,path:ref.path,line:ref.line??null,location:ref.location??null,declared:ref.declared,
 reference:ref.reference,role:ref.role,stage:ref.stage??null,stageName:ref.stageName??null,finalStage:ref.finalStage??null,
 digest:digest||null,binding:'registry-reference-resolution'};}
function eligible(ref){return ref?.scanEligible!==false && (!ref?.classification||ref.classification==='registry') && typeof ref.reference==='string' && !ref.unresolved?.length;}
async function scanSourceImages(input,options={}){
 const references=(input||[]).map(ref=>({...ref,boundArtifactIds:[]})),warnings=[],notices=[],empty={artifacts:[],matches:[],resolvedDeps:new Map(),warnings,notices,references};
 if(options.images===false)return empty;
 warnings.push(...require('./references').unpinnedImageWarnings(references));
 const groups=new Map();
 for(const ref of references){
  if(!eligible(ref)){ref.scanStatus='not-scannable';ref.imageScan={status:'not-scannable',reasonCode:ref.classification||'unresolved',message:ref.blockReason||'The image declaration cannot be resolved to a registry image.',artifactIds:[]};continue;}
  try{const parsed=parseReference(ref.reference),platform=ref.platform||options.rootImagePlatform||options.platform||'linux/amd64',key=JSON.stringify([parsed.registry,parsed.repository,parsed.reference,platform]);
   ref.platform=platform;if(!groups.has(key))groups.set(key,{reference:ref.reference,platform,refs:[]});groups.get(key).refs.push(ref);
  }catch(error){ref.scanStatus='failed';ref.scanReason=error.message;ref.imageScan={status:'failed',reasonCode:'invalid-image-reference',message:error.message,artifactIds:[]};warnings.push({type:'image-scan-failed',capability:'inventory',reason:'invalid-image-reference',manifestPath:ref.path,message:`Image reference in ${ref.path||'source'} could not be parsed: ${error.message}`});}
 }
 const targets=new Map();
 let completed=0;
 for(const group of groups.values()){
  options.onImageProgress?.({phase:'acquiring',reference:group.reference,completed,total:groups.size});
  try{
   const acquired=await (options.sourceImageAcquire||acquireInventories)(group.reference,{...options,registry:true,inventory:false,sbom:false,...(group.platform?{platform:group.platform}:{})});
   if(!Array.isArray(acquired)||!acquired.length)throw Error('image inventory is empty');
   for(const item of acquired){const target=targets.get(item.id)||item;target.metadata||={};target.metadata.definitions||=[];
    for(const ref of group.refs){if(!ref.boundArtifactIds.includes(target.id))ref.boundArtifactIds.push(target.id);ref.scanStatus='inventoried';ref.imageScan={status:'inventoried',reasonCode:null,message:null,artifactIds:ref.boundArtifactIds};ref.contentVerified=true;ref.evidence='registry-inventory';
     const d=declaration(ref,target.metadata.digest||target.metadata.acquisition?.resolvedDigest);if(!target.metadata.definitions.some(existing=>existing.id===d.id))target.metadata.definitions.push(d);}
    targets.set(target.id,target);
   }
  }catch(error){if(options.signal?.aborted)throw error;for(const ref of group.refs){ref.scanStatus='failed';ref.scanReason=error.message;ref.imageScan={status:'failed',reasonCode:options.offline?'offline-image-inventory-unavailable':'image-acquisition-failed',message:error.message,artifactIds:[]};}
   const list=warnings,code=options.offline?'offline-image-inventory-unavailable':'image-acquisition-failed',http=/HTTP\s+(\d{3})/i.exec(error.message),cause=http?`HTTP ${http[1]}`:error.message;let diagnostic=list.find(w=>w.reason===code && w.cause===cause);if(!diagnostic){diagnostic={type:'image-scan-failed',capability:'inventory',reason:code,cause,references:[],items:[],count:0,_groupedDiagnostics:true,message:options.offline?'Required image inventory was not prepared or imported into the offline cache.':`Image acquisition failed: ${cause}`};list.push(diagnostic);}diagnostic.references.push(group.reference);diagnostic.items.push(...group.refs.map(ref=>({id:ref.reference,manifestPaths:ref.path?[ref.path]:[]})));diagnostic.count=diagnostic.items.length;}
  completed++;options.onImageProgress?.({phase:'acquired',reference:group.reference,completed,total:groups.size});
 }
 if(!targets.size)return empty;
 const artifacts=[],matches=[],resolvedDeps=new Map();
 let assessedCount=0;
 for(const target of targets.values()){
  const progress={artifactTargetId:target.id,reference:target.metadata?.acquisition?.reference || target.metadata?.definitions?.[0]?.reference || target.id,completed:assessedCount,total:targets.size};
  const reportProgress=detail=>options.onImageProgress?.({...progress,phase:'assessing',...detail});
  reportProgress({});
  const assessmentOptions={...options,onArtifactProgress:event=>{options.onArtifactProgress?.(event);reportProgress({stage:event.stage,processed:event.completed,items:event.total});},onEnrichmentProgress:event=>{options.onEnrichmentProgress?.(event);reportProgress({stage:event.source,processed:event.completed,items:event.total});}};
  try{const assessed=await (options.sourceImageAssess||assessInventories)([target],assessmentOptions);artifacts.push(...(assessed.artifacts||[]));matches.push(...(assessed.cveMatches||[]));for(const [key,value] of assessed.resolvedDeps||[])resolvedDeps.set(key,value);warnings.push(...(assessed.warnings||[]));notices.push(...(assessed.notices||[]));
   for(const ref of references)if(ref.boundArtifactIds.includes(target.id)){ref.scanStatus='scanned';ref.imageScan={...ref.imageScan,status:'scanned'};}
  }catch(error){if(options.signal?.aborted)throw error;warnings.push({type:'image-scan-failed',capability:'advisories',reason:'image-assessment-failed',artifactTargetId:target.id,message:`Image advisory assessment failed: ${error.message}`});
   artifacts.push({id:target.id,kind:target.kind,metadata:target.metadata,evidence:target.evidence,distribution:target.distribution,inventoryAt:target.inventoryAt,componentCount:target.deps?.length||0,components:target.deps||[],coverage:[...(target.coverage||[]),{artifactTargetId:target.id,capability:'advisories',collector:'image-assessment',execution:'failed',result:'indeterminate',reason:error.message}]});
   for(const ref of references)if(ref.boundArtifactIds.includes(target.id)){ref.scanStatus='assessment-failed';ref.scanReason=error.message;ref.imageScan={...ref.imageScan,status:'assessment-failed',reasonCode:'image-assessment-failed',message:error.message};}
  }
  assessedCount++;options.onImageProgress?.({...progress,phase:'assessed',completed:assessedCount});
 }
 return {artifacts,matches,resolvedDeps,warnings,notices,references};
}
module.exports={scanSourceImages};
