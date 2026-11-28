'use strict';
const {isInformational}=require('../scan/diagnostics');
// Older data did not mark ordinary cached observations as informational. Only
// this exact dated, neutral wording is a compatibility notice; refresh failures,
// stale/unknown-age data and explicit warning severities remain warnings.
function legacyFreshness(w){
 if(w?.severity && w.severity!=='info')return null;
 if(w?.type!=='source-stale' || typeof w.message!=='string')return null;
 const match=/^([A-Za-z][\w.-]*): cached data from (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) was used\.$/.exec(w.message);
 return match ? {source:match[1],at:match[2],message:w.message}:null;
}
function partitionReportNotices(values=[]){
 const warnings=[],notices=[],freshness=[];
 for(const item of values){
  if(isInformational(item)){notices.push(item);continue;}
  const legacy=legacyFreshness(item);if(legacy){freshness.push(legacy);continue;}
  warnings.push(item);
 }
 return {warnings,notices,freshness};
}
// The CVE-record enrichment summary is shared across scans, even when its
// underlying records include image findings. All other image diagnostics are
// identified by their explicit image identity or image-specific type.
function warningScope(item,systemIds) {
 if(item?.type==='cve-enrichment-summary')return 'global';
 const ids=item?.artifactTargetIds?.length ? item.artifactTargetIds : [item?.artifactTargetId];
 if(systemIds && ids.every(id=>systemIds.has(id)) && !['image-scan-failed','image-unpinned','image-source-unavailable'].includes(item.type))return 'system';
 if(item?.artifactTargetId || item?.artifactTargetIds?.length || item?.type==='image-unpinned' || item?.type==='image-source-unavailable' || item?.type==='image-scan-failed')return 'image';
 return 'project';
}
// Group causes for presentation, retaining every distinct location and detail.
// Raw diagnostics remain available in JSON; unrelated causes never collapse
// merely because they share a broad warning type.
function groupReportWarnings(values=[],systemIds) {
 const imageIssues=[],other=[];
 for(const w of values) {
  if(w.type==='image-source-unavailable')imageIssues.push(...(w.diagnostics||[w]));
  else if(w.type==='image-scan-failed' || (warningScope(w,systemIds)==='image' && ['source-unavailable','source-stale','osv-coverage'].includes(w.type)))imageIssues.push(w);
  else other.push(w);
 }
 if(imageIssues.length){
  const byImage=new Map();
  for(const w of imageIssues){
   const entries=w.items?.length?w.items:w.artifactTargetIds?.length?w.artifactTargetIds.map(id=>({id,artifactTargetId:id})):[{id:w.artifactTargetId||w.manifestPath||w.source||'',...(w.artifactTargetId?{artifactTargetId:w.artifactTargetId}:{}),...(w.manifestPath&&!w.artifactTargetId?{pathItem:true}:{})}];
   for(const entry of entries){
    const item={...(typeof entry==='string'?{id:entry}:entry)};
    if(w.artifactTargetId)item.artifactTargetId ||= w.artifactTargetId;
    const key=item.artifactTargetId||item.id;
    if(!byImage.has(key))byImage.set(key,{...item,id:key,details:new Set(),paths:new Set(),resources:new Set()});
    const image=byImage.get(key);
    image.details.add([w.source,item.detail||w.message].filter(Boolean).join(': '));
    for(const path of item.manifestPaths||[])image.paths.add(path);
    if(item.artifactTargetId && item.id!==key)image.resources.add(item.id);
   }
  }
  const items=[...byImage.values()].map(({details,paths,resources,...item})=>({...item,detail:[...details].join('; '),manifestPaths:[...paths],resources:[...resources]}));
  other.push({type:'image-source-unavailable',count:items.length,items,diagnostics:imageIssues,artifactTargetIds:[...new Set(items.map(x=>x.artifactTargetId).filter(Boolean))],
   affectsCompleteness:imageIssues.some(w=>w.affectsCompleteness!==false),
   message:'Some images or their advisory data are unavailable from public sources. See the affected images and reasons below.',_groupedDiagnostics:true});
 }
 values=other;
 const groups=new Map(),out=[];
 for(const item of values) {
  if(item._groupedDiagnostics){out.push(item);continue;}
  const perManifest=item.type==='no-lockfile'||item.type==='parse-error';
  const cause=perManifest ? null : item.reason||item.code||item.message;
  const key=JSON.stringify([warningScope(item,systemIds),item.type,item.severity,item.source||item.sourceId,item.capability,item.applicationId,cause,item.cause,item.status,item.refreshFailure]);
  if(!groups.has(key)){const group=[];groups.set(key,group);out.push(group);}
  groups.get(key).push(item);
 }
 return out.map(group=>{
  if(!Array.isArray(group))return group;
  if(group.length===1)return group[0];
  const messages=new Set(group.map(w=>w.message||'')),items=[],seen=new Set();
  for(const w of group){
   const entries=[...(w.items||[])];
   if(w.manifestPath||w.path||w.artifactTargetId||messages.size>1)entries.unshift({id:w.manifestPath||w.path||w.artifactId||w.artifactTargetId||'',...(w.artifactTargetId?{artifactTargetId:w.artifactTargetId,...((w.manifestPath||w.path)?{manifestPaths:[w.manifestPath||w.path]}:{})}:{}),...((w.manifestPath||w.path)?{pathItem:true}:{}),...(messages.size>1?{detail:w.message||''}:{})});
   for(const entry of entries){const key=JSON.stringify(entry);if(!seen.has(key)){seen.add(key);items.push(entry);}}
  }
  const {manifestPath,path,artifactTargetId,...first}=group[0];
  return {...first,artifactTargetIds:[...new Set(group.flatMap(w=>[w.artifactTargetId,...(w.artifactTargetIds||[])]).filter(Boolean))],message:messages.size===1?first.message:'',count:group.reduce((n,w)=>n+(w.count||1),0),items,_groupedDiagnostics:true};
 });
}
module.exports={legacyFreshness,partitionReportNotices,groupReportWarnings,warningScope};
