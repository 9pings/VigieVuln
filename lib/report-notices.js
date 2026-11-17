'use strict';
const {isInformational}=require('./diagnostics');
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
// Group causes for presentation, retaining every distinct location and detail.
// Raw diagnostics remain available in JSON; unrelated causes never collapse
// merely because they share a broad warning type.
function groupReportWarnings(values=[]) {
 const groups=new Map(),out=[];
 for(const item of values) {
  if(item._groupedDiagnostics){out.push(item);continue;}
  const perManifest=item.type==='no-lockfile'||item.type==='parse-error';
  const cause=perManifest ? null : item.reason||item.code||item.message;
  const key=JSON.stringify([item.type,item.severity,item.source||item.sourceId,item.capability,item.applicationId,cause,item.cause,item.status,item.refreshFailure]);
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
  return {...first,artifactTargetIds:[...new Set(group.map(w=>w.artifactTargetId).filter(Boolean))],message:messages.size===1?first.message:'',count:group.reduce((n,w)=>n+(w.count||1),0),items,_groupedDiagnostics:true};
 });
}
module.exports={legacyFreshness,partitionReportNotices,groupReportWarnings};
