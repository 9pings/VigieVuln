'use strict';
const {createCacheRepository}=require('../cache-repository');
// Each adapter owns its scope, comparisons and evidence. Failed consultations
// never prevent the independent adapters or OSV from returning their results.
const adapters=[
 {id:'nginx-vendor-advisories',supports:(d,inventory)=>inventory?.packages?.some(require('./nginx-advisories').isNginxPackage),identifyPackageOrigin:(pkg,options)=>require('./nginx-advisories').nginxPackageOrigin(pkg,options),async assess(inventory,options){return require('./nginx-advisories').assessNginxAdvisories(inventory.packages,options);}},
 {id:'debian-security-tracker-history',supports:d=>d?.id==='debian',async assess(inventory,options){
  const source=require('./historical-debian');
  try{source.checkDistribution(inventory.distribution);}catch{return {matches:[],observations:[],warnings:[],coverage:[{source:this.id,execution:'not-applicable',result:'indeterminate',reason:'Exact Debian release codename is unavailable.'}]};}
  const repository=options.repository||createCacheRepository(options.cacheDir);
  const packages=[...new Set(inventory.packages.map(p=>p.sourceName).filter(Boolean))].sort();
  if(!packages.length)return {matches:[],observations:[],warnings:[],coverage:[{source:this.id,execution:'not-applicable',result:'indeterminate',reason:'Source package identities are unavailable.'}]};
  const d=inventory.distribution,ns=`system-debian-history:${String(d.versionId).split('.')[0]}:${d.codename}`,snapshot=repository.getSnapshot(ns);
  const lifecycle=repository.get('catalogue',`freexian-lifecycle-${String(d.versionId).split('.')[0]}-${d.codename}`)?.value;
  if(!snapshot && options.offline && Date.parse(lifecycle?.cutoff+'T23:59:59Z')>Date.now())
   return {matches:[],observations:[],warnings:[],coverage:[{source:this.id,execution:'not-applicable',result:'not-applicable',reason:'Release has not reached its historical cutoff.'}]};
  let failure=null;
  if(!options.offline && (!snapshot || snapshot.metadata?.parserVersion!==source.PARSER_VERSION || options.refresh || (!snapshot.complete && packages.some(p=>!snapshot.metadata?.queriedPackages?.includes(p))))){
   try{const result=await source.syncHistoricalDebian(d,{...options,repository,packages});if(result.notApplicable)return {matches:[],observations:[],warnings:[],coverage:[{source:this.id,execution:'not-applicable',result:'not-applicable',reason:result.reason}]};}
   catch(error){failure={type:'source-unavailable',source:this.id,message:`Debian historical source consultation failed: ${error.message}`};}
  }
  const result=source.assessHistoricalDebian(inventory,{...options,repository});
  if(failure){result.warnings=[...(result.warnings||[]),failure];result.coverage=result.coverage.map(c=>({...c,execution:'partial',reason:failure.message}));}
  return result;
 }},
 {id:'freexian-ela',operatorRegion:'eu',supports:d=>d?.id==='debian',async assess(inventory,options){return require('./freexian-ela').assessFreexianEla(inventory,options);}},
 {id:'freexian-tracker',operatorRegion:'eu',supports:d=>d?.id==='debian',async assess(inventory,options){return require('./freexian-tracker').assessFreexianTracker(inventory,options);},async refine(result,inventory,options){return refineFreexianEvidence(result,inventory,options);}},
 {id:'debian-security-tracker-current-candidates',supports:d=>d?.id==='debian',async assess(inventory,options){return require('./current-debian').assessCurrentDebianCandidates(inventory,options);}},
 {id:'alpine-tracker',supports:d=>d?.id==='alpine',async assess(inventory,options){
  const result=await require('./alpine-tracker').assessAlpineTracker(inventory.packages,inventory.distribution,options);
  return {matches:[],observations:result.observations,coverage:[result.coverage],warnings:result.diagnostics.map(d=>({type:'source-unavailable',source:this.id,code:d.code,...(d.code==='record-not-listed'?{affectsCompleteness:false}:{}),items:(d.resources||[]).map(id=>({id})),message:d.reason}))};
 }},
];
async function assessDistributionSources(inventory,options={}){
 const result={matches:[],observations:[],coverage:[],warnings:[],assessments:[]};
 if(options.distroAdvisories===false)return result;
 const active=[];
 for(const adapter of options.distributionSourceAdapters||adapters){
  if(!adapter || typeof adapter.id!=='string' || typeof adapter.supports!=='function'||typeof adapter.assess!=='function')throw Error('Invalid distribution source adapter');
  if(!adapter.supports(inventory.distribution,inventory))continue;
  if(['eu','us'].includes(options.distributionSourceRegion) && adapter.operatorRegion!==options.distributionSourceRegion){result.coverage.push({source:adapter.id,execution:'not-applicable',result:'not-consulted',expected:false,reason:'Source operator is outside the selected region or its region is not established.'});continue;}
  active.push(adapter);
  try{const answer=await adapter.assess(inventory,{...options,confirmedMatches:[...(options.confirmedMatches||[]),...result.matches]});for(const key of Object.keys(result))result[key].push(...(answer[key]||[]));}
  catch(error){result.warnings.push({type:'source-unavailable',source:adapter.id,message:`${adapter.id}: ${error.message}`});result.coverage.push({source:adapter.id,execution:'failed',result:'indeterminate',reason:error.message});}
 }
 for(const adapter of active)if(typeof adapter.refine==='function')try{
  const refined=await adapter.refine(result,inventory,options);if(refined?.assessments)result.assessments=refined.assessments;
  for(const key of ['observations','coverage','warnings'])if(Array.isArray(refined?.[key]))result[key].push(...refined[key]);
 }catch(error){if(options.signal?.aborted || error?.name==='AbortError')throw error;result.warnings.push({type:'source-unavailable',source:adapter.id,message:`${adapter.id} evidence refinement: ${error.message}`});result.coverage.push({source:`${adapter.id}-refinement`,execution:'failed',result:'indeterminate',reason:error.message});}
 return reconcileAssessments(result,inventory,options.confirmedMatches||[]);
}
// Reconcile only records that identify the same distribution, installed source
// and binary occurrence. A release verdict never erases an independent finding.
function assessmentKey(dep,id,distribution){
 if(!dep || !id || !distribution?.id || !distribution.versionId || !distribution.codename || !dep.sourceName || !dep.sourceVersion || !dep.name || !dep.version)return null;
 return JSON.stringify([distribution.id,distribution.versionId,distribution.codename,dep.manager||'',dep.sourceName,dep.sourceVersion,dep.name,dep.version,dep.architecture||'',id]);
}
async function refineFreexianEvidence(result,inventory,options={}){
 const source='freexian-release-evidence',d=inventory.distribution;
 const limit=options.maxFreexianReleaseEvidenceCves??1000;
 if(!Number.isSafeInteger(limit)||limit<0)throw Error('invalid Freexian release evidence CVE limit');
 const concurrency=options.freexianReleaseConcurrency??3,interval=options.freexianReleaseIntervalMs??3000;
 if(!Number.isSafeInteger(concurrency)||concurrency<1||!Number.isSafeInteger(interval)||interval<0)throw Error('invalid Freexian release evidence concurrency or pacing');
 const keys=new Set(result.observations.filter(o=>o.source==='debian-security-tracker-current-candidates').map(o=>assessmentKey(o.dep,o.cveId||o.id,d)).filter(Boolean));
 const selected=(result.assessments||[]).filter(a=>a.source==='freexian-tracker' && a.status==='unknown' && keys.has(assessmentKey(a.dep,a.cveId,d)) && a.evidence?.distribution?.id===d?.id && a.evidence?.distribution?.versionId===d?.versionId && a.evidence?.distribution?.codename===d?.codename && a.evidence?.sourceName===a.dep?.sourceName && a.evidence?.sourceVersion===a.dep?.sourceVersion);
 if(!selected.length)return {coverage:[{source,execution:'not-applicable',result:'not-applicable',reason:'No matching indeterminate release assessments.'}]};
 const ids=[...new Set(selected.map(a=>a.cveId))],allowed=new Set(ids.slice(0,limit)),groups=new Map();
 for(const a of selected){if(!allowed.has(a.cveId))continue;const key=JSON.stringify([a.cveId,a.dep.sourceName,a.dep.sourceVersion]);const group=groups.get(key)||[];group.push(a);groups.set(key,group);}
 const byId=new Map();for(const group of groups.values()){const id=group[0].cveId,items=byId.get(id)||[];items.push(group);byId.set(id,items);}
 const limiter=options.freexianReleaseThrottle||require('../proxy-throttle').createProxyThrottle({intervalMs:interval,maxWaitMs:45000,maxRateRetries:15});
 const resolverOptions={...options,freexianReleaseThrottle:limiter};
 const resolve=options.resolveReleaseEvidence||require('./freexian-release-evidence').resolveReleaseEvidence,work=require('p-limit')(concurrency);let failures=0,outages=0,checked=0,resolved=0,cacheOnly=false,cacheOnlyCves=0;const reasons=new Set();
 await Promise.all([...byId.values()].map(groupList=>work(async()=>{
  const afterRateLimit=cacheOnly;
  if(afterRateLimit)cacheOnlyCves++;
  let first=true,failed=false,outage=false;
  for(const group of groupList){const a=group[0];try{
   // One fetch per CVE; subsequent source-package evaluations use the same
   // locally cached page, including when the caller requested a refresh.
   const proof=await resolve({id:a.cveId,sourceName:a.dep.sourceName,sourceVersion:a.dep.sourceVersion,distribution:d},first && !afterRateLimit ? resolverOptions : {...resolverOptions,offline:true});checked++;first=false;
   if(!proof || !['not-affected','fixed','unknown'].includes(proof.status))throw Error('invalid release evidence result');
   if(!options.offline && !cacheOnly && /rate limit|HTTP 429/i.test(proof.evidence?.failure || '')){
    cacheOnly=true;
    options.onSourceWarning?.(options.lang==='fr'
     ? 'Freexian limite les requêtes. Les vérifications Freexian restantes utilisent le cache. L’analyse des autres sources continue.'
     : 'Freexian rate limit reached. Remaining Freexian checks use the cache. Analysis continues with the other sources.');
   }
   if(proof.evidence?.failure){failed=true;if(!options.offline){outage=true;reasons.add(String(proof.evidence.failure).slice(0,300));}}
   const p=proof.evidence||{},pd=p.distribution,exact=p.id===a.cveId && p.sourceName===a.dep.sourceName && p.sourceVersion===a.dep.sourceVersion && pd?.id===d.id && pd.versionId===d.versionId && pd.codename===d.codename;
   for(const row of group){if(proof.status!=='unknown'&&exact){row.status=proof.status;resolved++;}row.evidence={...row.evidence,releaseEvidence:proof.evidence||null};}
  }catch(error){if(options.signal?.aborted || error?.name==='AbortError')throw error;failed=true;first=false;if(!options.offline){outage=true;reasons.add(String(error?.message||'consultation failed').slice(0,300));}}}
  if(failed)failures++;if(outage)outages++;
 })));
 const limited=ids.length>limit,coverage=[{source,execution:failures||limited?'partial':'completed',result:'consulted',candidateCves:ids.length,queriedCves:allowed.size-cacheOnlyCves,checked,resolved,failed:failures,...(cacheOnly?{rateLimitFallback:"cache-only",cacheOnlyCves}:{}),affectsCompleteness:false,affectsAssessment:true,...(limited?{reason:`Additional release evidence considered for ${allowed.size} of ${ids.length} candidate CVEs.`}:{})}];
 const fallback=cacheOnly ? (options.lang==='fr' ? ` Après limitation du débit, ${cacheOnlyCves} CVE vérifiées uniquement dans le cache Freexian.` : ` After rate limiting, ${cacheOnlyCves} CVEs checked only in the Freexian cache.`) : '';
 const warnings=outages?[{type:'source-unavailable',source,message:options.lang==='fr' ?
  `Vérification Freexian partielle pour ${d.id} ${d.versionId} : échec de consultation pour ${outages} CVE. ${[...reasons].slice(0,3).join('; ')}.${fallback}` :`${outages} Freexian release evidence consultation(s) failed: ${[...reasons].slice(0,3).join('; ')}.${fallback}`}]:[];
 return {assessments:result.assessments,coverage,warnings};
}
function reconcileAssessments(result,inventory,existingMatches=[]){
 const d=inventory.distribution,byKey=new Map();
 for(const a of result.assessments||[]){
  const proof=a.evidence||{},dist=proof.distribution;
  if(!dist || dist.id!==d?.id || dist.versionId!==d?.versionId || dist.codename!==d?.codename || proof.sourceName!==a.dep?.sourceName || proof.sourceVersion!==a.dep?.sourceVersion || !['affected','not-affected','fixed','unknown'].includes(a.status))continue;
  const key=assessmentKey(a.dep,a.cveId,d);if(!key)continue;const items=byKey.get(key)||[];items.push(a);byKey.set(key,items);
 }
 const reconciled=new Set();
 result.observations=result.observations.map(item=>{
  if(item.source!=='debian-security-tracker-current-candidates')return item;
  const key=assessmentKey(item.dep,item.cveId||item.id,d),items=byKey.get(key);if(!items?.length)return item;
  reconciled.add(key);const verdicts=[...new Set(items.map(a=>a.status).filter(s=>s!=='unknown'))],status=verdicts.length===1?verdicts[0]:'unknown';
  return {...item,status:status==='affected'?'possible':status,evidence:{...item.evidence,reconciliation:{status,assessments:items.map(({source,status,evidence})=>({source,status,evidence}))}}};
 });
 result.observations=result.observations.filter(item=>item.source!=='freexian-tracker' || !reconciled.has(assessmentKey(item.dep,item.cveId||item.id,d)));
 for(const match of [...existingMatches,...result.matches]){
  const key=assessmentKey(match.dep,match.cve?.id,d),negative=(byKey.get(key)||[]).filter(a=>(a.status==='fixed'||a.status==='not-affected') && a.source!==match.source);
  if(!negative.length)continue;
  const existing=result.observations.find(item=>assessmentKey(item.dep,item.cveId||item.id,d)===key && item.evidence?.reconciliation);
  if(existing){existing.evidence={...existing.evidence,conflictingFinding:true};continue;}
  if(reconciled.has(key))continue;reconciled.add(key);
  const a=negative[0];result.observations.push({dep:a.dep,cveId:a.cveId,source:a.source,status:a.status,sourceUrl:a.evidence.sourceURL,evidence:{...a.evidence,conflictingFinding:true,reconciliation:{status:a.status,assessments:negative.map(({source,status,evidence})=>({source,status,evidence}))}}});
 }
 const confirmed=new Map();
 for(const match of [...existingMatches,...result.matches])for(const id of [match.cve?.id,...(match.cve?.aliases||[])]){const key=assessmentKey(match.dep,id,d);if(key){const list=confirmed.get(key)||[];list.push(match);confirmed.set(key,list);}}
 result.observations=result.observations.filter(item=>{
  if(!['unknown','possible'].includes(item.status) || item.evidence?.conflictingFinding)return true;
  const matches=confirmed.get(assessmentKey(item.dep,item.cveId||item.id,d));if(!matches?.length)return true;
  for(const match of matches){const evidence={source:item.source,status:item.status,reason:item.reason||null,details:item.evidence||{}};match.cve.applicabilityEvidence=require('../applicability-evidence').applicabilityEvidence(match.cve,{applicabilityEvidence:[{kind:'source-observation',evidence}]});}
  return false;
 });
 result.matches=result.matches.map(match=>{
  const key=assessmentKey(match.dep,match.cve?.id,d),negative=(byKey.get(key)||[]).filter(a=>a.status==='fixed'||a.status==='not-affected');
  if(!negative.length || negative.every(a=>a.source===match.source))return match;
  return {...match,assessmentConflicts:negative.map(({source,status,evidence})=>({source,status,evidence}))};
 });
 return result;
}
function identifyPackageOrigin(pkg,options={}){
 const candidates=pkg?.packageOrigin?[{...pkg.packageOrigin,classifier:'existing-evidence'}]:[];
 for(const adapter of options.distributionSourceAdapters||adapters){if(typeof adapter?.identifyPackageOrigin!=='function')continue;const origin=adapter.identifyPackageOrigin(pkg,options);if(origin)candidates.push({...origin,classifier:adapter.id});}
 if(!candidates.length)return null;
 const signatures=new Set(candidates.map(x=>JSON.stringify([x.status,x.declared||null])));
 return signatures.size===1?candidates[0]:{status:'ambiguous',source:'conflicting-origin-classifiers',candidates};
}
module.exports={adapters,assessDistributionSources,identifyPackageOrigin,reconcileAssessments,refineFreexianEvidence};
