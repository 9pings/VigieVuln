'use strict';
// Shared European context for already identified CVEs. This module does not
// discover package vulnerabilities or change version applicability.
const {createCacheRepository}=require('./cache-repository');
const {getCacheDir}=require('./cache-directory');
const TTL=4*3600*1000;
const CVE=/^CVE-\d{4}-\d{4,}$/i;
const ids=c=>[...new Set([c?.id,...(c?.aliases||[]),...(c?.upstream||[])].filter(x=>typeof x==='string'&&CVE.test(x)).map(x=>x.toUpperCase()))];
function record(cve,id){if(!Array.isArray(cve.cveEvidence))cve.cveEvidence=[];let entry=cve.cveEvidence.find(x=>x.id===id);if(!entry){entry={id};cve.cveEvidence.push(entry);}return entry;}
function assign(matches,id,key,value){
 for(const m of matches){if(!ids(m.cve).includes(id))continue;record(m.cve,id)[key]=value;
  const c=m.cve,identity=String(c.id||'').toUpperCase()===id || (ids(c).length===1 && (c.aliases||[]).some(x=>String(x).toUpperCase()===id));
  if(identity)c[key]=value;
 }
}
function responseTime(res){const at=Date.parse(res.headers?.get?.('x-fad-proxy-fetched-at')||'');const valid=Number.isFinite(at)&&at>0&&at<=Date.now()+300000;return {fetchedAt:valid?at:null,stale:!valid||res.headers?.get?.('x-fad-proxy')==='stale'};}
function freshness(stamp,stale,offline=false){return !!stale || !stamp || (!offline && Date.now()-stamp>=TTL);}
function severityFromScore(score){return score>=9?'CRITICAL':score>=7?'HIGH':score>=4?'MEDIUM':score>0?'LOW':'NONE';}
async function boundedJson(response,maxBytes){
 const budgetError=()=>{const error=Error(`EUVD response exceeds the scanner's ${maxBytes}-byte metadata budget`);error.code='metadata-budget-exceeded';return error;};
 const declared=Number(response.headers?.get?.('content-length'));if(declared>maxBytes){await response.body?.cancel();throw budgetError();}
 if(!response.body)throw Error('empty EUVD metadata response');let length=0;const chunks=[];
 for await(const part of response.body){length+=part.length;if(length>maxBytes)throw budgetError();chunks.push(Buffer.from(part));}
 try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw Error('invalid EUVD metadata JSON');}
}
function parseEuvdDetail(body,id,cve){
 if(!body || body.id!==id)throw Error('EUVD metadata identifier mismatch');
 const aliases=Array.isArray(body.aliases)?body.aliases:typeof body.aliases==='string'?body.aliases.split(/[\s,]+/):[];
 if(!aliases.some(alias=>String(alias).toUpperCase()===cve))throw Error('EUVD metadata lacks the requested CVE identity');
 const score=typeof body.baseScore==='number' && Number.isFinite(body.baseScore) && body.baseScore>=0 && body.baseScore<=10?body.baseScore:null;
 const version=typeof body.baseScoreVersion==='string' && /^\d+(?:\.\d+)?$/.test(body.baseScoreVersion)?`CVSS:${body.baseScoreVersion}`:null;
 const text=(x,max)=>typeof x==='string' && x.length<=max ? x : null;
 const rawRefs=Array.isArray(body.references)?body.references:typeof body.references==='string'?body.references.split(/\s+/):[];
 const references=rawRefs.map(x=>typeof x==='string'?x:x?.url).filter(x=>typeof x==='string').slice(0,1000).filter(x=>{try{const u=new URL(x);return ['http:','https:'].includes(u.protocol)&&!u.username&&!u.password;}catch{return false;}});
 const date=raw=>require('./euvd').normalizeEuvdCalendarDate(text(raw,128));
 return {id,source:'euvd',description:text(body.description,100000),score,severity:score===null?null:severityFromScore(score),cvssVersion:version,
  cvssVector:text(body.baseScoreVector,1024),published:date(body.datePublished),modified:date(body.dateUpdated),publishedOriginal:text(body.datePublished,128),modifiedOriginal:text(body.dateUpdated,128),references};
}
function applyEuvdDetails(matches,id,detail){
 detail=require('./euvd').normalizeEuvdDetailDates(detail);
 for(const m of matches){if(!ids(m.cve).includes(id))continue;const c=m.cve;record(c,id).euvdDetails=detail;
  if(ids(c).length!==1)continue;
  const identity=String(c.id||'').toUpperCase()===id || (c.aliases||[]).some(x=>String(x).toUpperCase()===id);
  c.euvdDetails=detail;
  if(!c.description && detail.description)c.description=detail.description;
  if(c.riskEvidence && c.riskEvidence.source!=='euvd')continue;
  const knownSeverity=!!c.severity && String(c.severity).toUpperCase()!=='UNKNOWN';
  const compatible=!knownSeverity || !detail.severity || String(c.severity).toUpperCase()===detail.severity;
  let filled=false;
  if(c.score==null && detail.score!=null && compatible){c.score=detail.score;c.scoreSource='euvd';filled=true;}
  if(c.scoreSource==='euvd'){
   if(!knownSeverity && detail.severity){c.severity=detail.severity;c.severitySource='euvd';filled=true;}
   if(!c.cvssVector && detail.cvssVector)c.cvssVector=detail.cvssVector;
   if(!c.cvssVersion && detail.cvssVersion)c.cvssVersion=detail.cvssVersion;
  }
  if(filled)c.riskEvidence={source:'euvd',id,relationship:identity?'identity':'upstream'};
 }
}

const europeanAdapters=[
 {id:'gcve',async run(matches,opts,context){for(const id of context.ids){const value=require('./gcve').gcveId(id);if(!value)continue;
  for(const m of matches){const c=m.cve;if(!ids(c).includes(id))continue;const entry=record(c,id);entry.gcveAlias=value;entry.gcveEvidence={kind:'derived-alias',source:'gcve-rules'};
   const identity=String(c.id||'').toUpperCase()===id || (ids(c).length===1 && (c.aliases||[]).some(x=>String(x).toUpperCase()===id));
   if(identity && !c.gcve){c.gcve=value;c.gcveEvidence=entry.gcveEvidence;}
  }
 }return {result:'derived-alias',count:context.ids.length};}},
 {id:'euvd',async run(matches,opts,context){
  const copies=context.ids.map(id=>({cve:{id}}));
  let failure=null;
  await require('./euvd').enrichEuvd(copies,{...opts,hostedProxy:context.hosted,onEuvdFailure:error=>{failure=error.message;}});
  const targeted=context.repo.get('catalogue','euvd-targeted')?.value?.entries || {},bulkEntry=context.repo.get('catalogue','euvd'),bulk=bulkEntry?.value;
  let consulted=0,stale=0,matched=0;
  for(const copy of copies){const id=copy.cve.id,entry=targeted[id];let available=false,old=false;
   if(entry && (opts.offline || context.hosted)){available=true;old=freshness(entry.fetchedAt,entry.stale,opts.offline);}
   else if(bulk?.body?.byCve && typeof bulk.body.byCve==='object'){available=true;old=freshness(bulk._fetchedAt,bulkEntry.stale,opts.offline);}
   if(!available){assign(matches,id,'euvdEvidence',{status:'unavailable',reason:failure || (opts.offline?'offline':'unavailable')});continue;}consulted++;if(old)stale++;
   assign(matches,id,'euvdEvidence',{status:copy.cve.euvd?'enriched':'no-match',stale:old,...(failure?{reason:failure,refreshFailed:true}:{})});
   if(copy.cve.euvd){assign(matches,id,'euvd',copy.cve.euvd);matched++;}
  }
  return {result:matched?'enriched':consulted===context.ids.length?'no-match':'unavailable',count:matched,consulted,missing:context.ids.length-consulted,stale};
 }},
 {id:'euvd-details',parent:'euvd',async run(matches,opts,context){
  const stored=context.repo.get('catalogue','euvd-targeted')?.value || {entries:{}},pending=[],failures=[];let missing=0,stale=0,enriched=0;
  // ENISA records include large product catalogues; real individual records
  // exceed 12 MiB. Keep a configurable finite bound without truncating them.
  const limit=opts.maxEuvdDetails ?? 10000,maxBytes=opts.maxEuvdMetadataBytes ?? 32*1024*1024;
  if(!Number.isSafeInteger(limit)||limit<1||!Number.isSafeInteger(maxBytes)||maxBytes<1)throw Error('invalid EUVD metadata limits');
  for(const id of context.ids){
   const related=matches.filter(m=>ids(m.cve).includes(id));
   const euvd=related.map(m=>m.cve.cveEvidence?.find(x=>x.id===id)?.euvd?.id).find(Boolean);
   if(!euvd){assign(matches,id,'euvdDetailsEvidence',{status:'not-consulted'});continue;}
   const old=stored.entries[id],detail=old?.details;
   const stable=detail && !old?.detailsStale && old?.detailsFetchedAt > 0 && old.detailsFetchedAt <= Date.now() && old?.detailsOrigin === require('./providers').resourceOrigin() && require('./record-freshness').stableRecord('euvd',detail,opts);
   if(detail && detail.id===euvd && (opts.offline || stable || (!opts.forceUpdate && (opts.reuseStableAdvisories === false || old.detailsOrigin === require('./providers').resourceOrigin()) && !freshness(old.detailsFetchedAt,old.detailsStale)))){applyEuvdDetails(matches,id,detail);enriched++;const oldStamp=stable ? false : freshness(old.detailsFetchedAt,old.detailsStale,opts.offline);const failure=oldStamp && old.detailsFailure;if(failure)failures.push(failure);assign(matches,id,'euvdDetailsEvidence',{status:'enriched',stale:oldStamp,...(failure?{failure}:{}),...(stable?{reusedStable:true,fetchedAt:old.detailsFetchedAt}: {})});if(oldStamp)stale++;continue;}
   if(opts.offline){missing++;const failure=old?.detailsFailure;if(failure)failures.push(failure);assign(matches,id,'euvdDetailsEvidence',{status:'unavailable',...(failure?{failure}:{})});continue;}
   if(pending.length>=limit){missing++;assign(matches,id,'euvdDetailsEvidence',{status:'unavailable',reason:'request-limit'});continue;}const observed=related.map(m=>m.cve.cveEvidence?.find(x=>x.id===id)?.euvd).find(Boolean);pending.push({id,euvd,observed});
  }
  let processed=0;
  opts.onEnrichmentProgress?.({source:'euvd-details',completed:0,total:pending.length});
  const limitWork=require('p-limit')(6);
  await Promise.all(pending.map(item=>limitWork(async()=>{
   try{
    const res=await require('./providers').getResource('euvd','vulnerability',{id:item.euvd},{fetcher:opts.fetcher,streaming:true,noStore:true,forceRefresh:opts.forceUpdate || require('./cache-policy').shouldForceUpdate()});
    if(!res.ok){await res.body?.cancel();throw require('./request-failure').responseError('EUVD detail',res,{viaProxy:require('./providers').hasProxyRoute()});}
    const detail=parseEuvdDetail(await boundedJson(res,maxBytes),item.euvd,item.id);
    const stamp=require('./providers').hasProxyRoute()?responseTime(res):{fetchedAt:Date.now(),stale:false};
    const scope=res.headers.get('x-fad-proxy-scope'),checked=res.headers.get('x-fad-proxy-checked-at'),rawStaleReason=res.headers.get('x-fad-proxy-stale-reason');
    const staleReason=rawStaleReason && /^[a-z0-9-]{1,80}$/.test(rawStaleReason) ? rawStaleReason : null;
    const checkedAt=checked && Number.isFinite(Date.parse(checked)) ? new Date(Date.parse(checked)).toISOString() : null;
    detail.provenance={resource:require('./providers/euvd').build('vulnerability',{id:item.euvd}).url,origin:require('./providers').resourceOrigin(),sourceScope:scope && scope.length<=256 ? scope : (require('./providers').hasProxyRoute() ? 'unspecified' : 'enisa-detail'),observedAt:stamp.fetchedAt ? new Date(stamp.fetchedAt).toISOString() : null,...(checkedAt?{checkedAt}:{}),...(staleReason?{staleReason}:{})};
    const existing=stored.entries[item.id]||{},bulk=context.repo.get('catalogue','euvd')?.value;
    const mappingAt=existing.fetchedAt || bulk?._fetchedAt || stamp.fetchedAt;
    stored.entries[item.id]={...existing,item:existing.item || item.observed,fetchedAt:mappingAt,stale:existing.stale ?? freshness(mappingAt,false),details:detail,detailsFetchedAt:stamp.fetchedAt,detailsStale:stamp.stale,detailsOrigin:require('./providers').resourceOrigin()};delete stored.entries[item.id].detailsFailure;
    let failure;if(stamp.stale && staleReason){const http=/^upstream-http-(\d{3})$/.exec(staleReason);failure={code:'source-refresh-failed',source:'euvd-details',status:http?Number(http[1]):null,requestKey:require('./providers/common').failureKey('euvd','vulnerability',{id:item.euvd}),reason:`EUVD mirror refresh failed (${staleReason}); cached detail retained`,resources:[item.euvd],attemptedAt:Date.now()};failures.push(failure);stored.entries[item.id].detailsFailure=failure;}
    applyEuvdDetails(matches,item.id,detail);assign(matches,item.id,'euvdDetailsEvidence',{status:'enriched',stale:stamp.stale,...(failure?{failure}:{})});enriched++;if(stamp.stale)stale++;
   }catch(error){const old=stored.entries[item.id]||{},failure={code:error.code||'source-request-failed',source:'euvd-details',status:error.status||null,requestKey:require('./providers/common').failureKey('euvd','vulnerability',{id:item.euvd}),...(error.layer?{layer:error.layer}:{}),...(error.retryAfterSeconds!=null?{retryAfterSeconds:error.retryAfterSeconds}:{}),reason:error.message,resources:[item.euvd],attemptedAt:Date.now()};failures.push(failure);stored.entries[item.id]={...old,item:old.item||item.observed,detailsFailure:failure};if(old.details?.id===item.euvd){applyEuvdDetails(matches,item.id,old.details);assign(matches,item.id,'euvdDetailsEvidence',{status:'enriched',stale:true,failure});enriched++;stale++;}else{missing++;assign(matches,item.id,'euvdDetailsEvidence',{status:'unavailable',failure});}}
   processed++;opts.onEnrichmentProgress?.({source:'euvd-details',completed:processed,total:pending.length});
  })));
  if(pending.length)context.repo.put('catalogue','euvd-targeted',stored);
  return {result:enriched?'enriched':missing?'unavailable':'not-applicable',count:enriched,consulted:enriched,missing,stale,...(failures.length?{failures,reason:`${failures.length} EUVD detail request(s) failed: ${[...new Set(failures.map(f=>f.reason))].join('; ')}`}:{})};
 }},
 {id:'certfr',async run(matches,opts,context){
  const copies=context.ids.map(id=>({cve:{id}})),saved=context.repo.get('catalogue','certfr-targeted')?.value || {entries:{}};
  if(context.hosted&&!opts.offline){
   for(let i=0;i<context.ids.length;i+=100){const request=context.ids.slice(i,i+100),res=await require('./providers').getResource('certfr','cves',{ids:request},{fetcher:opts.fetcher,noStore:true,streaming:true});
    if(!res.ok)throw Error(`hosted CERT-FR unavailable (HTTP ${res.status})`);const payload=await res.json();if(!Array.isArray(payload.items))throw Error('invalid hosted CERT-FR response');
    const byId=new Map();for(const item of payload.items){if(!item||!request.includes(item.cve)||byId.has(item.cve)||!Array.isArray(item.advisories))throw Error('invalid hosted CERT-FR record');byId.set(item.cve,item.advisories);}
    const stamp=responseTime(res);for(const id of request)saved.entries[id]={items:byId.get(id)||[],...stamp};
   }
   context.repo.put('catalogue','certfr-targeted',saved);
  }else if(!opts.offline)await require('./certfr').enrichCertFr(copies,{...opts,hostedProxy:false});
  const bulkEntry=context.repo.get('catalogue','certfr'),bulk=bulkEntry?.value;const bulkByCve=opts.offline && bulk?.entries ? require('./certfr').indexByCve(bulk.entries) : null;let consulted=0,stale=0,matched=0;
  for(const copy of copies){const id=copy.cve.id,entry=saved.entries[id];let hits=copy.cve.certfr,available=false,old=false;
   if(entry && (opts.offline||context.hosted)){available=true;old=freshness(entry.fetchedAt,entry.stale,opts.offline);hits=entry.items;}
   else if(bulk?.entries && typeof bulk.entries==='object' && bulk.meta?.fetchedAt){available=true;old=freshness(bulk.meta.fetchedAt,bulkEntry.stale,opts.offline);if(opts.offline)hits=bulkByCve[id];}
   if(!available){assign(matches,id,'certfrEvidence',{status:'unavailable'});continue;}consulted++;if(old)stale++;assign(matches,id,'certfrEvidence',{status:hits?.length?'enriched':'no-match',stale:old});if(hits?.length){assign(matches,id,'certfr',hits);matched++;}
  }
  return {result:matched?'enriched':consulted===context.ids.length?'no-match':'unavailable',count:matched,consulted,missing:context.ids.length-consulted,stale};
 }},
];
/** Enrich matched CVEs without altering affected ranges. coverage records use
 * completed/partial/failed/not-run/not-applicable and result distinguishes
 * enriched/no-match/unavailable/not-consulted/derived-alias. Individual source
 * statuses and signals are attached to cve.cveEvidence by explicit CVE ID.
 * opts.europeanAdapters supports injected {id,run(matches,opts,context)} sources.
 */
async function enrichEuropeanFindings(matches,opts={}){
 const active=opts.europeanAdapters || europeanAdapters;if(!Array.isArray(active)||active.some(a=>!a || typeof a.id!=='string'||typeof a.run!=='function'))throw Error('Invalid European enrichment adapter registry');
 const context={ids:[...new Set((matches||[]).flatMap(m=>ids(m.cve)))],hosted:opts.hostedProxy ?? require('./providers').hasHostedProxy()};
 let repository;
 Object.defineProperty(context,'repo',{get(){if(!repository)repository=createCacheRepository(opts.cacheDir||getCacheDir());return repository;}});
 const coverage=[],warnings=[];
 for(const adapter of active){const requestKeys=[];const adapterOpts={...opts,onEuvdRequest:key=>{requestKeys.push(key);opts.onEuvdRequest?.(key);}};const disabled=opts[adapter.id]===false || (adapter.parent && opts[adapter.parent]===false) || (adapter.id==='gcve' && opts.disableGcve), evidenceKey=adapter.id==='euvd-details'?'euvdDetailsEvidence':`${adapter.id}Evidence`;
  if(disabled){for(const id of context.ids)assign(matches,id,evidenceKey,{status:'not-consulted'});coverage.push({capability:'sources',collector:adapter.id,execution:'not-applicable',result:'not-consulted',expected:false,reason:'Excluded by source configuration.'});continue;}
  if(!context.ids.length){coverage.push({capability:'sources',collector:adapter.id,execution:'not-applicable',result:'not-applicable'});continue;}
  try{opts.onEnrichmentProgress?.({source:adapter.id,completed:0,total:context.ids.length});const result=await adapter.run(matches,adapterOpts,context);opts.onEnrichmentProgress?.({source:adapter.id,completed:context.ids.length,total:context.ids.length});if(!result || typeof result.result!=='string')throw Error('Invalid European source result');
   const incomplete=!!result.missing||!!result.stale||result.result==='unavailable';
   const parts=[];if(result.consulted!=null)parts.push(`${result.consulted} of ${context.ids.length} CVEs consulted`);if(result.count!=null)parts.push(`${result.count} enriched`);if(result.missing)parts.push(`${result.missing} unavailable`);if(result.stale)parts.push(`${result.stale} stale`);
   const reason=incomplete ? (result.reason || (parts.length?parts.join('; '):'Source data unavailable.')) : result.reason;
   coverage.push({capability:'sources',collector:adapter.id,requestKeys,execution:incomplete?'partial':result.result==='not-applicable'?'not-applicable':'completed',...result,...(reason?{reason}:{})});
   if(incomplete)warnings.push({type:'source-unavailable',capability:'sources',source:adapter.id,...(result.failures?.length?{code:result.failures[0].code,status:result.failures[0].status,resources:result.failures.flatMap(f=>f.resources),requestKeys:result.failures.map(f=>f.requestKey).filter(Boolean),reason}:{severity:'info'}),message:`${adapter.id.toUpperCase()}: ${reason}`});
  }catch(error){for(const id of context.ids)assign(matches,id,evidenceKey,{status:'unavailable',reason:error.message});coverage.push({capability:'sources',collector:adapter.id,requestKeys,execution:'failed',result:'unavailable',reason:error.message});warnings.push({type:'source-unavailable',capability:'sources',source:adapter.id,message:`${adapter.id.toUpperCase()}: ${error.message}`});}
 }
 return {coverage,warnings};
}
module.exports={enrichEuropeanFindings,europeanAdapters};
