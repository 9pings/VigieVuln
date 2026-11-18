'use strict';
// Enrichment adds independent risk evidence; it never changes OS advisory verdicts.
const {createCacheRepository}=require('../cache-repository');
const {getCacheDir}=require('../cache-directory');
function cveIds(match){return [...new Set([match.cve?.id,...(match.cve?.aliases||[]),...(match.cve?.upstream||[])].filter(id=>/^CVE-\d{4}-\d{4,}$/i.test(id||'')))];}
function cveId(match){return cveIds(match)[0]||null;}
function relationship(cve,id){return cve.id===id || (cve.aliases||[]).includes(id) ? 'identity' : 'upstream';}
function proxies(matches){return matches.flatMap(m=>cveIds(m).map(id=>({...m,cve:{id}})));}
function cveEvidence(cve,id){if(!Array.isArray(cve.cveEvidence))cve.cveEvidence=[];let value=cve.cveEvidence.find(x=>x.id===id);if(!value){value={id};cve.cveEvidence.push(value);}return value;}
// Hosted proxies offer a targeted KEV operation. Persist both positive and
// negative observations so an air-gapped replay does not need a global catalog.
async function enrichKevCopies(copies,opts){
 const repo=createCacheRepository(opts.cacheDir||getCacheDir()),wanted=[...new Set(copies.map(m=>m.cve.id))];
 const targeted=repo.get('catalogue','kev-targeted')?.value || {entries:{}};
 const hosted=opts.hostedProxy ?? require('../providers').hasHostedProxy();let failure=null;
 if(hosted && !opts.offline){
  try{
   for(let i=0;i<wanted.length;i+=100){
    const group=wanted.slice(i,i+100),res=await require('../providers').getResource('kev','cves',{ids:group},{fetcher:opts.fetcher,noStore:true,streaming:true});
    if(!res.ok)throw Error(`KEV HTTP ${res.status}`);const body=await res.json();if(!Array.isArray(body?.items))throw Error('invalid KEV response');
    const seen=new Map();for(const row of body.items){if(!row || !group.includes(row.cve) || seen.has(row.cve) || (row.kev!=null && (typeof row.kev!=='object'||Array.isArray(row.kev))))throw Error('invalid KEV record');seen.set(row.cve,row.kev||null);}
    const stamp=Date.parse(res.headers?.get?.('x-fad-proxy-fetched-at')||'');const fetchedAt=Number.isFinite(stamp)&&stamp>0&&stamp<=Date.now()+300000?stamp:null,stale=fetchedAt===null || res.headers?.get?.('x-fad-proxy')==='stale';
    for(const id of group)targeted.entries[id]={item:seen.get(id)||null,fetchedAt,stale};
    repo.put('catalogue','kev-targeted',targeted);
   }
  }catch(error){failure=`KEV targeted lookup failed: ${error.message}`;}
 }else if(!opts.offline)await require('../kev').enrichKev(copies,{...opts,hostedProxy:false});
 else await require('../kev').enrichKev(copies,{...opts,offline:true});
 const bulk=repo.get('catalogue','kev')?.value,hasBulk=!!bulk?.body?.byId && typeof bulk.body.byId==='object';let missing=0,stale=0;
 for(const copy of copies){const saved=targeted.entries[copy.cve.id];if(saved && (opts.offline||hosted)){
   if(saved.stale || !Number.isFinite(saved.fetchedAt) || saved.fetchedAt<=0 || saved.fetchedAt>Date.now()+300000)stale++;const item=saved.item;if(item){copy.cve.kev=true;copy.cve.kevDateAdded=item.dateAdded;copy.cve.kevDueDate=item.dueDate;copy.cve.kevRansomware=item.ransomware;}
  }else if(!hasBulk)missing++;
 }
 return {complete:!failure && !missing && !stale,reason:failure || (missing?`KEV observations unavailable for ${missing} eligible CVE(s).`:`KEV observations stale for ${stale} eligible CVE(s).`)};
}

const enrichmentAdapters=[
 {id:'kev',async run(matches,opts){const copies=proxies(matches);if(!copies.length)return {complete:true,notApplicable:true,reason:'No eligible CVE identifier.'};const state=await enrichKevCopies(copies,opts);const byId=new Map(copies.map(x=>[x.cve.id,x]));for(const m of matches){for(const id of cveIds(m)){const item=byId.get(id)?.cve;if(item?.kev){const record=cveEvidence(m.cve,id);for(const key of ['kev','kevDateAdded','kevDueDate','kevRansomware'])if(item[key]!==undefined)record[key]=item[key];}}const hit=cveIds(m).map(id=>byId.get(id)).find(x=>x?.cve.kev);if(hit?.cve.kev){m.cve.kev=true;m.cve.kevDateAdded=hit.cve.kevDateAdded;m.cve.kevDueDate=hit.cve.kevDueDate;m.cve.kevRansomware=hit.cve.kevRansomware;m.cve.kevEvidence={source:'kev',id:hit.cve.id,relationship:relationship(m.cve,hit.cve.id)};}}return state;}},
 {id:'epss',async run(matches,opts){const copies=proxies(matches);if(!copies.length)return {complete:true,notApplicable:true,reason:'No eligible CVE identifier.'};await require('../epss').enrichEpss(copies,opts);const cache=createCacheRepository(opts.cacheDir||getCacheDir()).get('catalogue','epss')?.value;const byId=new Map(copies.map(x=>[x.cve.id,x]));for(const m of matches){for(const id of cveIds(m)){const item=byId.get(id)?.cve;if(item?.epssScore!=null || item?.epssPercentile!=null){const record=cveEvidence(m.cve,id);if(item.epssScore!=null)record.epssScore=item.epssScore;if(item.epssPercentile!=null)record.epssPercentile=item.epssPercentile;}}const hit=cveIds(m).map(id=>byId.get(id)).filter(Boolean).sort((a,b)=>(b.cve.epssScore??-1)-(a.cve.epssScore??-1))[0];if(hit?.cve.epssScore!=null){m.cve.epssScore=hit.cve.epssScore;m.cve.epssEvidence={source:'epss',id:hit.cve.id,relationship:relationship(m.cve,hit.cve.id)};}if(hit?.cve.epssPercentile!=null)m.cve.epssPercentile=hit.cve.epssPercentile;}return {complete:matches.every(m=>cveIds(m).every(id=>Object.hasOwn(cache?.entries||{},id))),reason:'EPSS scores are not cached for all eligible CVEs.'};}},
 {id:'nvd',async run(matches,opts){
  const copies=proxies(matches).map(m=>({...m,cve:{id:m.cve.id,severity:'UNKNOWN'}}));if(!copies.length)return {complete:true,notApplicable:true,reason:'No eligible CVE identifier.'};
  const nvd=require('../nvd'),absent=new Set(),failures=[];
  await nvd.enrichMatches(copies,{...opts,onAbsent:id=>absent.add(id),onFailure:(id,reason)=>failures.push({id,reason}),onProgress:(completed,total)=>opts.onEnrichmentProgress?.({source:'nvd',completed,total})});
  if(opts.offline)for(const copy of copies)if(nvd.hasCachedAbsence(copy.cve.id,{cacheDir:opts.cacheDir,offline:true}))absent.add(copy.cve.id);
  const byId=new Map(copies.map(x=>[x.cve.id,x]));
  for(const m of matches){
   const ids=cveIds(m), enriched=ids.map(id=>byId.get(id)).filter(x=>x?.source?.split('+').includes('nvd'));
   for(const id of ids){const evidence=byId.get(id)?.cve?.nvdRecordEvidence;if(evidence)cveEvidence(m.cve,id).nvdRecordEvidence=evidence;}
   const records=enriched.map(x=>({id:x.cve.id,relationship:relationship(m.cve,x.cve.id),severity:x.cve.severity||null,score:x.cve.score??null,
    cvssVector:x.cve.cvssVector||null,cvssVersion:x.cve.cvssVersion||null,description:x.cve.description||null,
    cwes:x.cve.cwes||[],references:x.cve.nvdRefs||[],published:x.cve.published||null,modified:x.cve.modified||null}));
   if(records.length){m.cve.nvdEvidence={...records[0],records};const sources=new Set(String(m.source||'').split('+').filter(Boolean));sources.add('nvd');m.source=[...sources].sort().join('+');}
   // A single explicitly related CVE can fill missing display metadata without
   // changing the distribution's advisory identity or affected/fixed verdict.
   // Multi-CVE advisories retain separate records and never acquire a made-up
   // aggregate severity or score.
   if(ids.length===1 && enriched.length===1){
    const item=enriched[0].cve;let riskFilled=false;
    if((!m.cve.severity || String(m.cve.severity).toUpperCase()==='UNKNOWN') && item.severity && item.severity!=='UNKNOWN'){
     m.cve.severity=item.severity; m.cve.severitySource='nvd'; riskFilled=true;
    }
    if(m.cve.score==null && typeof item.score==='number' && Number.isFinite(item.score)){m.cve.score=item.score;m.cve.scoreSource='nvd';riskFilled=true;}
    if(riskFilled)m.cve.riskEvidence={source:'nvd',id:item.id,relationship:relationship(m.cve,item.id)};
    if(!m.cve.cvssVector && item.cvssVector)m.cve.cvssVector=item.cvssVector;
    if(!m.cve.cvssVersion && item.cvssVersion)m.cve.cvssVersion=item.cvssVersion;
    if(!m.cve.cwes?.length && item.cwes?.length)m.cve.cwes=item.cwes;
    if(!m.cve.nvdRefs?.length && item.nvdRefs?.length)m.cve.nvdRefs=item.nvdRefs;
    if(!m.cve.published && item.published)m.cve.published=item.published;
    if(!m.cve.modified && item.modified)m.cve.modified=item.modified;
   }
  }
  const complete=matches.every(m=>cveIds(m).every(id=>absent.has(id)||m.cve.nvdEvidence?.records.some(record=>record.id===id)));
  return {complete,result:copies.every(copy=>absent.has(copy.cve.id))?'no-match':undefined,reason:failures.length?`NVD lookup failed: ${[...new Set(failures.map(f=>f.reason))].join('; ')} (${failures.length} CVE(s)).`:'NVD metadata unavailable for some eligible CVEs.'};
 }},
];
async function enrichArtifactFindings(matches,opts={}) {
 const registry=opts.enrichmentAdapters||enrichmentAdapters;if(!Array.isArray(registry)||registry.some(a=>!a||typeof a.id!=='string'||typeof a.run!=='function'))throw Error('Invalid enrichment adapter registry');
 const selected=opts.enrich || ['nvd','kev','epss','gcve','euvd','certfr'];if(!Array.isArray(selected))throw Error('Invalid enrichment selection');
 const coverage=[],warnings=[];
 const european=opts.europeanAdapters || require('../finding-enrichment').europeanAdapters;
 const europeanIds=new Set(european.map(a=>a.id));
 for(const id of selected.filter(id=>!europeanIds.has(id))){if(opts[id]===false){const reason=`${id} is excluded by the selected source profile.`;coverage.push({capability:'sources',collector:id,execution:'not-applicable',result:'not-consulted',expected:false,reason});continue;}const adapter=registry.find(a=>a.id===id);if(!adapter)throw Error(`Unknown enrichment adapter ${id}`);try{opts.onEnrichmentProgress?.({source:id,completed:0,total:matches.length});const result=await adapter.run(matches,opts);opts.onEnrichmentProgress?.({source:id,completed:matches.length,total:matches.length});if(!result||typeof result.complete!=='boolean')throw Error('Invalid enrichment result');coverage.push({capability:'sources',collector:id,execution:result.notApplicable?'not-applicable':result.complete?'completed':'partial',result:result.notApplicable?'not-applicable':result.complete?(result.result||'available'):'indeterminate',...(result.notApplicable?{expected:false,reason:result.reason}:!result.complete?{reason:result.reason}:{})});if(!result.complete)warnings.push({type:'source-unavailable',capability:'sources',source:id,message:result.reason||`${id} unavailable`});}catch(e){coverage.push({capability:'sources',collector:id,execution:'partial',result:'indeterminate',reason:e.message});warnings.push({type:'source-unavailable',capability:'sources',source:id,message:`${id}: ${e.message}`});}}
 const selectedEuropean=european.filter(a=>selected.includes(a.id) || (a.parent && selected.includes(a.parent)));
 if(selectedEuropean.length){const result=await require('../finding-enrichment').enrichEuropeanFindings(matches,{...opts,europeanAdapters:selectedEuropean});coverage.push(...result.coverage);warnings.push(...result.warnings);}
 return {coverage,warnings};
}
module.exports={enrichArtifactFindings,enrichmentAdapters,cveId};
