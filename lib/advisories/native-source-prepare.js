'use strict';
// Prepare the native source stores independently of OSV/NVD. Failed refreshes
// keep earlier observations and are returned as coverage, never clean verdicts.
const path=require('node:path');
const {openAdvisoryStore}=require('./store');
function selectedNativeSources(options={}){
 const requested=options.nativeSources||['cveproject','gcve'];if(!Array.isArray(requested)||requested.some(s=>!['cveproject','gcve'].includes(s)))throw Error('invalid native source selection');
 return [...new Set(requested)].filter(s=>s==='cveproject'?!options.disableCveProject:!options.disableGcve&&options.gcve!==false);
}
async function prepareNativeSources(deps,options={}){
 const cacheDir=options.cacheDir||require('../cache/directory').getCacheDir(),store=options.store||openAdvisoryStore({cacheDir}),close=!options.store;
 const sources=selectedNativeSources(options),coverage=[],warnings=[],ttlMs=options.advisoryQueryTtlMs??4*3600000;
 try{
  const packages=require('../providers/cveproject/packages-proxy').packageIdentities(deps);
  if(!packages.length)return {sources:[],coverage:[],warnings:[]};
  for(const source of sources){
   let refreshError=null;
   const existing=store.getSourceCoverage(source,'*');
   const stale=!existing || existing.provenance?.stale===true || Date.now()<existing.fetchedAt || Date.now()-existing.fetchedAt>=ttlMs;
   const offline=options.offline || (source==='gcve'?options.gcveOffline:options.cveOffline);
   if(!offline && (stale||options.forceUpdate)){
    try{
     if(options.nativeSourceAdapters?.[source]) await options.nativeSourceAdapters[source]({deps,store,cacheDir,options});
     else if(source==='gcve'){
      const feed=require('../providers/gcve/feed');await feed.updateGcveIndex({...(options.gcveOptions||{}),cacheFile:path.join(cacheDir,'gcve-data','index.json'),fetcher:require('../providers').hasProxyRoute()?feed.proxyGcveFetcher:(options.fetcher||globalThis.fetch)});
     } else if(require('../providers').hasProxyRoute()){
      options.onCveProgress?.('Querying package advisories via proxy');
      // Ask the fleet's typed native package index for all ecosystems. Older
      // servers can still supply their legacy npm/Maven projections, while a
      // failed generic lookup remains an explicit incomplete source.
      try{await require('../providers/cveproject/packages-proxy').refreshPackageCves(deps,store,{ttlMs});}
      catch(error){
       if(require('../providers/cveproject/npm-proxy').packageNames(deps).length)await require('../providers/cveproject/npm-proxy').refreshNpmCves(deps,store,{ttlMs});
       if([...deps.values()].some(d=>d.ecosystem==='maven' && d.provenance!=='binary')){const scanner=(require('../codecs/maven.codec').nativeScanners||[]).find(x=>x.kind==='cve');if(scanner?.scan)await scanner.scan(deps,{hostedProxy:true,offline:false,queryTtlMs:ttlMs});}
       throw error;
      }
     } else {
      await require('../providers/cveproject/download').ensureCveIndex({force:!!options.forceUpdate,offline:false,ttlMs,cacheDir,onProgress:options.onCveProgress});
     }
    }catch(e){refreshError=e.message;warnings.push({type:'source-unavailable',code:'source-request-failed',source,status:e.status||null,reason:e.message,resources:[source],message:`${source} refresh failed: ${e.message}`});}
   }
   const current=store.getSourceCoverage(source,'*');
   const exists=!!store.db.prepare('SELECT 1 AS n FROM advisory_records WHERE source=? LIMIT 1').get(source);
   const identities=new Map(packages.map(p=>[JSON.stringify([p.ecosystem,p.name]),{source,ecosystem:p.ecosystem,name:p.name,version:'*'}]));
   const queries=[...identities.values()].map(tuple=>store.getQuery(tuple,{ttlMs})).filter(Boolean);
   const scoped=identities.size>0 && queries.length===identities.size && queries.every(q=>q.complete!==false);
   const scopedAt=scoped?Math.min(...queries.map(q=>q.fetchedAt)):null;
   const fetchedAt=current?.fetchedAt || scopedAt;
   const age=fetchedAt && Date.now()-fetchedAt;
   const expired=age>=ttlMs, invalidDate=fetchedAt>Date.now();
   const declaredStale=current?.stale===true || current?.provenance?.stale===true || (scoped && queries.some(q=>q.provenance?.stale===true));
   const available=exists || !!current || scoped;
   const issue=refreshError?'refresh-failed':!available?'missing-source':invalidDate?'invalid-timestamp':declaredStale||(!offline&&expired)?'stale-source':null;
   const complete=!!current?.complete&&!expired&&!declaredStale&&!invalidDate&&!refreshError;
   const reason=refreshError || (!available?(offline ? `The offline auditor cache contains no ${source} snapshot or verified lookup for the selected packages.` : `${source} returned no verifiable package consultation.`):invalidDate?'Source collection timestamp is in the future':declaredStale?'The provider marked its source data stale':!offline&&expired?'Source evidence could not be refreshed':scoped?'Selected package identities checked':!current?.complete?'Prepared advisory records checked':expired?'Prepared source snapshot used offline':'Source snapshot consulted');
   coverage.push({source,status:complete?'complete':available?'incomplete':'missing',complete,
    execution:issue?(available?'partial':'not-run'):'completed',result:issue?'indeterminate':'available',
    scope:scoped?'consulted-packages':'available-native-records',issue,fetchedAt:fetchedAt||null,freshness:!fetchedAt?'unknown':expired?'expired':'current',reason});
  }
  return {sources,coverage,warnings};
 } finally {if(close)store.close();}
}
module.exports={selectedNativeSources,prepareNativeSources};
