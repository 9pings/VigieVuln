'use strict';
// Targeted consultations preserve an observation per exact distro/name/version;
// they never claim the whole distribution corpus was imported.
const crypto=require('node:crypto');
const {scope,assessSystemInventory}=require('./advisories');
const {createCacheRepository}=require('../cache-repository');
const {getResource}=require('../providers');
const idOk=id=>typeof id==='string' && /^[A-Za-z0-9][A-Za-z0-9._:+-]{0,255}$/.test(id);
const key=q=>crypto.createHash('sha256').update(JSON.stringify(q)).digest('hex');
const observed=response=>{
 const stamp=Date.parse(response.headers?.get?.('x-fad-proxy-fetched-at')||'');
 const proxy=require('../providers').hasProxyRoute();
 return {fetchedAt:Number.isFinite(stamp)&&stamp>0&&stamp<=Date.now()+300000?stamp:proxy?1:Date.now(),stale:response.headers?.get?.('x-fad-proxy')==='stale' || (proxy&&!Number.isFinite(stamp))};
};
async function assessTargetedSystemInventory(inventory,opts={}){
 const s=scope(inventory.distribution,opts),matches=[],warnings=[],assessedPackages=[];
 if(!s)return {matches,coverage:[{source:'system-osv-targeted',status:'unknown',reason:'unsupported or missing distribution identity'}],warnings};
 const repo=opts.repository || createCacheRepository(opts.cacheDir),ns='system-osv-query:'+s.ecosystem,items=[],unique=new Map();let unknown=0;
 for(const dep of inventory.packages||[]){
  const source=dep.manager==='dpkg'||dep.manager==='apk';
  const name=source?dep.sourceName:dep.name,version=source?dep.sourceVersion:dep.version;
  if(!name||!version||s.compare(version,version)!==0){unknown++;continue;}
  const query={ecosystem:s.ecosystem,name,version},k=key(query);items.push({dep,query,k});if(!unique.has(k))unique.set(k,query);
 }
 const pending=[...unique].filter(([k])=>{const entry=repo.get(ns,k);return !opts.offline && (!entry || entry.stale || Date.now()-entry.fetchedAt>=require('../cache-policy').DEFAULT_TTL_MS || opts.refresh);});
 let error=null;
 if(pending.length){
  try{
   for(let start=0;start<pending.length;start+=500){
    const batch=pending.slice(start,start+500),states=batch.map(([k,query])=>({k,query,ids:[],seen:new Set(),fetchedAt:Date.now(),stale:false}));let active=states;
    while(active.length){
     const response=await getResource('osv','packages',{queries:active.map(x=>({...x.query,...(x.page?{page_token:x.page}:{})}))},{fetcher:opts.fetcher,forceRefresh:true,signal:opts.signal});
     if(!response.ok)throw Error(`OSV query HTTP ${response.status}`);
     const stamp=observed(response),body=await response.json();if(!Array.isArray(body?.results)||body.results.length!==active.length)throw Error('OSV query result incomplete');
     const next=[];
     for(let i=0;i<active.length;i++){
      const state=active[i],row=body.results[i];state.fetchedAt=Math.min(state.fetchedAt,stamp.fetchedAt);state.stale ||= stamp.stale;
      if(!row||typeof row!=='object'||Array.isArray(row)||row.error||(row.vulns!==undefined&&(!Array.isArray(row.vulns)||!row.vulns.every(v=>idOk(v?.id)))))throw Error('OSV query result invalid');
      state.ids.push(...(row.vulns||[]).map(v=>v.id));
      if(row.next_page_token!==undefined && typeof row.next_page_token!=='string')throw Error('OSV pagination invalid');
      if(row.next_page_token){if(state.seen.has(row.next_page_token)||state.seen.size>=1000)throw Error('OSV pagination invalid');state.seen.add(row.next_page_token);state.page=row.next_page_token;next.push(state);}
     }
     active=next;
    }
    const ids=[...new Set(states.flatMap(x=>x.ids))],docs=new Map();
    for(let i=0;i<ids.length;i+=10)await Promise.all(ids.slice(i,i+10).map(async id=>{
     const response=await getResource('osv','vuln',{id},{fetcher:opts.fetcher,forceRefresh:true,signal:opts.signal});if(!response.ok)throw Error(`OSV advisory HTTP ${response.status}`);
     const doc=await response.json();if(doc?.id!==id || !Array.isArray(doc.affected))throw Error('OSV advisory detail invalid');docs.set(id,{doc,...observed(response)});
    }));
    for(const state of states){
     const selected=[...new Set(state.ids)].map(id=>docs.get(id));
     if(selected.some(x=>!x.doc.affected.some(a=>a?.package?.ecosystem===state.query.ecosystem && a?.package?.name===state.query.name)))throw Error('OSV detail does not match consulted package');
     const fetchedAt=Math.min(state.fetchedAt,...selected.map(x=>x.fetchedAt));const stale=state.stale||selected.some(x=>x.stale);
     repo.put(ns,state.k,{query:state.query,records:selected.map(x=>x.doc),complete:true},{fetchedAt,stale});
    }
   }
  }catch(e){error=e.message;warnings.push(`System OSV targeted consultation failed: ${error}`);}
 }
 for(const item of items){
  const entry=repo.get(ns,item.k);
  if(!entry || !entry.value?.complete || JSON.stringify(entry.value.query)!==JSON.stringify(item.query)){unknown++;continue;}
  if(entry.stale || (!opts.offline && Date.now()-entry.fetchedAt>require('../cache-policy').DEFAULT_TTL_MS))warnings.push('System OSV targeted consultation is stale');
  const queryDep={...item.dep,version:item.query.version};
  const result=await assessSystemInventory({distribution:inventory.distribution,packages:[queryDep]},{...opts,records:entry.value.records,complete:true});
  if(result.assessedPackages?.length && !entry.stale)assessedPackages.push(item.dep);
  matches.push(...result.matches.map(match=>({...match,dep:item.dep})));unknown+=result.coverage[0]?.unknown||0;
 }
 const incomplete=unknown>0 || !!error || warnings.length>0;
 return {matches,assessedPackages,coverage:[{source:'system-osv-targeted',ecosystem:s.ecosystem,status:incomplete?'incomplete':'complete',result:incomplete?'indeterminate':matches.length?'affected':'no-match',scope:'consulted-package-versions',consulted:items.length,unknown}],warnings:[...new Set(warnings)]};
}
module.exports={assessTargetedSystemInventory};
