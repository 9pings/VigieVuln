'use strict';
// Native CVEProject records selected by explicit package identity; no product
// names, guessed aliases or unverified negative results enter the index.
const {packageName}=require('../../advisories/store');
const tuple=(ecosystem,name)=>({source:'cveproject',ecosystem,name:packageName(ecosystem,name),version:'*'});
const key=p=>JSON.stringify([p.ecosystem,packageName(p.ecosystem,p.name)]);
function packageIdentities(deps){const found=new Map();for(const dep of deps.values()){if(dep.provenance==='binary')continue;const identity=require('../../advisories/native-package-match').depIdentity(dep);if(identity)for(const ecosystem of [identity.ecosystem,...(identity.ecosystem.startsWith('system:deb:debian:')?['system:deb:debian:*']:[])])for(const name of identity.names){const p={ecosystem,name:packageName(ecosystem,name)};found.set(key(p),p);}}return [...found.values()].sort((a,b)=>key(a).localeCompare(key(b)));}
async function refreshPackageCves(deps,store,{ttlMs=4*3600000,getResource=require('..').getResource}={}){
 const packages=packageIdentities(deps),needed=packages.filter(p=>require('../../cache/policy').shouldForceUpdate() || !store.getQuery(tuple(p.ecosystem,p.name),{ttlMs})?.fresh);let incomplete=false,received=0;
 for(let i=0;i<needed.length;i+=200){const batch=needed.slice(i,i+200),res=await getResource('github','cve-packages',{packages:batch},{forceRefresh:true});if(!res.ok)throw Error(`CVEProject package proxy HTTP ${res.status}`);const body=await res.json();if(!Array.isArray(body.records)||typeof body.complete!=='boolean'||body.scope!=='explicit-package-identities')throw Error('invalid CVEProject package proxy response');
  const at=Date.parse(res.headers?.get('x-fad-proxy-fetched-at')||'');if(!Number.isFinite(at)||at<=0||at>Date.now()+300000)throw Error('CVEProject package response has no trustworthy source timestamp');
  const stale=res.headers?.get('x-fad-proxy')==='stale'||Date.now()-at>=require('../../cache/policy').DEFAULT_TTL_MS,byKey=new Map(batch.map(p=>[key(p),new Set()])),records=[];
  for(const raw of body.records){const record=require('../../advisories/native').cveEnvelope(raw,{fetchedAt:at,provenance:{transport:'proxy',stale}});let relevant=false;for(const container of [raw.containers?.cna,...(raw.containers?.adp||[])])for(const affected of container?.affected||[]){const p=require('../../advisories/native-package-match').explicitNativePackage(affected,{source:'cveproject',record:raw,container});if(!p)continue;const k=key(p);if(byKey.has(k)){byKey.get(k).add(record.id);relevant=true;}}if(!relevant)throw Error('CVEProject package proxy returned an unrelated record');records.push(record);}
  if(new Set(records.map(x=>x.id)).size!==records.length)throw Error('CVEProject package proxy returned duplicate records');
  const queries=body.complete&&!stale?batch.map(p=>({...tuple(p.ecosystem,p.name),ids:[...byKey.get(key(p))].sort(),fetchedAt:at,complete:true,provenance:{transport:'proxy',scope:'explicit-package-identities'}})):[];store.commit({records,queries});received+=records.length;if(!body.complete||stale)incomplete=true;
 }
 return {packages:packages.length,requested:needed.length,received,incomplete};
}
module.exports={packageIdentities,refreshPackageCves,tuple};
