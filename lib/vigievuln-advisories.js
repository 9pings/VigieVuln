'use strict';
// Targeted consultations of our published advisories. A query is a snapshot of
// one package, including an empty result; it can supersede older cached entries.
const {packageName,queryCoversRecord}=require('./advisory-store');
const tuple=p=>({source:'vigievuln',ecosystem:p.ecosystem,name:p.name,version:'*'});
const key=p=>JSON.stringify([p.ecosystem,p.ecosystem==='Maven'?p.name:packageName(p.ecosystem,p.name)]);
function packagesFor(resolved){
 const {osvEcosystemFor,osvPkgName}=require('./osv'),out=new Map();
 for(const dep of resolved.values()){
  if(!dep || dep.scope==='parent'||dep.provenance==='binary'||!['maven','npm','yarn'].includes(dep.ecosystem))continue;
  const ecosystem=osvEcosystemFor(dep),name=osvPkgName(dep);if(!name)continue;
  const p={ecosystem,name:ecosystem==='Maven'?name:packageName(ecosystem,name)};out.set(key(p),p);
 }
 return [...out.values()].sort((a,b)=>key(a).localeCompare(key(b)));
}
async function refreshReviewed(resolved,store,{ttlMs=4 * 3600000,getResource=require('./providers').getResource}={}){
 const packages=packagesFor(resolved),needed=packages.filter(p=>require('./cache-policy').shouldForceUpdate() || !store.getQuery(tuple(p),{ttlMs})?.fresh);let received=0;
 for(let i=0;i<needed.length;i+=200){
  const batch=needed.slice(i,i+200),response=await getResource('vigievuln','advisories',{packages:batch},{forceRefresh:true});
  if(!response.ok)throw Error(`reviewed advisory proxy HTTP ${response.status}`);
  const body=await response.json();if(body?.complete!==true||!Array.isArray(body.records))throw Error('incomplete reviewed advisory response');
  const serverAt=Date.parse(response.headers?.get('x-fad-proxy-fetched-at')||''),now=Date.now();
  if(!Number.isFinite(serverAt)||serverAt<=0||serverAt>now+300000)throw Error('reviewed advisory response has no trustworthy timestamp');
  // Clock skew must not make a just-observed snapshot appear stale locally.
  // Clamping backward is conservative for later withdrawal comparisons.
  const at=Math.min(serverAt,now);
  if(response.headers?.get('x-fad-proxy')==='stale')throw Error('reviewed advisory response is stale');
  const expected=new Map(batch.map(p=>[key(p),new Set()])),records=[];
  for(const document of body.records){
   if(!document||!/^(?:VV:CVE-\d{4}-\d{4,}|vv:CVE-\d{4}-\d{4,}:[a-zA-Z0-9._-]+)$/.test(document.id||'')||!Array.isArray(document.affected)||!document.curation?.method||!Array.isArray(document.references))throw Error('invalid reviewed advisory');
   const bindings=[];
   for(const entry of document.affected){const p=entry?.package;if(!p||!['Maven','npm'].includes(p.ecosystem)||typeof p.name!=='string'||!p.name||!Array.isArray(entry.ranges)||!Array.isArray(entry.versions))throw Error('invalid reviewed advisory package');bindings.push(p);if(expected.has(key(p)))expected.get(key(p)).add(document.id);}
   if(!bindings.some(p=>expected.has(key(p))))throw Error('unrelated reviewed advisory');
   records.push({source:'vigievuln',document,packages:bindings,fetchedAt:at,modifiedAt:document.modifiedAt||null,provenance:{transport:'vigievuln-proxy'}});
  }
  if(new Set(records.map(r=>r.document.id)).size!==records.length)throw Error('duplicate reviewed advisory');
  const queries=batch.map(p=>({...tuple(p),ids:[...expected.get(key(p))].sort(),fetchedAt:at,complete:true,provenance:{transport:'vigievuln-proxy'}}));
  store.commit({records,queries});received+=records.length;
 }
 return {packages:packages.length,requested:needed.length,received};
}
function isCurrentForPackage(store,p,record){
 const query=store.getQuery(tuple(p),{ttlMs:Number.MAX_SAFE_INTEGER});
 // A confirmed absence supersedes only a record no newer than the snapshot.
 return !(query && query.provenance?.stale!==true && queryCoversRecord(query,record) && !query.ids.includes(record.document.id));
}
module.exports={packagesFor,refreshReviewed,isCurrentForPackage};
