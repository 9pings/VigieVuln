'use strict';
// Current unqualified Debian tracker notes for an end-of-support release are
// candidates, never a Debian release verdict or evidence of a fixed package.
const crypto=require('node:crypto');
const {createCacheRepository}=require('../cache-repository');
const {getCacheDir}=require('../cache-directory');
const historical=require('./historical-debian');
const {debian:compare}=require('./versions');
const SOURCE='debian-security-tracker-current-candidates',VERSION=1;
const namespace=d=>`system-debian-current:${d.versionId}:${d.codename}`;
const repository=opts=>opts.repository||createCacheRepository(opts.cacheDir||getCacheDir());
const namesOf=inventory=>[...new Set((inventory.packages||[]).map(p=>p.sourceName).filter(p=>typeof p==='string'&&/^[a-z0-9][a-z0-9+.-]{0,199}$/.test(p)))].sort();
async function bounded(response,max){
 if(!response?.ok)throw Error(`Debian current source HTTP ${response?.status||'failure'}`);
 const parts=[];let size=0;
 for await(const chunk of response.body||[]){size+=chunk.length;if(size>max)throw Error('Debian current source exceeds download limit');parts.push(Buffer.from(chunk));}
 return Buffer.concat(parts,size);
}
function dates(res,now){const n=Date.parse(res.headers?.get?.('x-fad-proxy-fetched-at')||'');return Number.isFinite(n)&&n<=now?n:now;}
function writeAtomically(repo,fn){
 if(!repo.db?.exec)return fn();
 repo.db.exec('BEGIN IMMEDIATE');try{const out=fn();repo.db.exec('COMMIT');return out;}catch(error){try{repo.db.exec('ROLLBACK');}catch{}throw error;}
}
async function syncCurrentDebianCandidates(inventory,opts={}){
 if(opts.offline)throw Error('cannot sync Debian current candidates offline');
 const d=historical.checkDistribution(inventory.distribution),cache=repository(opts),past=cache.getSnapshot(historical.namespace(d));
 if(!past || past.metadata?.parserVersion!==historical.PARSER_VERSION)return {notApplicable:true,reason:'historical-snapshot-unavailable'};
 const packages=namesOf(inventory);if(!packages.length)return {notApplicable:true,reason:'no-source-packages'};
 const maxPackages=opts.maxPackages??100000;if(!Number.isSafeInteger(maxPackages)||maxPackages<1||packages.length>maxPackages)throw Error('Debian current package scope exceeds limit');
 const now=Number.isFinite(opts.now)?opts.now:Date.now(),until=new Date(now).toISOString().replace(/\.\d{3}Z$/,'Z');
 const transport=opts.fetchResource||((kind,params)=>require('../providers').getResource('debian',kind,params,{streaming:true,fetcher:opts.fetcher,signal:opts.signal}));
 const historyResponse=await transport('history',{until}), history=JSON.parse((await bounded(historyResponse,opts.maxMetadataBytes??4*1024*1024)).toString());
 const commit=history?.[0]?.id,commitTimestamp=history?.[0]?.committed_date;
 if(!/^[a-f0-9]{40}$/.test(commit||'')||!Number.isFinite(Date.parse(commitTimestamp))||Date.parse(commitTimestamp)>now)throw Error('Invalid current Debian tracker commit');
 const cutoff=Date.parse(`${past.metadata.cutoff}T23:59:59Z`);
 if(!Number.isFinite(cutoff)||Date.parse(commitTimestamp)<=cutoff)throw Error('Current Debian tracker commit does not postdate the historical snapshot');
 const fetched=[dates(historyResponse,now)],hashes=[],chunks=Array.from({length:Math.ceil(packages.length/1000)},(_,i)=>packages.slice(i*1000,i*1000+1000));
 const direct=!opts.fetchResource&&!require('../providers').hasProxyRoute(),parts=[];
 for(let i=0;i<(direct?1:chunks.length);i++){
  const response=await transport('list',{commit,list:'CVE',packages:chunks[i]});fetched.push(dates(response,now));
  const sourceHash=response.headers?.get?.('x-vigievuln-source-sha256');if(/^[a-f0-9]{64}$/.test(sourceHash||'')){if(hashes.length&&hashes[0]!==sourceHash)throw Error('Debian current tracker projection source changed between pages');hashes.push(sourceHash);}
  parts.push(await bounded(response,opts.maxDownloadBytes??128*1024*1024));
 }
 const body=Buffer.concat(parts.flatMap((part,i)=>i?[Buffer.from('\n'),part]:[part]));
 if(body.toString('utf8').trim()&&!/^CVE-\d{4}-\d{4,}(?:\s|$)/m.test(body.toString('utf8')))throw Error('Invalid Debian current tracker response');
 const parsed=historical.parseHistoricalDebian({CVE:body,DSA:'',DLA:''},d,{...opts,packages,includeContextReleases:true});
 const allowed=new Set(packages);for(const name of parsed.packages.keys())if(!allowed.has(name))parsed.packages.delete(name);
 const ns=namespace(d),previous=cache.getSnapshot(ns),fetchedAt=Math.min(...fetched),same=previous?.metadata?.commit===commit&&previous.metadata.parserVersion===VERSION;
 writeAtomically(cache,()=>{
  if(!same){for(const [key] of cache.entries(ns))cache.delete(ns,key);}else for(const name of packages)cache.delete(ns,name);
  for(const [name,records] of parsed.packages)cache.put(ns,name,records,{fetchedAt});
  const queriedPackages=[...new Set([...(same?previous.metadata.queriedPackages||[]:[]),...packages])].sort();
  cache.putSnapshot(ns,{fetchedAt,complete:false,recordCount:[...parsed.packages.values()].reduce((n,x)=>n+x.length,0),metadata:{distribution:d,parserVersion:VERSION,commit,commitTimestamp,queriedPackages,sourceSha256:hashes[0]||null,projectionSha256:crypto.createHash('sha256').update(body).digest('hex'),historicalCutoff:past.metadata.cutoff}});
 });
 return {source:SOURCE,commit,commitTimestamp,fetchedAt,queriedPackages:packages.length,sourceSha256:hashes[0]||null};
}
function confirmedKeys(matches){
 const out=new Set();for(const m of matches||[]){const name=m.dep?.name||m.dep?.coord, c=m.cve||m,ids=[c.id,...(c.aliases||[])];if(!name)continue;for(const id of ids)if(typeof id==='string')out.add(`${name}\0${id}`);}return out;
}
async function assessCurrentDebianCandidates(inventory,opts={}){
 let d;try{d=historical.checkDistribution(inventory?.distribution);}catch{return {observations:[],coverage:[{source:SOURCE,execution:'not-applicable',result:'indeterminate',reason:'Exact Debian distribution identity unavailable.'}],warnings:[]};}
 const cache=repository(opts),past=cache.getSnapshot(historical.namespace(d)),packages=namesOf(inventory),coverage=[],warnings=[],observations=[];
 if(!past || past.metadata?.parserVersion!==historical.PARSER_VERSION)return {observations,coverage:[{source:SOURCE,execution:'not-applicable',result:'indeterminate',reason:'Historical release snapshot is unavailable or outdated.'}],warnings};
 if(!packages.length)return {observations,coverage:[{source:SOURCE,execution:'not-applicable',result:'not-applicable',reason:'No source package identities.'}],warnings};
 const ns=namespace(d),now=Number.isFinite(opts.now)?opts.now:Date.now(),ttl=opts.currentDebianTtlMs??4*60*60*1000;
 if(!Number.isSafeInteger(ttl)||ttl<1)throw Error('invalid Debian current candidate TTL');
 let current=cache.getSnapshot(ns),failure=null;
 const missing=()=>packages.some(name=>!current?.metadata?.queriedPackages?.includes(name));
 if(!opts.offline && (!current || current.metadata?.parserVersion!==VERSION || current.metadata?.historicalCutoff!==past.metadata.cutoff || current.fetchedAt>now || now-current.fetchedAt>=ttl || missing() || opts.refreshCurrentDebian)){
  try{await syncCurrentDebianCandidates(inventory,{...opts,repository:cache,now});current=cache.getSnapshot(ns);}catch(error){failure=error;}
 }
 if(!current || current.metadata?.parserVersion!==VERSION || current.metadata?.historicalCutoff!==past.metadata.cutoff){if(failure)warnings.push({type:'source-unavailable',source:SOURCE,message:`Debian current candidate consultation failed: ${failure.message}`});return {observations,coverage:[{source:SOURCE,execution:'not-run',result:'indeterminate',reason:'No compatible current Debian candidate snapshot is cached.'}],warnings};}
 const known=confirmedKeys(opts.confirmedMatches),historyScope=p=>past.complete||past.metadata?.queriedPackages?.includes(p);
 let unknown=0,examined=0;
 for(const dep of inventory.packages||[]){
  if(!dep.sourceName||!dep.sourceVersion||compare(dep.sourceVersion,dep.sourceVersion)!==0||!current.metadata.queriedPackages?.includes(dep.sourceName)||!historyScope(dep.sourceName)){unknown++;continue;}
  const currentRows=cache.get(ns,dep.sourceName)?.value||[],pastRows=cache.get(historical.namespace(d),dep.sourceName)?.value||[],historicalIds=new Set(pastRows.map(r=>r.id));
  for(const rec of currentRows){
   if(historicalIds.has(rec.id)||known.has(`${dep.name}\0${rec.id}`))continue;
   const result=historical.evaluateTrackerRecord(rec,dep.sourceVersion);examined++;
   if(result.affected!==true)continue;
   const comparison=result.threshold ? {scheme:'debian',installedVersion:dep.sourceVersion,operator:'<',threshold:result.threshold,source:result.scope} : {scheme:'debian',installedVersion:dep.sourceVersion,operator:'tracker-unfixed',threshold:null,source:result.scope};
   const contextReleases=(rec.contextNotes||[]).filter(n=>n.kind==='not-affected').map(n=>({releases:n.releases,status:n.kind,note:n.note}));
   const context=contextReleases.length?` Other releases marked not affected: ${contextReleases.map(c=>c.releases.join(', ')).join('; ')}.`:'';
   const rule=result.threshold?`Source version ${dep.sourceVersion} is below the current tracker threshold ${result.threshold}.`:`The current tracker marks the source package unfixed.`;
   observations.push({dep,cveId:rec.id,source:SOURCE,status:'possible',sourceUrl:`https://security-tracker.debian.org/tracker/${rec.id}`,observedAt:current.fetchedAt,
    reason:`${rule} Debian ${d.versionId} (${d.codename}) applicability after end of support is not established.${context}`,
    evidence:{distribution:d,comparison,globalNotes:result.globalNotes,releaseStatuses:result.statuses,triage:result.annotations,trackerUrgency:result.trackerUrgency,contextReleases,
     currentCommit:current.metadata.commit,currentCommitTimestamp:current.metadata.commitTimestamp,historicalCommit:past.metadata.commit,historicalCutoff:past.metadata.cutoff,
     sourceSha256:current.metadata.sourceSha256,sourceURL:`https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/${current.metadata.commit}/data/CVE/list`,releaseApplicability:'unknown',packageFixVerified:false}});
  }
 }
 if(failure)warnings.push({type:'source-unavailable',source:SOURCE,message:`Debian current candidate refresh failed: ${failure.message}`});
 coverage.push({source:SOURCE,execution:failure||unknown?'partial':'completed',result:'indeterminate',completeness:'candidate-only',scope:'current-source-notes-for-historical-release',commit:current.metadata.commit,commitTimestamp:current.metadata.commitTimestamp,
  fetchedAt:current.fetchedAt,stale:now<current.fetchedAt||now-current.fetchedAt>=ttl,queriedPackages:current.metadata.queriedPackages,examined,unknown,count:observations.length,
  reason:'Current unqualified tracker notes are observations; their applicability to an unsupported release is not established.'});
 return {observations,coverage,warnings};
}
module.exports={SOURCE,VERSION,namespace,syncCurrentDebianCandidates,assessCurrentDebianCandidates};
