'use strict';
// Debian tracker computes release status from unqualified source notes, then
// replaces them with release-specific notes; DSA/DLA provide release fixes.
const fs = require('node:fs');
const crypto = require('node:crypto');
const {createCacheRepository} = require('../cache-repository');
const {getCacheDir} = require('../cache-directory');
const {debian:compare} = require('./versions');

const SOURCE = 'debian-security-tracker-history';
const PARSER_VERSION = 2;
const SALSA = 'https://salsa.debian.org/security-tracker-team/security-tracker';
const NAMESPACE = distribution => `system-debian-history:${distribution.versionId}:${distribution.codename}`;
const CVE = /^CVE-\d{4}-\d{4,}$/;
function validDate(value){if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(value))return false;const n=Date.parse(value+'T00:00:00Z');return Number.isFinite(n)&&new Date(n).toISOString().slice(0,10)===value;}
function checkDistribution(d) {
 if (String(d?.id||'').toLowerCase()!=='debian' || !/^\d+(?:\.\d+)*$/.test(String(d.versionId||'')) || !/^[a-z][a-z0-9-]{0,30}$/.test(String(d.codename||''))) throw Error('Debian release version and codename are required');
 return {id:'debian',versionId:String(d.versionId).split('.')[0],codename:String(d.codename)};
}
function repository(opts){return opts.repository || createCacheRepository(opts.cacheDir || getCacheDir());}
const originKey = (name,version) => JSON.stringify([name,version]);
async function syncDebianPackageOrigins(packages,opts={}) {
 if(opts.offline)throw Error('cannot check Debian package origin offline');
 if(!Array.isArray(packages) || packages.length>(opts.maxOriginQueries??1000))throw Error('invalid Debian package origin query');
 const cache=repository(opts),out=[];
 for(const p of packages){
  if(!/^[a-z0-9][a-z0-9+.-]{0,199}$/.test(p?.name||'') || typeof p.version!=='string' || compare(p.version,p.version)!==0)throw Error('invalid Debian package origin identity');
  const sourceURL=`https://sources.debian.org/api/src/${encodeURIComponent(p.name)}/${encodeURIComponent(p.version)}/`;
  let observation;
  try{
   const response=opts.fetchResource?await opts.fetchResource('source-version',{name:p.name,version:p.version}):await require('../providers').getResource('debian','source-version',{name:p.name,version:p.version},{fetcher:opts.fetcher,signal:opts.signal});
   const payload=JSON.parse((await bounded(response,opts.maxMetadataBytes??4*1024*1024)).toString());
   const stamp=Date.parse(response.headers?.get?.('x-fad-proxy-fetched-at')||''),fetchedAt=Number.isFinite(stamp)&&stamp<=Date.now()?stamp:Date.now();
   observation={status:payload && !payload.error && payload.package===p.name && payload.version===p.version?'corroborated':'unknown',suites:Array.isArray(payload?.pkg_infos?.suites)?payload.pkg_infos.suites.filter(x=>typeof x==='string'):[],sourceURL,fetchedAt};
  }catch{observation={status:'unknown',sourceURL,fetchedAt:Date.now()};}
  cache.put('system-debian-origin',originKey(p.name,p.version),observation,{fetchedAt:observation.fetchedAt});out.push({name:p.name,version:p.version,...observation});
 }
 return out;
}
function normalizeList(input,limit,allowEmpty=false){const bytes=Buffer.isBuffer(input)?input:Buffer.from(String(input));if((!allowEmpty&&!bytes.length)||bytes.length>limit)throw Error('Debian tracker list exceeds size limit or is empty');return bytes.toString('utf8');}
// Preserve whole upstream blocks, including cross references and every release
// line, so server-side package projection cannot alter a record's meaning.
function projectDebianList(input,{list,packages,maxListBytes=128*1024*1024}={}) {
 if(!['CVE','DSA','DLA'].includes(list)||!Array.isArray(packages)||packages.length>5000 || packages.some(p=>typeof p!=='string'||!/^[a-z0-9][a-z0-9+.-]{0,199}$/.test(p)))throw Error('invalid Debian tracker projection');
 const wanted=new Set(packages),text=normalizeList(input,maxListBytes),out=[];let block=[],keep=false;
 const flush=()=>{if(keep)out.push(block.join('\n'));block=[];keep=false;};
 for(const line of text.split(/\r?\n/)){
  if(line && !/^\s/.test(line)){flush();block=[line];continue;}
  if(!block.length)continue;block.push(line);
  const m=line.match(/^\s+(?:\[[^\]]+\]\s+)?-\s+([a-z0-9][a-z0-9+.-]*)\s+/);
  if(m&&wanted.has(m[1]))keep=true;
 }
 flush();return out.length?out.join('\n')+'\n':'';
}
function parseHistoricalDebian(lists, distribution, options={}) {
 const d=checkDistribution(distribution),limit=options.maxListBytes??128*1024*1024;
 const partial=Array.isArray(options.packages),cves=normalizeList(lists.CVE,limit,partial), notices=['DSA','DLA'].map(k=>[k,normalizeList(lists[k],limit,partial)]);
 const grouped=new Map(),rejected=new Set(); let id=null,description='',releaseLines=0,headers=0;
 const add=(pkg,record)=>{if(!grouped.has(pkg))grouped.set(pkg,new Map());const by=grouped.get(pkg);if(!by.has(record.id))by.set(record.id,{id:record.id,description:record.description||'',statuses:[],fixes:[],globalNotes:[],contextNotes:[]});const r=by.get(record.id);if(record.description&&!r.description)r.description=record.description;if(record.status)r.statuses.push(record.status);if(record.fix)r.fixes.push(record.fix);if(record.globalNote)r.globalNotes.push(record.globalNote);if(record.contextNote)r.contextNotes.push(record.contextNote);};
 for(const line of cves.split(/\r?\n/)) {
  if(!/^\s/.test(line)){const m=line.match(/^(CVE-\d{4}-\d{4,})\b\s*(.*)$/);id=m?.[1]||null;description=m?.[2]||'';if(id)headers++;continue;}
  if(!id)continue;
  if(/^\s+REJECTED\s*$/.test(line)){rejected.add(id);continue;}
  const m=line.match(/^\s+(?:\[([^\]]+)\]\s+)?-\s+([a-z0-9][a-z0-9+.-]*)\s+(\S+)(.*)$/);
  if(!m)continue;
  const token=m[3],tag=token.match(/^<([^>]+)>$/);
  if(m[1]&&!m[1].split(/[,\s]+/).includes(d.codename)){
   if(options.includeContextReleases)add(m[2],{id,description,contextNote:{releases:m[1].split(/[,\s]+/).filter(Boolean),kind:tag?tag[1]:'fixed',version:tag?null:token,note:m[4].trim(),source:'CVE/list'}});
   continue;
  }
  if(!m[1]){add(m[2],{id,description,globalNote:{kind:tag?tag[1]:'fixed',version:tag?null:token,note:m[4].trim(),source:'CVE/list'}});continue;}
  releaseLines++;
  if(tag)add(m[2],{id,description,status:{kind:tag[1],note:m[4].trim(),source:'CVE/list'}});
  else add(m[2],{id,description,fix:{version:token,source:'CVE/list',note:m[4].trim()}});
 }
 if(!partial && (!headers || !releaseLines))throw Error('Debian tracker snapshot lacks release-scoped records');
 for(const [kind,text] of notices){let notice=null,ids=[],entries=[];const flush=()=>{if(!notice)return;for(const entry of entries)for(const cve of ids)if(CVE.test(cve))add(entry.pkg,{id:cve,fix:{version:entry.version,source:`${kind}/list`,advisory:notice}});};
  for(const line of text.split(/\r?\n/)){
   if(!/^\s/.test(line)){flush();const m=line.match(/^\[[^\]]+\]\s+((?:DSA|DLA)-\d+-\d+)\b/);notice=m?.[1]||null;ids=[];entries=[];continue;}
   if(!notice)continue;const m=line.match(/^\s+\{([^}]+)\}/);if(m)ids.push(...m[1].split(/\s+/));
   const r=line.match(/^\s+\[([^\]]+)\]\s+-\s+([a-z0-9][a-z0-9+.-]*)\s+(\S+)/);
   if(r&&r[1].split(/[,\s]+/).includes(d.codename) && !r[3].startsWith('<'))entries.push({pkg:r[2],version:r[3]});
  }flush();
 }
 for(const records of grouped.values())for(const cve of records.keys())if(rejected.has(cve))records.delete(cve);
 return {distribution:d,packages:new Map([...grouped].filter(([,v])=>v.size).map(([k,v])=>[k,[...v.values()]])),releaseLines};
}
async function importHistoricalDebian(lists,opts={}) {
 const distribution=checkDistribution(opts.distribution),commit=String(opts.commit||'');
 if(!/^[a-f0-9]{40}$/.test(commit))throw Error('immutable Debian tracker commit is required');
 if(!validDate(opts.cutoff))throw Error('historical cutoff date is required');
 if(Date.parse(opts.cutoff+'T23:59:59Z')>Date.now())throw Error('Explicit historical Debian cutoff is in the future');
 if(opts.commitTimestamp && (!Number.isFinite(Date.parse(opts.commitTimestamp)) || Date.parse(opts.commitTimestamp)>Date.parse(opts.cutoff+'T23:59:59Z')))throw Error('Debian tracker commit is outside the historical cutoff');
 const normalized={};for(const k of ['CVE','DSA','DLA']){const v=lists[k];normalized[k]=typeof v==='string'&&fs.existsSync(v)?fs.readFileSync(v):v;if(normalized[k]==null)throw Error('all Debian tracker lists are required');}
 if(opts.packages && (!Array.isArray(opts.packages)||opts.packages.some(p=>typeof p!=='string'||!/^[a-z0-9][a-z0-9+.-]{0,199}$/.test(p))))throw Error('invalid Debian tracker package scope');
 const parsed=parseHistoricalDebian(normalized,distribution,opts),cache=repository(opts),ns=NAMESPACE(distribution),now=Number.isFinite(opts.fetchedAt)?opts.fetchedAt:Date.now(),previous=cache.getSnapshot(ns),partial=Array.isArray(opts.packages);
 if(partial){const permitted=new Set(opts.packages);for(const name of parsed.packages.keys())if(!permitted.has(name))parsed.packages.delete(name);}
 const hashes=Object.fromEntries(Object.entries(normalized).map(([k,v])=>[k,crypto.createHash('sha256').update(v).digest('hex')]));
 const write=()=>{
  if(!partial || previous?.metadata?.commit!==commit || previous?.metadata?.parserVersion!==PARSER_VERSION){for(const [key] of cache.entries(ns))cache.delete(ns,key);}
  else if(previous.complete)throw Error('partial Debian tracker snapshot cannot replace a complete snapshot');
  if(partial)for(const name of opts.packages)cache.delete(ns,name);
  for(const [name,records] of parsed.packages)cache.put(ns,name,records,{fetchedAt:now});
  const queriedPackages=partial?[...new Set([...(previous?.metadata?.commit===commit&&previous.metadata.parserVersion===PARSER_VERSION?previous.metadata.queriedPackages||[]:[]),...opts.packages])].sort():null;
  cache.putSnapshot(ns,{fetchedAt:now,complete:!partial,recordCount:[...parsed.packages.values()].reduce((n,x)=>n+x.length,0),metadata:{distribution,commit,parserVersion:PARSER_VERSION,commitTimestamp:opts.commitTimestamp||null,cutoff:opts.cutoff,hashes,source:SALSA,acquisition:opts.acquisition||'import',sourceFetchedAt:opts.sourceFetchedAt||null,sourceHashes:opts.sourceHashes||null,releaseLines:parsed.releaseLines,queriedPackages}});
 };
 if(cache.db?.transaction)cache.db.transaction(write);else write();
 return {distribution,commit,cutoff:opts.cutoff,packageCount:parsed.packages.size,releaseLines:parsed.releaseLines,hashes,fetchedAt:now};
}
async function bounded(response,max) {if(!response?.ok)throw Error(`Debian historical source HTTP ${response?.status||'failure'}`);const chunks=[];let n=0;for await(const part of response.body||[]){n+=part.length;if(n>max)throw Error('Debian historical source exceeds download limit');chunks.push(Buffer.from(part));}return Buffer.concat(chunks,n);}
async function syncHistoricalDebian(distribution,opts={}) {
 const d=checkDistribution(distribution);if(opts.offline)throw Error('cannot sync Debian history offline');
 if(opts.packages!==undefined&&!Array.isArray(opts.packages))throw Error('invalid Debian tracker package scope');
 const packages=opts.packages===undefined?null:[...new Set(opts.packages)];
 if(packages && (packages.length>(opts.maxPackages??100000) || packages.some(p=>typeof p!=='string'||!/^[a-z0-9][a-z0-9+.-]{0,199}$/.test(p))))throw Error('invalid Debian tracker package scope');
 if(packages && !packages.length)return {notApplicable:true,reason:'no-source-packages'};
 const transport=opts.fetchResource || ((kind,p)=>kind==='lifecycle' ? require('../providers').getResource('eol','product',{product:p.distribution},{fetcher:opts.fetcher,signal:opts.signal}) : require('../providers').getResource('debian',kind,p,{streaming:true,fetcher:opts.fetcher,signal:opts.signal}));
 const sourceFetchedAt={},sourceHashes={};
 const get=async(kind,params,key,max)=>{const res=await transport(kind,params);const stamp=Date.parse(res.headers?.get?.('x-fad-proxy-fetched-at')||'');sourceFetchedAt[key]=Number.isFinite(stamp)&&stamp<=Date.now()?stamp:Date.now();const hash=res.headers?.get?.('x-vigievuln-source-sha256');if(/^[a-f0-9]{64}$/.test(hash||''))sourceHashes[key]=hash;return bounded(res,max);};
 let cutoff=opts.cutoff;
 if(!cutoff){const cycles=JSON.parse((await get('lifecycle',{distribution:'debian'},'lifecycle',opts.maxMetadataBytes??4*1024*1024)).toString());const cycle=Array.isArray(cycles)&&cycles.find(x=>String(x.cycle)===d.versionId && String(x.codename||'').toLowerCase()===d.codename);cutoff=cycle?.eol;}
 if(!validDate(cutoff))throw Error('No valid historical Debian release cutoff is available');
 if(Date.parse(cutoff+'T23:59:59Z')>Date.now()){
  if(opts.cutoff)throw Error('Explicit historical Debian cutoff is in the future');
  return {notApplicable:true,reason:'release-not-historical'};
 }
 const until=cutoff+'T23:59:59Z',history=JSON.parse((await get('history',{until},'history',opts.maxMetadataBytes??4*1024*1024)).toString());
 const commit=Array.isArray(history)&&history[0]?.id,at=history?.[0]?.committed_date;
 if(!/^[a-f0-9]{40}$/.test(commit||'')||!Number.isFinite(Date.parse(at))||Date.parse(at)>Date.parse(until))throw Error('Invalid Debian tracker historical commit');
 const lists={};
 // The relay projects at most 1000 package names per request. The direct
 // source returns the whole list irrespective of params, so download it once.
 if(!packages && !opts.fetchResource)throw Error('Debian history sync requires source package names');
 const chunks=packages?Array.from({length:Math.ceil(packages.length/1000)},(_,i)=>packages.slice(i*1000,i*1000+1000)):[null];
 const direct=!opts.fetchResource&&!require('../providers').hasProxyRoute();
 for(const name of ['CVE','DSA','DLA']){
  const parts=[];for(let i=0;i<(direct?1:chunks.length);i++){
   const bytes=await get('list',{commit,list:name,...(chunks[i]?{packages:chunks[i]}:{})},i?`${name}:${i}`:name,opts.maxDownloadBytes??128*1024*1024);
   if(i && sourceHashes[name] && sourceHashes[`${name}:${i}`] && sourceHashes[name]!==sourceHashes[`${name}:${i}`])throw Error('Debian tracker projection source changed between pages');
   parts.push(bytes);
  }lists[name]=Buffer.concat(parts.flatMap((part,i)=>i?[Buffer.from('\n'),part]:[part]));
 }
 return importHistoricalDebian(lists,{...opts,packages,distribution:d,commit,commitTimestamp:at,cutoff,acquisition:'network',sourceFetchedAt,sourceHashes,fetchedAt:Math.min(...Object.values(sourceFetchedAt))});
}
function evaluateTrackerRecord(rec,version) {
 const statuses=rec.statuses||[],fixes=rec.fixes||[],globalNotes=rec.globalNotes||[];
 const tags=new Set(statuses.map(s=>s.kind)),fixed=fixes.map(f=>f.version).filter(v=>compare(v,v)===0).sort(compare);
 const annotations=statuses.filter(s=>['no-dsa','ignored','postponed'].includes(s.kind));
 const unsupported=[...tags].some(t=>!['not-affected','unfixed','removed','no-dsa','ignored','postponed'].includes(t));
 let threshold=null,releaseFix=null,affected=null,scope='release-specific';
 if(!version || compare(version,version)!==0 || unsupported || fixes.some(f=>compare(f.version,f.version)!==0)) affected=null;
 else if(tags.has('unfixed') || tags.has('removed')) affected=true;
 else if(fixed.length){releaseFix=fixed[fixed.length-1];threshold=releaseFix;affected=compare(version,threshold)<0;}
 else if(tags.has('not-affected')) affected=false;
 else {
  scope='inherited-source-note';
  const globalKinds=new Set(globalNotes.map(n=>n.kind)),globalFixed=globalNotes.filter(n=>n.kind==='fixed').map(n=>n.version);
  if(globalNotes.some(n=>n.kind==='fixed' && compare(n.version,n.version)!==0) || [...globalKinds].some(k=>!['fixed','unfixed','removed','not-affected'].includes(k))) affected=null;
  else if(globalKinds.has('unfixed') || globalKinds.has('removed')) affected=true;
  else if(globalFixed.length){globalFixed.sort(compare);threshold=globalFixed[globalFixed.length-1];affected=compare(version,threshold)<0;}
  else if(globalKinds.has('not-affected')) affected=false;
 }
 const effectiveNotes=scope==='inherited-source-note' ? globalNotes : [...statuses.filter(s=>s.kind==='unfixed'||s.kind==='removed'),...fixes.filter(f=>f.version===releaseFix)];
 const trackerUrgency=effectiveNotes.some(n=>/\(unimportant(?:\s*[;)]|$)/i.test(n.note||''))?'unimportant':null;
 return {affected,threshold,releaseFix,scope,annotations,trackerUrgency,statuses,fixes,globalNotes};
}
function assessHistoricalDebian(inventory,opts={}) {
 let d;try{d=checkDistribution(inventory?.distribution);}catch{return {matches:[],coverage:[{source:SOURCE,status:'unknown',result:'indeterminate',reason:'missing exact Debian distribution identity'}],warnings:[]};}
 const cache=repository(opts),ns=NAMESPACE(d),snapshot=cache.getSnapshot(ns),matches=[],observations=[],warnings=[],coverage=[];
 if(!snapshot)return {matches,observations,coverage:[{source:SOURCE,status:'missing',result:'indeterminate'}],warnings:['No historical Debian release snapshot is cached']};
 let unknown=0,examined=0;
 for(const dep of inventory.packages||[]){if(!dep.sourceName || !dep.sourceVersion || (!snapshot.complete && !snapshot.metadata?.queriedPackages?.includes(dep.sourceName))){unknown++;continue;}const version=dep.sourceVersion;if(compare(version,version)!==0){unknown++;continue;}
  const entry=cache.get(ns,dep.sourceName);if(!entry)continue;
  for(const rec of entry.value){
   examined++;
   const {affected,threshold,releaseFix,scope,annotations,trackerUrgency,statuses,fixes,globalNotes}=evaluateTrackerRecord(rec,version);
   if(affected===null){unknown++;observations.push({dep,cveId:rec.id,status:'unknown',reason:'no usable tracker package/version verdict',evidence:{statuses,fixes,globalNotes}});continue;}
   if(!affected)continue;
   {
    const evidence={distribution:d,commit:snapshot.metadata.commit,commitTimestamp:snapshot.metadata.commitTimestamp||null,cutoff:snapshot.metadata.cutoff,fixes,globalNotes,annotations,scope,comparisonThreshold:threshold,trackerUrgency};
    // Identity is conditional on the installed package metadata, like the OSV
    // adapter. Archive corroboration is separate from authenticating its bytes.
    const declared=typeof dep.packageMetadata?.origin==='string' ? dep.packageMetadata.origin.trim() : '';
    const declaredOrigin=declared && declared.toLowerCase()!=='debian' ? {status:'third-party',source:'dpkg-origin',declared} : null;
    const origin=(typeof opts.packageOrigin==='function'?opts.packageOrigin(dep,d):dep.packageOrigin) || declaredOrigin || cache.get('system-debian-origin',originKey(dep.sourceName,version))?.value || {status:'distribution-context'};
    if(['third-party','ambiguous'].includes(origin.status)){unknown++;observations.push({dep,cveId:rec.id,status:'possible',reason:'package vendor provenance does not establish Debian origin',evidence:{...evidence,origin}});continue;}
    const originStatus=origin.status==='corroborated' && (!Array.isArray(origin.suites) || origin.suites.includes(d.codename))?'corroborated':'distribution-context';
    matches.push({dep,source:SOURCE,advisoryId:rec.id,cve:{id:rec.id,summary:rec.description,description:rec.description,severity:'UNKNOWN',fixVersion:releaseFix,advisorySource:`https://security-tracker.debian.org/tracker/${rec.id}`,historicalEvidence:{...evidence,originStatus,origin}}});
   }
  }
 }
 const meta=snapshot.metadata||{},legacy=meta.parserVersion!==PARSER_VERSION;
 coverage.push({source:SOURCE,status:legacy?'incomplete':'complete',execution:legacy?'partial':'completed',result:'indeterminate',complete:!legacy,completeness:'historical-only',scope:'historical-release-evidence',parserVersion:meta.parserVersion||1,queriedPackages:meta.queriedPackages||null,historicalCutoff:meta.cutoff,commit:meta.commit,commitTimestamp:meta.commitTimestamp||null,fetchedAt:snapshot.fetchedAt,sourceFetchedAt:meta.sourceFetchedAt,examined,unknown,reason:legacy?'Historical cache predates inherited source notes; refresh for complete historical assessment.':'Historical release evidence ends at the snapshot; later vulnerabilities remain unassessed.'});
 return {matches,observations,coverage,warnings};
}
module.exports={SOURCE,PARSER_VERSION,namespace:NAMESPACE,checkDistribution,projectDebianList,parseHistoricalDebian,evaluateTrackerRecord,importHistoricalDebian,syncHistoricalDebian,syncDebianPackageOrigins,assessHistoricalDebian};
