'use strict';
const fs=require('node:fs');
const {unzipSync}=require('fflate');
const {createCacheRepository}=require('../cache/repository');
const versions=require('./versions');
const {severityFromOsv}=require('../providers/osv/query');
// One entry per distribution: the os-release ids it answers to, the OSV archive that holds its
// advisories (`base`), how its package versions compare, and which OSV ecosystem(s) describe
// an installed release: one name (`release`) or, for a product whose packages are published
// under several names (RHEL repositories, SUSE modules), a `label` and a predicate (`accepts`).
// `fixedOnly`: the distribution publishes errata, so a vulnerability it has not fixed yet has
// no record (Debian, Ubuntu and Alpine track those; Azure Linux records them too).
const escape=text=>text.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
const servicePack=v=>{const [major,minor]=v.split('.');return minor && minor!=='0' ? `${major} SP${minor}` : major;};
const DISTRIBUTIONS=[
 {ids:['debian'],base:'Debian',scheme:'debian',release:v=>v.split('.')[0]},
 {ids:['ubuntu'],base:'Ubuntu',scheme:'debian',release:v=>{const p=v.split('.');const release=p.slice(0,2).join('.');return p[1]==='04' && Number(p[0])%2===0 ? release+':LTS' : release;}},
 {ids:['alpine'],base:'Alpine',scheme:'apk',release:v=>'v'+v.replace(/^v/,'').split('.').slice(0,2).join('.')},
 ...[['almalinux','AlmaLinux'],['rocky','Rocky Linux']].map(([id,base])=>({ids:[id],base,scheme:'rpm',release:v=>v.split('.')[0],fixedOnly:true})),
 {ids:['mageia'],base:'Mageia',scheme:'rpm',release:v=>v.split('.')[0],fixedOnly:true},
 {ids:['azurelinux','mariner'],base:'Azure Linux',scheme:'rpm',release:v=>v.split('.')[0]},
 {ids:['opensuse-leap'],base:'openSUSE',scheme:'rpm',release:v=>'Leap '+v,fixedOnly:true},
 {ids:['opensuse-tumbleweed'],base:'openSUSE',scheme:'rpm',release:()=>'Tumbleweed',fixedOnly:true},
 // os-release gives VERSION_ID="24.03" and the service pack only in its name: "openEuler 24.03 (LTS-SP1)", "openEuler 22.03 LTS".
 {ids:['openeuler'],base:'openEuler',scheme:'rpm',fixedOnly:true,release:(v,d)=>{const pack=/\b(LTS(?:-SP\d+)?)\b/.exec(String(d.name||''));return pack ? `${v}-${pack[1]}` : v;}},
 // Red Hat files an erratum under the repository that ships the package (baseos, appstream,
 // crb…), and under the extended-support stream of one minor release when it only fixes that.
 // CentOS Linux and Oracle Linux rebuild the same packages and have no feed of their own
 // here: they are assessed against the Red Hat errata of the release they rebuild (CentOS
 // Stream is not a rebuild of a released RHEL and is left out).
 {ids:['rhel','centos','ol'],applies:d=>String(d.id).toLowerCase()!=='centos' || !/stream/i.test(String(d.name||'')),
  base:'Red Hat',scheme:'rpm',fixedOnly:true,label:v=>'enterprise_linux:'+v.split('.')[0],accepts(v){
  const [major,minor]=v.split('.'),m=escape(major),own=minor===undefined?null:Number(minor);
  const general=new RegExp(`^Red Hat:enterprise_linux:${m}(?:\\.(\\d+))?(?:::[a-z0-9_]+)?$`),stream=new RegExp(`^Red Hat:rhel_[a-z0-9_]+:${m}\\.(\\d+)(?:::[a-z0-9_]+)?$`);
  return ecosystem=>{const g=general.exec(ecosystem);if(g)return g[1]===undefined || own===null || Number(g[1])<=own;const e=stream.exec(ecosystem);return !!e && own!==null && Number(e[1])===own;};
 }},
 // SUSE Linux Enterprise ships its packages through the product and its modules, each an
 // ecosystem of its own: "Linux Enterprise Server 15 SP5", "…Module for Basesystem 15 SP5".
 {ids:['sles','sled','sles_sap','sle_hpc'],base:'SUSE',scheme:'rpm',fixedOnly:true,label:v=>'Linux Enterprise '+servicePack(v),accepts(v){
  const pattern=new RegExp(`^SUSE:Linux Enterprise (?!Micro\\b).*\\b${escape(servicePack(v))}(?:-[A-Z]+)?$`);return ecosystem=>pattern.test(ecosystem);
 }},
 {ids:['sle-micro','sl-micro'],base:'SUSE',scheme:'rpm',fixedOnly:true,release:v=>'Linux Enterprise Micro '+v},
 // Rolling distributions without releases. Their advisories come from the security database of
 // their package repositories (lib/providers/wolfi), not from an OSV archive of several hundred MB.
 {ids:['wolfi'],base:'Wolfi',scheme:'apk',fixedOnly:true,rolling:true,secdb:['wolfi']},
 {ids:['chainguard'],base:'Chainguard',scheme:'apk',fixedOnly:true,rolling:true,secdb:['chainguard','wolfi']},
];
const defaultAdapters=DISTRIBUTIONS.map(d=>({id:d.base,resolveScope(distribution){
 if(!d.ids.includes(String(distribution?.id||'').toLowerCase()) || (!distribution?.versionId && !d.rolling) || (d.applies && !d.applies(distribution)))return null;
 if(d.rolling)return {base:d.base,ecosystem:d.base,compare:versions[d.scheme],fixedOnly:!!d.fixedOnly,secdb:d.secdb};
 const v=String(distribution.versionId);if(!/^[A-Za-z0-9._-]+$/.test(v))return null;
 return {base:d.base,ecosystem:d.base+':'+(d.label ? d.label(v,distribution) : d.release(v,distribution)),compare:versions[d.scheme],fixedOnly:!!d.fixedOnly,
  ...(d.accepts ? {accepts:d.accepts(v,distribution)} : {})};
}}));
// The OSV ecosystems a scope covers: its own name, or every name its predicate accepts.
const inScope=(s,ecosystem)=>typeof ecosystem==='string' && (s.accepts ? s.accepts(ecosystem) : ecosystem===s.ecosystem);
function scope(d,opts={}) {
 if(opts.advisoryConfig) {
  const c=opts.advisoryConfig;
  if(!c || typeof c!=='object' || !c.distribution || typeof c.distribution.id!=='string' || typeof c.distribution.versionId!=='string' || typeof c.base!=='string' || !/^[A-Za-z0-9 ._+-]+$/.test(c.base) || typeof c.ecosystem!=='string' || !c.ecosystem.startsWith(c.base+':') || !/^[A-Za-z0-9 ._:+-]+$/.test(c.ecosystem) || !Object.hasOwn(versions,c.versionScheme))throw Error('invalid system advisory configuration');
  if(c.distribution.id===d?.id && c.distribution.versionId===d?.versionId){
   let sourceUrl=null;
   if(c.sourceUrl!==undefined){
    let u;try{u=new URL(c.sourceUrl);}catch{throw Error('invalid advisory source URL');}
    if(u.username || u.password || !(u.protocol==='https:' || (u.protocol==='http:' && c.allowInsecure===true)))throw Error('advisory source URL requires HTTPS and must not include credentials');
    sourceUrl=u.toString();
   }
   return {base:c.base,ecosystem:c.ecosystem,compare:versions[c.versionScheme],sourceUrl};
  }
 }
 for(const adapter of opts.adapters||defaultAdapters){
  if(!adapter || typeof adapter.resolveScope!=='function')throw Error('invalid system advisory adapter');
  const result=adapter.resolveScope(d);if(!result)continue;
  if(typeof result.base!=='string' || !/^[A-Za-z0-9 ._+-]+$/.test(result.base) || typeof result.ecosystem!=='string' || typeof result.compare!=='function')throw Error('invalid system advisory scope');
  return result;
 }
 return null;
}
function repo(opts){return opts.repository || createCacheRepository(opts.cacheDir);}
function namespace(s){return 'system-osv:'+s.ecosystem;}
function recordsFrom(input,opts={}) {
 const maxEntries=opts.maxEntries ?? 500000, maxEntryBytes=opts.maxEntryBytes ?? 64*1024*1024, maxExpandedBytes=opts.maxExpandedBytes ?? 1024*1024*1024;
 if(Array.isArray(input))return input;
 if(input && typeof input==='object' && !Buffer.isBuffer(input) && !(input instanceof Uint8Array))return input.records || [input];
 const b=Buffer.isBuffer(input)?input:Buffer.from(input);
 if(b[0]===0x50 && b[1]===0x4b) {
  let expanded=0, entries=0;
  const files=unzipSync(b,{filter(entry){
   if(++entries>maxEntries || entry.originalSize>maxEntryBytes || (expanded+=entry.originalSize)>maxExpandedBytes)throw Error('OSV archive exceeds resource limits');
   return entry.name.endsWith('.json');
  }}), out=[];
  for(const [name,bytes] of Object.entries(files))if(name.endsWith('.json'))out.push(JSON.parse(Buffer.from(bytes).toString('utf8')));
  return out;
 }
 const text=b.toString('utf8').trim();try {const json=JSON.parse(text);return Array.isArray(json)?json:json.records || [json];}catch{return text.split(/\r?\n/).filter(Boolean).map(line=>JSON.parse(line));}
}
async function importSystemAdvisories(file,opts={}) {
 const distribution=opts.distribution, s=scope(distribution,opts);if(!s)throw Error('unsupported or missing distribution identity');
 const input=typeof file==='string'?fs.readFileSync(file):file, records=recordsFrom(input,opts), grouped=new Map();
 if(!records.length)throw Error('empty OSV snapshot');
 for(const record of records) {
  if(!record || typeof record.id!=='string' || !Array.isArray(record.affected))throw Error('invalid OSV advisory');
  if(record.withdrawn)continue;
  for(const a of record.affected) {
   if(!inScope(s,a?.package?.ecosystem) || !a.package.name)continue;
   const name=a.package.name; if(!grouped.has(name))grouped.set(name,[]);
   // Some feeds publish a bound with stray whitespace (" 1.57.0-1"): it is the version, not an unknown one.
   const ranges=Array.isArray(a.ranges) ? a.ranges.map(r=>Array.isArray(r?.events) ? {...r,events:r.events.map(e=>e && typeof e==='object' ? Object.fromEntries(Object.entries(e).map(([k,v])=>[k,typeof v==='string'?v.trim():v])) : e)} : r) : a.ranges;
   grouped.get(name).push({...record,affected:[{...a,...(ranges ? {ranges} : {})}]});
  }
 }
 if(!grouped.size)throw Error(`OSV snapshot contains no records for ${s.ecosystem}`);
 const cache=repo(opts), ns=namespace(s), now=Date.now(), complete=opts.complete===true;
 if(!complete && cache.getSnapshot(ns)?.complete && !opts.replaceComplete)throw Error('partial snapshot cannot replace a complete snapshot');
 const save=()=>{
  for(const [key] of cache.entries(ns))cache.delete(ns,key);
  for(const [key,value] of grouped)cache.put(ns,key,value,{fetchedAt:now});
  cache.putSnapshot(ns,{fetchedAt:now,complete,recordCount:records.length,metadata:{ecosystem:s.ecosystem,packageCount:grouped.size,source:opts.source||'import'}});
 };
 if(cache.db?.transaction)cache.db.transaction(save);else save();
 return {ecosystem:s.ecosystem,recordCount:records.length,packageCount:grouped.size,complete,fetchedAt:now};
}
async function syncSystemAdvisories(distribution,opts={}) {
 const s=scope(distribution,opts);if(!s)throw Error('unsupported or missing distribution identity');
 if(opts.offline)throw Error('cannot sync system advisories offline');
 if(s.secdb && !s.sourceUrl){
  let records;try{records=await require('../providers/wolfi/secdb').fetchRecords(s,opts);}catch(error){throw Error(`system advisory download failed: ${error.message}`);}
  return importSystemAdvisories(records,{...opts,distribution,complete:true,source:s.secdb.map(r=>require('../providers/wolfi').REPOSITORIES[r]).join(' ')});
 }
 const url=s.sourceUrl || `https://osv-vulnerabilities.storage.googleapis.com/${encodeURIComponent(s.base)}/all.zip`;
 const source=new URL(url);source.search='';source.hash='';
 const timeout=opts.systemAdvisoryTimeoutMs??120000;
 if(!Number.isSafeInteger(timeout)||timeout<=0)throw Error('invalid system advisory timeout');
 const deadline=AbortSignal.timeout(timeout),signal=opts.signal?AbortSignal.any([opts.signal,deadline]):deadline;
 let response;try{response=await require('../providers').getResource('osvdb','ecosystem-archive',{ecosystem:s.base},{streaming:true,fetcher:opts.fetcher,...(s.sourceUrl?{urlOverride:s.sourceUrl}:{}),signal});}catch{throw Error('system advisory download failed');}if(!response.ok)throw Error(`OSV snapshot HTTP ${response.status}`);
 const maxBytes=opts.maxDownloadBytes ?? 512*1024*1024;
 const declared=Number(response.headers?.get?.('content-length'));if(declared>maxBytes)throw Error('OSV snapshot exceeds download limit');
 let bytes;
 try {
  if(response.body?.[Symbol.asyncIterator]){const chunks=[];let total=0;for await(const chunk of response.body){total+=chunk.length;if(total>maxBytes){await response.body.cancel?.().catch(()=>{});throw Error('OSV snapshot exceeds download limit');}chunks.push(Buffer.from(chunk));}bytes=Buffer.concat(chunks,total);}
  else {bytes=Buffer.from(await response.arrayBuffer());if(bytes.length>maxBytes)throw Error('OSV snapshot exceeds download limit');}
 } catch(e) {if(e.message==='OSV snapshot exceeds download limit')throw e;throw Error('system advisory download failed');}
 if(!bytes.length)throw Error('empty OSV snapshot');
 return importSystemAdvisories(bytes,{...opts,distribution,complete:true,source:source.toString()});
}
// RPM modularity. An erratum built for a module stream (release ".module+el8…", summary
// "php:7.4 security update") states the fix of that stream only. It does not describe a
// non-modular package of the same name, nor a package installed from another stream.
function rpmModuleApplies(dep,version,record,affected) {
 const modular=value=>/\.module[+_]/.test(String(value||''));
 const bounds=(affected.ranges||[]).flatMap(r=>r.events||[]).flatMap(e=>[e.fixed,e.last_affected]).filter(v=>typeof v==='string');
 if(!bounds.length)return true;
 const advisoryModular=bounds.every(modular);
 if(advisoryModular!==modular(dep.version) && bounds.every(v=>modular(v)===advisoryModular))return false;
 if(!advisoryModular || !dep.modularityLabel)return true;
 const stream=String(record.summary||'').match(/(?:^|[\s:])([A-Za-z0-9][A-Za-z0-9_+.-]*):([A-Za-z0-9][A-Za-z0-9_.+-]*)\s+(?:security|bug fix|enhancement)/);
 if(!stream)return true;
 const [name,installed]=dep.modularityLabel.split(':');
 return name===stream[1] && installed===stream[2];
}
function verdict(version,affected,compare) {
 if(!version || compare(version,version)!==0)return null;
 let unknown=false;
 // OSV: affected when listed in versions[] OR inside a range — the list counts even beside ranges.
 if(Array.isArray(affected.versions))for(const v of affected.versions)if(compare(version,v)===0)return true;
 for(const range of affected.ranges||[]) {
  if(range.type!=='ECOSYSTEM' || !Array.isArray(range.events) || !range.events.length){unknown=true;continue;}
  let active=false,valid=true;
  const events=range.events.map(ev=>{const keys=['introduced','fixed','last_affected','limit'].filter(k=>ev[k]!==undefined);return keys.length===1?{kind:keys[0],value:String(ev[keys[0]])}:null;});
  if(events.some(e=>!e)){unknown=true;continue;}
  for(const ev of events) if(!(ev.kind==='introduced'&&ev.value==='0') && compare(ev.value,ev.value)!==0)valid=false;
  if(!valid){unknown=true;continue;}
  const cmpEvent=(a,b)=>{if(a.kind==='introduced'&&a.value==='0')return b.kind==='introduced'&&b.value==='0'?0:-1;if(b.kind==='introduced'&&b.value==='0')return 1;return compare(a.value,b.value)||({introduced:0,last_affected:1,fixed:2,limit:3}[a.kind]-{introduced:0,last_affected:1,fixed:2,limit:3}[b.kind]);};
  events.sort(cmpEvent);
  let opened=false;
  for(const event of events){
   if(event.kind==='introduced'){if(opened){valid=false;break;}opened=true;}
   else if(event.kind==='fixed' || event.kind==='last_affected'){if(!opened){valid=false;break;}opened=false;}
  }
  if(!valid){unknown=true;continue;}
  for(const event of events) {
   const ev={[event.kind]:event.value};
   const keys=['introduced','fixed','last_affected','limit'].filter(k=>ev[k]!==undefined);
   if(keys.length!==1){valid=false;break;}const k=keys[0],v=String(ev[k]);
   const c=v==='0'&&k==='introduced'?1:compare(version,v);if(c===null){valid=false;break;}
   if(k==='introduced'&&c>=0)active=true;
   else if(k==='fixed'&&c>=0)active=false;
   else if(k==='last_affected'&&c>0)active=false;
   else if(k==='limit'&&c>=0)active=false;
  }
  if(valid&&active)return true;if(!valid)unknown=true;
 }
 if(!(affected.ranges||[]).length && !(affected.versions||[]).length)unknown=true;
 return unknown?null:false;
}
async function assessSystemInventory(inventory,opts={}) {
 const s=scope(inventory.distribution,opts),matches=[],warnings=[],coverage=[];
 if(!s)return {matches,coverage:[{source:'system-osv',status:'unknown',reason:'unsupported or missing distribution identity'}],warnings};
 const cache=opts.records?null:repo(opts),ns=namespace(s),snapshot=opts.records?{complete:opts.complete===true,fetchedAt:opts.fetchedAt}:cache.getSnapshot(ns);
 if(!snapshot)return {matches,coverage:[{source:'system-osv',status:'missing',ecosystem:s.ecosystem}],warnings:['No offline system advisory snapshot for '+s.ecosystem]};
 let uncertain=0; const uncertainItems=[], assessedPackages=[];
 const unknown=(dep,reason,id)=>{uncertain++;uncertainItems.push({id,package:dep.name,version:dep.version,reason});};
 for(const dep of inventory.packages||[]) {
  const before=uncertain;
  const names=[...new Set([dep.sourceName,dep.name].filter(Boolean))];
  if(!dep.sourceName)unknown(dep,'Source package identity is not declared in the installed metadata.');
  const records=opts.records ? opts.records.filter(r=>r.affected?.some(a=>inScope(s,a.package?.ecosystem) && names.includes(a.package?.name))) : names.flatMap(name=>{const entry=cache.get(ns,name);return entry && entry.fetchedAt===snapshot.fetchedAt ? entry.value : [];});
  for(const record of records)for(const a of record.affected||[]) {
   if(!inScope(s,a.package?.ecosystem) || !names.includes(a.package?.name))continue;
   const purl=a.package.purl||'', arch=(purl.match(/[?&]arch=([^&]+)/)||[])[1];
   const sourceArch=arch==='source' || (a.package.name===dep.sourceName && dep.sourceName!==dep.name);
   if(arch && arch!=='source' && dep.architecture && arch!==dep.architecture)continue;
   if(arch && arch!=='source' && !dep.architecture){unknown(dep,'Installed architecture is not declared.',record.id);continue;}
   let ver=sourceArch ? dep.sourceVersion : dep.version;
   // An RPM subpackage with its own version does not reveal its source epoch. The advisory
   // names that source package: its bounds carry the epoch, when they agree on one.
   if(dep.manager==='rpm' && sourceArch && dep.sourceEpochUnknown && ver){
    const epochs=new Set((a.ranges||[]).flatMap(r=>r.events||[]).flatMap(e=>[e.introduced,e.fixed,e.last_affected]).filter(v=>typeof v==='string' && v!=='0').map(v=>(v.match(/^(\d+):/)||[,'0'])[1]));
    ver=epochs.size===1 ? ([...epochs][0]==='0' ? ver : [...epochs][0]+':'+ver) : epochs.size ? null : ver;
   }
   if(dep.manager==='rpm' && !rpmModuleApplies(dep,ver,record,a))continue;
   const result=verdict(ver,a,s.compare);
   if(result===null){unknown(dep,'The available version range or installed source version does not establish applicability.',record.id);continue;}if(!result)continue;
   // A per-CVE distribution record (DEBIAN-CVE-…, UBUNTU-CVE-…, ALPINE-CVE-…) is shown under its CVE id.
   const severity=severityFromOsv(record), id=(record.aliases||[]).find(x=>/^CVE-/.test(x))||(/^[A-Z]+-(CVE-\d{4}-\d{4,})$/.exec(record.id)||[])[1]||record.id;
   const fixes=(a.ranges||[]).flatMap(r=>r.events||[]).map(e=>e.fixed).filter(v=>typeof v==='string' && s.compare(v,ver)>0).sort((x,y)=>s.compare(x,y));
   matches.push({dep,cve:{id,summary:record.summary||'',description:record.details||record.summary||'',severity:severity.severity,score:severity.score,
    sourceAdvisoryId:record.id,distributionAdvisory:{source:s.base,release:s.ecosystem},
    ...(typeof a.ecosystem_specific?.urgency==='string' ? {distributionUrgency:{source:s.base,release:s.ecosystem,value:a.ecosystem_specific.urgency}} : {}),
    published:record.published||null,modified:record.modified||null,
    aliases:Array.isArray(record.aliases)?record.aliases.filter(id=>typeof id==='string'):[],
    upstream:Array.isArray(record.upstream)?record.upstream.filter(id=>typeof id==='string'):[],
    related:Array.isArray(record.related)?record.related.filter(id=>typeof id==='string'):[],
    advisorySource:typeof a.database_specific?.source==='string'?a.database_specific.source:typeof record.database_specific?.source==='string'?record.database_specific.source:null,
    osvRefs:Array.isArray(record.references)?record.references:[],fixVersion:fixes[0]||null},source:'osv',advisoryId:record.id});
  }
  if(snapshot.complete && before===uncertain)assessedPackages.push(dep);
 }
 coverage.push({source:'system-osv',ecosystem:s.ecosystem,status:snapshot.complete && !uncertain?'complete':'incomplete',result:snapshot.complete && !uncertain?(matches.length?'affected':'no-match'):'indeterminate',complete:!!snapshot.complete,...(snapshot.complete?{affectsCompleteness:false}:{}),affectsAssessment:uncertain>0,fetchedAt:snapshot.fetchedAt||null,unknown:uncertain});
 if(uncertain)warnings.push({...require('../scan/diagnostics').advisoryEvidenceDiagnostic(uncertainItems),source:'system-osv'});
 return {matches,coverage,warnings,assessedPackages};
}
module.exports={scope,defaultAdapters,recordsFrom,verdict,importSystemAdvisories,syncSystemAdvisories,assessSystemInventory};
