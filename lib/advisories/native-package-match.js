'use strict';
// Shared native-record package matching. A typed PURL is required; neither
// product names nor advisory identifiers establish a package identity.
const {explicitPackage,identity}=require('../providers/gcve/local-index');
const {osvEcosystemFor,osvPkgName}=require('../providers/osv/query');
const {packageName}=require('./store');
const nativeVersions=require('../system-inventory/versions');
function systemPackage(a){
 const raw=typeof a?.packageURL==='string'?a.packageURL:typeof a?.purl==='string'?a.purl:null;
 if(!raw){
  const name=a?.packageName,url=a?.collectionURL;
  if(typeof name==='string'&&/^[a-z0-9][a-z0-9+.-]*$/.test(name)&&typeof url==='string'&&/^https:\/\/packages\.debian\.org\/?$/i.test(url)&&Array.isArray(a.versions)&&a.versions.some(v=>String(v?.versionType||'').toLowerCase()==='dpkg'))return {ecosystem:'system:deb:debian:*',name,manager:'deb',distribution:'debian',release:null,arch:'source'};
  return null;
 }
 if(!/^pkg:(?:deb|apk|rpm)\//i.test(raw))return null;
 const unqualified=/^pkg:deb\/debian\/([a-z0-9][a-z0-9+.-]*)$/i.exec(raw);
 if(unqualified&&Array.isArray(a.versions)&&a.versions.some(v=>String(v?.versionType||'').toLowerCase()==='dpkg'))return {ecosystem:'system:deb:debian:*',name:unqualified[1],manager:'deb',distribution:'debian',release:null,arch:'source'};
 const m=/^pkg:(deb|apk|rpm)\/([^/@?#]+)\/([^/@?#]+)\?([^#]+)$/i.exec(raw);if(!m)return null;
 try{
  const type=m[1].toLowerCase(),namespace=decodeURIComponent(m[2]).toLowerCase(),name=decodeURIComponent(m[3]);
  if(!/^[a-z0-9][a-z0-9.+_-]*$/i.test(name)||!/^[a-z0-9][a-z0-9.+_-]*$/.test(namespace))return null;
  const q=new URLSearchParams(m[4]), keys=[...q.keys()];if(new Set(keys).size!==keys.length || keys.some(k=>!['distro','arch'].includes(k)))return null;
  const distro=q.get('distro'),arch=q.get('arch');if(!distro||!arch||!/^[a-z0-9][a-z0-9.+_-]*$/i.test(arch))return null;
  const prefix=namespace+'-';if(!distro.toLowerCase().startsWith(prefix))return null;
  const release=distro.slice(prefix.length);if(!/^[0-9][A-Za-z0-9._+-]*$/.test(release))return null;
  return {ecosystem:`system:${type}:${namespace}:${release}`,name,manager:type,distribution:namespace,release,arch};
 }catch{return null;}
}
function explicitNativePackage(a,context){return systemPackage(a)||require('../providers/cveproject/cna-identities').cnaSystemPackage(a,context,context?.cnaIdentities)||explicitPackage(a)||require('./native').explicitNpmPackage(a);}
function depIdentity(dep){
 if(dep.ecosystem==='system'){
  const manager=({dpkg:'deb',deb:'deb',apk:'apk',rpm:'rpm'})[dep.manager||dep.packageType],d=dep.distribution;
  if(!manager||!d?.id||!d?.versionId)return null;
  return {ecosystem:`system:${manager}:${String(d.id).toLowerCase()}:${d.versionId}`,names:[...new Set([dep.sourceName,dep.name].filter(Boolean))]};
 }
 const ecosystem=osvEcosystemFor(dep),name=osvPkgName(dep);return ecosystem&&name?{ecosystem,names:[name]}:null;
}
function typeComparator(type,ecosystem){
 type=String(type||'').toLowerCase();
 if(ecosystem.startsWith('system:')){
  const manager=ecosystem.split(':')[1],valid={deb:['deb','debian','dpkg'],apk:['apk','alpine'],rpm:['rpm']}[manager];
  return valid?.includes(type)?nativeVersions[manager==='deb'?'debian':manager]:null;
 }
 if(type==='maven'&&ecosystem==='Maven')return require('../providers/cveproject/version-verdict').comparator('maven');
 if(type==='semver')return require('../providers/osv/db').compareSemver;
 return null;
}
function versionVerdict(version,a,ecosystem){
 if(typeof version!=='string'||!version||!Array.isArray(a?.versions))return null;
 let unknown=false,affected=false,unaffected=false;
 for(const v of a.versions){
  if(!v||typeof v.version!=='string'||!['affected','unaffected','unknown'].includes(v.status)||v.lessThan!=null&&v.lessThanOrEqual!=null){unknown=true;continue;}
  const upper=v.lessThan??v.lessThanOrEqual,cmp=typeComparator(v.versionType,ecosystem);
  let member;
  if(upper==null && version===v.version && String(v.versionType||'').toLowerCase()!=='git')member=true;
  else if(!cmp||cmp(version,version)!==0)member=null;
  else if(upper==null){const c=cmp(version,v.version);member=c===null?null:c===0;}
  else {
   const lower=v.version==='0'?-1:cmp(v.version,version),limit=upper==='*'?1:cmp(upper,version),bounds=upper==='*'||v.version==='0'?-1:cmp(v.version,upper);
   if(lower===null||limit===null||bounds===null||bounds>0||bounds===0&&v.lessThan!=null)member=null;
   else member=lower<=0 && (upper==='*' || (v.lessThan!=null?limit>0:limit>=0));
  }
  if(member===null){unknown=true;continue;}if(!member)continue;
  let state=v.status;
  if(v.changes!=null){
   if(!cmp||!Array.isArray(v.changes)||v.changes.some(c=>!c||typeof c.at!=='string'||!['affected','unaffected','unknown'].includes(c.status)||cmp(c.at,c.at)!==0)){unknown=true;continue;}
   const sorted=[...v.changes].sort((x,y)=>cmp(x.at,y.at));let invalid=false;
   for(const c of sorted){
    const lower=v.version==='0'?-1:cmp(v.version,c.at),higher=upper==null?cmp(c.at,v.version):upper==='*'?-1:cmp(c.at,upper),atVersion=cmp(c.at,version);
    if(lower===null||higher===null||atVersion===null||lower>0||upper!=null && upper!=='*' && (higher>0||higher===0&&v.lessThan!=null) || upper==null && higher!==0){invalid=true;break;}
    if(atVersion<=0)state=c.status;
   }
   if(invalid){unknown=true;continue;}
  }
  if(state==='affected')affected=true;else if(state==='unaffected')unaffected=true;else unknown=true;
 }
 if(unknown || affected&&unaffected)return null;if(affected)return true;if(unaffected)return false;
 const fallback=String(a.defaultStatus||'unknown').toLowerCase();return fallback==='affected'?true:fallback==='unaffected'?false:null;
}
function containers(record){return [record?.containers?.cna,...(Array.isArray(record?.containers?.adp)?record.containers.adp:[])].filter(Boolean);}
function sourceReferences(record,source){
 const references=[],relatedAdvisories=[],seen=new Set();
 for(const container of containers(record))for(const ref of Array.isArray(container.references)?container.references:[]){
  let url;try{const u=new URL(ref?.url);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)continue;url=u.href;}catch{continue;}
  if(!seen.has(url)){seen.add(url);references.push({url,tags:Array.isArray(ref.tags)?ref.tags.filter(x=>typeof x==='string'):[],name:typeof ref.name==='string'?ref.name:null,source});}
  if(source!=='cveproject'||container!==record.containers?.cna||!Array.isArray(ref.tags)||!ref.tags.includes('vendor-advisory'))continue;
  const m=/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/security\/advisories\/(GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4})$/i.exec(url);
  if(m && typeof ref.name==='string' && ref.name.includes(m[1]))relatedAdvisories.push({id:m[1],url,relationship:'reference',source:'CVEProject'});
 }
 return {references,relatedAdvisories:[...new Map(relatedAdvisories.map(item=>[item.url,item])).values()]};
}
function metric(containers) {
 for(const c of containers)for(const m of c.metrics || [])for(const k of ['cvssV4_0','cvssV3_1','cvssV3_0','cvssV2_0']){
  const v=m?.[k],score=v?.baseScore;
  if(!Number.isFinite(score) || score<0 || score>10)continue;
  const severity=v.baseSeverity || (k==='cvssV2_0' ? (score>=7?'HIGH':score>=4?'MEDIUM':'LOW') :
   score>=9?'CRITICAL':score>=7?'HIGH':score>=4?'MEDIUM':score>0?'LOW':'NONE');
  return {score,severity:String(severity).toUpperCase(),cvssVector:v.vectorString||null,cvssVersion:'CVSS:'+k.slice(5).replace('_','.')};
 }
 return {score:null,severity:'UNKNOWN'};
}
function loadRecords(store,sources){
 if(!store?.db?.prepare || typeof store.getRecord!=='function')return [];
 const sql=`SELECT source,id FROM advisory_records WHERE source IN (${sources.map(()=>'?').join(',')}) ORDER BY source,id`;
 const stmt=store.db.prepare(sql),rows=typeof stmt.iterate==='function'?stmt.iterate(...sources):stmt.all(...sources);
 return (function*(){for(const row of rows){const rec=store.getRecord(row.source,row.id);if(rec)yield rec;}})();
}
function matchNativePackages(deps,store,opts={}){
 const sources=(opts.sources||['cveproject','gcve']).filter(x=>['cveproject','gcve'].includes(x));
 const wanted=new Map(),unknown=[],matches=[];
 for(const dep of deps instanceof Map?deps.values():deps||[]){if(dep.provenance==='binary')continue;const ident=depIdentity(dep);if(!ident)continue;const ecosystems=[ident.ecosystem,...(ident.ecosystem.startsWith('system:deb:debian:')?['system:deb:debian:*']:[])];for(const ecosystem of ecosystems)for(const name of ident.names){const key=JSON.stringify([ecosystem,packageName(ecosystem,name)]),list=wanted.get(key)||[];list.push(dep);wanted.set(key,list);}}
 if(!wanted.size||!sources.length)return {matches,unknown,coverage:{status:'not-applicable',sources}};
 const snapshots=new Map(),seenRecords=new Set();
 function* records(){
  for(const [key] of wanted){const [ecosystem,name]=JSON.parse(key);for(const source of sources)yield* store.getPackageRecords(ecosystem,name,{source});}
  // Older envelopes indexed only selected ecosystems. Stream their documents
  // once without retaining them or modifying the historical cache.
  if(opts.scanLegacy!==false)yield* loadRecords(store,sources);
 }
 for(const rec of records()){
  const recordKey=rec.source+'\0'+rec.id;if(seenRecords.has(recordKey))continue;seenRecords.add(recordKey);
  if (seenRecords.size % 5000 === 0) opts.onProgress?.(seenRecords.size);
  const raw=rec.document;if(raw?.cveMetadata?.state!=='PUBLISHED')continue;
  let gcve=null;if(rec.source==='gcve'){
   try{gcve=identity(raw,rec.provenance?.gna);if(gcve.recordType!=='advisory')continue;}catch{continue;}
   const gna=rec.provenance?.gna;if(!Number.isSafeInteger(gna)){unknown.push({id:rec.id,reason:'GCVE source identity unavailable'});continue;}
   if(!snapshots.has(gna))snapshots.set(gna,store.getRecord('gcve-snapshot',`gna:${gna}`));
   const snapshot=snapshots.get(gna),observed=Math.max(rec.fetchedAt,...(rec.observations||[]).map(o=>o.fetchedAt).filter(Number.isFinite));
   if(snapshot && snapshot.provenance?.gna===gna && rec.provenance?.sourceUrl && snapshot.provenance?.sourceUrl===rec.provenance.sourceUrl && snapshot.fetchedAt>observed && Array.isArray(snapshot.document?.ids) && !snapshot.document.ids.includes(rec.id))continue;
  }
  const cs=containers(raw),description=cs.flatMap(c=>Array.isArray(c.descriptions)?c.descriptions:[]).find(d=>String(d?.lang||'').startsWith('en'))?.value || '';
  const evaluations=new Map();
  for(const container of cs)for(const a of (Array.isArray(container.affected)?container.affected:[])){
   const p=explicitNativePackage(a,{source:rec.source,record:raw,container,cnaIdentities:opts.cnaIdentities});if(!p)continue;
   const candidates=wanted.get(JSON.stringify([p.ecosystem,packageName(p.ecosystem,p.name)]))||[];
   const consultation=rec.source==='cveproject' && typeof store.getQuery==='function' ? store.getQuery({source:'cveproject',ecosystem:p.ecosystem,name:p.name,version:'*'},{ttlMs:Number.MAX_SAFE_INTEGER}) : null;
   if(consultation && consultation.provenance?.stale!==true && consultation.fetchedAt >= (rec.contentChangedAt||rec.fetchedAt) && !consultation.ids.includes(rec.id))continue;
   for(const dep of candidates){
    if(p.ecosystem==='system:deb:debian:*'&&['third-party','ambiguous'].includes(dep.packageOrigin?.status))continue;
    if(p.manager && p.arch!=='source' && dep.architecture && dep.architecture!==p.arch)continue;
    if(p.manager && p.arch!=='source' && dep.name!==p.name)continue;
    const versions=p.manager ? [dep.version] : [...new Set([...(Array.isArray(dep.versions)?dep.versions:[]),dep.version].filter(Boolean))];
    for(const installedVersion of versions){
     const location=dep.manifestPaths?.[0] || dep.pomPaths?.[0] || dep.manifestPath || '';
     const occurrence=dep.coordKey || JSON.stringify([dep.artifactTargetId||'',dep.ecosystem,dep.namespace||dep.groupId||'',dep.name||dep.artifactId||'',location,dep.architecture||'']);
     const k=JSON.stringify([occurrence,installedVersion]);let entry=evaluations.get(k);
     if(!entry){entry={dep,installedVersion,name:p.name,verdicts:[]};evaluations.set(k,entry);}
     let version=installedVersion,reason=null;
     if(p.manager && p.arch==='source'){
      if(!dep.sourceName||dep.sourceName!==p.name||!dep.sourceVersion)reason='source identity or version unavailable';else version=dep.sourceVersion;
     } else if(p.manager && !dep.architecture)reason='architecture unavailable';
     const result=reason?null:versionVerdict(version,a,p.ecosystem);
     entry.verdicts.push(result);if(result===null)entry.reason=reason||'version semantics unknown';
    }
   }
  }
  for(const entry of evaluations.values()){
   const values=entry.verdicts;
   if(values.includes(null) || values.includes(true)&&values.includes(false)){unknown.push({id:rec.id,artifactTargetId:entry.dep.artifactTargetId||null,name:entry.name,version:entry.installedVersion,reason:entry.reason||'contradictory affected statuses'});continue;}
   if(!values.includes(true))continue;
   const aliases=gcve?.aliases||[],cveId=aliases.find(id=>/^CVE-\d{4}-\d{4,}$/i.test(id))||rec.id;
   const dep=entry.installedVersion===entry.dep.version?entry.dep:{...entry.dep,version:entry.installedVersion};
   matches.push({dep,source:rec.source==='gcve'?`GCVE:GNA-${gcve.gna}`:'CVEProject',confidence:'exact',cve:{id:cveId,sourceAdvisoryId:rec.id,...metric(cs),...sourceReferences(raw,rec.source),description:String(description),published:raw.cveMetadata.datePublished||null,modified:raw.cveMetadata.dateUpdated||null,fixVersion:null,...(gcve?{gcve:gcve.id,gcveSource:rec.provenance?.sourceUrl||null,gcveRecordType:gcve.recordType,gcveRelationships:gcve.relationships,aliases}: {})}});
  }
 }
 return {matches,unknown,coverage:{status:unknown.length?'incomplete':'partial',sources,reason:unknown.length?'native comparisons undecidable':'native source completeness must be evaluated separately'}};
}
module.exports={metric,systemPackage,explicitNativePackage,depIdentity,versionVerdict,matchNativePackages};
