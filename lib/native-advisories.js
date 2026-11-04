'use strict';
// Native CVE and GCVE envelopes for the shared store. Legacy indexes remain
// separate: they cannot establish withdrawals or native-source completeness.
const fs = require('node:fs');
const path = require('node:path');
const MAX_RECORD = 16 * 1024 * 1024;

function explicitNpmPackage(affected) {
 const p=require('./gcve-index').explicitPackage(affected);
 if(p?.ecosystem==='npm')return p;
 if(affected?.packageURL!=null || affected?.purl!=null)return null;
 // Some CNA records use a package name with an explicit npm registry
 // collection instead of a PURL. A bare product/name is not sufficient.
 const name=affected?.packageName,url=affected?.collectionURL;
 if(typeof name==='string' && /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(name) &&
    typeof url==='string' && /^https:\/\/(?:registry\.npmjs\.org\/?|www\.npmjs\.com\/package\/?)$/.test(url))
  return {ecosystem:'npm',name};
 return null;
}

function cveEnvelope(raw, { fetchedAt, provenance = {transport:'direct'} } = {}) {
 const id = raw?.cveMetadata?.cveId;
 if (!/^CVE-\d{4}-\d{4,}$/i.test(String(id || '')) || !['PUBLISHED','REJECTED','RESERVED'].includes(raw?.cveMetadata?.state)) throw new Error('invalid native CVEProject record');
 const packages = [];
 if (raw.cveMetadata.state === 'PUBLISHED') {
  const projected = require('./cve-download').extractMavenRelevantCve(raw);
  for (const a of projected?.affected || []) {
   for (const name of (a.packageNames || [])) packages.push({ecosystem:'Maven',name});
   if (a.product) packages.push({ecosystem:'CVEProduct',name:String(a.product).toLowerCase()});
  }
  // Preserve only explicitly typed npm package identities. Product names do
  // not establish that an arbitrary npm package is the affected component.
  for (const container of [raw.containers?.cna,...(Array.isArray(raw.containers?.adp)?raw.containers.adp:[])])
   for (const affected of (Array.isArray(container?.affected)?container.affected:[])) {
    const p=explicitNpmPackage(affected);
    if (p) packages.push(p);
   }
 }
 return {source:'cveproject',id:id.toUpperCase(),document:raw,fetchedAt,provenance,packages};
}
function gcveEnvelope(stored, { provenance = {transport:'direct'} } = {}) {
 const {identity,explicitPackage}=require('./gcve-index');
 const raw=stored?.raw, ident=identity(raw,stored?.gna), at=Date.parse(stored.collectedAt);
 if (!Number.isSafeInteger(at) || at <= 0 || at > Date.now()+300000) throw new Error('invalid GCVE collection date');
 const packages=[];
 if (ident.recordType === 'advisory' && raw?.cveMetadata?.state === 'PUBLISHED') for (const a of raw?.containers?.cna?.affected || []) {
  const p=explicitPackage(a);if (p) packages.push(p);
 }
 return {source:'gcve',id:ident.id,document:raw,fetchedAt:at,provenance:{...provenance,gna:ident.gna,sourceUrl:stored.sourceUrl || null},packages};
}
async function importGcveIndex(store,index,{provenance={transport:'direct'}}={}) {
 if (!index || !Array.isArray(index.records) || !Array.isArray(index.coverage)) throw new Error('invalid GCVE index');
 const times=index.coverage.map(c=>Date.parse(c.collectedAt));
 if (!times.length || times.some(t=>!Number.isSafeInteger(t) || t<=0 || t>Date.now()+300000)) throw new Error('invalid GCVE coverage');
 // Per-GNA membership is reconciled below. Global completeness remains
 // partial because removed or uncollected GNAs have no absence proof.
 const fetchedAt=Math.min(...times), complete=false;
 // An independently timestamped membership proof per GNA establishes absence
 // without fabricating a REJECTED record or deleting its native document.
 const snapshots=new Map();
 for (const c of index.coverage) {
  if (!Number.isSafeInteger(c.gna) || c.gna<0 || snapshots.has(c.gna)) throw new Error('invalid GCVE GNA coverage');
  snapshots.set(c.gna,{coverage:c,ids:new Set(),valid:true});
 }
 function* entries() {
  for (const record of index.records) {
   const envelope=gcveEnvelope(record,{provenance}), snapshot=snapshots.get(record.gna);
   if (!snapshot) throw new Error('GCVE record has no GNA coverage');
   if (Date.parse(record.collectedAt)!==Date.parse(snapshot.coverage.collectedAt) || record.sourceUrl !== snapshot.coverage.sourceUrl || snapshot.ids.has(envelope.id)) snapshot.valid=false;
   snapshot.ids.add(envelope.id);yield envelope;
  }
  for (const [gna,snapshot] of snapshots) {
   const c=snapshot.coverage;
   if (!index.directory?.verified || typeof c.sourceUrl !== 'string' || !c.sourceUrl || !snapshot.valid || c.complete!==true || !Number.isSafeInteger(c.records) || c.records!==snapshot.ids.size) continue;
   const document={id:`gna:${gna}`,gna,ids:[...snapshot.ids]};
   if (Buffer.byteLength(JSON.stringify(document))>8*1024*1024) continue;
   yield {source:'gcve-snapshot',id:document.id,document,fetchedAt:Date.parse(c.collectedAt),provenance:{...provenance,gna,sourceUrl:c.sourceUrl || null}};
  }
 }
 await store.importEnvelopes(entries(),{coverages:[{source:'gcve',ecosystem:'*',fetchedAt,complete,provenance}]});
 return {count:index.records.length,complete};
}
async function importCveDirectory(store, root, {fetchedAt=Date.now(),provenance={transport:'direct'}}={}) {
 async function* entries() {
  const dirs=[root];
  while (dirs.length) {
   const dir=dirs.pop();
   for (const entry of await fs.promises.readdir(dir,{withFileTypes:true})) {
    const file=path.join(dir,entry.name);
    if (entry.isDirectory()) dirs.push(file);
    else if (entry.isFile() && /^CVE-\d{4}-\d{4,}\.json$/i.test(entry.name)) {
     const stat=await fs.promises.stat(file);if(stat.size>MAX_RECORD) throw new Error('CVEProject record exceeds size limit');
     const raw=JSON.parse(await fs.promises.readFile(file,'utf8'));
     if (raw?.cveMetadata?.cveId?.toLowerCase() !== entry.name.slice(0,-5).toLowerCase()) throw new Error('CVEProject record filename mismatch');
     yield cveEnvelope(raw,{fetchedAt,provenance});
    }
   }
  }
 }
 // This import cannot prove that absent historical records were withdrawn.
 return store.importEnvelopes(entries(),{coverages:[{source:'cveproject',ecosystem:'*',fetchedAt,complete:false,provenance}]});
}
module.exports={cveEnvelope,gcveEnvelope,importGcveIndex,importCveDirectory,explicitNpmPackage};

function projectedCveEnvelope(document, fetchedAt, provenance = {transport:'proxy'}) {
 if (!document || !/^CVE-\d{4}-\d{4,}$/i.test(String(document.id || '')) || !Array.isArray(document.affected)) throw new Error('invalid projected CVEProject record');
 const packages=[];
 for (const affected of document.affected) {
  for (const name of (affected.packageNames || (affected.packageName ? [affected.packageName] : []))) packages.push({ecosystem:'Maven',name});
  if (affected.product) packages.push({ecosystem:'CVEProduct',name:String(affected.product).toLowerCase()});
 }
 return {source:'cveproject-legacy',id:document.id.toUpperCase(),document,fetchedAt,provenance,packages};
}
module.exports.projectedCveEnvelope=projectedCveEnvelope;

/** Match native CVEProject records first; legacy projections never resurrect an ID
 * for which any native revision or rejection is known. Legacy lacks per-record
 * revision stamps, so its coverage remains explicitly partial. */
function matchCveStore(deps, store, legacyIndex = null) {
 const {newIndex,addToIndex,extractMavenRelevantCve}=require('./cve-download');
 const {matchDepsAgainstCves}=require('./cve-match');
 const index=newIndex(), legacyStoreIndex=newIndex(), seen=new Set(), legacySeen=new Set();
 for (const dep of deps.values()) {
  if ((dep.ecosystem && dep.ecosystem !== 'maven') || dep.provenance === 'binary') continue;
  const group=dep.groupId || dep.namespace, artifact=dep.artifactId || dep.name;
  if (!group || !artifact) continue;
  const candidates=[...store.getPackageRecords('Maven',`${group}:${artifact}`,{source:'cveproject'}),
   ...store.getPackageRecords('CVEProduct',String(artifact).toLowerCase(),{source:'cveproject'})];
  for (const record of candidates) {
   if (seen.has(record.id)) continue;
   seen.add(record.id);
   const cve=extractMavenRelevantCve(record.document);if(cve)addToIndex(index,cve);
  }
  const projected=[...store.getPackageRecords('Maven',`${group}:${artifact}`,{source:'cveproject-legacy'}),
   ...store.getPackageRecords('CVEProduct',String(artifact).toLowerCase(),{source:'cveproject-legacy'})];
  for (const record of projected) if(!legacySeen.has(record.id)) {legacySeen.add(record.id);addToIndex(legacyStoreIndex,record.document);}
 }
 const uncertain = [], capture = {onUncertain:m=>uncertain.push(m)};
 const legacyMatches=[...matchDepsAgainstCves(deps,legacyStoreIndex,capture), ...(legacyIndex ? matchDepsAgainstCves(deps,legacyIndex,capture) : [])];
 // A product/vendor legacy candidate may point to a native record that has no
 // package binding. Project that record before suppressing the legacy match.
 const survivingLegacy=[];
 // An uncertain legacy projection can still identify a native record with an
 // explicit coordinate. Inspect it, but never promote the projection itself.
 for (const match of [...legacyMatches, ...uncertain]) {
  const native=store.getRecord('cveproject',match.cve.id);
  if (!native) {if(match.confidence !== 'possible') survivingLegacy.push(match);continue;}
  if (seen.has(native.id) || native.document.cveMetadata?.state !== 'PUBLISHED') continue;
  seen.add(native.id);
  const cve=extractMavenRelevantCve(native.document);if(cve)addToIndex(index,cve);
 }
 const candidates=matchDepsAgainstCves(deps,index,capture).concat(survivingLegacy), ids=new Set();
 const matches=candidates.filter(m=>{const k=`${m.dep.coordKey}:${m.dep.version}|${m.cve.id}`;if(ids.has(k))return false;ids.add(k);return true;});
 return {matches,coverage:store.getSourceCoverage('cveproject','*'),legacy:survivingLegacy.length > 0,
  identityUncertain:uncertain.length > 0,uncertainCandidates:uncertain};
}
module.exports.matchCveStore=matchCveStore;

// A CNA sometimes labels ordinary npm release bounds "custom". For a
// version strictly above every affected upper bound, a matching independent
// OSV advisory can corroborate the negative without changing CVE semantics.
function corroboratedNpmNegative(store, record, name, version, entries) {
 const compare=require('./osv-db').compareSemver;
 if (!entries.length || entries.some(a => a.platforms?.length || a.defaultStatus !== 'unaffected' ||
  !Array.isArray(a.versions) || !a.versions.length || a.versions.some(v =>
   !v || v.status !== 'affected' || String(v.versionType || '').toLowerCase() !== 'custom' ||
   v.changes?.length || (!!v.lessThan === !!v.lessThanOrEqual) ||
   compare(String(version), String(v.lessThan || v.lessThanOrEqual)) !== 1))) return false;
 const {packageName}=require('./advisory-store'), {vulnVerdict}=require('./osv-db');
 const docs=store.getPackageRecords('npm',name,{source:'osv'}).filter(item => {
  const doc=item.document;
  return !item.withdrawnAt && !doc?.withdrawn && [doc?.id,...(doc?.aliases || [])].includes(record.id);
 });
 if(!docs.length)return false;
 return docs.every(({document}) => {
  const affected=(document.affected || []).filter(a => a?.package?.ecosystem==='npm' &&
   typeof a.package.name==='string' && packageName('npm',a.package.name)===packageName('npm',name));
  return affected.length > 0 && vulnVerdict(String(version),{...document,affected},'npm') === false;
 });
}

/** Match explicit npm PURLs in native CVEProject records. A missing package
 * or undecidable range is never interpreted as proof that it is unaffected. */
function matchNativeNpmCves(deps, store) {
 const {extractAffectedRanges}=require('./cve-download');
 const {affectedVerdict}=require('./cve-version-verdict');
 const {osvPkgName}=require('./osv');
 const {packageName}=require('./advisory-store');
 const matches=[], unknown=[], seen=new Set();
 for(const dep of deps.values()) {
  if(!['npm','yarn'].includes(dep.ecosystem) || dep.provenance==='binary')continue;
  const name=osvPkgName(dep);if(!name)continue;
  const consulted=store.getQuery({source:'cveproject',ecosystem:'npm',name,version:'*'},{ttlMs:Number.MAX_SAFE_INTEGER});
  for(const record of store.getPackageRecords('npm',name,{source:'cveproject'})) {
   // A later complete package consultation proves that the old record no
   // longer applies to this package; preserve a newer native update instead.
   if(consulted && consulted.provenance?.stale!==true && consulted.fetchedAt >= (record.contentChangedAt || record.fetchedAt) && !consulted.ids.includes(record.id))continue;
   const raw=record.document;if(raw?.cveMetadata?.state!=='PUBLISHED')continue;
   const containers=[raw.containers?.cna,...(Array.isArray(raw.containers?.adp)?raw.containers.adp:[])];
   const entries=containers.flatMap(c=>(Array.isArray(c?.affected)?c.affected:[])).filter(a=>{
    const p=explicitNpmPackage(a);return p && packageName('npm',p.name)===packageName('npm',name);
   });
   if(!entries.length)continue;
   for(const ver of dep.versions?.length?dep.versions:[dep.version]) {
    if(!ver)continue;
    const key=`${dep.coordKey||name}|${ver}|${record.id}`;if(seen.has(key))continue;
    const results=entries.map(a=>{
     // Version semantics and platform restrictions must be explicit.
     if((a.platforms?.length) || !Array.isArray(a.versions) || a.versions.some(v=>
      !v || (v.versionType && String(v.versionType).toLowerCase()!=='semver') ||
      (!v.versionType && (v.lessThan!=null || v.lessThanOrEqual!=null))))return null;
     const projected=extractAffectedRanges([a])[0];
     return affectedVerdict(String(ver),projected.ranges,projected.defaultStatus);
    });
    if(results.some(x=>x===null) || (results.includes(true)&&results.includes(false))) {
     if(!corroboratedNpmNegative(store,record,name,ver,entries)) unknown.push({id:record.id,package:name,version:ver});
     continue;
    }
    if(!results.includes(true))continue;
    seen.add(key);
    const cna=raw.containers?.cna || {},descriptions=Array.isArray(cna.descriptions)?cna.descriptions:[],description=descriptions.find(d=>String(d?.lang||'').startsWith('en'))?.value || descriptions[0]?.value || '';
    let score=null,severity='UNKNOWN',cvssVector=null;
    for(const c of containers){for(const m of (Array.isArray(c?.metrics)?c.metrics:[])){const v=m?.cvssV3_1||m?.cvssV3_0||m?.cvssV4_0||m?.cvssV2_0;if(typeof v?.baseScore==='number'&&v.baseScore>=0&&v.baseScore<=10){score=v.baseScore;severity=String(v.baseSeverity|| (score>=9?'CRITICAL':score>=7?'HIGH':score>=4?'MEDIUM':score>0?'LOW':'NONE')).toUpperCase();cvssVector=v.vectorString||null;break;}}if(score!==null)break;}
    matches.push({dep:ver===dep.version?dep:{...dep,version:ver},source:'CVEProject',confidence:'exact',cve:{id:record.id,description:String(description),severity,score,cvssVector,published:raw.cveMetadata.datePublished||null,modified:raw.cveMetadata.dateUpdated||null,fixVersion:null,fixEvaluation:'unknown'}});
   }
  }
 }
 return {matches,unknown};
}
module.exports.matchNativeNpmCves=matchNativeNpmCves;

/** Use the existing GCVE matcher on native candidates and filter legacy IDs
 * superseded by any native revision, including rejected records. */
function matchGcveStore(deps, store, legacyIndex = null) {
 const {buildGcveIndex,matchGcveDeps}=require('./gcve-index');
 const {osvEcosystemFor,osvPkgName}=require('./osv');
 const native=new Map();
 for (const dep of deps.values()) {
  if (dep.provenance === 'binary') continue;
  const ecosystem=osvEcosystemFor(dep),name=osvPkgName(dep);if(!ecosystem || !name)continue;
  for (const record of store.getPackageRecords(ecosystem,name,{source:'gcve'})) native.set(record.id,record);
 }
 const grouped=new Map(), snapshotCache=new Map();
 for (const record of native.values()) {
  const gna=record.provenance?.gna, sourceUrl=record.provenance?.sourceUrl;
  if (!Number.isSafeInteger(gna)) throw new Error('GCVE record has no GNA provenance');
  if (!snapshotCache.has(gna)) {
   const proof=store.getRecord('gcve-snapshot',`gna:${gna}`);
   snapshotCache.set(gna,proof ? {proof,ids:Array.isArray(proof.document.ids) ? new Set(proof.document.ids) : null} : null);
  }
  const cached=snapshotCache.get(gna), snapshot=cached?.proof;
  const observed=Math.max(record.fetchedAt,...(record.observations || []).map(o=>o.fetchedAt).filter(Number.isFinite));
  if (snapshot && snapshot.provenance?.gna===gna && sourceUrl && snapshot.provenance.sourceUrl===sourceUrl && snapshot.fetchedAt>observed && cached.ids && !cached.ids.has(record.id)) continue;
  if (!grouped.has(gna)) grouped.set(gna,{gna,sourceUrl,collectedAt:new Date(record.fetchedAt).toISOString(),complete:false,records:[]});
  grouped.get(gna).records.push(record.document);
 }
 const index=buildGcveIndex([...grouped.values()]);
 const result=matchGcveDeps(deps,index);
 if (legacyIndex) {
  const legacy=matchGcveDeps(deps,legacyIndex);
  result.matches.push(...legacy.matches.filter(m=>!store.getRecord('gcve',m.cve.gcve)));
  result.unknown.push(...legacy.unknown.filter(m=>!store.getRecord('gcve',m.id)));
  result.coverage=legacy.coverage;
 } else result.coverage=[];
 result.sourceCoverage=store.getSourceCoverage('gcve','*');
 return result;
}
module.exports.matchGcveStore=matchGcveStore;
