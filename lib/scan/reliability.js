'use strict';

const {osvPkgName, osvEcosystemFor} = require('../providers/osv/query');
const {depIdentity} = require('../advisories/native-package-match');
const structure = new Set(['dependency-coverage','go-coverage','unresolved-versions','no-lockfile','parse-error','missing-include','local-replace','image-scan-failed']);
const discovery = new Set(['osv-coverage','packagist-advisory-data-unknown','packagist-non-packagist-package','retire-failed']);
const ecosystems = new Set(['npm','yarn','maven','gradle','composer','pypi','go','ruby','nuget','system']);

function isBlocking(w) {
 return w?.reliabilityFailure === true || (w?.severity !== 'info' && w?.affectsCompleteness !== false &&
  (structure.has(w?.type) || discovery.has(w?.type)));
}
function incompleteCheck(check) {
 return ['failed','partial','not-run'].includes(check.execution) && check.expected !== false &&
  check.affectsCompleteness !== false && ['inventory','advisories'].includes(check.capability);
}
function coverageWarning(message, extra={}) {
 return {type:'scan-reliability', reliabilityFailure:true, message,...extra};
}
function createDiscoveryCoverage() {
 const verified = new Map();
 function identity(dep,version) {
  return JSON.stringify([dep.ecosystem==='system' ? depIdentity(dep)?.ecosystem || 'system' : osvEcosystemFor(dep),
   dep.ecosystem==='system' ? dep.name : osvPkgName(dep), String(version || ''), dep.artifactTargetId || '', dep.architecture || '']);
 }
 function consulted(dep,source,version=dep.version) {
  const key=identity(dep,version);
  if(!verified.has(key))verified.set(key,new Set());
  verified.get(key).add(source);
 }
 function privateMatcher({privateDeps=[],privateMavenIds=[]}={}) {
  // Consume the existing registry classification, never infer absence from an
  // advisory miss, an authentication error, or a source outage.
  const privateVersions=new Set(privateDeps.flatMap(dep=>(dep.versions?.length ? dep.versions : [dep.version]).map(version=>identity(dep,version))));
  const privateMaven=new Set(privateMavenIds);
  return (dep,version)=>privateVersions.has(identity(dep,version)) ||
   (['maven','gradle'].includes(dep.ecosystem) &&
    (privateMaven.has(`${dep.groupId || dep.namespace}:${dep.artifactId || dep.name}`) ||
     privateMaven.has(`${dep.groupId || dep.namespace}:${dep.artifactId || dep.name}:${version}`)));
 }
 function publicDependencies(deps,privateOptions,privateOnly=false) {
  const isPrivate=privateMatcher(privateOptions),result=new Map();
  for(const [key,dep] of deps){
   const all=dep.versions?.length ? dep.versions : [dep.version];
   const versions=all.filter(v=>isPrivate(dep,v)===privateOnly);
   if(!versions.length)continue;
   result.set(key,versions.length===all.length ? dep : {...dep,versions,version:versions.includes(dep.version)?dep.version:versions[0]});
  }
  return result;
 }
 function assess(deps,{store,options={},nativeSources=[],completeSources=[],reviewed=false,privateDeps=[],privateMavenIds=[]}={}) {
  const missing = new Map(), global = new Set(completeSources), ttlMs=options.advisoryQueryTtlMs??4*3600000;
  let assessed = 0, unassessed = 0;
  const native = new Set(nativeSources),isPrivate=privateMatcher({privateDeps,privateMavenIds});
  const usable = q=>q?.complete && !q.provenance?.stale && !q.provenance?.refreshFailure && !q.stale && (options.offline || q.fresh);
  for(const source of native) {
   if(usable(store.getSourceCoverage(source,'*',{ttlMs}))) global.add(source);
  }
  if(native.has('cveproject')) {
   const snapshot=store.db?.prepare("SELECT fetched_at,metadata_json FROM cache_snapshots WHERE namespace='cve_lookup' AND complete=1 AND stale=0").get();
   const local=snapshot && JSON.parse(snapshot.metadata_json);
   const nativeCoverage=store.getSourceCoverage('cveproject','*',{ttlMs});
   if(local?.fullArchive && local.releaseTag && nativeCoverage?.provenance?.releaseTag===local.releaseTag &&
      (options.offline || Date.now()-snapshot.fetched_at<=ttlMs))global.add('cveproject');
  }
  for(const dep of deps.values()) {
   if(dep.scope==='parent')continue;
   // Raw binary identification is an inventory check, not a package advisory
   // query. A product/version (or a hash lookup miss) cannot establish the
   // package ecosystem required by OSV. Keep these in the unmanaged inventory.
   // Dependencies extracted from build metadata use binary-module provenance
   // and retain the normal package/version coverage requirement below.
   if(dep.provenance==='binary' || dep.ecosystem==='binary')continue;
   const versions=dep.versions?.length ? dep.versions : [dep.version];
   if(versions.every(version=>isPrivate(dep,version)))continue;
   if(!ecosystems.has(dep.ecosystem)){
    // An unsupported package codec does not establish inapplicability.
    const name=dep.identity?.name || dep.name || dep.artifactId || dep.coordKey;
    const version=dep.identity?.version || dep.version;
    const id=version ? `${name}@${version}` : name;
    const key=JSON.stringify([dep.ecosystem,dep.coordKey,id]);
    if(!missing.has(key)){assessed++;unassessed++;}
    missing.set(key,{id,ecosystem:dep.ecosystem,detail:'No verified package/version assessment for this component.'});
    continue;
   }
   const pkg=depIdentity(dep);
   const sources=new Set(pkg ? global : []);
   if(store && pkg) {
    for(const source of [...native,...(reviewed && ['maven','npm','yarn'].includes(dep.ecosystem)?['vigievuln']:[])]) {
     if(sources.has(source))continue;
     if(pkg.names.every(name=>usable(store.getQuery({source,ecosystem:pkg.ecosystem,name,version:'*'},{ttlMs}))))sources.add(source);
    }
   }
   for(const version of versions) {
    if(isPrivate(dep,version))continue;
    const key=identity(dep,version), hits=verified.get(key)||new Set();
    const absent=[];
    if(!hits.has('osv'))absent.push('OSV');
    if(!sources.size && ![...hits].some(s=>s!=='osv'))absent.push('a second advisory source');
    assessed++;
    if(absent.length===2)unassessed++;
    if(absent.length)missing.set(key,{id:`${pkg?.names?.[0] || dep.name}@${version || '?'}`,ecosystem:dep.ecosystem,missing:absent,detail:absent.join(' + ')});
   }
  }
  if(!missing.size)return null;
  return coverageWarning(`Advisory discovery is incomplete for ${missing.size} package/version(s). Each requires OSV and another package advisory source.`,
   {code:'package-advisory-coverage',count:missing.size,assessed,unassessed,
    // No advisory source assessed any package: nothing reliable can be published.
    fatal:assessed>0 && unassessed===assessed,items:[...missing].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([,item])=>item)});
 }
 return {consulted,assess,publicDependencies};
}
// Publication policy. An incomplete scan still publishes its report, marked
// incomplete, with every gap listed. It is cancelled only when nothing reliable
// can be shown: no dependency inventory, or no advisory source assessed any
// package. --fail-on-incomplete restores the strict behaviour for the listed
// capabilities.
function warningCapability(w) {
 if (w?.capability) return w.capability === 'sources' ? 'advisories' : w.capability;
 return structure.has(w?.type) ? 'inventory' : 'advisories';
}
function publication(warnings,{inventoryCount=null,strict=[]}={}) {
 const blockers=(warnings||[]).filter(isBlocking);
 const required=new Set((strict||[]).map(c=>c==='sources'?'advisories':c));
 const fatal=blockers.filter(w=>w.fatal===true);
 const noInventory=inventoryCount===0 && blockers.some(w=>warningCapability(w)==='inventory');
 const strictBlockers=required.size ? blockers.filter(w=>required.has(warningCapability(w))) : [];
 const cancel=fatal.length>0 || noInventory || strictBlockers.length>0;
 // The decisive gaps come first; the cancellation still names every other gap.
 const decisive=fatal.length ? fatal : noInventory ? blockers.filter(w=>warningCapability(w)==='inventory') : strictBlockers;
 return {blockers,cancel,incomplete:!cancel && blockers.length>0,
  reasons:cancel ? [...decisive,...blockers.filter(w=>!decisive.includes(w))] : []};
}
const LISTED_ITEMS=20;
function describe(warnings,lang) {
 const lines=[];
 for(const warning of warnings){
  lines.push(warning.message);
  const items=warning.items || [];
  for(const item of items.slice(0,LISTED_ITEMS))lines.push('  '+(item.id || item)+(item.detail ? ' — '+item.detail : ''));
  if(items.length>LISTED_ITEMS)lines.push('  '+(lang==='fr' ? `… et ${items.length-LISTED_ITEMS} autre(s), détaillé(s) dans le rapport` : `… and ${items.length-LISTED_ITEMS} more, listed in the report`));
 }
 return lines;
}
function incompleteNotice(blockers,lang) {
 const n=blockers.length;
 const head=lang==='fr'
  ? `Couverture incomplète : ${n} contrôle(s) non abouti(s). Le rapport est publié et marqué incomplet ; des vulnérabilités peuvent manquer. --fail-on-incomplete traite ce cas comme un échec.`
  : `Coverage incomplete: ${n} check(s) could not be completed. The report is published and marked incomplete; vulnerabilities may be missing. Use --fail-on-incomplete to treat this as a failure.`;
 return [...new Set([head,...describe(blockers,lang)])].join('\n');
}
function cancellation(warnings,lang) {
 const fr=lang==='fr';
 const lines=[fr ? 'Scan annulé. Aucun rapport publié.' : 'Scan cancelled. No report published.',...describe(warnings,lang)];
 return [...new Set(lines)].join('\n');
}
module.exports={createDiscoveryCoverage,isBlocking,incompleteCheck,coverageWarning,cancellation,publication,incompleteNotice,warningCapability};
