'use strict';
const {parseCpe23,matchVersionRange,loadCpeCoordMap}=require('./cpe');

// NVD now carries native CNA/ADP affected entries independently of its CPEs.
// Reuse the native normalizer and version evaluator, including exclusions,
// version changes, platform restrictions and disagreement between providers.
function projectNvdAffected(record) {
 const {extractAffectedRanges}=require('./cve-download');
 const {normalizeLegacySplitRanges}=require('./cve-legacy-ranges');
 if(!record || !/^CVE-\d{4}-\d+$/.test(record.id || '') || /^rejected$/i.test(record.vulnStatus || ''))return null;
 const affected=[];
 for(const group of Array.isArray(record.affected) ? record.affected : []) {
  if(!group || typeof group.source!=='string' || !group.source || !Array.isArray(group.affectedData))continue;
  const entries=group.affectedData.filter(a=>a && typeof a==='object' && !Array.isArray(a));
  affected.push(...extractAffectedRanges(entries.map(a=>({...normalizeLegacySplitRanges(a,record.description),_affectedProvider:{kind:'nvd-affected',name:group.source}}))));
 }
 return {...record,source:'nvd',affected,fixVersion:null};
}

function matchNvdAffected(deps,matches,opts={}) {
 const {newIndex,addToIndex}=require('./cve-download');
 const {matchDepsAgainstCves}=require('./cve-match');
 const index=newIndex(),seen=new Set(),records=new Map();
 for(const m of matches) {
  const c=m.cve;
  if(!c || seen.has(c.id) || !Array.isArray(c.nvdAffected))continue;
  seen.add(c.id);
  const projected=projectNvdAffected({...c,affected:c.nvdAffected,vulnStatus:c.nvdVulnStatus});
  if(projected){addToIndex(index,projected);records.set(c.id,c);}
 }
 return matchDepsAgainstCves(deps,index,opts).map(m=>{
  const {branchFix,fixVersion,fixEvaluation,...metadata}=records.get(m.cve.id);
  return {...m,cve:{...metadata,...m.cve,identityEvidence:m.cve.coordinateEvidence}};
 });
}

// A package binding is a lookup candidate, NOT a finding. Read the full stored
// OSV documents independently of whether their ranges match this scan's version.
// This allows an older release scanned alone to reuse the same NVD evidence as
// it would in a reactor containing a newer release of that package.
function collectPackageNvdBindings(deps,store) {
 const out=[],seen=new Set();
 for(const dep of deps.values()) {
  if(dep.ecosystem!=='maven' || dep.provenance==='binary')continue;
  const coord=`${dep.groupId}:${dep.artifactId}`;
  if(seen.has(coord))continue;
  // Native affected entries can name an exact package absent from our CPE map.
  // The CPE-only matcher below still requires its unique curated mapping.
  seen.add(coord);
  const ids=new Set();
  for(const record of store.getPackageRecords('Maven',coord,{source:'osv'})) {
   const document=record.document;
   if(record.source!=='osv' || record.withdrawnAt || !document || document.withdrawn)continue;
   if(!document.affected?.some(a=>a.package?.ecosystem==='Maven' && a.package.name===coord))continue;
   const cves=[...new Set([document.id,...document.aliases||[]].filter(id=>/^CVE-\d{4}-\d+$/.test(id)))];
   // Multi-CVE aggregate advisories don't identify which CVE belongs to which
   // affected entry. Do not manufacture a package binding for every alias.
   if(cves.length!==1 || ids.has(cves[0]))continue;
   ids.add(cves[0]);
   out.push({dep,source:'osv',bindingOnly:true,cve:{id:cves[0]}});
  }
 }
 return out;
}

// Extend version coverage only for a CVE already bound by OSV to this exact
// Maven artifact. A one-to-one curated CPE must name the artifact itself;
// framework products, runtime constraints and negated configurations do not qualify.
function matchBoundNvdRanges(deps,matches,map=loadCpeCoordMap()) {
 const out=[],seen=new Set(matches.filter(m=>!m.bindingOnly).flatMap(m=>[m.cve?.id,...m.cve?.aliases||[]].filter(Boolean).map(id=>`${m.dep?.coordKey}|${m.dep?.version}|${id}`)));
 function leaves(node) {
  if(!node || node.negate || (node.operator && node.operator!=='OR'))return [];
  return [...(node.cpeMatch||[]),...(node.nodes||node.children||[]).flatMap(leaves)];
 }
 for(const match of matches) {
  if(match.suppressed || match.cpeFiltered || !(match.source||'').split('+').includes('osv'))continue;
  const {dep,cve}=match;
  if(dep?.ecosystem!=='maven' || !/^CVE-\d{4}-\d+$/.test(cve?.id||''))continue;
  const coord=`${dep.groupId}:${dep.artifactId}`;
  const ranges=(cve.configurations||[]).flatMap(leaves).filter(r=>{
   const c=parseCpe23(r.criteria||r.cpe23Uri);
   if(r.vulnerable !== true || !c || c.part!=='a' || c.product!==dep.artifactId)return false;
   const mapping=map.byVendorProduct?.[`${c.vendor}:${c.product}`];
   if(mapping?.length!==1 || mapping[0]!==coord)return false;
   // Unmodelled CPE qualifiers can restrict applicability to a deployment.
   const fields=(r.criteria||r.cpe23Uri).split(':');
   if(fields.length!==13 || fields.slice(6).some(x=>x!=='*'))return false;
   if(['versionStartIncluding','versionStartExcluding','versionEndIncluding','versionEndExcluding'].some(k=>r[k]!=null && !/^[0-9][A-Za-z0-9._+-]*$/.test(r[k])))return false;
   return true;
  });
  if(!ranges.length)continue;
  for(const d of deps.values()) {
   if(d.ecosystem!=='maven' || `${d.groupId}:${d.artifactId}`!==coord || d.provenance==='binary')continue;
   for(const version of d.versions?.length?d.versions:[d.version]) {
    if(typeof version!=='string' || !/^[0-9][A-Za-z0-9._+-]*$/.test(version))continue;
    const key=`${d.coordKey}|${version}|${cve.id}`;
    if(seen.has(key) || !ranges.some(r=>matchVersionRange(version,r)))continue;
    seen.add(key);
    out.push({dep:{...d,version},confidence:'exact',source:'nvd',cve:{
     id:cve.id,description:cve.description,severity:cve.severity,score:cve.score,
     configurations:cve.configurations,fixVersion:null,fixEvaluation:'unknown',
     identityEvidence:'OSV package binding and unique artifact CPE'
    }});
   }
  }
 }
 return out;
}
module.exports={matchBoundNvdRanges,collectPackageNvdBindings,projectNvdAffected,matchNvdAffected};
