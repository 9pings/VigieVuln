const fs=require('fs'),root=process.cwd(),{extractMavenRelevantCve,newIndex,addToIndex}=require(root+'/lib/cve-download'),{matchDepsAgainstCves}=require(root+'/lib/cve-match'),{makeDepRecord}=require(root+'/lib/dep-record'),{evaluateCveForDep}=require(root+'/lib/cpe'),{vulnVerdict}=require(root+'/lib/osv-db');
const x=JSON.parse(fs.readFileSync(process.argv[2]));const counts={};const finalReport=process.argv[4]?JSON.parse(fs.readFileSync(process.argv[4])):null;
for(const r of x.rows){
 const [namespace,name]=r.package.split(':'),dep=makeDepRecord({ecosystem:'maven',namespace,name,version:r.version});
 for(const n of r.native){
  const c=extractMavenRelevantCve({cveMetadata:{cveId:n.id,state:n.state},containers:{cna:{affected:n.affected}}}),i=newIndex();if(c)addToIndex(i,c);
  n.matchesAfter=matchDepsAgainstCves(new Map([[dep.coordKey,dep]]),i).length;
  n.nvdEvaluation=evaluateCveForDep({configurations:n.nvdConfigurations},dep,undefined,{curatedOnly:true});
 }
 const exact=r.osv.flatMap(o=>o.affected||[]).filter(a=>a.package?.ecosystem==='Maven'&&a.package.name===r.package);
 r.osvExact=exact.length;r.osvVerdict=exact.length?vulnVerdict(r.version,{affected:exact},'Maven'):null;
 r.category=r.native.some(n=>n.matchesAfter)?'matcher_corrected':!r.native.length?'no_public_identifier_in_observation':exact.length?(r.osvVerdict===false?'osv_ranges_exclude_version':r.osvVerdict===true?'unexpected_osv_miss':'osv_ranges_undecidable'):r.osv.length?'osv_names_other_artifact':'native_only_without_usable_package_binding';
 if(r.category!=='matcher_corrected' && finalReport?.cve.some(m=>!m.suppressed && !m.cpeFiltered && m.dep.coord===r.package && m.dep.version===r.version && [m.id,...m.aliases||[]].some(id=>r.ids.includes(id))))r.category='corrected_by_bound_nvd_range';
 counts[r.category]=(counts[r.category]||0)+1;
}
x.counts=counts;x.method='Read the actual cached native CVEProject, OSV and NVD records; replay native projection and matching, and OSV matching restricted to exact package identity. NVD product-level matches are not artifact proof. The category describes the first remaining blocker, not whether the software is vulnerable.';fs.writeFileSync(process.argv[3],JSON.stringify(x,null,2)+'\n');console.log(counts);
