const fs=require('fs'),root=process.cwd();
require(root+'/lib/cache-directory').setActiveCacheDir('/tmp/vv-nvd-fields/cache');
const {projectNvdAffected}=require(root+'/lib/nvd-package-ranges');
const {newIndex,addToIndex}=require(root+'/lib/cve-download');
const {matchDepsAgainstCves}=require(root+'/lib/cve-match');
const {makeDepRecord}=require(root+'/lib/dep-record');
const cases=JSON.parse(fs.readFileSync('/tmp/vv-nvd-fields/cases.json'));
const rows=cases.map(c=>{
 const [namespace,name]=c.package.split(':'),dep=makeDepRecord({ecosystem:'maven',namespace,name,version:c.version});
 const records=c.ids.filter(i=>i.startsWith('CVE-')).map(id=>{
  const p='/tmp/vv-nvd-fields/'+id+'.json';if(!fs.existsSync(p))return {id,absent:true};
  const raw=JSON.parse(fs.readFileSync(p)),idx=newIndex(),projected=projectNvdAffected(require(root+'/lib/nvd').extractFromNvdRecord(raw));if(projected)addToIndex(idx,projected);
  const unknown=[];const matches=matchDepsAgainstCves(new Map([[dep.coordKey,dep]]),idx,{onUncertain:m=>unknown.push(m)});
  return {id,sha256:require('crypto').createHash('sha256').update(fs.readFileSync(p)).digest('hex'),affected:raw.affected||[],hasCpe:!!raw.configurations?.length,matched:matches.length>0,uncertain:unknown.length>0};
 });return {...c,records};
});
const summary={observations:rows.length,withCve:rows.filter(r=>r.records.length).length,withAffected:rows.filter(r=>r.records.some(c=>c.affected?.length)).length,recovered:rows.filter(r=>r.records.some(c=>c.matched)).map(r=>({project:r.project,package:r.package,version:r.version,ids:r.records.filter(c=>c.matched).map(c=>c.id)}))};
fs.writeFileSync('/tmp/vv-nvd-fields/audit.json',JSON.stringify({date:'2026-11-02',source:'https://services.nvd.nist.gov/rest/json/cves/2.0',summary,rows},null,2));console.log(JSON.stringify(summary));
