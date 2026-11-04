'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const root=process.cwd(),base=process.argv[2];
const read=p=>JSON.parse(fs.readFileSync(p));
const store=require(root+'/lib/advisory-store').openAdvisoryStore();
const {extractMavenRelevantCve,newIndex,addToIndex}=require(root+'/lib/cve-download');
const {matchDepsAgainstCves}=require(root+'/lib/cve-match');
const {makeDepRecord}=require(root+'/lib/dep-record');
const old=read(root+'/docs/benchmark-evidence/2026-11-02/dubbo-snyk-consolidated.json');
const remaining=read(base+'/output/dubbo-snyk-comparison-matching-repair.json').snykOnlyFindings;
const key=x=>[x.coord,x.version,x.id].join('|'),oldKey=x=>[x.package,x.version,x.snykId].join('|');
const confirmed=new Set(old.cases.filter(x=>x.category==='confirmed_missing_package_advisory').map(oldKey));
const rows=[];
const report=read(base+'/output/dubbo-vv-62-online.json');
for(const item of remaining.filter(x=>confirmed.has(key(x)))){
 const [namespace,name]=item.coord.split(':'),dep=makeDepRecord({ecosystem:'maven',namespace,name,version:item.version}),deps=new Map([[dep.coordKey,dep]]);
 const ids=item.ids, records=new Map();
 for(const id of ids){const r=store.getRecord('osv',id);if(r)records.set(r.document.id,r);}
 // CVE IDs are aliases of GHSA records, not their primary store keys. Inspect
 // other reported packages for the same CVE as well, without treating those
 // other packages as proof that the target artifact is affected.
 const relatedPackages=new Set([item.coord]);
 for(const m of report.cve)if([m.id,...m.aliases||[]].some(id=>ids.includes(id)) && m.dep?.ecosystem==='maven')relatedPackages.add(m.dep.coord);
 for(const id of ids.filter(x=>x.startsWith('CVE-'))){
  const raw=store.getRecord('cveproject',id)?.document;
  for(const ref of [raw?.containers?.cna,...raw?.containers?.adp||[]].flatMap(c=>c?.references||[])){
   const ghsa=ref.url?.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i)?.[0];
   const r=ghsa&&store.getRecord('osv',ghsa);
   if(r && [r.document.id,...r.document.aliases||[]].some(id=>ids.includes(id)))records.set(r.document.id,r);
  }
 }
 for(const pkg of relatedPackages)for(const r of store.getPackageRecords('Maven',pkg,{source:'osv'}))if([r.document.id,...r.document.aliases||[]].some(id=>ids.includes(id)))records.set(r.document.id,r);
 const osv=[...records.values()].map(r=>({id:r.document.id,withdrawn:r.document.withdrawn||null,affected:r.document.affected,hash:crypto.createHash('sha256').update(JSON.stringify(r.document)).digest('hex')}));
 const osvExact=osv.flatMap(o=>o.affected||[]).filter(a=>a.package?.ecosystem==='Maven' && a.package.name===item.coord);
 const osvVerdict=osvExact.length ? require(root+'/lib/osv-db').vulnVerdict(item.version,{affected:osvExact},'Maven') : null;
 const native=[];
 for(const id of ids.filter(x=>x.startsWith('CVE-'))){
  const record=store.getRecord('cveproject',id),raw=record?.document,cve=raw&&extractMavenRelevantCve(raw),idx=newIndex();if(cve)addToIndex(idx,cve);const uncertain=[];
  const matches=matchDepsAgainstCves(deps,idx,{onUncertain:m=>uncertain.push(m)});
  const nvd=require(root+'/lib/nvd').readCache(id,true);
  native.push({id,present:!!record,state:raw?.cveMetadata?.state,affected:raw?.containers?.cna?.affected,adpAffected:raw?.containers?.adp?.flatMap(x=>x.affected||[]),projected:cve?.affected||null,matches:matches.length,uncertain:uncertain.map(x=>({confidence:x.confidence,ranges:x.cve.ranges,identity:x.cve.coordinateEvidence})),nvdPresent:!!nvd,nvdConfigurations:nvd?.configurations||[],nvdDescription:nvd?.description,hash:raw?crypto.createHash('sha256').update(JSON.stringify(raw)).digest('hex'):null});
 }
 rows.push({package:item.coord,version:item.version,snykId:item.id,ids,native,osv,osvExact:osvExact.length,osvVerdict});
}
fs.writeFileSync(base+'/output/remaining-62-native-audit.json',JSON.stringify({rows},null,2));console.log('Audited',rows.length,'cases');
