'use strict';
// Run from repository root after compare.cjs and fetching the primary tracker.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const repoRoot=path.resolve(__dirname,'../../../..');
const {createCacheRepository}=require(path.join(repoRoot,'lib/cache-repository'));
const {verdict}=require(path.join(repoRoot,'lib/system-inventory/advisories'));
const compare=require(path.join(repoRoot,'lib/system-inventory/versions')).debian;
const base=process.argv[2]||'/tmp/vv-image-benchmark-20261105';
const out=path.resolve(__dirname,'..');
const results=JSON.parse(fs.readFileSync(path.join(out,'nginx-comparison.json')));
const inventory=JSON.parse(fs.readFileSync(path.join(base,'nginx/inventory.json'))).targets[0];
const cache=createCacheRepository(path.join(base,'nginx/direct-cache'));
const trackerBytes=fs.readFileSync(path.join(base,'debian-tracker.json'));
const tracker=JSON.parse(trackerBytes);
const packages=new Map(inventory.packages.map(p=>[JSON.stringify([p.name,p.version]),p]));
const nativeRecords=new Map();
const ids=r=>[r.id,...(r.aliases||[]),...(r.upstream||[])];
const rows=[];
for(const tool of ['trivy','grype'])for(const row of results.pairwise[tool+'AgainstVv'].missing){
 const pkg=packages.get(JSON.stringify([row.name,row.version]));
 const names=[...new Set([pkg?.sourceName,row.name].filter(Boolean))];
 const records=names.flatMap(name=>cache.get('system-osv:Debian:11',name)?.value||[]);
 const matching=records.filter(r=>ids(r).some(id=>row.ids.includes(id)));
 matching.forEach(r=>nativeRecords.set(r.id,r));
 const evidence=matching.flatMap(r=>(r.affected||[]).map(a=>({id:r.id,package:a.package,sourceVersion:pkg?.sourceVersion,
  ranges:a.ranges,versions:a.versions,verdict:verdict(pkg?.sourceVersion||pkg?.version,a,compare)})));
 const cves=row.ids.filter(id=>/^CVE-\d{4}-\d+$/.test(id));
 const primary=cves.map(id=>({id,sourcePackage:pkg?.sourceName,record:tracker[pkg?.sourceName]?.[id]||null}));
 const status=!matching.length?'absent-from-selected-osv-release':evidence.some(e=>e.verdict===true)?'requires-engine-review':evidence.some(e=>e.verdict===null)?'indeterminate-native-range':'excluded-by-native-range';
 rows.push({tool,...row,sourceName:pkg?.sourceName,sourceVersion:pkg?.sourceVersion,status,osvEvidence:evidence,
   primary:primary.map(p=>({id:p.id,sourcePackage:p.sourcePackage,present:!!p.record,releasePresent:!!p.record?.releases?.[inventory.distribution.codename],availableReleases:Object.keys(p.record?.releases||{}),selectedRelease:p.record?.releases?.[inventory.distribution.codename]||null}))});
}
const summary={};for(const row of rows){const k=row.tool+':'+row.status;summary[k]=(summary[k]||0)+1;}
const selectedPrimary={};for(const row of rows)for(const p of row.primary)if(p.present){selectedPrimary[p.sourcePackage]??={};selectedPrimary[p.sourcePackage][p.id]=tracker[p.sourcePackage][p.id];}
const result={generatedAt:new Date().toISOString(),distribution:inventory.distribution,snapshot:cache.getSnapshot('system-osv:Debian:11'),
 tracker:{url:'https://security-tracker.debian.org/tracker/data/json',sha256:crypto.createHash('sha256').update(trackerBytes).digest('hex'),bytes:trackerBytes.length},
 summary,primaryReleasePresent:rows.filter(r=>r.primary.some(p=>p.releasePresent)).length,rows};
fs.writeFileSync(path.join(out,'nginx-source-audit.json'),JSON.stringify(result,null,2)+'\n');
fs.writeFileSync(path.join(out,'nginx-primary-records.json'),JSON.stringify({osv:[...nativeRecords.values()],debianTracker:selectedPrimary},null,2)+'\n');
console.log(JSON.stringify({summary,primaryReleasePresent:result.primaryReleasePresent,snapshot:result.snapshot}));
require(path.join(repoRoot,'lib/cache-db')).closeCacheDbs();
