'use strict';
// Offline benchmark analysis. Inputs are the saved, unmodified benchmark outputs,
// complete Debian tracker list and its matching imported snapshot cache.
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const root=path.resolve(__dirname,'../../../..');
const comparisonPath=process.argv[2]||'/tmp/vv-recall-20261105/comparison/nginx-comparison.json';
const findingsPath=process.argv[3]||'/tmp/vv-recall-20261105/nginx/enriched/findings.json';
const inventoryPath=process.argv[4]||'/tmp/vv-image-benchmark-20261105/nginx/inventory.json';
const listPath=process.argv[5]||'/tmp/vv-debian-CVE-historical.list';
const cacheDir=process.argv[6]||'/tmp/vv-history-debian-test';
const output=process.argv[7]||path.join(__dirname,'nginx-gap-audit.json');
const comparison=JSON.parse(fs.readFileSync(comparisonPath)),findings=JSON.parse(fs.readFileSync(findingsPath)),inventory=JSON.parse(fs.readFileSync(inventoryPath)).targets[0];
const cache=require(path.join(root,'lib/cache-repository')).createCacheRepository(cacheDir);
const historical=require(path.join(root,'lib/system-inventory/historical-debian'));
const cmp=require(path.join(root,'lib/system-inventory/versions')).debian;
const ns=historical.namespace({id:'debian',versionId:'11',codename:'bullseye'}),snapshot=cache.getSnapshot(ns);
if(!snapshot?.complete || snapshot.metadata.commit!=='b66660b4eb40ad61cf5d8235defe557f26fde81c')throw Error('Expected full fixed historical Debian snapshot');
const sha=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const listBytes=fs.readFileSync(listPath);if(crypto.createHash('sha256').update(listBytes).digest('hex')!==snapshot.metadata.hashes.CVE)throw Error('CVE list does not match the historical cache');
const needed=new Set(Object.values(comparison.cveComparison).flatMap(v=>v.comparatorOnly.map(r=>r[3])));
const sourceLines=new Map();let active=null;
for(const line of listBytes.toString('utf8').split(/\r?\n/)){
 if(line && !/^\s/.test(line)){const m=line.match(/^(CVE-\d{4}-\d{4,})\b/);active=m&&needed.has(m[1])?m[1]:null;if(active)sourceLines.set(active,new Set());continue;}
 if(active){const m=line.match(/^\s+(?:\[([^\]]+)\]\s+)?-\s+([a-z0-9][a-z0-9+.-]*)\s+(\S+)/);if(m)sourceLines.get(active).add(m[2]);}
}
const packages=new Map(inventory.packages.map(p=>[p.name,p]));
const observations=findings.artifacts.flatMap(a=>a.advisoryObservations||[]);
const classes={not_in_inventory:'Package or exact version not identified in the VV inventory',missing_source_version:'Installed source package/version unavailable',not_in_historical_tracker:'CVE absent from the historical CVE/list',no_release_evidence:'CVE and source package present in historical list, but no bullseye-specific status or advisory fix',no_source_package_evidence:'CVE present historically but no matching source package line',historical_unbounded:'Historical release-specific observation has no version bound or otherwise remains indeterminate',historical_not_affected:'Historical release status explicitly not affected',historical_fixed_at_or_before_installed:'Historical release fixed threshold at or before installed source version',historical_affected_not_matched:'Historical release fixed threshold above installed source version, but no matching VV tuple',historical_other:'Historical release record cannot be classified safely'};
function classify(tuple){const [ecosystem,name,version,id]=tuple,pkg=packages.get(name),base={ecosystem,name,version,id,sourceName:pkg?.sourceName||null,sourceVersion:pkg?.sourceVersion||null};
 if(ecosystem!=='deb'||!pkg || cmp(pkg.version,version)!==0)return {...base,class:'not_in_inventory'};
 if(!pkg.sourceName||!pkg.sourceVersion||cmp(pkg.sourceVersion,pkg.sourceVersion)!==0)return {...base,class:'missing_source_version'};
 const observationsFor=observations.filter(o=>o.cveId===id && o.dep?.name===name);
 const cached=cache.get(ns,pkg.sourceName)?.value||[],rec=cached.find(r=>r.id===id);
 if(!sourceLines.has(id)&&!rec)return {...base,class:'not_in_historical_tracker'};
 if(!rec)return {...base,class:sourceLines.get(id)?.has(pkg.sourceName)?'no_release_evidence':'no_source_package_evidence'};
 const tags=[...new Set((rec.statuses||[]).map(s=>s.kind))],fixes=[...new Set((rec.fixes||[]).map(f=>f.version).filter(v=>cmp(v,v)===0))].sort(cmp);
 const extra={statuses:tags,fixes,observationStatuses:[...new Set(observationsFor.map(o=>o.status))]};
 if(observationsFor.length)return {...base,...extra,class:'historical_unbounded'};
 if(tags.includes('not-affected')&&!fixes.length)return {...base,...extra,class:'historical_not_affected'};
 if(fixes.length){const order=cmp(pkg.sourceVersion,fixes[0]);return {...base,...extra,class:order>=0?'historical_fixed_at_or_before_installed':'historical_affected_not_matched'};}
 return {...base,...extra,class:tags.length?'historical_unbounded':'historical_other'};
}
const tools={};for(const tool of ['trivy','grype']){const rows=comparison.cveComparison[tool].comparatorOnly.map(classify),counts={};for(const row of rows)counts[row.class]=(counts[row.class]||0)+1;tools[tool]={tuples:rows.length,counts,rows};}
const tupleKey=r=>JSON.stringify([r.ecosystem,r.name,r.version,r.id]);
const trivyKeys=new Set(tools.trivy.rows.map(tupleKey)),sharedMissing=tools.grype.rows.filter(r=>trivyKeys.has(tupleKey(r))).length;
const result={generatedAt:new Date().toISOString(),method:'Distinct comparator-only package/version/CVE tuples; explicit release evidence only, matched by binary package then installed source package and source version.',inputs:{comparisonSha256:sha(comparisonPath),findingsSha256:sha(findingsPath),inventorySha256:sha(inventoryPath),historicalCveListSha256:snapshot.metadata.hashes.CVE,historicalDsaSha256:snapshot.metadata.hashes.DSA,historicalDlaSha256:snapshot.metadata.hashes.DLA,commit:snapshot.metadata.commit,cutoff:snapshot.metadata.cutoff},classes,sharedMissing,tools};fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(Object.fromEntries(Object.entries(tools).map(([name,v])=>[name,{tuples:v.tuples,counts:v.counts}])),null,2));require(path.join(root,'lib/cache-db')).closeCacheDbs();
