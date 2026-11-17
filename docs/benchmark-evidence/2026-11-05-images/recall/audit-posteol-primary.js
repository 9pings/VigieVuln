'use strict';
// Offline, benchmark-specific evidence review. No package-name rules are used in runtime scanning.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'../../../..'),compareDeb=require(path.join(root,'lib/system-inventory/versions')).debian;
const primaryFile=process.argv[2]||'/tmp/vv-nginx-posteol-primary-audit.json',elaFile=process.argv[3]||'/tmp/vv-freexian-gap-audit.json';
const cveRoot=process.argv[4]||'/tmp/vv-recall-20261105/nginx/cache/cve-data/extracted/cves',currentList=process.argv[5]||'/tmp/vv-debian-CVE-current.list';
const output=process.argv[6]||path.join(__dirname,'nginx-posteol-primary-audit.json'),commitFile=process.argv[7]||'/tmp/vv-debian-current-commit.json';
const data=JSON.parse(fs.readFileSync(primaryFile)),elas=JSON.parse(fs.readFileSync(elaFile)),excluded=new Set(elas.flatMap(e=>e.matched.map(([name,id])=>`${name}\0${id}`)));
const rows=data.filter(r=>!excluded.has(`${r.name}\0${r.id}`));if(rows.length!==185)throw Error('Unexpected input tuple count');
const ids=new Set(rows.map(x=>x.id)),tracker=new Map();let id=null;
const currentBytes=fs.readFileSync(currentList);
for(const line of currentBytes.toString('utf8').split(/\r?\n/)){
 if(line && !/^\s/.test(line)){const m=line.match(/^(CVE-\d{4}-\d{4,})\b/);id=m&&ids.has(m[1])?m[1]:null;if(id)tracker.set(id,[]);continue;}
 if(id){const m=line.match(/^\s+(?:\[([^\]]+)\]\s+)?-\s+([a-z0-9][a-z0-9+.-]*)\s+(\S+)/);if(m)tracker.get(id).push({release:m[1]||null,sourceName:m[2],status:m[3]});}
}
const readCve=id=>{const m=/^CVE-(\d{4})-(\d+)$/.exec(id);if(!m)return null;const file=path.join(cveRoot,m[1],`${Math.floor(Number(m[2])/1000)}xxx`,`${id}.json`);try{const bytes=fs.readFileSync(file);return {data:JSON.parse(bytes),sha256:crypto.createHash('sha256').update(bytes).digest('hex')};}catch{return null;}};
const upstreamVersion=v=>{const s=String(v||'').replace(/^\d+:/,'');const i=s.lastIndexOf('-');return i<0?s:s.slice(0,i)};
const numeric=s=>/^\d+(?:\.\d+){1,3}$/.test(s||'')?s.split('.').map(x=>BigInt(x)):null;
const numcmp=(a,b)=>{a=numeric(a);b=numeric(b);if(!a||!b)return null;for(let i=0;i<Math.max(a.length,b.length);i++){const x=a[i]||0n,y=b[i]||0n;if(x<y)return -1;if(x>y)return 1}return 0};
function membership(v,entry,scheme){
 const start=entry?.version,upper=entry?.lessThan??entry?.lessThanOrEqual;
 if(typeof start!=='string'||entry.lessThan!=null&&entry.lessThanOrEqual!=null||entry.changes?.length)return null;
 if(upper==null)return v===start?true:false;
 const compare=scheme==='dpkg'?compareDeb:scheme==='semver'?(a,b)=>/^\d+\.\d+\.\d+$/.test(a)&&/^\d+\.\d+\.\d+$/.test(b)?numcmp(a,b):null:scheme==='custom-numeric'?numcmp:null;
 if(!compare)return null;
 const lo=start==='0'?-1:compare(start,v),hi=upper==='*'?1:compare(upper,v),valid=start==='0'||upper==='*'?-1:compare(start,upper);
 if(lo===null||hi===null||valid===null||valid>0||valid===0&&entry.lessThan!=null)return null;
 return lo<=0&&(upper==='*'||(entry.lessThan!=null?hi>0:hi>=0));
}
function review(row){const record=readCve(row.id), cna=record?.data?.containers?.cna, affected=Array.isArray(cna?.affected)?cna.affected:[], rawVersion=upstreamVersion(row.sourceVersion),proof=[];
 for(const a of affected){
  const isDebian=String(a.vendor||'').toLowerCase()==='debian' && String(a.packageName||'').toLowerCase()===row.sourceName.toLowerCase();
  const isUpstream=String(a.product||'').toLowerCase()===row.sourceName.toLowerCase() && !isDebian;
  if(!isDebian&&!isUpstream)continue;
  const selected=isDebian?row.sourceVersion:rawVersion,items=[];
  for(const v of a.versions||[]){const type=String(v.versionType||'').toLowerCase(),scheme=isDebian?(type==='dpkg'||type==='debian'?'dpkg':null):(type==='semver'?'semver':type==='custom'?'custom-numeric':null);if(type==='git')continue;const member=membership(selected,v,scheme);items.push({version:v.version,status:v.status,lessThan:v.lessThan??null,lessThanOrEqual:v.lessThanOrEqual??null,versionType:v.versionType||null,membership:member,ordering:scheme||'exact-or-unknown'});}
  if(items.length)proof.push({kind:isDebian?'debian-package':'upstream-product',vendor:a.vendor||null,product:a.product||null,packageName:a.packageName||null,packageURL:a.packageURL||null,defaultStatus:a.defaultStatus||'unknown',comparedVersion:selected,ranges:items});
 }
 const direct=proof.filter(p=>p.kind==='debian-package'),up=proof.filter(p=>p.kind==='upstream-product');
 const statusFor=group=>{let hit=[],unknown=false,hasDecidable=false;for(const p of group){for(const r of p.ranges){if(r.membership===true)hit.push(r.status);if(r.membership===null)unknown=true;else hasDecidable=true;}}if(unknown||new Set(hit).size>1||hit.includes('unknown'))return 'unknown';if(hit.includes('affected'))return 'affected';if(hit.includes('unaffected'))return 'unaffected';if(hasDecidable&&group.every(p=>p.defaultStatus==='unaffected'))return 'unaffected';return 'unknown';};
 const deb=statusFor(direct),upstream=statusFor(up);
 let classification=deb==='affected'?'debian-package-affected':deb==='unaffected'?'debian-package-unaffected':upstream==='affected'?'upstream-version-affected-conditional':upstream==='unaffected'?'upstream-version-unaffected-conditional':'unknown';
 const now=(tracker.get(row.id)||[]).filter(x=>x.sourceName===row.sourceName),bookwormNotAffected=now.some(x=>x.release==='bookworm'&&x.status==='<not-affected>');
 const descriptions=Array.isArray(cna?.descriptions)?cna.descriptions.filter(x=>/^en(?:-|$)/i.test(x.lang||'')).map(x=>x.value).filter(x=>typeof x==='string'):[];
 return {package:row.name,installedVersion:row.version,sourcePackage:row.sourceName,sourceVersion:row.sourceVersion,id:row.id,published:row.published||null,classification,bookwormNotAffected,upstreamVersion:rawVersion,runtimeApplicability:'not-assessed',
  cna:record?{source:`https://www.cve.org/CVERecord?id=${encodeURIComponent(row.id)}`,sha256:record.sha256,publisher:cna?.providerMetadata?.shortName||null,description:descriptions[0]||null,references:(cna?.references||[]).map(r=>r.url).filter(x=>typeof x==='string'&&/^https?:\/\//.test(x)).slice(0,20),proof}:null};
}
const results=rows.map(review),counts={},sources={};for(const r of results){counts[r.classification]=(counts[r.classification]||0)+1;const k=r.bookwormNotAffected?'bookworm-not-affected':'without-bookworm-not-affected';sources[k]=(sources[k]||0)+1;}
const commit=JSON.parse(fs.readFileSync(commitFile));if(!/^[a-f0-9]{40}$/.test(commit.id||''))throw Error('Invalid current tracker commit');
const obj={generatedAt:new Date().toISOString(),method:'CNA product/version declarations compared to the reported source version; upstream results are conditional on downstream packaging and backports. No runtime applicability asserted.',inputs:{primarySha256:crypto.createHash('sha256').update(fs.readFileSync(primaryFile)).digest('hex'),elaSha256:crypto.createHash('sha256').update(fs.readFileSync(elaFile)).digest('hex'),currentTrackerCommit:commit.id,currentTrackerCommitTimestamp:commit.committed_date,currentTrackerSha256:crypto.createHash('sha256').update(currentBytes).digest('hex')},total:results.length,uniqueCves:new Set(results.map(r=>r.id)).size,counts,bookworm:sources,rows:results};
fs.writeFileSync(output,JSON.stringify(obj,null,2)+'\n');console.log(JSON.stringify({total:obj.total,uniqueCves:obj.uniqueCves,counts,bookworm:sources},null,2));
