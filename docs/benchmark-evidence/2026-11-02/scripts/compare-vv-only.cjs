const fs=require('fs');
const ecos={pypi:'PyPI',npm:'npm',go:'Go',ruby:'RubyGems',composer:'Packagist'};
const cn=(n,e)=>e==='PyPI'?n.toLowerCase().replace(/[-_.]+/g,'-'):e==='Go'?n:n.toLowerCase();
const cv=v=>String(v).replace(/^v(?=\d)/,'');
for(const name of ['nodegoat','prometheus','poetry','mastodon','phpmyadmin']){
 const o=JSON.parse(fs.readFileSync(`/tmp/vv-bench-multi/results/${name}-osv.json`));const v=JSON.parse(fs.readFileSync(`/tmp/vv-bench-multi/results/${name}-vv.json`));const entries=[];
 for(const r of o.results||[])for(const p of r.packages||[]){const a=p.package;for(const g of p.groups||[])entries.push({package:a,ids:new Set([...g.ids,...(g.aliases||[])])});}
 const extra=[];for(const f of v.cve||[]){const dep=f.dep,eco=ecos[dep?.ecosystem];if(!eco)continue;const ids=[f.id,...(f.aliases||[])];const matches=entries.filter(x=>x.package.ecosystem===eco&&cn(x.package.name,eco)===cn(dep.coord,eco)&&cv(x.package.version)===cv(dep.version)&&ids.some(id=>x.ids.has(id)));if(!matches.length)extra.push({name:dep.coord,version:dep.version,id:f.id,aliases:f.aliases,manifestPaths:dep.manifestPaths});}
 fs.writeFileSync(`/tmp/vv-bench-multi/results/${name}-vv-only.json`,JSON.stringify(extra,null,2));console.log(name,'VV findings absent OSV:',extra.length);
}
