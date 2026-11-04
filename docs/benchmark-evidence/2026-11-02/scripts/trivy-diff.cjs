const fs=require('fs');const metas={nodegoat:'npm',prometheus:'Go',poetry:'PyPI',mastodon:'RubyGems',phpmyadmin:'Packagist'};const vvEco={npm:'npm',Go:'go',PyPI:'pypi',RubyGems:'ruby',Packagist:'composer'};
const cn=(n,e)=>e==='PyPI'?n.toLowerCase().replace(/[-_.]+/g,'-'):e==='Go'?n:n.toLowerCase();const cv=v=>String(v).replace(/^v(?=\d)/,'');
for(const name of Object.keys(metas)){
 const eco=metas[name],o=JSON.parse(fs.readFileSync(`/tmp/vv-bench-multi/results/${name}-osv.json`)),v=JSON.parse(fs.readFileSync(`/tmp/vv-bench-multi/results/${name}${name==='phpmyadmin'?'-vv-after':'-vv'}.json`)),t=JSON.parse(fs.readFileSync(`/tmp/vv-bench-multi/results/${name}-trivy.json`));const rows=[];
 for(const r of t.Results||[])for(const f of r.Vulnerabilities||[]){const matches=[];for(const x of o.results||[])for(const p of x.packages||[])if(p.package.ecosystem===eco&&cn(p.package.name,eco)===cn(f.PkgName,eco)&&cv(p.package.version)===cv(f.InstalledVersion))for(const g of p.groups||[]){const ids=[...g.ids,...g.aliases||[]];if(ids.includes(f.VulnerabilityID))matches.push(...ids);}
 const ids=new Set([f.VulnerabilityID,...matches]);const match=(v.cve||[]).some(x=>x.dep?.ecosystem===vvEco[eco]&&cn(x.dep.coord,eco)===cn(f.PkgName,eco)&&cv(x.dep.version)===cv(f.InstalledVersion)&&[x.id,...x.aliases||[]].some(z=>ids.has(z)));
 if(!match)rows.push({name:f.PkgName,version:f.InstalledVersion,id:f.VulnerabilityID,osvGroup:matches,source:f.DataSource?.ID,primary:f.PrimaryURL});}
 fs.writeFileSync(`/tmp/vv-bench-multi/results/${name}-trivy-only.json`,JSON.stringify(rows,null,2));console.log(name,'trivy matches absent VV',rows.length);
}
