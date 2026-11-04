const fs=require('fs');
const norms={PyPI:'pypi',npm:'npm',Go:'go',RubyGems:'ruby',Packagist:'composer'};
const canonName=(name,eco)=>eco==='PyPI'?name.toLowerCase().replace(/[-_.]+/g,'-'):eco==='Go'?name:name.toLowerCase();
const normver=v=>String(v).replace(/^v(?=\d)/,'');
for(const name of ['nodegoat','prometheus','poetry','mastodon','phpmyadmin']){
 const o=JSON.parse(fs.readFileSync(`/tmp/vv-bench-multi/results/${name}-osv.json`));const v=JSON.parse(fs.readFileSync(`/tmp/vv-bench-multi/results/${name}-vv.json`));const rec=[];
 for(const r of o.results||[])for(const p of r.packages||[]){const a=p.package,eco=norms[a.ecosystem];if(!eco)continue;
  for(const group of p.groups||[]){const ids=new Set([...group.ids,...(group.aliases||[])]);const matches=(v.cve||[]).filter(x=>x.dep?.ecosystem===eco&&canonName(x.dep.coord,a.ecosystem)===canonName(a.name,a.ecosystem)&&normver(x.dep.version)===normver(a.version)&&[x.id,...(x.aliases||[])].some(z=>ids.has(z)));
  if(!matches.length){const docs=(p.vulnerabilities||[]).filter(z=>ids.has(z.id)||z.aliases?.some(id=>ids.has(id)));const affected=docs.flatMap(z=>(z.affected||[]).filter(b=>b.package?.ecosystem===a.ecosystem&&canonName(b.package.name,a.ecosystem)===canonName(a.name,a.ecosystem)).map(b=>({id:z.id,modified:z.modified,versionExact:(b.versions||[]).includes(a.version),ranges:(b.ranges||[]).map(t=>({type:t.type,events:t.events}))})));rec.push({name:a.name,version:a.version,ids:[...ids],source:r.source?.path,affected});}
  }
 }
 const out=`/tmp/vv-bench-multi/results/${name}-osv-only.json`;fs.writeFileSync(out,JSON.stringify(rec,null,2));console.log(name,'OSV groups absent VV:',rec.length);
}
