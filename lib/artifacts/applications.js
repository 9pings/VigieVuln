// Installed application metadata in an extracted image. Never execute package code.
const fs = require('fs');
const path = require('path');
const {makeDepRecord} = require('../dep-record');
const {isNpmPackageDescriptor,isProjectDescriptor} = require('./component-scope');
const MAX_METADATA = 16 * 1024 * 1024;
const handlers = [
 {id:'npm', matches:(n,fp)=>n==='package.json' && isNpmPackageDescriptor(fp), parse:(text)=>{const j=JSON.parse(text);return j.name || j.version ? [{ecosystem:'npm',name:j.name,version:j.version}] : [];}},
 {id:'composer-project', matches:(n,fp)=>n==='composer.json' && isProjectDescriptor(fp), parse:(text)=>{const j=JSON.parse(text);return j.name || j.version ? [{ecosystem:'composer',name:j.name,version:j.version}] : [];}},
 {id:'pypi-project', matches:(n,fp)=>n==='pyproject.toml' && isProjectDescriptor(fp), parse:(text)=>{const j=require('smol-toml').parse(text),p=j.project || j.tool?.poetry || {};return p.name || p.version ? [{ecosystem:'pypi',name:p.name,version:p.version}] : [];}},
 {id:'maven-project', matches:(n,fp)=>n==='pom.xml' && isProjectDescriptor(fp), async parse(text){const j=await require('xml2js').parseStringPromise(text),p=j.project;if(!p)return [];const parent=p.parent?.[0]||{},name=p.artifactId?.[0],namespace=p.groupId?.[0]||parent.groupId?.[0],version=p.version?.[0]||parent.version?.[0];if(!name)return [];if(!namespace || /\$\{/.test(String(namespace)+String(version)))throw Error('project coordinates are not literal');return [{ecosystem:'maven',namespace,name,version}];}},
 {id:'pypi', matches:(n,fp)=>(n==='METADATA' && /\.dist-info$/i.test(path.basename(path.dirname(fp)))) || (n==='PKG-INFO' && /\.egg-info$/i.test(path.basename(path.dirname(fp)))), parse:(text)=>{const name=/^Name:\s*(.+)$/im.exec(text)?.[1]?.trim(), version=/^Version:\s*(.+)$/im.exec(text)?.[1]?.trim();return [{ecosystem:'pypi',name,version}];}},
 {id:'composer', matches:(n,fp)=>n==='installed.json' && path.basename(path.dirname(fp))==='composer', parse:(text)=>{const j=JSON.parse(text), pkgs=Array.isArray(j)?j:j.packages;if(!Array.isArray(pkgs))throw Error('missing packages');return pkgs.map(p=>({ecosystem:'composer',name:p.name,version:p.version}));}},
 {id:'composer-php', matches:(n,fp)=>n==='installed.php' && path.basename(path.dirname(fp))==='composer', parse:(text)=>{
  // Composer's generated PHP is data, but parse literal version entries only.
  // Never evaluate PHP or interpolate its expressions.
  const re=/['"]([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)['"]\s*=>\s*(?:array\s*\(|\[)/g, starts=[]; let match;
  while((match=re.exec(text))) starts.push({name:match[1],start:re.lastIndex});
  return starts.map(item=>{let depth=1,end=item.start,quote=null;for(;end<text.length && depth;end++){const c=text[end];if(quote){if(c==='\\')end++;else if(c===quote)quote=null;continue}if(c==='\"'||c==="'"){quote=c;continue}if(c==='('||c==='[')depth++;else if(c===')'||c===']')depth--;}const block=depth?'':text.slice(item.start,end-1);const version=/['"]pretty_version['"]\s*=>\s*['"]([^'"\r\n]+)['"]/.exec(block)?.[1];return {ecosystem:'composer',name:item.name,version};});
 }},
 {id:'ruby', matches:(n,fp)=>n.endsWith('.gemspec') && path.dirname(fp).split(path.sep).includes('specifications'), parse:(text)=>{const name=/\b(?:s|spec)\.name\s*=\s*["']([^"']+)["']/.exec(text)?.[1],version=/\b(?:s|spec)\.version\s*=\s*(?:Gem::Version\.new\(\s*)?["']([^"']+)["']/.exec(text)?.[1];return [{ecosystem:'ruby',name,version}];}},
 {id:'nuget', matches:n=>n.endsWith('.deps.json'), parse:(text)=>{const j=JSON.parse(text);return Object.entries(j.libraries||{}).filter(([,v])=>v?.type==='package').map(([key])=>{const i=key.lastIndexOf('/');return {ecosystem:'nuget',name:key.slice(0,i),version:key.slice(i+1)};});}},
];
function valid(x) {return x && typeof x.name==='string' && x.name.trim() && typeof x.version==='string' && x.version.trim() && !/[\r\n\0]/.test(x.name+x.version);}
const archiveCollectors = [{id:'jar', async collect(root) {return require('../codecs/maven/jar-scan').scanEmbeddedJars(root,{defaultExcludes:false});}}];
async function collectInstalledApplications(root,opts={}) {
 const activeHandlers=opts.handlers || handlers, archives=opts.archiveCollectors || archiveCollectors;
 for(const h of activeHandlers) if(!h || typeof h.id!=='string' || typeof h.matches!=='function' || typeof h.parse!=='function') throw Error('Invalid installed metadata handler');
 for(const h of archives) if(!h || typeof h.id!=='string' || typeof h.collect!=='function') throw Error('Invalid installed archive collector');
 const deps=new Map(),warnings=[], coverage={files:0,records:0,handlers:{}}; const stack=[root], max=opts.maxMetadataBytes ?? MAX_METADATA;
 function warning(fp,error) {warnings.push({type:'dependency-coverage',reason:'installed-metadata-error',manifestPath:fp,message:`installed metadata incomplete for ${fp}: ${error.message}`});}
 function add(item,fp,source) {if(item.ecosystem==='composer' && typeof item.name==='string' && !item.namespace) {const slash=item.name.indexOf('/');if(slash>0)item={...item,namespace:item.name.slice(0,slash),name:item.name.slice(slash+1)};}if(!valid(item)){warning(fp,Error('missing package name or version'));return;} const dep=makeDepRecord({...item,manifestPath:fp,provenance:'installed',scope:'transitive'});dep.coordKey=`installed:${fp}:${item.ecosystem}:${item.name}@${item.version}`;dep.installEvidence={path:fp,source};deps.set(dep.coordKey,dep);}
 while(stack.length) {const dir=stack.pop();let entries;try{entries=fs.readdirSync(dir,{withFileTypes:true})}catch(e){warning(dir,e);continue}for(const entry of entries){const fp=path.join(dir,entry.name);if(entry.isDirectory()){stack.push(fp);continue}if(!entry.isFile())continue;if(entry.name==='installed.php' && entries.some(e=>e.name==='installed.json' && e.isFile()))continue;for(const h of activeHandlers){if(!h.matches(entry.name,fp))continue;coverage.files++;coverage.handlers[h.id]=(coverage.handlers[h.id]||0)+1;try{const st=fs.statSync(fp);if(st.size>max)throw Error(`metadata exceeds ${max} bytes`);const parsed=await h.parse(fs.readFileSync(fp,'utf8'));for(const item of parsed)add(item,fp,h.id)}catch(e){warning(fp,e)}break;}}}
 for(const collector of archives){try{const result=await collector.collect(root,opts);warnings.push(...(result.warnings||[]));coverage.handlers[collector.id]=(result.deps||[]).length;for(const item of result.deps||[]){const fp=item.manifestPaths?.[0]||root;if(!item.namespace && item.ecosystem==='maven'){warning(fp,Error('archive has no complete Maven coordinate'));continue}add({ecosystem:item.ecosystem,namespace:item.namespace,name:item.name,version:item.version},fp,collector.id);}}catch(e){warning(root,e)}}coverage.records=deps.size;coverage.complete=warnings.length===0;return {deps,warnings,coverage};
}
// Reclassify only an unidentifiable top-level JAR whose exact installed owner
// has itself been assessed. Corrupt archives and nested contents remain gaps.
function classifyOwnedArchiveWarnings(warnings, packages, assessedPackages) {
 const assessed = assessedPackages instanceof Set ? assessedPackages : new Set();
 const byPath = new Map();
 const normalize = value => {
  if(typeof value!=="string" || !value || value.includes("!") || value.includes("\\") || value.includes("\0") || value.split('/').includes('..'))return null;
  return path.posix.normalize('/'+value.replace(/^\/+/,''));
 };
 for(const pkg of packages || []) {
  if(!pkg?.manager || !pkg?.name || !pkg?.version || !assessed.has(`${pkg.manager}:${pkg.name}@${pkg.version}`))continue;
  for(const owned of pkg.ownedPaths||[]) {const p=normalize(owned);if(p && !byPath.has(p))byPath.set(p,pkg);}
 }
 const remaining=[],informational=[];
 for(const warning of warnings || []) {
  const p=normalize(warning?.manifestPath);
  const eligible=warning?.reason==='installed-metadata-error' && /\.jar$/i.test(p||'') && typeof warning.message==='string' && warning.message.endsWith(': archive has no complete Maven coordinate');
  const owner=eligible?byPath.get(p):null;
  if(owner)informational.push({warning,owner:{manager:owner.manager,name:owner.name,version:owner.version},path:p});else remaining.push(warning);
 }
 return {warnings:remaining,informational};
}
module.exports={collectInstalledApplications,handlers,archiveCollectors,classifyOwnedArchiveWarnings,MAX_METADATA};
