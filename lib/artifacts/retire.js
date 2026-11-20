'use strict';
// Inspect image bytes only. Do not execute the image's JavaScript or follow its
// symlinks. Persist identities, then reassess them with the current signature DB.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const retire=require('retire/lib/retire');
const POLICY='image-retire/1';
const EXCLUDED=new Set(['node_modules','bower_components','jspm_packages','vendor','site-packages','dist-packages','__pypackages__','.git','.npm','.yarn','.pnpm-store','.cache','.m2','.gradle','.nuget']);
async function repository(options){
 const helper=require('../retire');
 const refreshed=await helper.warmRetireSignatures({...options,force:options.forceUpdate});
 const entry=helper.cachedSignatureEntry(options.cacheDir);
 if(!entry || !refreshed.ok && !options.offline && require('../providers').hasHostedProxy())throw Error(refreshed.error || 'RetireJS signatures are unavailable');
 const repo=JSON.parse(retire.replaceVersion(entry.value));
 if(!repo || typeof repo!=='object' || Array.isArray(repo))throw Error('Invalid RetireJS signatures');
 for(const [name,record] of Object.entries(repo))if(name.startsWith('$'))delete repo[name];else if(!record?.extractors)throw Error('Invalid RetireJS extractor');
 return {repo,signaturesAt:new Date(entry.fetchedAt).toISOString(),refreshError:refreshed.ok?null:refreshed.error || 'RetireJS signatures could not be refreshed'};
}
const warning=(error,capability='inventory')=>({type:'dependency-coverage',capability,reason:'image-retire-incomplete',message:error.message});
async function collectImageJs(root,options={},ownedPaths=[]){
 const deps=[],warnings=[],coverage={collector:'image-retire',capability:'inventory',execution:'completed',result:'indeterminate',files:0,excludedDirectories:[...EXCLUDED],policy:POLICY};
 const owned=new Set(ownedPaths.map(p=>path.posix.normalize('/'+String(p).replace(/\\/g,'/').replace(/^\/+/,''))));
 coverage.excludedOwnedFiles=0;
 let signatures;
 try{signatures=await repository(options);coverage.signaturesAt=signatures.signaturesAt;if(signatures.refreshError)warnings.push(warning(Error(signatures.refreshError)));}
 catch(error){return {deps,warnings:[warning(error)],coverage:{...coverage,execution:'not-run',reason:error.message}};}
 const maxFile=options.maxImageJsFileBytes ?? 16*1024*1024,maxBytes=options.maxImageJsBytes ?? 128*1024*1024,maxFiles=options.maxImageJsFiles ?? 10000;
 let bytes=0,stopped=false;const stack=[root];
 while(stack.length && !stopped){
  options.signal?.throwIfAborted();
  const dir=stack.pop();let entries;
  try{entries=fs.readdirSync(dir,{withFileTypes:true});}catch(error){warnings.push(warning(error));continue;}
  for(const entry of entries){
   const fp=path.join(dir,entry.name),rel=path.relative(root,fp).split(path.sep).join('/');
   if(entry.isDirectory()){
    if(!EXCLUDED.has(entry.name) && !['proc','sys','dev','usr/share/nodejs'].includes(rel))stack.push(fp);
    continue;
   }
   if(!entry.isFile() || !/\.(?:js|mjs|cjs)$/i.test(entry.name))continue;
   // OS-owned libraries may be backported without changing their embedded
   // upstream version. Their distribution advisories remain authoritative.
   if(owned.has('/'+rel)){coverage.excludedOwnedFiles++;continue;}
   try{
    const size=fs.statSync(fp).size;
    if(size>maxFile){warnings.push(warning(Error(`RetireJS file exceeds ${maxFile} bytes: ${rel}`)));continue;}
    if(++coverage.files>maxFiles || bytes+size>maxBytes){warnings.push(warning(Error('RetireJS image scan resource limit reached')));stopped=true;break;}
    bytes+=size;
    let results=retire.scanFileName(rel,signatures.repo);
    if(!results.length)results=retire.scanFileContent(fs.readFileSync(fp),signatures.repo,{sha1:text=>crypto.createHash('sha1').update(text).digest('hex')});
    for(const result of results){
     if(!result.component || !result.version)continue;
     const dep=require('../dep-record').makeDepRecord({ecosystem:'npm',name:result.component,version:result.version,manifestPath:rel,provenance:'vendored',scope:'vendored'});
     dep.coordKey=`retire:${rel}:${result.component}@${result.version}`;
     dep.ecosystemType='retire';dep.installEvidence={source:'retire',path:rel,detection:result.detection};deps.push(dep);
    }
   }catch(error){warnings.push(warning(Error(`${rel}: ${error.message}`)));}
  }
 }
 coverage.bytes=bytes;coverage.count=deps.length;if(warnings.length)coverage.execution='partial';
 return {deps,warnings,coverage};
}
async function assessImageJs(target,options={}){
 const coverage={artifactTargetId:target.id,capability:'advisories',collector:'image-retire',execution:'completed',result:'no-match'};
 if(!options.imageRetire)return {matches:[],warnings:[],coverage:{...coverage,execution:'not-applicable',result:'not-consulted',expected:false}};
 const collected=target.coverage.find(c=>c.collector==='image-retire' && c.capability==='inventory');
 if(!collected || collected.policy!==POLICY)return {matches:[],warnings:[warning(Error('RetireJS image inventory is unavailable; reacquire image contents with --image-retire.'))],coverage:{...coverage,execution:'not-run',result:'indeterminate'}};
 try{
  const {repo,signaturesAt,refreshError}=await repository(options),matches=[],missing=[];
  for(const dep of target.deps.filter(d=>d.installEvidence?.source==='retire' && !d.osPackageOwners?.length)){
   if(!repo[dep.name]){missing.push(dep.name);continue;}
   const raw=[{file:dep.artifactPath,results:retire.check(dep.name,dep.version,repo)}];
   matches.push(...require('../retire').normaliseRetireResults(raw).map(m=>({...m,dep})));
  }
  const incomplete=collected.execution!=='completed'||missing.length>0||!!refreshError;
  const warnings=[];
  if(missing.length)warnings.push(warning(Error(`RetireJS no longer identifies: ${[...new Set(missing)].join(', ')}`),'advisories'));
  if(refreshError)warnings.push(warning(Error(refreshError),'advisories'));
  return {matches,warnings,coverage:{...coverage,signaturesAt,execution:incomplete?'partial':'completed',result:matches.length?'affected':incomplete?'indeterminate':'no-match'}};
 }catch(error){return {matches:[],warnings:[warning(error,'advisories')],coverage:{...coverage,execution:'not-run',result:'indeterminate',reason:error.message}};}
}
module.exports={POLICY,EXCLUDED,collectImageJs,assessImageJs};
