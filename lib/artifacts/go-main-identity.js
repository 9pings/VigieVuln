'use strict';
// Bind a Go main module to a version only when independent Go proxy VCS
// provenance matches the clean revision embedded in the binary. OCI labels
// propose a lookup; neither a label nor an image tag proves a version alone.
const {makeDepRecord}=require('../dep-record');
const VERSION=/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$/;
function repo(value){try{const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.port||u.search||u.hash)return null;const pathname=u.pathname.replace(/\/+$/,'').replace(/\.git$/i,'');if(!pathname||pathname==='/'||pathname.split('/').some(x=>x==='.'||x==='..'))return null;return `${u.hostname.toLowerCase()}${pathname}`;}catch{return null;}}
function escapeModule(value){return value.replace(/[A-Z]/g,c=>'!'+c.toLowerCase());}
function tagRef(module,source,version){const suffix=module.slice(source.length).split('/').filter(Boolean);if(/^v(?:[2-9]|[1-9]\d+)$/.test(suffix.at(-1)||''))suffix.pop();return `refs/tags/${suffix.length?suffix.join('/')+'/':''}${version}`;}
async function resolveGoMainIdentities(target,options={}){
 const metadata=target?.metadata||{},labels=metadata.imageConfig?.labels||{},version=labels['org.opencontainers.image.version'],source=repo(labels['org.opencontainers.image.source']);
 const outputs=[],warnings=[],seen=new Set();let candidates=0,unavailable=0,conflicts=0,stale=0;
 if(!source || !VERSION.test(version||'') || !/^sha256:[a-f0-9]{64}$/i.test(metadata.configDigest||''))return {deps:outputs,warnings,coverage:{collector:'go-main-identity',execution:'not-applicable',result:'no-candidate',count:0}};
 const lookup=options.lookup || (async(module,ver)=>{const providers=require('../providers'),response=await providers.getResource('go','module-info',{module:escapeModule(module),version:ver},{offline:false,fetcher:options.fetcher,...(options.store?{store:options.store}:{})});if(!response.ok)throw Error(`Go proxy HTTP ${response.status}`);const proxied=providers.hasProxyRoute(),stamp=Date.parse(response.headers.get('x-fad-proxy-fetched-at')||'');if(proxied&&(!Number.isFinite(stamp)||stamp<=0||stamp>Date.now()+300000))throw Error('Go proxy evidence has no valid observation timestamp');return {info:await response.json(),observedAt:proxied?stamp:Date.now(),stale:proxied&&response.headers.get('x-fad-proxy')==='stale'};});
 let repository;const cacheRepo=()=>repository||(repository=require('../cache-repository').createCacheRepository(options.cacheDir||require('../cache-directory').getCacheDir()));
 const cache=new Map();
 for(const binary of target.deps||[]){
  if(binary.ecosystem!=='binary')continue;const go=binary.binaryMetadata?.go,settings=go?.settings||{},main=(go?.modules||[]).filter(m=>m.kind==='mod');
  if(main.length!==1 || main[0].version!=='(devel)' || main[0].replace || !main[0].path || !(main[0].path===source || main[0].path.startsWith(source+'/')))continue;
  const module=main[0].path,revision=settings['vcs.revision'],binaryPath=binary.artifactPath||binary.manifestPaths?.[0];
  if(settings.vcs!=='git'||settings['vcs.modified']!=='false'||!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(revision||'')||!binaryPath||!/^[a-f0-9]{64}$/i.test(binary.hashes?.sha256||'')){conflicts++;continue;}
  if((settings.GOOS && metadata.platform?.os && settings.GOOS!==metadata.platform.os)||(settings.GOARCH && metadata.platform?.architecture && settings.GOARCH!==metadata.platform.architecture)){conflicts++;continue;}
  candidates++;let info,observation,key=JSON.stringify([module,version,source,revision.toLowerCase()]);try{
   if(options.offline){const saved=cacheRepo().get('go-main-identity',key);if(!saved)throw Error('no cached Go proxy version evidence');observation={info:saved.value,observedAt:saved.fetchedAt,stale:saved.stale};}
   else{const requestKey=`${module}\0${version}`;if(!cache.has(requestKey))cache.set(requestKey,Promise.resolve().then(()=>lookup(module,version)));const value=await cache.get(requestKey);observation=value?.info?value:{info:value,observedAt:Date.now(),stale:false};}
   if(!Number.isFinite(observation.observedAt)||observation.observedAt<=0||observation.observedAt>Date.now()+300000)throw Error('invalid Go proxy evidence timestamp');
   info=observation.info;
  }catch(error){
   let saved;try{if(!options.offline)saved=cacheRepo().get('go-main-identity',key);}catch{}
   if(saved && Number.isFinite(saved.fetchedAt) && saved.fetchedAt>0 && saved.fetchedAt<=Date.now()+300000){observation={info:saved.value,observedAt:saved.fetchedAt,stale:true};info=observation.info;warnings.push({type:'source-unavailable',capability:'identity',source:'go-proxy',message:`Go module version refresh failed for ${module}@${version}; cached evidence is stale: ${error.message}`});}
   else{unavailable++;warnings.push({type:'source-unavailable',capability:'identity',source:'go-proxy',message:`Go module version evidence unavailable for ${module}@${version}: ${error.message}`});continue;}
  }
  const origin=info?.Origin||{};
  if(info?.Version!==version||origin.VCS!=='git'||repo(origin.URL)!==source||origin.Ref!==tagRef(module,source,version)||String(origin.Hash||'').toLowerCase()!==revision.toLowerCase()){conflicts++;if(!options.offline)try{cacheRepo().delete('go-main-identity',key);}catch{}continue;}
  if(observation.stale){stale++;if(!warnings.some(w=>w.source==='go-proxy' && w.message.includes(`${module}@${version}`)))warnings.push({type:'source-unavailable',capability:'identity',source:'go-proxy',message:`Go module version evidence is stale for ${module}@${version}.`});}
  if(!options.offline)try{cacheRepo().put('go-main-identity',key,info,{fetchedAt:observation.observedAt,stale:!!observation.stale,metadata:{source:'go-module-proxy',module,version}});}catch(error){warnings.push({type:'source-unavailable',capability:'identity',source:'go-proxy-cache',message:`Could not cache Go module version evidence: ${error.message}`});}
  const occurrence=`${binaryPath}\0${module}\0${version}`;if(seen.has(occurrence))continue;seen.add(occurrence);
  const dep=makeDepRecord({ecosystem:'go',name:module,version,manifestPath:binaryPath,provenance:'binary-module',scope:'runtime'});
  dep.coordKey=`binary-module:${binaryPath}:${module}@${version}`;
  dep.binaryEvidence={binaryPath,source:'go-vcs-and-module-proxy',binarySha256:binary.hashes.sha256,original:main[0],revision,modified:false,configDigest:metadata.configDigest,declaredSource:labels['org.opencontainers.image.source'],declaredVersion:version,proxyOrigin:{VCS:origin.VCS,URL:origin.URL,Ref:origin.Ref,Hash:origin.Hash},observedAt:observation.observedAt,stale:!!observation.stale,verification:'vcs-metadata-consistent',symbolReachability:'unknown'};
  outputs.push(dep);
 }
 return {deps:outputs,warnings,coverage:{collector:'go-main-identity',execution:unavailable||conflicts||stale?'partial':candidates?'completed':'not-applicable',result:outputs.length?'identified':unavailable?'unavailable':conflicts?'conflicting-evidence':'no-match',count:outputs.length,candidates,conflicts,stale}};
}
module.exports={resolveGoMainIdentities};
