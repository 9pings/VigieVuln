'use strict';
// A Go binary built from a checkout names its main module "(devel)": the application's own
// advisories cannot be matched without its version. A version is only ever *proposed*:
//   - by the image's OCI labels (version + source repository holding the module), or
//   - by the build itself, `-ldflags -X main.Version=…`, recorded in the binary.
// It is *proved* independently: the Go module proxy must record that this module at that
// version was cut from the very git revision embedded in the binary, itself built from an
// unmodified checkout. Neither a label, a tag nor a linker flag binds a version alone.
const {makeDepRecord}=require('../dep-record');

const VERSION=/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$/;
const REVISION=/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;
const MAX_LINKER_CANDIDATES=3;

function repo(value){
 try{
  const u=new URL(value);
  if(u.protocol!=='https:'||u.username||u.password||u.port||u.search||u.hash)return null;
  const pathname=u.pathname.replace(/\/+$/,'').replace(/\.git$/i,'');
  if(!pathname||pathname==='/'||pathname.split('/').some(x=>x==='.'||x==='..'))return null;
  return `${u.hostname.toLowerCase()}${pathname}`;
 }catch{return null;}
}
function escapeModule(value){return value.replace(/[A-Z]/g,c=>'!'+c.toLowerCase());}
// "1.23.8" and "v1.23.8" name the same Go module version.
function moduleVersion(raw){
 const text=String(raw??'').trim(),version=/^\d/.test(text)?'v'+text:text;
 return VERSION.test(version)?version:null;
}
// Versions the build wrote into the binary: -X main.Version=1.23.8, -X pkg/version.Version=v2.1.0.
// The toolchain's own versions (GoVersion, MakeVersion) are not the application's.
function linkerVersions(settings={}){
 const found=[];
 for(const m of String(settings['-ldflags']||'').matchAll(/-X\s+[\\"']*([A-Za-z0-9_./~-]+)=([^\s"'\\]+)/g)){
  const name=m[1].split('.').pop();
  if(!/version$/i.test(name)||/^(?:go|make|compiler|runtime|build)version$/i.test(name))continue;
  const version=moduleVersion(m[2]);
  if(version&&!found.includes(version))found.push(version);
 }
 return found.slice(0,MAX_LINKER_CANDIDATES);
}
// A module below the repository root is tagged "<directory>/<version>".
function tagRef(module,source,version){
 const suffix=module.slice(source.length).split('/').filter(Boolean);
 if(/^v(?:[2-9]|[1-9]\d+)$/.test(suffix.at(-1)||''))suffix.pop();
 return `refs/tags/${suffix.length?suffix.join('/')+'/':''}${version}`;
}
function proves(info,candidate,module,revision){
 const origin=info?.Origin||{};
 if(info?.Version!==candidate.version||origin.VCS!=='git'||String(origin.Hash||'').toLowerCase()!==revision.toLowerCase())return false;
 // Under a declared source repository the repository and the exact tag must match. A module
 // served from a vanity path (code.gitea.io/gitea → github.com/go-gitea/gitea) has no such
 // relation to check: the revision recorded by the proxy for that version is the proof.
 if(candidate.source)return repo(origin.URL)===candidate.source&&origin.Ref===tagRef(module,candidate.source,candidate.version);
 return origin.Ref===`refs/tags/${candidate.version}`||(String(origin.Ref||'').startsWith('refs/tags/')&&origin.Ref.endsWith('/'+candidate.version));
}
const validStamp=at=>Number.isFinite(at)&&at>0&&at<=Date.now()+300000;

async function resolveGoMainIdentities(target,options={}){
 const metadata=target?.metadata||{},labels=metadata.imageConfig?.labels||{};
 const labelVersion=moduleVersion(labels['org.opencontainers.image.version']),labelSource=repo(labels['org.opencontainers.image.source']);
 const configDigest=/^sha256:[a-f0-9]{64}$/i.test(metadata.configDigest||'')?metadata.configDigest:null;
 const outputs=[],warnings=[],seen=new Set();let candidates=0,unavailable=0,conflicts=0,stale=0;
 const lookup=options.lookup || (async(module,version)=>{
  const providers=require('../providers');
  const response=await providers.getResource('go','module-info',{module:escapeModule(module),version},{offline:false,fetcher:options.fetcher,...(options.store?{store:options.store}:{})});
  if(!response.ok)throw Object.assign(Error(`Go proxy HTTP ${response.status}`),{status:response.status});
  const proxied=providers.hasProxyRoute(),stamp=Date.parse(response.headers.get('x-fad-proxy-fetched-at')||'');
  if(proxied&&!validStamp(stamp))throw Error('Go proxy evidence has no valid observation timestamp');
  return {info:await response.json(),observedAt:proxied?stamp:Date.now(),stale:proxied&&response.headers.get('x-fad-proxy')==='stale'};
 });
 let repository;const cacheRepo=()=>repository||(repository=require('../cache-repository').createCacheRepository(options.cacheDir||require('../cache-directory').getCacheDir()));
 const requests=new Map();
 const warn=message=>{if(!warnings.some(w=>w.message===message))warnings.push({type:'source-unavailable',capability:'identity',source:'go-proxy',message});};

 for(const binary of target?.deps||[]){
  if(binary.ecosystem!=='binary')continue;
  const go=binary.binaryMetadata?.go,settings=go?.settings||{},main=(go?.modules||[]).filter(m=>m.kind==='mod');
  if(main.length!==1||main[0].version!=='(devel)'||main[0].replace||!main[0].path)continue;
  const module=main[0].path,revision=settings['vcs.revision'],binaryPath=binary.artifactPath||binary.manifestPaths?.[0];
  // The publisher's label speaks for the modules of the repository it names, in an image.
  const labelled=!!(configDigest&&labelVersion&&labelSource&&(module===labelSource||module.startsWith(labelSource+'/')));
  const proposals=[...(labelled?[{version:labelVersion,source:labelSource,proposedBy:'oci-label'}]:[]),
   ...linkerVersions(settings).filter(v=>!labelled||v!==labelVersion).map(version=>({version,source:null,proposedBy:'linker-flag'}))];
  if(!proposals.length)continue;
  const clean=settings.vcs==='git'&&settings['vcs.modified']==='false'&&REVISION.test(revision||'')&&binaryPath&&/^[a-f0-9]{64}$/i.test(binary.hashes?.sha256||'');
  const platformConflict=(settings.GOOS&&metadata.platform?.os&&settings.GOOS!==metadata.platform.os)||(settings.GOARCH&&metadata.platform?.architecture&&settings.GOARCH!==metadata.platform.architecture);
  // A labelled binary that cannot be verified contradicts the label; one that only carries a
  // linker flag simply offers nothing to verify.
  if(!clean||platformConflict){if(labelled)conflicts++;continue;}
  candidates++;
  let identified=false,conflicting=false,failed=false;
  for(const candidate of proposals){
   const {version}=candidate,key=JSON.stringify([module,version,candidate.source,revision.toLowerCase()]);
   let observation;
   try{
    if(options.offline){
     const saved=cacheRepo().get('go-main-identity',key);
     if(!saved)throw Error('no cached Go proxy version evidence');
     observation={info:saved.value,observedAt:saved.fetchedAt,stale:saved.stale};
    }else{
     const requestKey=`${module}\0${version}`;
     if(!requests.has(requestKey))requests.set(requestKey,Promise.resolve().then(()=>lookup(module,version)));
     const value=await requests.get(requestKey);
     observation=value?.info?value:{info:value,observedAt:Date.now(),stale:false};
    }
    if(!validStamp(observation.observedAt))throw Error('invalid Go proxy evidence timestamp');
   }catch(error){
    // The proxy does not know this version of the module: the proposal was wrong, not the source.
    if(!options.offline&&[404,410].includes(error.status)){conflicting=true;continue;}
    let saved;try{if(!options.offline)saved=cacheRepo().get('go-main-identity',key);}catch{}
    if(saved&&validStamp(saved.fetchedAt)){
     observation={info:saved.value,observedAt:saved.fetchedAt,stale:true};
     warn(`Go module version refresh failed for ${module}@${version}; cached evidence is stale: ${error.message}`);
    }else{failed=true;warn(`Go module version evidence unavailable for ${module}@${version}: ${error.message}`);continue;}
   }
   const info=observation.info,origin=info?.Origin||{};
   if(!proves(info,candidate,module,revision)){
    conflicting=true;
    if(!options.offline)try{cacheRepo().delete('go-main-identity',key);}catch{}
    continue;
   }
   if(observation.stale){stale++;if(!warnings.some(w=>w.message.includes(`${module}@${version}`)))warn(`Go module version evidence is stale for ${module}@${version}.`);}
   if(!options.offline)try{cacheRepo().put('go-main-identity',key,info,{fetchedAt:observation.observedAt,stale:!!observation.stale,metadata:{source:'go-module-proxy',module,version}});}
    catch(error){warnings.push({type:'source-unavailable',capability:'identity',source:'go-proxy-cache',message:`Could not cache Go module version evidence for ${module}@${version}: ${error.message}`});}
   identified=true;
   const occurrence=`${binaryPath}\0${module}\0${version}`;
   if(seen.has(occurrence))break;
   seen.add(occurrence);
   const dep=makeDepRecord({ecosystem:'go',name:module,version,manifestPath:binaryPath,provenance:'binary-module',scope:'runtime'});
   dep.coordKey=`binary-module:${binaryPath}:${module}@${version}`;
   dep.binaryEvidence={binaryPath,source:'go-vcs-and-module-proxy',versionProposedBy:candidate.proposedBy,binarySha256:binary.hashes.sha256,original:main[0],revision,modified:false,configDigest,
    declaredSource:candidate.source?labels['org.opencontainers.image.source']:null,declaredVersion:version,
    proxyOrigin:{VCS:origin.VCS,URL:origin.URL,Ref:origin.Ref,Hash:origin.Hash},observedAt:observation.observedAt,stale:!!observation.stale};
   outputs.push(dep);
   break;
  }
  if(!identified){if(failed)unavailable++;else if(conflicting)conflicts++;}
 }
 const examined=candidates||conflicts;
 return {deps:outputs,warnings,coverage:{collector:'go-main-identity',execution:unavailable||conflicts||stale?'partial':candidates?'completed':'not-applicable',
  result:outputs.length?'identified':unavailable?'unavailable':conflicts?'conflicting-evidence':examined?'no-match':'no-candidate',count:outputs.length,candidates,conflicts,stale}};
}
module.exports={resolveGoMainIdentities,linkerVersions,moduleVersion};
