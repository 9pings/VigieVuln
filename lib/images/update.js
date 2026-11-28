'use strict';
const crypto=require('node:crypto');
const {createCacheRepository}=require('../cache/repository');
const {getCacheDir}=require('../cache/directory');
const {parseReference,fetchRegistryTags,fetchRegistryTagPlatform}=require('./registry');

// Only patch releases with an exact major.minor branch and suffix are ordered.
// A suffix is treated as an opaque variant, never as a guessed version.
function numericTag(tag){const m=/^(v?)(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(-[A-Za-z][A-Za-z0-9._-]*)?$/.exec(tag||'');return m?{prefix:m[1],major:m[2],minor:m[3],patch:m[4]===undefined?null:BigInt(m[4]),suffix:m[5]||''}:null;}
async function resolveImageUpdate(metadata,options={}){
 const binding=metadata?.registryReference,scannedDigest=metadata?.digest||metadata?.acquisition?.resolvedDigest||null;
 const bound=binding && typeof binding.reference==='string' && /^sha256:[a-f0-9]{64}$/.test(binding.platformDigest||'') && binding.platformDigest===scannedDigest;
 const reference=metadata?.acquisition?.kind==='registry'?metadata.acquisition.reference:bound?binding.reference:null;
 const fallback=(reason,reasonCode='unavailable')=>({status:'unknown',reference:reference||null,currentTag:null,targetReference:null,targetTag:null,branch:null,observedAt:null,source:null,reason,reasonCode,verifiedFix:false});
 if(!reference)return fallback('No registry image reference is available; update the image or its affected package or binary.','no-reference');
 let ref;try{ref=parseReference(reference);}catch{return fallback('The image reference cannot be parsed; update the image or affected package or binary.');}
 const name=String(reference).replace(/^docker:\/\//,'').split('@')[0],at=name.lastIndexOf(':'),slash=name.lastIndexOf('/'),currentTag=at>slash?name.slice(at+1):ref.reference;
 const parsed=numericTag(currentTag);if(!parsed)return {...fallback('The image tag does not identify a comparable patch-release branch; update the image or affected package or binary.','unsupported-tag'),currentTag};
 const base={reference,currentTag,branch:`${parsed.prefix}${parsed.major}.${parsed.minor}${parsed.suffix}`,source:'registry-tags',verifiedFix:false};
 const platform=metadata.platform;if(!platform?.os||!platform?.architecture)return {...fallback('The image platform is unavailable; update the image or affected package or binary.','platform-unknown'),...base,status:'unknown'};
 const key='image-tags-'+crypto.createHash('sha256').update(`${ref.registry}/${ref.repository}`).digest('hex'),repo=createCacheRepository(options.cacheDir||getCacheDir());let observation=repo.get('catalogue',key)?.value;
 const transport={...options,fetcher:options.registryFetcher||options.fetcher,limits:options.registryLimits},ttl=options.imageUpdateTtlMs??4*3600000;
 if(!Number.isSafeInteger(ttl)||ttl<=0)throw Error('invalid image update cache TTL');
 const age=Date.now()-Date.parse(observation?.observedAt);
 if(!options.offline && (!observation || !Number.isFinite(age) || age<0 || age>=ttl)){try{const found=await fetchRegistryTags(reference,transport);observation={tags:found.tags,registry:found.registry,repository:found.repository,observedAt:new Date().toISOString(),platforms:{}};repo.put('catalogue',key,observation);}catch(error){return {...fallback(`Registry tag lookup failed: ${error.message}`,'registry-error'),...base,status:'unknown'};}}
 if(options.offline && (!Number.isFinite(age)||age<0))return {...fallback('Registry observation has an invalid collection date.','cache-miss'),...base,status:'unknown'};
 if(!observation || !Array.isArray(observation.tags))return {...fallback('No registry tag observation is available offline; update the image or affected package or binary.','cache-miss'),...base,status:'unknown'};
 const repository=at>slash?name.slice(0,at):name,candidates=[];
 for(const tag of observation.tags){const version=numericTag(tag);if(version&&version.patch!==null&&version.prefix===parsed.prefix&&version.major===parsed.major&&version.minor===parsed.minor&&version.suffix===parsed.suffix&&(parsed.patch===null||version.patch>=parsed.patch))candidates.push({tag,version});}
 candidates.sort((a,b)=>a.version.patch>b.version.patch?-1:a.version.patch<b.version.patch?1:0);
 observation.platforms ||= {};const platformKey=JSON.stringify([platform.os,platform.architecture,platform.variant||'']);
 for(const candidate of candidates){const candidateKey=JSON.stringify([candidate.tag,platformKey]);let proof=observation.platforms[candidateKey];
  if(proof===undefined&&!options.offline){try{proof=await fetchRegistryTagPlatform(`${repository}:${candidate.tag}`,platform,transport);observation.platforms[candidateKey]=proof;repo.put('catalogue',key,observation);}catch(error){return {...fallback(`Registry manifest lookup failed: ${error.message}`,'registry-error'),...base,observedAt:observation.observedAt,status:'unknown'};}}
  if(proof){const rebuilt=parsed.patch!==null&&candidate.version.patch===parsed.patch&&!!scannedDigest&&proof.platformDigest!==scannedDigest;return {...base,status:parsed.patch===null||candidate.version.patch>parsed.patch||rebuilt?'available':'current',...(rebuilt?{reasonCode:'rebuilt-tag'}:{}),targetTag:candidate.tag,targetReference:`${repository}:${candidate.tag}`,targetDigest:proof.digest,platformDigest:proof.platformDigest,observedAt:observation.observedAt,reason:'Registry tag ordering does not establish that any vulnerability is fixed.'};}
  if(proof===undefined && options.offline)break;
 }
 return {...fallback('No comparable tag with verified image platform is available in the registry observation.','platform-mismatch'),...base,observedAt:observation.observedAt,status:'unknown'};
}
module.exports={resolveImageUpdate,numericTag};
