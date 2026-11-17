'use strict';
// Freexian's ELTS tracker provides distribution-scoped statuses, independent
// from both Debian's retired-release snapshot and OSV.
const crypto=require('node:crypto');
const {Readable,Transform}=require('node:stream');
const {chain}=require('stream-chain');
const {parser}=require('stream-json');
const {streamObject}=require('stream-json/streamers/StreamObject');
const {createCacheRepository}=require('../cache-repository');
const {getCacheDir}=require('../cache-directory');
const compare=require('./versions').debian;
const SOURCE='freexian-tracker', VERSION=1, URL='https://deb.freexian.com/extended-lts/tracker/data/json';
const packageName=p=>typeof p==='string' && /^[a-z0-9][a-z0-9+.-]{0,199}$/.test(p);
const plain=x=>!!x && typeof x==='object' && !Array.isArray(x);
function validatePackage(value){if(!plain(value)||!Object.keys(value).length)return false;return Object.entries(value).every(([id,record])=>/^(?:CVE-\d{4}-\d{4,}|TEMP-[A-Za-z0-9-]+)$/.test(id) && plain(record) && plain(record.releases));}
function validateTrackerSnapshot(body){return plain(body) && Object.keys(body).length>0 && Object.entries(body).every(([key,value])=>packageName(key)&&validatePackage(value));}
function projectTrackerSnapshot(body,params){if(!validateTrackerSnapshot(body)||!Array.isArray(params?.packages)||!params.packages.length||params.packages.length>1000||!params.packages.every(packageName))throw Error('invalid Freexian tracker snapshot');return {packages:Object.fromEntries(params.packages.filter(p=>Object.hasOwn(body,p)).map(p=>[p,body[p]]))};}
async function readProjection(res,names,opts={}){
 if(!res.ok){await res.body?.cancel();throw Error(`Freexian tracker HTTP ${res.status}`);}
 const limit=opts.freexianTrackerMaxBytes??256*1024*1024;if(!Number.isSafeInteger(limit)||limit<1024||limit>1024*1024*1024)throw Error('invalid Freexian tracker byte limit');
 let size=0,entries=0;const hash=crypto.createHash('sha256'),wanted=new Set(names),packages={},keys=[];
 const count=new Transform({transform(chunk,_enc,cb){size+=chunk.length;if(size>limit)return cb(Error('Freexian tracker exceeds byte limit'));hash.update(chunk);cb(null,chunk);}});
 const unique=new Transform({objectMode:true,transform(token,_enc,cb){if(token.name==='startObject')keys.push(new Set());else if(token.name==='endObject')keys.pop();else if(token.name==='keyValue'){const set=keys.at(-1);if(set?.has(token.value))return cb(Error('duplicate Freexian tracker JSON key'));set?.add(token.value);}cb(null,token);}});
 // A cache hit can supply the whole dump as one Buffer. Tokenizers emit all
 // tokens from a chunk before backpressure resumes: bound chunks at the input
 // for cached bodies and network streams alike, without copying their bytes.
 async function* boundedChunks(){for await(const chunk of res.body){for(let offset=0;offset<chunk.length;offset+=65536)yield chunk.subarray(offset,offset+65536);}}
 const stream=chain([Readable.from(boundedChunks(),{objectMode:false,highWaterMark:65536}),count,parser(),unique,streamObject()]);
 try{for await(const {key,value} of stream){entries++;if(opts.projected){if(key!=='packages'||entries!==1||!plain(value))throw Error('invalid Freexian tracker projection');for(const [name,record] of Object.entries(value)){if(!wanted.has(name)||!validatePackage(record))throw Error('invalid Freexian tracker projection');packages[name]=record;}}else{if(!packageName(key)||!validatePackage(value))throw Error('invalid Freexian tracker package data');if(wanted.has(key))packages[key]=value;}}}finally{stream.destroy();}
 if(!entries)throw Error('empty Freexian tracker snapshot');
 const actualHash=hash.digest('hex'),header=res.headers.get('x-vigievuln-source-sha256');return {packages,sha256:opts.projected?(header&&/^[a-f0-9]{64}$/i.test(header)?header.toLowerCase():null):actualHash,projectionSha256:opts.projected?actualHash:null};
}
async function parseTrackerBytes(input,params,opts={}){
 const body=Buffer.isBuffer(input)||input instanceof Uint8Array?Readable.toWeb(Readable.from([input])):input;
 const result=await readProjection(new Response(body),params.packages,{...opts,projected:false});return {packages:result.packages,sourceSha256:result.sha256};
}

function releaseInfo(record,codename){const r=record?.releases?.[codename];return plain(r)?r:null;}
function evaluate(r,version){
 if(!r || !['open','resolved'].includes(r.status))return 'unknown';
 const known=Object.values(r.repositories||{}).some(v=>typeof v==='string' && compare(version,v)===0);
 if(r.status==='open')return known?'affected':'unknown';
 if(r.fixed_version==='0')return known?'not-affected':'unknown';
 if(typeof r.fixed_version!=='string' || compare(r.fixed_version,r.fixed_version)!==0)return 'unknown';
 const c=compare(version,r.fixed_version);return c===null?'unknown':c<0?'affected':'fixed';
}
async function assessFreexianTracker(inventory,opts={}){
 const d=inventory?.distribution,all=inventory?.packages||[],result={matches:[],observations:[],coverage:[],warnings:[],assessments:[]};
 if(d?.id!=='debian'||!/^\d+(?:\.\d+)*$/.test(d.versionId||'')||!/^[a-z][a-z0-9-]*$/.test(d.codename||'')){result.coverage.push({source:SOURCE,execution:'not-applicable',result:'indeterminate',reason:'Exact Debian release identity unavailable.'});return result;}
 const eligible=all.filter(p=>p.manager==='dpkg'&&packageName(p.sourceName)&&typeof p.sourceVersion==='string'&&compare(p.sourceVersion,p.sourceVersion)===0&&!['third-party','ambiguous'].includes(p.packageOrigin?.status));
 const names=[...new Set(eligible.map(p=>p.sourceName))].sort();if(!names.length){result.coverage.push({source:SOURCE,execution:'not-applicable',result:'not-applicable'});return result;}const maxPackages=opts.freexianTrackerMaxPackages??100000;if(!Number.isSafeInteger(maxPackages)||maxPackages<1||names.length>maxPackages)throw Error('Freexian tracker package limit exceeded');
 const repo=opts.cacheRepository||opts.repository||createCacheRepository(opts.cacheDir||getCacheDir()),ns=`freexian-tracker:v${VERSION}:${d.versionId.split('.')[0]}:${d.codename}`,now=Date.now(),ttl=opts.freexianTrackerTtlMs??4*3600*1000;
 if(!Number.isSafeInteger(ttl)||ttl<1)throw Error('invalid Freexian tracker TTL');
 let saved=repo.get(ns,'snapshot')?.value,failure=null;const origin=require('../providers').resourceOrigin();
 if(!opts.offline && (!saved||saved.origin!==origin||!Number.isFinite(saved.fetchedAt)||saved.fetchedAt<=0||saved.fetchedAt>now||now-saved.fetchedAt>=ttl||names.some(p=>!saved.queriedPackages?.includes(p))||opts.forceUpdate||opts.refresh)){
  try{const signal=opts.signal?AbortSignal.any([opts.signal,AbortSignal.timeout(opts.timeoutMs??120000)]):AbortSignal.timeout(opts.timeoutMs??120000),proxy=require('../providers').hasProxyRoute(),chunks=proxy?Array.from({length:Math.ceil(names.length/1000)},(_,i)=>names.slice(i*1000,(i+1)*1000)):[names];let combined={},sourceHash=null,stamp=Date.now(),stale=false,staleReason=null;
  for(const chunk of chunks){const params={packages:chunk.slice(0,1000)},res=await (opts.fetchResource?opts.fetchResource('tracker',params):require('../providers').getResource('freexian','tracker',params,{fetcher:opts.fetcher,streaming:true,noStore:true,signal}));const data=await readProjection(res,chunk,{...opts,projected:proxy});Object.assign(combined,data.packages);if(chunks.length>1&&!data.sha256)throw Error('Freexian tracker projection lacks source hash across pages');if(sourceHash&&data.sha256&&sourceHash!==data.sha256)throw Error('Freexian tracker source changed during projection');sourceHash=sourceHash||data.sha256;const at=Date.parse(res.headers.get('x-fad-proxy-fetched-at')||''),valid=Number.isFinite(at)&&at>0&&at<=Date.now();if(proxy){if(valid)stamp=Math.min(stamp,at);else {stamp=null;stale=true;}stale ||= res.headers.get('x-fad-proxy')==='stale';const reason=res.headers.get('x-fad-proxy-reason');if(reason==='refresh-failed')staleReason='proxy refresh failed';}}
  if(signal.aborted)throw signal.reason||Object.assign(Error('Freexian tracker request aborted'),{name:'AbortError'});
  saved={packages:combined,sha256:sourceHash,queriedPackages:names,fetchedAt:stamp,stale,staleReason,origin,sourceUrl:URL};repo.put(ns,'snapshot',saved,{fetchedAt:saved.fetchedAt||0,stale:saved.stale});repo.delete(ns,'failure');}catch(error){if(opts.signal?.aborted)throw error;failure=error;repo.put(ns,'failure',{origin,reason:error.message,attemptedAt:Date.now()});if(saved?.origin===origin){saved={...saved,stale:true,staleReason:`refresh failed: ${error.message}`};repo.put(ns,'snapshot',saved,{fetchedAt:saved.fetchedAt||0,stale:true});}else saved=null;result.warnings.push({type:'source-unavailable',source:SOURCE,message:`Freexian tracker: ${error.message}`});}
 }
 if(opts.offline){const cachedFailure=repo.get(ns,'failure')?.value;if(cachedFailure && (!saved || cachedFailure.origin===saved.origin)){failure=Error(cachedFailure.reason);result.warnings.push({type:'source-unavailable',source:SOURCE,message:`Freexian tracker: ${cachedFailure.reason}`});}}
 if(!saved){result.coverage.push({source:SOURCE,execution:failure?'failed':'not-run',result:'indeterminate',reason:failure?.message||'No Freexian tracker snapshot cached.'});return result;}
 if(saved.staleReason&&!failure)result.warnings.push({type:'source-unavailable',source:SOURCE,message:`Freexian tracker: ${saved.staleReason}; saved data retained.`});
 let missing=0;
 for(const dep of eligible){if(!saved.queriedPackages?.includes(dep.sourceName)){missing++;continue;}for(const [id,record] of Object.entries(saved.packages[dep.sourceName]||{})){if(!/^CVE-\d{4}-\d{4,}$/.test(id))continue;const release=releaseInfo(record,d.codename);if(!release)continue;const status=evaluate(release,dep.sourceVersion),evidence={distribution:d,sourceName:dep.sourceName,sourceVersion:dep.sourceVersion,releaseStatus:release.status,fixedVersion:release.fixed_version??null,sourceURL:`https://deb.freexian.com/extended-lts/tracker/${id}`,sha256:saved.sha256,fetchedAt:saved.fetchedAt,urgency:release.urgency??null,nodsa:release.nodsa??null,nodsaReason:release.nodsa_reason??null,repositories:release.repositories||{},signatureVerified:false};result.assessments.push({dep,cveId:id,source:SOURCE,status,evidence});if(status==='unknown' && !(release.status==='resolved' && release.fixed_version==='0'))result.observations.push({dep,cveId:id,source:SOURCE,status:'possible',sourceUrl:evidence.sourceURL,reason:'The tracker release status applies to a different archive source version; applicability to the installed version is undetermined.',evidence});if(status==='affected'){const cve={id,summary:record.description||'',severity:'UNKNOWN',fixVersion:release.fixed_version&&release.fixed_version!=='0'?release.fixed_version:null,historicalEvidence:evidence};result.matches.push({dep,source:SOURCE,cve});}}}
 // A not-affected archive entry is not positive evidence against an older
 // installed package. Keep its unknown assessment for independent refinement,
 // without manufacturing a suspected vulnerability from the missing proof.
 const assessmentCounts=result.assessments.reduce((counts,a)=>{counts[a.status]=(counts[a.status]||0)+1;return counts;},{});
 result.coverage.push({source:SOURCE,execution:failure||saved.stale||missing?'partial':'completed',result:'consulted',assessmentCounts,fetchedAt:saved.fetchedAt,sha256:saved.sha256,queriedPackages:saved.queriedPackages.length,...(missing?{missingPackages:missing}:{}),...(failure?{reason:failure.message}:{})});return result;
}
module.exports={SOURCE,validateTrackerSnapshot,projectTrackerSnapshot,parseTrackerBytes,assessFreexianTracker};
