'use strict';
// Alpine's tracker combines CPE rules and distro fix data. Its `fixed:false`
// rows are *possibly vulnerable*, not an Alpine affected verdict.
const crypto=require('node:crypto');
const {createCacheRepository}=require('../cache-repository');
const {getCacheDir}=require('../cache-directory');
const ORIGIN='https://security.alpinelinux.org';
const CVE=/^CVE-\d{4}-\d{4,}$/;
function key(kind,id){return `alpine-tracker-${kind}-${crypto.createHash('sha256').update(id).digest('hex')}`;}
function branch(distribution){const m=/^(\d+)\.(\d+)(?:\.\d+)?$/.exec(distribution?.versionId||'');return distribution?.id==='alpine'&&m?`${m[1]}.${m[2]}`:null;}
function packageUrl(name,version){if(!/^[a-z0-9][a-z0-9+_.-]*$/.test(name)||!/^[A-Za-z0-9][A-Za-z0-9+_.~-]*$/.test(version))throw Error('invalid Alpine source package identity');return `${ORIGIN}/srcpkg/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;}
function cveId(url){try{const u=new URL(url);if(u.origin!==ORIGIN)return null;const m=/^\/vuln\/(CVE-\d{4}-\d{4,})$/.exec(u.pathname);return m?.[1]||null;}catch{return null;}}
async function boundedJson(response,maxBytes){if(!response.body)throw Error('empty Alpine tracker response');const chunks=[];let n=0;for await(const chunk of response.body){n+=chunk.length;if(n>maxBytes)throw Error('Alpine tracker response exceeds configured limit');chunks.push(Buffer.from(chunk));}return JSON.parse(Buffer.concat(chunks).toString('utf8'));}
async function assessAlpineTracker(packages,distribution,options={}){
 const release=branch(distribution);if(!release)return {observations:[],coverage:{source:'alpine-tracker',execution:'not-applicable',reason:'Alpine release identity is unavailable.'},diagnostics:[]};
 const repo=options.cacheRepository||createCacheRepository(options.cacheDir||getCacheDir()),ttl=options.ttlMs??86400000,maxBytes=options.maxBytes??8*1024*1024,maxCves=options.maxCves??1000,concurrency=options.concurrency??6;
 if(![ttl,maxBytes,maxCves,concurrency].every(v=>Number.isSafeInteger(v)&&v>0))throw Error('invalid Alpine tracker limits');
 const groups=new Map(),diagnostics=[],observations=[],memo=new Map(),limit=require('p-limit')(concurrency);let unscoped=0;
 for(const p of packages||[]){if(p.manager!=='apk')continue;if(!p.sourceName||!p.sourceVersion){unscoped++;continue;}try{packageUrl(p.sourceName,p.sourceVersion);}catch{unscoped++;continue;}const id=JSON.stringify([p.sourceName,p.sourceVersion]);if(!groups.has(id))groups.set(id,{name:p.sourceName,version:p.sourceVersion,packages:[]});groups.get(id).packages.push(p.name);}
 async function get(kind,id,url){const memoKey=kind+':'+id;if(memo.has(memoKey))return memo.get(memoKey);
  const promise=limit(async()=>{const k=key(kind,id),cached=repo.get('catalogue',k)?.value,age=Date.now()-(cached?.fetchedAt||0);
   if(options.offline){if(cached?.document)return cached;throw Error('Alpine tracker observation is not cached');}
   if(cached?.document&&!cached.stale&&age>=0&&age<ttl)return cached;
   const signal=options.signal?AbortSignal.any([options.signal,AbortSignal.timeout(options.timeoutMs??30000)]):AbortSignal.timeout(options.timeoutMs??30000);
   const type=kind==='package'?'package':'vulnerability',params=kind==='package'?{name:id}:{id};
   const response=await require('../providers').getResource('alpine',type,params,{fetcher:options.fetcher,signal,streaming:true,noStore:true});
   if(!response.ok){await response.body?.cancel();throw Error(`Alpine tracker HTTP ${response.status}`);}
   const document=await boundedJson(response,maxBytes);
   if(document?.id!==url||!Array.isArray(kind==='package'?document.cpeMatch:document.state))throw Error('invalid Alpine tracker response');
   const proxy=require('../providers').hasProxyRoute(),stamp=Date.parse(response.headers?.get?.('x-fad-proxy-fetched-at')||''),valid=Number.isFinite(stamp)&&stamp>0&&stamp<=Date.now()+300000;
   const entry={document,fetchedAt:proxy?(valid?stamp:Date.now()):Date.now(),stale:proxy&&(!valid||response.headers?.get?.('x-fad-proxy')==='stale'),url};repo.put('catalogue',k,entry);return entry;
  });memo.set(memoKey,promise);return promise;
 }
 const indexes=await Promise.all([...groups.values()].map(async group=>{const sourceUrl=`${ORIGIN}/srcpkg/${encodeURIComponent(group.name)}`;try{const index=await get('package',group.name,sourceUrl);if(index.document?.id!==sourceUrl||!Array.isArray(index.document.cpeMatch))throw Error('invalid Alpine package index');return {group,sourceUrl,index};}catch(error){diagnostics.push({source:'alpine-tracker',code:options.offline?'cache-missing':'source-request-failed',reason:error.message,resources:[sourceUrl]});return null;}}));
 const work=[];let truncated=false;
 for(const index of indexes.filter(Boolean)){const {group,sourceUrl}=index,ids=[...new Set(index.index.document.cpeMatch.filter(m=>m.package===sourceUrl).map(m=>cveId(m.vuln)).filter(Boolean))];for(const id of ids){if(work.length>=maxCves){truncated=true;break;}work.push({...index,id});}}
 await Promise.all(work.map(async({group,sourceUrl,index,id})=>{const url=`${ORIGIN}/vuln/${id}`;let entry;try{entry=await get('vulnerability',id,url);if(entry.document?.id!==url||!Array.isArray(entry.document.state))throw Error('invalid Alpine vulnerability record');}catch(error){diagnostics.push({source:'alpine-tracker',code:options.offline?'cache-missing':'source-request-failed',reason:error.message,resources:[url]});return;}
  const expectedVersion=packageUrl(group.name,group.version),states=entry.document.state.filter(s=>s.packageVersion===expectedVersion&&typeof s.repo==='string'&&s.repo.startsWith(`${release}-`)&&typeof s.fixed==='boolean');
  const scoped=options.alpineRepository?states.filter(s=>s.repo===`${release}-${options.alpineRepository}`):states,statuses=new Set(scoped.map(s=>s.fixed?'fixed':'possible')),status=statuses.size===1?[...statuses][0]:'unknown';
  observations.push({id,source:'alpine-tracker',status,sourceName:group.name,sourceVersion:group.version,distribution:{id:'alpine',versionId:distribution.versionId,branch:release},repository:options.alpineRepository||null,repositoryVerified:!!options.alpineRepository,packages:[...new Set(group.packages)],sourceUrl:url,packageUrl:sourceUrl,observedAt:new Date(entry.fetchedAt).toISOString(),stale:!!entry.stale||!!index.stale,states:scoped.map(s=>({repo:s.repo,fixed:s.fixed,sourceUrl:s.id||null})),scope:'source-package',advisoryVerdict:false});
 }));
 observations.sort((a,b)=>a.sourceName.localeCompare(b.sourceName)||a.id.localeCompare(b.id));
 if(truncated)diagnostics.push({source:'alpine-tracker',code:'request-limit',reason:`Alpine tracker candidate limit ${maxCves} reached.`,resources:[]});
 const missing=diagnostics.filter(d=>d.code!=='request-limit').length,stale=observations.filter(o=>o.stale).length,incomplete=!!(missing||truncated||unscoped||stale);
 return {observations,coverage:{source:'alpine-tracker',execution:incomplete?'partial':'completed',result:incomplete?'indeterminate':'consulted',scope:'cpe-candidates',packages:groups.size,candidates:work.length,missing,unscoped,stale,reason:incomplete?'Some Alpine tracker observations were unavailable or incomplete.':'Consulted only CVEs discoverable from tracker CPE rules; this does not establish complete package coverage.'},diagnostics};
}
module.exports={assessAlpineTracker};
