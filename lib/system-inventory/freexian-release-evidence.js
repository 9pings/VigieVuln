'use strict';
const crypto=require('node:crypto');
const {parseDocument}=require('htmlparser2');
const {textContent}=require('domutils');
const {createCacheRepository}=require('../cache-repository');
const {getCacheDir}=require('../cache-directory');
const compare=require('./versions').debian;
const SOURCE='freexian-release-evidence';
function nodes(root,name){const out=[];function visit(n){if(n.type==='tag'&&n.name===name)out.push(n);for(const c of n.children||[])visit(c);}visit(root);return out;}
function text(n){return textContent(n).replace(/\s+/g,' ').trim();}
function parsePage(html,id){
 const root=parseDocument(html),titles=nodes(root,'h1').map(text);if(titles.length!==1||titles[0].toUpperCase()!==id)throw Error('Freexian tracker CVE identity mismatch');
 const matching=[];
 for(const table of nodes(root,'table')){const rows=nodes(table,'tr');if(!rows.length)continue;const heads=(rows[0].children||[]).filter(x=>x.type==='tag'&&x.name==='th').map(text);if(!['Package','Type','Release','Fixed Version'].every(h=>heads.includes(h)))continue;
  if(heads.length!==new Set(heads).size)throw Error('ambiguous Freexian tracker table headings');const idx=Object.fromEntries(heads.map((h,i)=>[h,i]));
  for(const row of rows.slice(1)){const cells=(row.children||[]).filter(x=>x.type==='tag'&&x.name==='td');if(cells.some(c=>c.attribs?.rowspan||c.attribs?.colspan)||cells.length!==heads.length)throw Error('unsupported Freexian tracker table row');const fields=cells.map(text);matching.push({package:fields[idx.Package],type:fields[idx.Type],release:fields[idx.Release],fixedVersion:fields[idx['Fixed Version']],urgency:fields[idx.Urgency]||null,origin:fields[idx.Origin]||null});}
 }
 if(!matching.length)throw Error('Freexian tracker release table unavailable');const notes=nodes(root,'pre').map(text).join('\n').slice(0,200000);return {rows:matching,notes};
}
async function resolveReleaseEvidence(input,opts={}){
 const {id,sourceName,sourceVersion,distribution:d}=input||{};
 if(!/^CVE-\d{4}-\d{4,7}$/.test(id||'')||!/^[a-z0-9][a-z0-9+.-]{0,199}$/.test(sourceName||'')||!sourceVersion||compare(sourceVersion,sourceVersion)!==0||d?.id!=='debian'||!/^[a-z][a-z0-9-]*$/.test(d.codename||''))return {status:'unknown',evidence:{reason:'Invalid source package or distribution identity.'}};
 const repo=opts.cacheRepository||opts.repository||createCacheRepository(opts.cacheDir||getCacheDir()),ns='freexian-release-evidence:v1',provider=require('../providers'),origin=provider.resourceOrigin(),now=Date.now(),ttl=opts.freexianReleaseTtlMs??4*3600*1000,max=opts.freexianReleaseMaxBytes??4*1024*1024,timeout=opts.freexianReleaseTimeoutMs??30000;
 if(!Number.isSafeInteger(ttl)||ttl<1||!Number.isSafeInteger(max)||max<1024||max>64*1024*1024||!Number.isSafeInteger(timeout)||timeout<1)throw Error('invalid Freexian release evidence limits');
 let entry=repo.get(ns,id)?.value, failure=null;const failureKey=`failure:${id}:${origin}`,priorFailure=repo.get(ns,failureKey)?.value;
 if(!opts.offline&&(!entry||entry.origin!==origin||!Number.isFinite(entry.fetchedAt)||entry.fetchedAt<=0||entry.fetchedAt>now||now-entry.fetchedAt>=ttl||opts.forceUpdate||opts.refresh)){
  try{const signal=opts.signal?AbortSignal.any([opts.signal,AbortSignal.timeout(timeout)]):AbortSignal.timeout(timeout),throttle=opts.freexianReleaseThrottle||require('../proxy-throttle').createProxyThrottle({intervalMs:opts.freexianReleaseIntervalMs??250,maxWaitMs:45000,maxRateRetries:15}),res=await throttle.request(()=>opts.fetchResource?opts.fetchResource('vulnerability',{id},signal):provider.getResource('freexian','vulnerability',{id},{fetcher:opts.fetcher,signal,streaming:true,noStore:true,retryProxyDenied:false,noSourceRetry:true}),signal,{retryTransient:false});if(!res.ok){await res.body?.cancel();throw Error(`Freexian tracker HTTP ${res.status}`);}const length=Number(res.headers.get('content-length'));if(length>max){await res.body?.cancel();throw Error('Freexian tracker page exceeds byte limit');}let size=0,chunks=[];for await(const chunk of res.body||[]){size+=chunk.length;if(size>max)throw Error('Freexian tracker page exceeds byte limit');chunks.push(Buffer.from(chunk));}const bytes=Buffer.concat(chunks,size),html=bytes.toString('utf8'),parsed=parsePage(html,id),proxy=provider.hasProxyRoute(),stamp=Date.parse(res.headers.get('x-fad-proxy-fetched-at')||''),valid=Number.isFinite(stamp)&&stamp>0&&stamp<=Date.now();entry={...parsed,origin,fetchedAt:proxy?(valid?stamp:null):Date.now(),stale:proxy&&(!valid||res.headers.get('x-fad-proxy')==='stale'),staleReason:res.headers.get('x-fad-proxy-reason')==='refresh-failed'?'proxy refresh failed':null,sha256:crypto.createHash('sha256').update(bytes).digest('hex')};if(signal.aborted)throw Object.assign(Error('Freexian tracker request aborted'),{name:'AbortError'});repo.put(ns,id,entry,{fetchedAt:entry.fetchedAt||0,stale:entry.stale});repo.delete(ns,failureKey);}catch(error){if(opts.signal?.aborted||error.name==='AbortError'||error.name==='TimeoutError')throw error;failure=error.message;repo.put(ns,failureKey,{reason:failure,attemptedAt:Date.now(),origin});if(entry?.origin===origin){entry={...entry,lastFailure:failure};repo.put(ns,id,entry,{fetchedAt:entry.fetchedAt||0,stale:true});}}
 }
 if(entry && !opts.offline && entry.origin!==origin)entry=null;
 failure ||= opts.offline ? (entry?.lastFailure||priorFailure?.reason) : null;
 if(!entry)return {status:'unknown',evidence:{source:SOURCE,reason:failure||'No cached Freexian tracker page.',...(failure?{failure}: {})}};
 const rows=entry.rows.filter(r=>r.package===sourceName&&r.type==='source'&&r.release===d.codename),row=rows.length===1?rows[0]:null;let status='unknown';if(row?.fixedVersion==='(not affected)')status='not-affected';else if(row?.fixedVersion&&compare(row.fixedVersion,row.fixedVersion)===0&&compare(sourceVersion,row.fixedVersion)>=0)status='fixed';
 return {status,evidence:{source:SOURCE,id,distribution:d,sourceName,sourceVersion,sourceURL:`https://deb.freexian.com/extended-lts/tracker/${id}`,sha256:entry.sha256,fetchedAt:entry.fetchedAt,origin:entry.origin,stale:entry.stale,row,notes:entry.notes,...(failure||entry.staleReason?{failure:failure||entry.staleReason}:{}),...(rows.length>1?{reason:'Multiple matching release rows.'}:{})}};
}
module.exports={SOURCE,parsePage,resolveReleaseEvidence};
