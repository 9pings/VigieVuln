'use strict';
// Official nginx.org advisory XML; upstream version ranges apply only to
// packages with an explicitly declared vendor identity, never generic distro builds.
const crypto=require('node:crypto');
const {createCacheRepository}=require('../../cache/repository');
const {getCacheDir}=require('../../cache/directory');
const PARSER_VERSION=2;
const SOURCE='nginx-vendor-advisories',URL='https://raw.githubusercontent.com/nginx/nginx.org/master/xml/en/security_advisories.xml',PAGE='https://nginx.org/en/security_advisories.html';
function ver(s){const m=/^(\d+)\.(\d+)\.(\d+)$/.exec(String(s));return m?m.slice(1).map(Number):null;}
function cmp(a,b){for(let i=0;i<3;i++)if(a[i]!==b[i])return a[i]-b[i];return 0;}
function inRange(version,text){const v=ver(version);if(!v)return null;const pieces=String(text||'').split(',').map(s=>s.trim());let unknown=false;for(const piece of pieces){if(piece==='all')return true;const m=/^(\d+\.\d+\.\d+)(?:-(\d+\.\d+\.\d+))?$/.exec(piece);if(!m){unknown=true;continue;}const low=ver(m[1]),high=ver(m[2]||m[1]);if(cmp(v,low)>=0&&cmp(v,high)<=0)return true;}return unknown?null:false;}
function isNginxPackage(p){return ['dpkg','apk'].includes(p?.manager)&&p.sourceName==='nginx';}
function fixedInBranch(version,text){
 const current=ver(version);if(!current)return false;
 // Stable fixes are exceptions to the broad vulnerable range, not fixes for
 // a later mainline branch (e.g. 1.30.7 does not fix 1.31.8).
 return String(text||'').split(',').some(piece=>{
  const match=/^(\d+\.\d+\.\d+)\+$/.exec(piece.trim()),fixed=match&&ver(match[1]);
  return fixed&&fixed[0]===current[0]&&fixed[1]===current[1]&&cmp(current,fixed)>=0;
 });
}
function vendor(p,domains){
 const meta=p.packageMetadata||{},origin=String(meta.origin||'').trim().toLowerCase(),maintainer=String(meta.maintainer||'');
 const email=/<[^<>@\s]+@([^<>\s]+)>\s*$/.exec(maintainer)?.[1]?.toLowerCase();
 // APK origin is a source package name, unlike the dpkg vendor Origin field.
 const vendorOrigin=p.manager==='dpkg'&&(origin==='nginx'||origin==='nginx, inc.');
 return vendorOrigin||!!email&&domains.includes(email)?{status:'third-party',source:vendorOrigin?'dpkg-origin':`${p.manager}-maintainer`,declared:vendorOrigin?meta.origin:meta.maintainer,signatureVerified:false}:null;
}
async function parseNginxAdvisories(input,{maxBytes=4*1024*1024}={}){
 const bytes=Buffer.isBuffer(input)?input:Buffer.from(String(input));if(!bytes.length||bytes.length>maxBytes)throw Error('NGINX advisory XML exceeds size limit or is empty');let text=bytes.toString('utf8');
 if(/<!ENTITY\b/i.test(text)||/<!DOCTYPE\s+[^>]*\[/i.test(text))throw Error('NGINX advisory XML contains entity declarations');
 text=text.replace(/<!DOCTYPE\s+article\s+SYSTEM\s+["']\.\.\/\.\.\/dtd\/article\.dtd["']\s*>/i,'');if(/<!DOCTYPE\b/i.test(text))throw Error('unsupported NGINX XML doctype');
 const doc=await require('xml2js').parseStringPromise(text,{strict:true}),sections=doc?.article?.section;if(!Array.isArray(sections))throw Error('invalid NGINX advisory XML');
 const items=sections.flatMap(s=>s.security||[]).flatMap(s=>s.item||[]);if(!items.length)throw Error('NGINX advisory XML has no records');
 const records=[];for(const item of items){const a=item.$||{},cve=/^(?:CVE-)?(\d{4}-\d{4,})$/.exec(a.cve||''),id=cve?`CVE-${cve[1]}`:null;if(!id)continue;if(typeof a.name!=='string'||typeof a.vulnerable!=='string')throw Error('invalid NGINX advisory record');records.push({id,title:a.name,severity:a.severity||null,vulnerable:a.vulnerable,good:a.good||null,sourceDetails:{attributes:a,content:Object.fromEntries(Object.entries(item).filter(([key])=>key!=='$'))},advisory:typeof a.advisory==='string'&&/^https:\/\//.test(a.advisory)?a.advisory:PAGE});}
 if(!records.length)throw Error('NGINX advisory XML has no identified records');return {records,parserVersion:PARSER_VERSION,sha256:crypto.createHash('sha256').update(bytes).digest('hex')};
}
async function syncNginxAdvisories(options={}){
 if(options.offline)throw Error('cannot refresh NGINX advisories offline');const timeout=AbortSignal.timeout(options.timeoutMs??30000),signal=options.signal?AbortSignal.any([options.signal,timeout]):timeout;const res=await require('..').getResource('nginx','advisories',{}, {fetcher:options.fetcher,signal,streaming:true,noStore:true});if(!res.ok){await res.body?.cancel();throw Error(`NGINX advisory HTTP ${res.status}`);}let size=0,chunks=[];for await(const chunk of res.body){size+=chunk.length;if(size>(options.maxBytes??4*1024*1024))throw Error('NGINX advisory XML exceeds size limit');chunks.push(Buffer.from(chunk));}const parsed=await parseNginxAdvisories(Buffer.concat(chunks),options),now=Date.now(),stamp=Date.parse(res.headers.get('x-fad-proxy-fetched-at')||''),proxy=require('..').hasProxyRoute(),valid=Number.isFinite(stamp)&&stamp>0&&stamp<=now;
 const snapshot={...parsed,sourceURL:URL,observedAt:proxy&&valid?stamp:now,stale:proxy&&(!valid||res.headers.get('x-fad-proxy')==='stale')};(options.cacheRepository||createCacheRepository(options.cacheDir||getCacheDir())).put('catalogue','nginx-advisories',snapshot);return snapshot;
}
async function assessNginxAdvisories(packages,options={}){
 const matches=[],observations=[],warnings=[],repo=options.cacheRepository||createCacheRepository(options.cacheDir||getCacheDir()),domains=options.allowedMaintainerDomains||['nginx.org','nginx.com','f5.com'];if(!Array.isArray(domains)||domains.some(d=>typeof d!=='string'||!/^[a-z0-9.-]+$/.test(d)))throw Error('invalid NGINX maintainer domains');
 const candidates=(packages||[]).filter(isNginxPackage),cached=repo.get('catalogue','nginx-advisories')?.value,ttl=options.ttlMs??86400000;if(!Number.isSafeInteger(ttl)||ttl<=0)throw Error('invalid NGINX advisory TTL');let snapshot=Array.isArray(cached?.records)&&/^[a-f0-9]{64}$/.test(cached.sha256||'')&&Number.isFinite(cached.observedAt)?cached:null;
 if(!candidates.length)return {matches,observations,coverage:[{source:SOURCE,execution:'not-applicable',result:'not-applicable'}],warnings};
 if(!options.offline&&(!snapshot||snapshot.parserVersion!==PARSER_VERSION||snapshot.stale||Date.now()-snapshot.observedAt>=ttl||Date.now()<snapshot.observedAt)){try{snapshot=await syncNginxAdvisories(options);}catch(error){warnings.push({type:'source-unavailable',source:SOURCE,message:`NGINX advisories: ${error.message}`});}}
 if(!snapshot){if(options.offline)warnings.push({type:'source-unavailable',source:SOURCE,message:'NGINX vendor advisory snapshot is not cached.'});return {matches,observations,coverage:[{source:SOURCE,execution:'partial',result:'indeterminate',reason:'NGINX vendor advisory snapshot unavailable.'}],warnings};}
 if(snapshot.parserVersion!==PARSER_VERSION)warnings.push({type:'source-unavailable',source:SOURCE,message:'Cached NGINX advisories use an older parser; refresh the catalogue online to restore complete advisory parsing.'});
 for(const p of candidates){const identity=p.packageOrigin?.status==='ambiguous'?null:vendor(p,domains),upstream=/^(\d+\.\d+\.\d+)(?:-[A-Za-z0-9.+~]+)?$/.exec(p.sourceVersion||'')?.[1];for(const record of snapshot.records){const affected=inRange(upstream,record.vulnerable);if(affected===false||fixedInBranch(upstream,record.good))continue;const evidence={sourceURL:URL,sha256:snapshot.sha256,observedAt:snapshot.observedAt,advisoryURL:record.advisory,upstreamVersion:upstream||null,versionRange:record.vulnerable,fixedVersions:record.good,vendorSeverity:record.severity,packageOrigin:identity,signatureVerified:false,configurationApplicability:'unknown',sourceDetails:record.sourceDetails||null};
  if(!identity||affected===null){observations.push({dep:p,cveId:record.id,status:'unknown',reason:!identity?'Vendor package origin is not established.':'Upstream version range cannot be evaluated.',evidence});continue;}
  const current=ver(upstream),fix=(record.good||'').split(',').map(s=>s.trim()).map(s=>/^(\d+\.\d+\.\d+)\+$/.exec(s)?.[1]).filter(Boolean).filter(s=>{const v=ver(s);return v[0]===current[0]&&v[1]===current[1]&&cmp(v,current)>0;}).sort((a,b)=>cmp(ver(a),ver(b)))[0]||null;
  matches.push({dep:{...p,packageOrigin:identity},source:SOURCE,advisoryId:record.id,cve:{id:record.id,summary:record.title,description:record.title,severity:'UNKNOWN',fixVersion:fix,advisorySource:record.advisory,vendorEvidence:evidence}});
 }}
 return {matches,observations,coverage:[{source:SOURCE,execution:snapshot.stale||warnings.length?'partial':'completed',result:'consulted',scope:'upstream-nginx-version',fetchedAt:snapshot.observedAt,sha256:snapshot.sha256,reason:'Version applicability is assessed from vendor declarations; runtime configuration and package signature remain unverified.'}],warnings};
}
function nginxPackageOrigin(pkg,options={}){if(!isNginxPackage(pkg))return null;return vendor(pkg,options.allowedMaintainerDomains||['nginx.org','nginx.com','f5.com']);}
module.exports={SOURCE,URL,isNginxPackage,nginxPackageOrigin,parseNginxAdvisories,syncNginxAdvisories,assessNginxAdvisories};
