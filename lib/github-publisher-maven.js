'use strict';
// Normalize public repository advisories; never infer a Maven identity from a
// repository, product name or code path. Ranges are source claims, not fixes.
const {compareMavenVersions}=require('./maven-version');
const VERSION='[0-9][0-9A-Za-z._+-]*';
const validVersion=v=>typeof v==='string'&&new RegExp(`^${VERSION}$`).test(v)&&v.length<=128&&!/\.\.|\+\+|--|__|\d{16}/.test(v);
const unknown=()=>({type:'UNKNOWN',events:[]});
function window(lower,upper,inclusive){
 if(!validVersion(lower)||!validVersion(upper))return null;
 const c=compareMavenVersions(lower,upper);if(c>0||(!inclusive&&c===0))return null;
 return {type:'ECOSYSTEM',events:[{introduced:lower},{[inclusive?'last_affected':'fixed']:upper}]};
}
function parsePublisherRange(input){
 if(typeof input!=='string'||!input.trim()||input.length>2048)return {ranges:[unknown()],versions:[],unsupported:true};
 const raw=input.trim(),ranges=[],versions=[];
 if(new RegExp(`^${VERSION}$`).test(raw)){if(validVersion(raw))return {ranges,versions:[raw],unsupported:false};return {ranges:[unknown()],versions,unsupported:true};}
 if(raw.startsWith('[')||raw.startsWith('(')){
  // Maven interval union, e.g. [4.0.0,4.5.29],[5.0.0,5.1.4].
  const re=new RegExp(`\\s*([\\[(])\\s*(${VERSION})\\s*,\\s*(${VERSION})\\s*([\\])])\\s*`,'gy');let offset=0;
  while(offset<raw.length){re.lastIndex=offset;const m=re.exec(raw);if(!m||m[1]!=='[')return {ranges:[unknown()],versions:[],unsupported:true};const r=window(m[2],m[3],m[4]===']');if(!r)return {ranges:[unknown()],versions:[],unsupported:true};ranges.push(r);offset=re.lastIndex;if(offset===raw.length)break;if(raw[offset]!==','||offset===raw.length-1)return {ranges:[unknown()],versions:[],unsupported:true};offset++;}
  return {ranges,versions,unsupported:false};
 }
 const part=new RegExp(`^(>=|<=|<|>)\\s*(${VERSION})$`);const pieces=raw.split(',').map(x=>x.trim());if(pieces.length<1||pieces.length>2)return {ranges:[unknown()],versions,unsupported:true};
 const clauses=pieces.map(x=>part.exec(x));if(clauses.some(x=>!x||!validVersion(x[2])))return {ranges:[unknown()],versions,unsupported:true};
 const lows=clauses.filter(x=>x[1]==='>='),highs=clauses.filter(x=>x[1]==='<'||x[1]==='<=');
 if(clauses.some(x=>x[1]==='>')||lows.length>1||highs.length>1||(!lows.length&&!highs.length))return {ranges:[unknown()],versions,unsupported:true};
 if(!highs.length)return {ranges:[{type:'ECOSYSTEM',events:[{introduced:lows[0][2]}]}],versions,unsupported:false};
 const r=window(lows[0]?.[2]||'0',highs[0][2],highs[0][1]==='<=');return r?{ranges:[r],versions,unsupported:false}:{ranges:[unknown()],versions,unsupported:true};
}
function normalizePublisherMavenAdvisory(advisory,repository){
 if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository||'')||!advisory||!/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/i.test(advisory.ghsa_id||'')||!['published','withdrawn'].includes(advisory.state))throw Error('invalid publisher advisory');
 let url;try{url=new URL(advisory.html_url)}catch{throw Error('invalid publisher advisory URL')}
 if(url.protocol!=='https:'||url.hostname!=='github.com'||url.username||url.password||url.search||url.hash||url.pathname.toLowerCase()!==`/${repository}/security/advisories/${advisory.ghsa_id}`.toLowerCase())throw Error('publisher advisory URL does not match repository');
 if(!Array.isArray(advisory.vulnerabilities)||advisory.vulnerabilities.length>10000 || (advisory.identifiers!=null&&!Array.isArray(advisory.identifiers)))throw Error('invalid publisher vulnerabilities');
 const groups=new Map();
 for(const item of advisory.vulnerabilities){if(String(item?.package?.ecosystem||'').toLowerCase()!=='maven')continue;const name=item.package.name;if(typeof name!=='string'||name.length>256||!/^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/.test(name))continue;let group=groups.get(name);if(!group){group={package:{ecosystem:'Maven',name},ranges:[],versions:[]};groups.set(name,group)}const r=parsePublisherRange(item.vulnerable_version_range);group.ranges.push(...r.ranges);group.versions.push(...r.versions);}
 const aliases=[...new Set([advisory.cve_id,...(advisory.identifiers||[]).filter(x=>x?.type==='CVE').map(x=>x.value)].filter(x=>/^CVE-\d{4}-\d{4,}$/i.test(x||'')).map(x=>x.toUpperCase()))];
 return {id:'GHSA-'+advisory.ghsa_id.slice(5).toLowerCase(),aliases,summary:typeof advisory.summary==='string'?advisory.summary:'',modified:advisory.updated_at||null,published:advisory.published_at||null,...(advisory.withdrawn_at?{withdrawn:advisory.withdrawn_at}:{}),affected:[...groups.values()],references:[{type:'ADVISORY',url:url.href}],database_specific:{source:'github-publisher',repository}};
}
module.exports={parsePublisherRange,normalizePublisherMavenAdvisory};
