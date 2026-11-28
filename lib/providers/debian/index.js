'use strict';
const BASE='https://salsa.debian.org/security-tracker-team/security-tracker';
module.exports={id:'debian',ttlMs:4*3600000,build(type,params={}){
 if(type==='cve' && /^CVE-\d{4}-\d{4,}$/.test(params.id))return {url:'https://security-tracker.debian.org/tracker/'+params.id};
 if(type==='source-version' && /^[a-z0-9][a-z0-9+.-]{0,199}$/.test(params.name||'') && typeof params.version==='string' && /^[0-9][A-Za-z0-9.+:~\-]{0,149}$/.test(params.version))
  return {url:`https://sources.debian.org/api/src/${encodeURIComponent(params.name)}/${encodeURIComponent(params.version)}/`};
 if(type==='history' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(params.until||'') && Number.isFinite(Date.parse(params.until)))
  return {url:`https://salsa.debian.org/api/v4/projects/security-tracker-team%2Fsecurity-tracker/repository/commits?until=${encodeURIComponent(params.until)}&per_page=1`};
 if(type==='list' && /^[a-f0-9]{40}$/.test(params.commit||'') && ['CVE','DSA','DLA'].includes(params.list) && Array.isArray(params.packages) && params.packages.length>0 && params.packages.length<=1000 && params.packages.every(p=>typeof p==='string' && /^[a-z0-9][a-z0-9+.-]{0,199}$/.test(p)))
  return {url:`${BASE}/-/raw/${params.commit}/data/${params.list}/list`};
 throw Error('invalid Debian tracker request');
}};
