'use strict';
// Durable, public, version-specific observations. Contradictory observations
// are retained and never chosen automatically.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const digest = s => crypto.createHash('sha256').update(s).digest('hex');
const origins = {maven:'https://repo1.maven.org',npm:'https://registry.npmjs.org'};
const issues = new Map();
function identityKey(r) { return digest(JSON.stringify([r.origin,r.ecosystem,r.name,r.version])); }
function valid(r) {
 if (!r || r._schema !== 1 || origins[r.ecosystem] !== r.origin || typeof r.name !== 'string' || !r.name || r.name.length>512 ||
     typeof r.version !== 'string' || !r.version || r.version.length>256 || /snapshot/i.test(r.version) ||
     typeof r.body !== 'string' || Buffer.byteLength(r.body)>8*1024*1024 || !/^[a-f0-9]{64}$/.test(r.sha256) || digest(r.body)!==r.sha256 ||
     !Number.isSafeInteger(r.collectedAt) || r.collectedAt<=0 || r.collectedAt>Date.now()+300000 ||
     typeof r.sourceUrl !== 'string' || r.sourceUrl.length>2048 || !/^https:\/\//.test(r.sourceUrl) ||
     r.format !== (r.ecosystem==='maven'?'maven-pom':'npm-manifest')) return false;
 try {
  const source=new URL(r.sourceUrl), allowed=r.ecosystem==='npm' ? ['https://registry.npmjs.org'] :
   ['https://repo1.maven.org','https://repo.maven.apache.org','https://maven-central-eu.storage-download.googleapis.com'];
  if (!allowed.includes(source.origin) || source.username || source.password || source.search || source.hash) return false;
  const expected=r.ecosystem==='maven' ? '/maven2/'+[...r.name.split(':')[0].split('.'),r.name.split(':')[1],r.version,`${r.name.split(':')[1]}-${r.version}.pom`].map(encodeURIComponent).join('/') :
   '/'+(r.name.startsWith('@') ? '@'+encodeURIComponent(r.name.slice(1).split('/')[0])+'%2F'+encodeURIComponent(r.name.split('/')[1]) : encodeURIComponent(r.name));
  if (source.pathname!==expected) return false;
 } catch { return false; }
 try {
  const validator=require('./package-metadata');
  if (r.ecosystem==='maven') validator.validateMavenPom(r.body,r.name,r.version);
  else validator.validateNpmManifest(r.body,r.name,r.version);
 } catch {return false;}
 return true;
}
function filename(r) { return `${identityKey(r)}-${r.sha256}.json`; }
function relativePath(r) {const f=filename(r);return path.join(f.slice(0,2),f);}
function readRecord(file) { try {const r=JSON.parse(fs.readFileSync(file,'utf8'));return valid(r) && path.basename(file)===filename(r) ? r : null;} catch {return null;} }
function getVersion(ecosystem,name,version,{cacheDir=require('./cache-directory').getCacheDir()}={}) {
 const origin=origins[ecosystem];if(!origin)return null;
 const rows=require('./cache-db').getCacheDb(cacheDir).prepare(
  'SELECT sha256,collected_at,source_url,format,body FROM package_versions WHERE origin=? AND ecosystem=? AND name=? AND version=?'
 ).all(origin,ecosystem,name,version);
 const records=[];
 for(const row of rows){
  const r={_schema:1,origin,ecosystem,name,version,sha256:row.sha256,collectedAt:row.collected_at,
   sourceUrl:row.source_url,format:row.format,body:Buffer.from(row.body).toString('utf8')};
  if(!valid(r)){issues.set(`${ecosystem}:${name}@${version}`,'invalid observation');return null}
  records.push(r);
 }
 if(records.length>1)issues.set(`${ecosystem}:${name}@${version}`,'conflicting observations');
 return records.length===1?records[0]:null;
}
function drainIssues() {const result=[...issues].map(([id,reason])=>({id,reason}));issues.clear();return result;}
module.exports={valid,filename,relativePath,readRecord,getVersion,drainIssues};
