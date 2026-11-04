'use strict';

// Project exports retain the complete advisory history for every resolved
// package, including versions other than the one in the descriptor.
const path=require('node:path');
const {openCacheDb}=require('./cache-db');
const {packageName}=require('./advisory-store');
const packageScope=(ecosystem,name)=>'project-package:'+JSON.stringify([ecosystem,ecosystem==='Maven'?name:packageName(ecosystem,name)]);

function buildProjectScope(resolved,{applications=[],cves=[]}={}){
 const {osvEcosystemFor,osvPkgName}=require('./osv');
 const packages=new Map();
 for(const d of resolved.values()){
  if(d.scope==='parent'||d.provenance==='binary'||d.ecosystem==='binary')continue;
  const ecosystem=osvEcosystemFor(d),name=osvPkgName(d);
  if(typeof name!=='string'||!name||name.includes('undefined'))continue;
  packages.set(JSON.stringify([ecosystem,name]),{ecosystem,name});
 }
 const project={schema:1,packages:[...packages.values()],cves:[...new Set(cves.filter(id=>/^CVE-\d{4}-\d{4,7}$/.test(id||'')))],retainAllNvd:applications.length>0||[...resolved.values()].some(d=>d.provenance==='binary'||d.ecosystem==='binary')};
 return project;
}

function buildProjectSnapshot(sourceDir,targetDir,project){
 if(project?.schema!==1||!Array.isArray(project.packages)||!project.packages.length)throw Error('invalid or empty prepared project scope');
 const db=openCacheDb({cacheDir:targetDir});
 const quote=s=>`'${s.replace(/'/g,"''")}'`;
 try{
  db.exec(`ATTACH DATABASE ${quote(path.join(sourceDir,'cache.sqlite'))} AS source`);
  // Pin one source snapshot while collecting identities and copying records.
  db.exec('BEGIN');
  db.exec('CREATE TEMP TABLE wanted_packages(ecosystem TEXT, package_key TEXT, query_key TEXT, PRIMARY KEY(ecosystem,query_key)) WITHOUT ROWID; CREATE TEMP TABLE wanted_advisories(source TEXT,id TEXT,PRIMARY KEY(source,id)) WITHOUT ROWID; CREATE TEMP TABLE wanted_cves(cve TEXT PRIMARY KEY) WITHOUT ROWID;');
  const add=db.prepare('INSERT OR IGNORE INTO wanted_packages VALUES(?,?,?)');
  for(const p of project.packages){if(!p||typeof p.ecosystem!=='string'||typeof p.name!=='string'||!p.name)throw Error('invalid project package');add.run(p.ecosystem,packageName(p.ecosystem,p.name),p.ecosystem==='Maven'?p.name:packageName(p.ecosystem,p.name));}
  db.exec(`INSERT OR IGNORE INTO wanted_advisories SELECT source,id FROM source.advisory_records WHERE source NOT IN ('osv','vigievuln');
   INSERT OR IGNORE INTO wanted_advisories SELECT p.source,p.id FROM source.advisory_packages p JOIN wanted_packages w ON w.ecosystem=p.ecosystem AND w.package_key=p.name_key WHERE p.source IN ('osv','vigievuln');
   INSERT OR IGNORE INTO wanted_advisories SELECT q.source,q.id FROM source.advisory_query_ids q JOIN wanted_packages w ON w.ecosystem=q.ecosystem AND w.query_key=q.name_key;
   INSERT OR IGNORE INTO wanted_cves SELECT DISTINCT cve FROM source.cve_lookup;
   INSERT OR IGNORE INTO wanted_cves SELECT DISTINCT cve FROM source.nvd_records WHERE kind='live';`);
  const {decompress}=require('./advisory-compression');
  const addCve=db.prepare('INSERT OR IGNORE INTO wanted_cves VALUES(?)');
  // Some findings (for example a vendored JS advisory) have no retained
  // package advisory or CVE lookup entry. Their explicitly warmed NVD records
  // must still travel with the project snapshot.
  for(const id of Array.isArray(project.cves)?project.cves:[]) {
   if(/^CVE-\d{4}-\d{4,7}$/.test(id||'')) addCve.run(id);
  }
  const rows=db.prepare('SELECT r.envelope_deflate,r.envelope_bytes FROM source.advisory_records r JOIN wanted_advisories w USING(source,id)');
  for(const row of rows.all()){
   const text=decompress(row.envelope_deflate,row.envelope_bytes).toString('utf8');
   for(const id of text.match(/CVE-\d{4}-\d{4,}/g)||[])addCve.run(id);
  }
  {
   db.exec(`INSERT INTO advisory_records SELECT r.* FROM source.advisory_records r JOIN wanted_advisories w USING(source,id);
    INSERT INTO advisory_packages SELECT p.* FROM source.advisory_packages p JOIN wanted_advisories w USING(source,id);
    INSERT INTO advisory_observations SELECT o.* FROM source.advisory_observations o JOIN wanted_advisories w USING(source,id);
    INSERT INTO advisory_queries SELECT q.* FROM source.advisory_queries q JOIN wanted_packages w ON w.ecosystem=q.ecosystem AND w.query_key=q.name_key;
    INSERT INTO advisory_query_ids SELECT q.* FROM source.advisory_query_ids q JOIN wanted_packages w ON w.ecosystem=q.ecosystem AND w.query_key=q.name_key;
    INSERT INTO advisory_coverage SELECT * FROM source.advisory_coverage WHERE source<>'osv';
    INSERT INTO cache_entries SELECT * FROM source.cache_entries WHERE namespace<>'airgap-project' AND NOT (namespace='catalogue' AND key IN ('euvd-targeted','epss'));
    INSERT INTO cache_snapshots SELECT * FROM source.cache_snapshots;
    INSERT INTO cve_lookup SELECT * FROM source.cve_lookup;
    INSERT INTO package_versions SELECT * FROM source.package_versions;
    INSERT INTO resource_bodies SELECT * FROM source.resource_bodies;
    INSERT INTO resource_chunks SELECT * FROM source.resource_chunks;
    INSERT INTO resources SELECT * FROM source.resources;`);
   // These per-CVE enrichments may contain observations from other projects.
   // Keep only CVEs actually encountered while preparing this descriptor.
   const keep=new Set(Array.isArray(project.cves)?project.cves:[]),zlib=require('node:zlib');
   const cached=db.prepare("SELECT * FROM source.cache_entries WHERE namespace='catalogue' AND key IN ('euvd-targeted','epss')").all();
   const insertCache=db.prepare('INSERT INTO cache_entries(namespace,key,fetched_at,expires_at,stale,encoding,payload,metadata_json) VALUES(?,?,?,?,?,?,?,?)');
   for(const row of cached){
    const raw=row.encoding==='json+deflate'?zlib.inflateRawSync(row.payload,{maxOutputLength:134217728}):row.encoding==='json'?row.payload:null;
    if(!raw)throw Error(`invalid ${row.key} cache encoding`);
    const value=JSON.parse(Buffer.from(raw).toString('utf8'));
    if(!value || !value.entries || typeof value.entries!=='object' || Array.isArray(value.entries))throw Error(`invalid ${row.key} cache`);
    value.entries=Object.fromEntries(Object.entries(value.entries).filter(([id])=>keep.has(id)));
    const bytes=Buffer.from(JSON.stringify(value)),compressed=bytes.length>=4096,metadata=JSON.parse(row.metadata_json);
    delete metadata.uncompressedBytes;if(compressed)metadata.uncompressedBytes=bytes.length;
    insertCache.run(row.namespace,row.key,row.fetched_at,row.expires_at,row.stale,compressed?'json+deflate':'json',compressed?zlib.deflateRawSync(bytes,{level:1}):bytes,JSON.stringify(metadata));
   }
   db.exec(project.retainAllNvd?'INSERT INTO nvd_records SELECT * FROM source.nvd_records':'INSERT INTO nvd_records SELECT n.* FROM source.nvd_records n JOIN wanted_cves w USING(cve)');
   const global=db.prepare("SELECT slot,fetched_at,complete,stale,entry_json FROM source.advisory_coverage WHERE source='osv' AND ecosystem=?");
   const insert=db.prepare('INSERT OR REPLACE INTO advisory_coverage(source,ecosystem,slot,fetched_at,complete,stale,entry_json) VALUES(?,?,?,?,?,?,?)');
   for(const p of project.packages)for(const row of global.all(p.ecosystem)){
    const ecosystem=packageScope(p.ecosystem,p.name),entry=JSON.parse(row.entry_json);entry.ecosystem=ecosystem;
    insert.run('osv',ecosystem,row.slot,row.fetched_at,row.complete,row.stale,JSON.stringify(entry));
   }
  }
  db.exec('COMMIT');
  db.exec('DETACH DATABASE source');
  db.exec('PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE');
 }finally{db.close()}
 return {packages:project.packages.length,fullNvd:!!project.retainAllNvd};
}
module.exports={buildProjectScope,buildProjectSnapshot,packageScope};
