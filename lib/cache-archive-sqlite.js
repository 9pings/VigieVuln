'use strict';

const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const zlib=require('node:zlib');
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const run=promisify(execFile);
const {openCacheDb,closeCacheDbs,SCHEMA_VERSION}=require('./cache-db');
const {proxyOrigin:canonicalOrigin}=require('./proxy-scope');
const FORMAT='vigievuln-sqlite-cache';
const ALLOWED=new Set(['.vigie-vuln/','.vigie-vuln/cache.sqlite','.vigie-vuln/cli-bundle-meta.json','.vigievuln-archive-origin.json']);
const sha256=file=>new Promise((resolve,reject)=>{const hash=crypto.createHash('sha256'),stream=fs.createReadStream(file);stream.on('data',part=>hash.update(part));stream.on('error',reject);stream.on('end',()=>resolve(hash.digest('hex')))});
async function inspectArchive(file){
 let names,details;
 try{
  ({stdout:names}=await run('tar',['-tzf',file],{maxBuffer:64*1024}));
  ({stdout:details}=await run('tar',['-tvzf',file],{maxBuffer:128*1024}));
 }catch(error){
  // Distinguish a malformed archive from an unavailable or resource-starved
  // tar process. Do not include stderr or command arguments: both can contain
  // private local paths and attacker-controlled member names.
  const code=error?.code;
  if(typeof code==='string' && /^[A-Z][A-Z0-9_]{0,31}$/.test(code))throw Error(`cannot inspect cache bundle: tar process failed (${code})`);
  if(typeof code==='number')throw Error(`unsupported cache bundle: tar exited with status ${code}`);
  if(typeof error?.signal==='string' && /^SIG[A-Z0-9]+$/.test(error.signal))throw Error(`cannot inspect cache bundle: tar terminated (${error.signal})`);
  throw Error('cannot inspect cache bundle: tar failed');
 }
 const listed=names.trim().split(/\r?\n/).filter(Boolean);
 if(!listed.length||listed.length>4||!listed.includes('.vigie-vuln/cache.sqlite')||!listed.includes('.vigie-vuln/cli-bundle-meta.json')||listed.some(name=>!ALLOWED.has(name)))throw Error('unsupported cache bundle: missing or unexpected archive entries');
 const types=details.trim().split(/\r?\n/);
 if(types.length!==listed.length||types.some(line=>!['-','d'].includes(line[0])))throw Error('cache bundle contains links or special files');
}
function verifyDb(file){
 const db=openCacheDb({cacheDir:path.dirname(file),readonly:true});
 try{
  const integrity=db.prepare('PRAGMA integrity_check').get();
  if(Object.values(integrity)[0]!=='ok')throw Error('SQLite cache integrity check failed');
  if(db.prepare('PRAGMA foreign_key_check').get())throw Error('SQLite cache foreign key check failed');
  return {advisories:db.prepare('SELECT COUNT(*) AS count FROM advisory_records').get().count};
 }finally{db.close()}
}
function verifyStandaloneSnapshot(file){
 const wal=file+'-wal';
 // The snapshot directory is private to this export. A nonempty WAL can
 // contain committed pages absent from the main file and must never be lost.
 try{if(fs.statSync(wal).size>0)throw Error('cache snapshot has uncheckpointed WAL data')}catch(error){if(error.code!=='ENOENT')throw error}
 const db=openCacheDb({cacheDir:path.dirname(file),readonly:true});
 try{if(db.prepare('PRAGMA journal_mode').get().journal_mode.toLowerCase()==='wal')throw Error('cache snapshot is still in WAL mode')}
 finally{db.close()}
}
function mergeDatabase(targetFile,incomingFile){
 const target=openCacheDb({cacheDir:path.dirname(targetFile)});
 const quote=file=>`'${file.replace(/'/g,"''")}'`;
 try{
  target.exec(`ATTACH DATABASE ${quote(incomingFile)} AS incoming`);
  const incomingCve=target.prepare("SELECT * FROM incoming.cache_snapshots WHERE namespace='cve_lookup'").get();
  const localCve=target.prepare("SELECT * FROM cache_snapshots WHERE namespace='cve_lookup'").get();
  const decodeMap=row=>{
   if(!row||!row.encoding.startsWith('json'))return null;
   const bytes=row.encoding.endsWith('+deflate')?zlib.inflateRawSync(Buffer.from(row.payload),{maxOutputLength:134217728}):Buffer.from(row.payload);
   const value=JSON.parse(bytes.toString('utf8'));
   return value&&typeof value==='object'&&!Array.isArray(value)&&value.entries&&typeof value.entries==='object'&&!Array.isArray(value.entries)?value:null;
  };
  const localMaps=target.prepare("SELECT * FROM cache_entries WHERE namespace='auxiliary'").all();
  const incomingMaps=new Map(target.prepare("SELECT * FROM incoming.cache_entries WHERE namespace='auxiliary'").all().map(row=>[row.key,row]));
  const mergedMaps=[];
  for(const localRow of localMaps){
   const incomingRow=incomingMaps.get(localRow.key);if(!incomingRow)continue;
   const local=decodeMap(localRow),incoming=decodeMap(incomingRow);if(!local||!incoming)continue;
   const preferIncoming=incomingRow.fetched_at>=localRow.fetched_at;
   const entries={...(preferIncoming?local.entries:incoming.entries),...(preferIncoming?incoming.entries:local.entries)};
   if(localRow.key==='maven-exists-cache.json'){
    for(const key of new Set([...Object.keys(local.entries),...Object.keys(incoming.entries)])){
     if(local.entries[key]===true||incoming.entries[key]===true)entries[key]=true;
    }
    require('./maven-presence').discardUnverifiedEntries({entries});
   }
   const stamp=Math.min(localRow.fetched_at,incomingRow.fetched_at);
   mergedMaps.push({key:localRow.key,stamp,value:{...local,...incoming,meta:{...local.meta,...incoming.meta,fetchedAt:stamp},entries}});
  }
  target.transaction(()=>{
   target.exec(`CREATE TEMP TABLE local_index_scopes AS SELECT key,fetched_at FROM cache_entries WHERE namespace='airgap-cve-index';
    CREATE TEMP TABLE winning_records AS
    SELECT i.source,i.id FROM incoming.advisory_records i LEFT JOIN advisory_records t USING(source,id)
    WHERE t.id IS NULL OR i.revision_ms>t.revision_ms OR
      (i.revision_ms=t.revision_ms AND i.withdrawn>t.withdrawn) OR
      (i.revision_ms=t.revision_ms AND i.withdrawn=t.withdrawn AND i.fetched_at>=t.fetched_at);
    CREATE UNIQUE INDEX winning_records_key ON winning_records(source,id);
    DELETE FROM advisory_packages WHERE EXISTS(SELECT 1 FROM winning_records w WHERE w.source=advisory_packages.source AND w.id=advisory_packages.id);
    INSERT INTO advisory_records SELECT i.* FROM incoming.advisory_records i JOIN winning_records w USING(source,id) WHERE 1
      ON CONFLICT(source,id) DO UPDATE SET revision_ms=excluded.revision_ms,withdrawn=excluded.withdrawn,
      fetched_at=excluded.fetched_at,content_changed_at=CASE WHEN excluded.document_sha256=advisory_records.document_sha256
      THEN advisory_records.content_changed_at ELSE excluded.fetched_at END,
      document_sha256=excluded.document_sha256,envelope_deflate=excluded.envelope_deflate,envelope_bytes=excluded.envelope_bytes;
    INSERT INTO advisory_packages SELECT p.* FROM incoming.advisory_packages p JOIN winning_records w USING(source,id);
    INSERT INTO advisory_observations SELECT * FROM incoming.advisory_observations WHERE 1
      ON CONFLICT(source,id,provenance_key) DO UPDATE SET fetched_at=max(advisory_observations.fetched_at,excluded.fetched_at);
    CREATE TEMP TABLE winning_queries AS
      SELECT i.source,i.ecosystem,i.name_key,i.version FROM incoming.advisory_queries i
      LEFT JOIN advisory_queries t USING(source,ecosystem,name_key,version)
      WHERE t.source IS NULL OR i.fetched_at>=t.fetched_at;
    CREATE UNIQUE INDEX winning_queries_key ON winning_queries(source,ecosystem,name_key,version);
    DELETE FROM advisory_query_ids WHERE EXISTS(SELECT 1 FROM winning_queries w WHERE w.source=advisory_query_ids.source
      AND w.ecosystem=advisory_query_ids.ecosystem AND w.name_key=advisory_query_ids.name_key AND w.version=advisory_query_ids.version);
    INSERT INTO advisory_queries SELECT i.* FROM incoming.advisory_queries i JOIN winning_queries w USING(source,ecosystem,name_key,version) WHERE 1
      ON CONFLICT(source,ecosystem,name_key,version) DO UPDATE SET original_name=excluded.original_name,
      fetched_at=excluded.fetched_at,stale=excluded.stale,provenance_json=excluded.provenance_json;
    INSERT INTO advisory_query_ids SELECT q.* FROM incoming.advisory_query_ids q JOIN winning_queries w USING(source,ecosystem,name_key,version);
    INSERT INTO advisory_coverage SELECT * FROM incoming.advisory_coverage WHERE 1
      ON CONFLICT(source,ecosystem,slot) DO UPDATE SET fetched_at=excluded.fetched_at,complete=excluded.complete,
      stale=excluded.stale,entry_json=excluded.entry_json WHERE excluded.fetched_at>=advisory_coverage.fetched_at;
    INSERT INTO cache_entries SELECT * FROM incoming.cache_entries WHERE 1
      ON CONFLICT(namespace,key) DO UPDATE SET fetched_at=excluded.fetched_at,expires_at=excluded.expires_at,
      stale=excluded.stale,encoding=excluded.encoding,payload=excluded.payload,metadata_json=excluded.metadata_json
      WHERE excluded.fetched_at>=cache_entries.fetched_at;
    INSERT INTO cache_snapshots SELECT * FROM incoming.cache_snapshots WHERE namespace<>'cve_lookup'
      ON CONFLICT(namespace) DO UPDATE SET fetched_at=excluded.fetched_at,complete=excluded.complete,
      stale=excluded.stale,record_count=excluded.record_count,metadata_json=excluded.metadata_json
      WHERE excluded.fetched_at>=cache_snapshots.fetched_at;
    INSERT INTO nvd_records SELECT * FROM incoming.nvd_records WHERE 1
      ON CONFLICT(cve,kind) DO UPDATE SET fetched_at=excluded.fetched_at,revision_ms=excluded.revision_ms,
      body_deflate=excluded.body_deflate,body_bytes=excluded.body_bytes,metadata_json=excluded.metadata_json WHERE excluded.fetched_at>=nvd_records.fetched_at;
    INSERT OR IGNORE INTO package_versions SELECT * FROM incoming.package_versions;
    INSERT OR IGNORE INTO resource_bodies SELECT * FROM incoming.resource_bodies;
    INSERT OR IGNORE INTO resource_chunks SELECT * FROM incoming.resource_chunks;
    INSERT INTO resources SELECT * FROM incoming.resources WHERE 1
      ON CONFLICT(key) DO UPDATE SET body_id=excluded.body_id,fetched_at=excluded.fetched_at,ttl_ms=excluded.ttl_ms,
      content_type=excluded.content_type,response_headers_json=excluded.response_headers_json,metadata_json=excluded.metadata_json
      WHERE excluded.fetched_at>=resources.fetched_at;
    DROP TABLE winning_records; DROP TABLE winning_queries;`);
   if(incomingCve){
    const scoped=!!JSON.parse(incomingCve.metadata_json).projectScoped;
    if(scoped){
     // Replace only covered buckets. Empty buckets are evidence too; do not
     // erase the rest of a previously imported index or a complete local one.
     if(!localCve || localCve.complete!==1 || incomingCve.fetched_at>=localCve.fetched_at){
      target.exec("DELETE FROM cve_lookup WHERE EXISTS (SELECT 1 FROM incoming.cache_entries m LEFT JOIN local_index_scopes old ON old.key=m.key WHERE m.namespace='airgap-cve-index' AND m.key=(CASE cve_lookup.kind WHEN 'package' THEN 'p:' ELSE 'a:' END)||cve_lookup.lookup_key AND (old.key IS NULL OR m.fetched_at>=old.fetched_at))");
      target.exec("INSERT OR IGNORE INTO cve_lookup SELECT i.* FROM incoming.cve_lookup i LEFT JOIN incoming.cache_entries m ON m.namespace='airgap-cve-index' AND m.key=(CASE i.kind WHEN 'package' THEN 'p:' ELSE 'a:' END)||i.lookup_key LEFT JOIN local_index_scopes old ON old.key=(CASE i.kind WHEN 'package' THEN 'p:' ELSE 'a:' END)||i.lookup_key WHERE old.key IS NULL OR m.fetched_at>=old.fetched_at");
     }
     if(!localCve)target.exec("INSERT INTO cache_snapshots SELECT * FROM incoming.cache_snapshots WHERE namespace='cve_lookup'");
    }else if(!localCve || incomingCve.fetched_at>=localCve.fetched_at || JSON.parse(localCve.metadata_json).projectScoped){
     target.exec("DELETE FROM cve_lookup; INSERT INTO cve_lookup SELECT * FROM incoming.cve_lookup; DELETE FROM cache_snapshots WHERE namespace='cve_lookup'; INSERT INTO cache_snapshots SELECT * FROM incoming.cache_snapshots WHERE namespace='cve_lookup'");
    }
   }
   target.exec('DROP TABLE local_index_scopes');
   const updateMap=target.prepare('UPDATE cache_entries SET fetched_at=?,encoding=?,payload=?,metadata_json=? WHERE namespace=? AND key=?');
   for(const item of mergedMaps){
    const bytes=Buffer.from(JSON.stringify(item.value)),compressed=bytes.length>=4096;
    updateMap.run(item.stamp,compressed?'json+deflate':'json',compressed?zlib.deflateRawSync(bytes,{level:1}):bytes,
     JSON.stringify(compressed?{uncompressedBytes:bytes.length}:{}),'auxiliary',item.key);
   }
  });
  target.exec('DETACH DATABASE incoming');
 }finally{target.close()}
}
async function importCache(source,{targetDir=require('./cache-directory').getCacheDir(),proxyOrigin,replace=false,force=false,onProgress,requireUsableSeed=false}={}){
 const abs=path.resolve(source);if(!fs.statSync(abs).isFile())throw Error('cache bundle is not a file');
 onProgress?.({phase:'validating'});await inspectArchive(abs);
 const stage=fs.mkdtempSync(path.join(path.dirname(targetDir),'vigievuln-sqlite-import-'));
 try{
  onProgress?.({phase:'extracting'});
  await run('tar',['-xzf',abs,'--no-same-owner','-C',stage],{maxBuffer:64*1024});
  const root=path.join(stage,'.vigie-vuln'),file=path.join(root,'cache.sqlite'),manifestPath=path.join(root,'cli-bundle-meta.json');
  for(const item of [root,file,manifestPath]){const st=fs.lstatSync(item);if(st.isSymbolicLink()||st.nlink!==1&&st.isFile()||!(st.isFile()||st.isDirectory()))throw Error('unsafe cache bundle entry')}
  const manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
  if(manifest.format!==FORMAT||manifest.schemaVersion!==SCHEMA_VERSION||manifest.payload?.file!=='cache.sqlite'||manifest.payload?.bytes!==fs.statSync(file).size||manifest.payload?.sha256!==await sha256(file))throw Error('cache bundle checksum or format mismatch');
  if(proxyOrigin){const marker=JSON.parse(fs.readFileSync(path.join(stage,'.vigievuln-archive-origin.json'),'utf8'));if(marker.origin!==canonicalOrigin(proxyOrigin))throw Error('cache bundle proxy origin mismatch')}
  onProgress?.({phase:'checking'});
  const summary=verifyDb(file);
  if(requireUsableSeed&&summary.advisories===0)throw Error('SQLite cache bundle contains no advisories');
  fs.mkdirSync(targetDir,{recursive:true,mode:0o700});
  const targetFile=path.join(targetDir,'cache.sqlite');
  if(!fs.existsSync(targetFile)||replace||force){
   closeCacheDbs();
   const backup=fs.existsSync(targetFile)?`${targetDir}.bak-${Date.now()}.sqlite`:null;
   if(backup)fs.renameSync(targetFile,backup);
   for(const suffix of ['-wal','-shm'])fs.rmSync(targetFile+suffix,{force:true});
   try{fs.renameSync(file,targetFile)}catch(error){if(backup)fs.renameSync(backup,targetFile);throw error}
   if(backup&&force)fs.rmSync(backup,{force:true});
   return {dir:targetDir,mode:'replace',stats:{added:1,updated:0,merged:0,kept:0,skipped:[]}};
  }
  onProgress?.({phase:'merging'});mergeDatabase(targetFile,file);
  return {dir:targetDir,mode:'merge',stats:{added:0,updated:0,merged:1,kept:0,skipped:[]}};
 }finally{fs.rmSync(stage,{recursive:true,force:true})}
}
async function exportCache(destination,{sourceDir=require('./cache-directory').getCacheDir(),proxyOrigin,project=null}={}){
 const stage=fs.mkdtempSync(path.join(os.tmpdir(),'vigievuln-sqlite-export-'));
 const root=path.join(stage,'.vigie-vuln');fs.mkdirSync(root);
 try{
  if(project)require('./airgap-project').buildProjectSnapshot(sourceDir,root,project);
  else {
   const source=openCacheDb({cacheDir:sourceDir});
   try{source.prepare('VACUUM INTO ?').run(path.join(root,'cache.sqlite'))}finally{source.close()}
  }
  const file=path.join(root,'cache.sqlite');verifyStandaloneSnapshot(file);verifyDb(file);
  const payload={file:'cache.sqlite',bytes:fs.statSync(file).size,sha256:await sha256(file)};
  fs.writeFileSync(path.join(root,'cli-bundle-meta.json'),JSON.stringify({format:FORMAT,schemaVersion:SCHEMA_VERSION,minimumCliVersion:'1.2.0',createdAt:new Date().toISOString(),payload}));
  if(proxyOrigin)fs.writeFileSync(path.join(stage,'.vigievuln-archive-origin.json'),JSON.stringify({version:1,origin:canonicalOrigin(proxyOrigin)}));
  const abs=path.resolve(destination);fs.mkdirSync(path.dirname(abs),{recursive:true});
  const temporary=path.join(path.dirname(abs),`.${path.basename(abs)}.${crypto.randomUUID()}.tmp`);
  try {
   // Enumerate exactly the files accepted by the reader. SQLite may create
   // sidecars in a temporary directory; never include them implicitly.
   const args=['-czf',temporary,'-C',stage,'.vigie-vuln/cache.sqlite','.vigie-vuln/cli-bundle-meta.json'];if(proxyOrigin)args.push('.vigievuln-archive-origin.json');
   await run('tar',args,{maxBuffer:64*1024});
   verifyStandaloneSnapshot(file);
   fs.renameSync(temporary,abs);
  } finally {fs.rmSync(temporary,{force:true})}
  return {path:abs,size:fs.statSync(abs).size,excluded:['config.json'],scope:project?'project':'full'};
 }finally{fs.rmSync(stage,{recursive:true,force:true})}
}
module.exports={importCache,exportCache,mergeDatabase,FORMAT};
