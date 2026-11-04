'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const {openSqlite} = require('./sqlite-driver');
const {DICTIONARY} = require('./compression-dictionary');

const APPLICATION_ID = 1448502092;
const SCHEMA_VERSION = 2;
const DICTIONARY_SHA256 = crypto.createHash('sha256').update(DICTIONARY).digest('hex');
const SCHEMA = `
PRAGMA application_id=${APPLICATION_ID};
PRAGMA user_version=${SCHEMA_VERSION};
CREATE TABLE cache_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE advisory_records (
 source TEXT NOT NULL, id TEXT NOT NULL, revision_ms INTEGER NOT NULL,
 withdrawn INTEGER NOT NULL CHECK(withdrawn IN (0,1)), fetched_at INTEGER NOT NULL CHECK(fetched_at>0),
 content_changed_at INTEGER NOT NULL CHECK(content_changed_at>0),
 document_sha256 TEXT NOT NULL CHECK(length(document_sha256)=64),
 envelope_deflate BLOB NOT NULL, envelope_bytes INTEGER NOT NULL CHECK(envelope_bytes BETWEEN 1 AND 16777216),
 PRIMARY KEY(source,id)
) WITHOUT ROWID;
CREATE TABLE advisory_packages (
 ecosystem TEXT NOT NULL, name_key TEXT NOT NULL, source TEXT NOT NULL, id TEXT NOT NULL,
 PRIMARY KEY(ecosystem,name_key,source,id),
 FOREIGN KEY(source,id) REFERENCES advisory_records(source,id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX advisory_packages_record ON advisory_packages(source,id);
CREATE TABLE advisory_observations (
 source TEXT NOT NULL, id TEXT NOT NULL, provenance_key TEXT NOT NULL,
 fetched_at INTEGER NOT NULL CHECK(fetched_at>0), provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json)),
 PRIMARY KEY(source,id,provenance_key),
 FOREIGN KEY(source,id) REFERENCES advisory_records(source,id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TABLE advisory_queries (
 source TEXT NOT NULL, ecosystem TEXT NOT NULL, name_key TEXT NOT NULL, version TEXT NOT NULL,
 original_name TEXT NOT NULL, fetched_at INTEGER NOT NULL CHECK(fetched_at>0),
 stale INTEGER NOT NULL CHECK(stale IN (0,1)), provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json)),
 PRIMARY KEY(source,ecosystem,name_key,version)
) WITHOUT ROWID;
CREATE INDEX advisory_queries_summary ON advisory_queries(source,fetched_at,stale);
CREATE TABLE advisory_query_ids (
 source TEXT NOT NULL, ecosystem TEXT NOT NULL, name_key TEXT NOT NULL, version TEXT NOT NULL,
 id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0), document_sha256 TEXT,
 PRIMARY KEY(source,ecosystem,name_key,version,id),
 FOREIGN KEY(source,ecosystem,name_key,version) REFERENCES advisory_queries(source,ecosystem,name_key,version) ON DELETE CASCADE,
 FOREIGN KEY(source,id) REFERENCES advisory_records(source,id)
) WITHOUT ROWID;
CREATE INDEX advisory_query_ids_record ON advisory_query_ids(source,id);
CREATE TABLE advisory_coverage (
 source TEXT NOT NULL, ecosystem TEXT NOT NULL, slot TEXT NOT NULL CHECK(slot IN ('current','last_complete')),
 fetched_at INTEGER NOT NULL CHECK(fetched_at>0), complete INTEGER NOT NULL CHECK(complete IN (0,1)),
 stale INTEGER NOT NULL CHECK(stale IN (0,1)), entry_json TEXT NOT NULL CHECK(json_valid(entry_json)),
 PRIMARY KEY(source,ecosystem,slot), CHECK(slot<>'last_complete' OR complete=1)
) WITHOUT ROWID;
CREATE TABLE cache_entries (
 namespace TEXT NOT NULL, key TEXT NOT NULL, fetched_at INTEGER NOT NULL CHECK(fetched_at>=0),
 expires_at INTEGER, stale INTEGER NOT NULL DEFAULT 0 CHECK(stale IN (0,1)),
 encoding TEXT NOT NULL CHECK(encoding IN ('json','text','binary','json+deflate','text+deflate','binary+deflate')), payload BLOB NOT NULL,
 metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)), PRIMARY KEY(namespace,key)
) WITHOUT ROWID;
CREATE INDEX cache_entries_expiry ON cache_entries(namespace,expires_at);
CREATE TABLE cache_snapshots (
 namespace TEXT PRIMARY KEY, fetched_at INTEGER NOT NULL, complete INTEGER NOT NULL CHECK(complete IN (0,1)),
 stale INTEGER NOT NULL CHECK(stale IN (0,1)), record_count INTEGER NOT NULL CHECK(record_count>=0),
 metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json))
) WITHOUT ROWID;
CREATE TABLE nvd_records (
 cve TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('live','bulk')),
 fetched_at INTEGER NOT NULL CHECK(fetched_at>0), revision_ms INTEGER,
 body_deflate BLOB NOT NULL, body_bytes INTEGER NOT NULL CHECK(body_bytes BETWEEN 1 AND 16777216),
 metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)),
 PRIMARY KEY(cve,kind)
) WITHOUT ROWID;
CREATE TABLE package_versions (
 origin TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
 sha256 TEXT NOT NULL CHECK(length(sha256)=64), collected_at INTEGER NOT NULL CHECK(collected_at>0),
 source_url TEXT NOT NULL, format TEXT NOT NULL, body BLOB NOT NULL,
 PRIMARY KEY(origin,ecosystem,name,version,sha256)
) WITHOUT ROWID;
CREATE TABLE cve_lookup (
 kind TEXT NOT NULL CHECK(kind IN ('package','product')), lookup_key TEXT NOT NULL,
 source TEXT NOT NULL, cve TEXT NOT NULL, affected_key TEXT NOT NULL,
 projection_json TEXT NOT NULL CHECK(json_valid(projection_json)),
 PRIMARY KEY(kind,lookup_key,source,cve,affected_key)
) WITHOUT ROWID;
CREATE INDEX cve_lookup_record ON cve_lookup(source,cve);
CREATE TABLE resource_bodies (
 body_id TEXT PRIMARY KEY, bytes INTEGER NOT NULL CHECK(bytes>=0), sha256 TEXT NOT NULL CHECK(length(sha256)=64)
) WITHOUT ROWID;
CREATE TABLE resource_chunks (
 body_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0), data BLOB NOT NULL,
 PRIMARY KEY(body_id,ordinal), FOREIGN KEY(body_id) REFERENCES resource_bodies(body_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TABLE resources (
 key TEXT PRIMARY KEY, body_id TEXT NOT NULL, fetched_at INTEGER NOT NULL CHECK(fetched_at>0),
 ttl_ms INTEGER NOT NULL CHECK(ttl_ms>=0), content_type TEXT,
 response_headers_json TEXT NOT NULL CHECK(json_valid(response_headers_json)),
 metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)),
 FOREIGN KEY(body_id) REFERENCES resource_bodies(body_id)
) WITHOUT ROWID;
CREATE INDEX resources_eviction ON resources(fetched_at);
CREATE INDEX resources_body ON resources(body_id);
`;

function openCacheDb({cacheDir, readonly=false}={}) {
 if (!cacheDir) throw new Error('cacheDir is required');
 const file=path.join(cacheDir,'cache.sqlite');
 const db=openSqlite(file,{readonly});
 try {
  if(!readonly){
   db.exec('BEGIN IMMEDIATE');
   try{
    const id=db.prepare('PRAGMA application_id').get().application_id;
    const version=db.prepare('PRAGMA user_version').get().user_version;
    if(id===0&&version===0){
     db.exec(SCHEMA);
     db.prepare('INSERT INTO cache_meta(key,value) VALUES (?,?)').run('compression_dictionary_sha256',DICTIONARY_SHA256);
    }else if(id!==APPLICATION_ID||version!==SCHEMA_VERSION)throw new Error('unsupported VigieVuln SQLite cache schema');
    db.exec('COMMIT');
   }catch(error){try{db.exec('ROLLBACK')}catch{}throw error}
  }else{
   const id=db.prepare('PRAGMA application_id').get().application_id;
   const version=db.prepare('PRAGMA user_version').get().user_version;
   if(id!==APPLICATION_ID||version!==SCHEMA_VERSION)throw new Error('unsupported VigieVuln SQLite cache schema');
  }
  if(db.prepare('SELECT value FROM cache_meta WHERE key=?').get('compression_dictionary_sha256')?.value!==DICTIONARY_SHA256)
   throw new Error('unsupported VigieVuln cache compression dictionary');
  return db;
 } catch (error) {db.close();throw error}
}

const shared=new Map();
function getCacheDb(cacheDir=require('./cache-directory').getCacheDir()){
 const key=path.resolve(cacheDir);
 let db=shared.get(key);
 if(!db){db=openCacheDb({cacheDir:key});shared.set(key,db)}
 return db;
}
function closeCacheDbs(){for(const db of shared.values())db.close();shared.clear()}

module.exports={openCacheDb,getCacheDb,closeCacheDbs,APPLICATION_ID,SCHEMA_VERSION,SCHEMA,DICTIONARY_SHA256};
