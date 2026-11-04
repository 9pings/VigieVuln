'use strict';

const {getCacheDb}=require('./cache-db');
const zlib=require('node:zlib');

function createCacheRepository(cacheDir){
 const db=getCacheDb(cacheDir);
 const get=db.prepare('SELECT fetched_at,expires_at,stale,encoding,payload,metadata_json FROM cache_entries WHERE namespace=? AND key=?');
 const put=db.prepare(`INSERT INTO cache_entries(namespace,key,fetched_at,expires_at,stale,encoding,payload,metadata_json)
  VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(namespace,key) DO UPDATE SET fetched_at=excluded.fetched_at,
  expires_at=excluded.expires_at,stale=excluded.stale,encoding=excluded.encoding,payload=excluded.payload,metadata_json=excluded.metadata_json`);
 const remove=db.prepare('DELETE FROM cache_entries WHERE namespace=? AND key=?');
 return {
  db,
  get(namespace,key){
   const row=get.get(namespace,key);if(!row)return null;
   const compressed=row.encoding.endsWith('+deflate');
   const body=compressed?zlib.inflateRawSync(Buffer.from(row.payload),{maxOutputLength:134217728}):Buffer.from(row.payload);
   const encoding=compressed?row.encoding.slice(0,-8):row.encoding;
   return {value:encoding==='json'?JSON.parse(body.toString('utf8')):encoding==='text'?body.toString('utf8'):body,
    fetchedAt:row.fetched_at,expiresAt:row.expires_at,stale:!!row.stale,metadata:JSON.parse(row.metadata_json)};
  },
  put(namespace,key,value,{fetchedAt=Date.now(),expiresAt=null,stale=false,metadata={}}={}){
   const encoding=Buffer.isBuffer(value)||value instanceof Uint8Array?'binary':typeof value==='string'?'text':'json';
   const bytes=encoding==='binary'?Buffer.from(value):Buffer.from(encoding==='text'?value:JSON.stringify(value));
   const compressed=bytes.length>=4096;
   put.run(namespace,key,fetchedAt,expiresAt,stale?1:0,compressed?encoding+'+deflate':encoding,
    compressed?zlib.deflateRawSync(bytes,{level:1}):bytes,JSON.stringify({...metadata,...(compressed?{uncompressedBytes:bytes.length}:{})}));
  },
  delete(namespace,key){return remove.run(namespace,key).changes>0},
  *entries(namespace){
   let last='';
   for(;;){
    const rows=db.prepare('SELECT key FROM cache_entries WHERE namespace=? AND key>? ORDER BY key LIMIT 1000').all(namespace,last);
    if(!rows.length)return;
    for(const row of rows){last=row.key;yield [row.key,this.get(namespace,row.key)]}
   }
  },
  getSnapshot(namespace){const row=db.prepare('SELECT * FROM cache_snapshots WHERE namespace=?').get(namespace);return row?{fetchedAt:row.fetched_at,complete:!!row.complete,stale:!!row.stale,recordCount:row.record_count,metadata:JSON.parse(row.metadata_json)}:null},
  putSnapshot(namespace,{fetchedAt=Date.now(),complete=false,stale=false,recordCount=0,metadata={}}={}){
   db.prepare(`INSERT INTO cache_snapshots(namespace,fetched_at,complete,stale,record_count,metadata_json) VALUES (?,?,?,?,?,?)
    ON CONFLICT(namespace) DO UPDATE SET fetched_at=excluded.fetched_at,complete=excluded.complete,
    stale=excluded.stale,record_count=excluded.record_count,metadata_json=excluded.metadata_json`).run(namespace,fetchedAt,complete?1:0,stale?1:0,recordCount,JSON.stringify(metadata));
  },
 };
}

module.exports={createCacheRepository};
