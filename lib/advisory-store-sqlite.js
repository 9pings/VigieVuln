'use strict';

const fs=require('node:fs');
const path=require('node:path');
const {openCacheDb}=require('./cache-db');
const {compress,decompress}=require('./advisory-compression');
const rules=require('./advisory-store');
const {validateRecord,validateQuery,validateCoverage,packageName,packageKeys,queryKey,coverageKey,advisoryId,queryCoversRecord,isWithdrawn,revision,wins,hash,key}=rules;
const DEFAULT_QUERY_TTL_MS=4 * 3600e3;
const parse=value=>JSON.parse(value);
const text=value=>JSON.stringify(value);

class SqliteAdvisoryStore {
 constructor({cacheDir=require('./cache-directory').getCacheDir()}={}){
  this.cacheDir=cacheDir;
  this.db=openCacheDb({cacheDir});
 }
 close(){this.db.close()}
 _rowRecord(source,id){return this.db.prepare('SELECT * FROM advisory_records WHERE source=? AND id=?').get(source,id)||null}
 _record(source,id){
  const row=this._rowRecord(source,id);if(!row)return null;
  const body=decompress(row.envelope_deflate,row.envelope_bytes);
  const record=parse(body.toString('utf8'));validateRecord(record);
  if(record.source!==source||advisoryId(record)!==id||hash(text(record.document))!==row.document_sha256)throw Error('advisory record integrity mismatch');
  const observations=this.db.prepare('SELECT fetched_at,provenance_json FROM advisory_observations WHERE source=? AND id=? ORDER BY provenance_key').all(source,id).map(x=>({fetchedAt:x.fetched_at,provenance:parse(x.provenance_json)}));
  return {...record,contentChangedAt:row.content_changed_at,observations};
 }
 _putRecord(record){
  const source=record.source,id=advisoryId(record),previous=this._record(source,id);
  const winner=wins(record,previous);
  if(winner){
   const documentHash=hash(text(record.document));
   const changedAt=previous&&hash(text(previous.document))===documentHash?previous.contentChangedAt:record.fetchedAt;
   const encoded=Buffer.from(text(record));
   if(encoded.length>16777216)throw Error('advisory record exceeds SQLite cache limit');
   this.db.prepare(`INSERT INTO advisory_records(source,id,revision_ms,withdrawn,fetched_at,content_changed_at,document_sha256,envelope_deflate,envelope_bytes)
    VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(source,id) DO UPDATE SET revision_ms=excluded.revision_ms,
    withdrawn=excluded.withdrawn,fetched_at=excluded.fetched_at,content_changed_at=excluded.content_changed_at,
    document_sha256=excluded.document_sha256,envelope_deflate=excluded.envelope_deflate,envelope_bytes=excluded.envelope_bytes`).run(source,id,revision(record),isWithdrawn(record)?1:0,record.fetchedAt,changedAt,documentHash,compress(encoded),encoded.length);
   this.db.prepare('DELETE FROM advisory_packages WHERE source=? AND id=?').run(source,id);
   const insert=this.db.prepare('INSERT INTO advisory_packages(ecosystem,name_key,source,id) VALUES (?,?,?,?)');
   for(const identity of packageKeys(record)){const [ecosystem,nameKey]=parse(identity);insert.run(ecosystem,nameKey,source,id)}
  }
  const provenance=record.provenance||{};
  this.db.prepare(`INSERT INTO advisory_observations(source,id,provenance_key,fetched_at,provenance_json)
   VALUES (?,?,?,?,?) ON CONFLICT(source,id,provenance_key) DO UPDATE SET fetched_at=max(fetched_at,excluded.fetched_at)`).run(source,id,hash(text(provenance)),record.fetchedAt,text(provenance));
 }
 _putQuery(query){
  const source=query.source,ecosystem=query.ecosystem,nameKey=ecosystem==='Maven'?query.name:packageName(ecosystem,query.name),version=query.version;
  const previous=this.db.prepare('SELECT fetched_at FROM advisory_queries WHERE source=? AND ecosystem=? AND name_key=? AND version=?').get(source,ecosystem,nameKey,version);
  if(previous&&previous.fetched_at>query.fetchedAt)return;
  this.db.prepare(`INSERT INTO advisory_queries(source,ecosystem,name_key,version,original_name,fetched_at,stale,provenance_json)
   VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(source,ecosystem,name_key,version) DO UPDATE SET original_name=excluded.original_name,
   fetched_at=excluded.fetched_at,stale=excluded.stale,provenance_json=excluded.provenance_json`).run(source,ecosystem,nameKey,version,query.name,query.fetchedAt,query.provenance?.stale===true?1:0,text(query.provenance||{}));
  this.db.prepare('DELETE FROM advisory_query_ids WHERE source=? AND ecosystem=? AND name_key=? AND version=?').run(source,ecosystem,nameKey,version);
  const insert=this.db.prepare('INSERT INTO advisory_query_ids(source,ecosystem,name_key,version,id,ordinal,document_sha256) VALUES (?,?,?,?,?,?,?)');
  for(let i=0;i<query.ids.length;i++)insert.run(source,ecosystem,nameKey,version,query.ids[i],i,query.provenance?.documentHashes?.[query.ids[i]]||null);
 }
 _putCoverage(coverage){
  const source=coverage.source,ecosystem=coverage.ecosystem;
  const current=this.db.prepare("SELECT fetched_at FROM advisory_coverage WHERE source=? AND ecosystem=? AND slot='current'").get(source,ecosystem);
  const put=this.db.prepare(`INSERT INTO advisory_coverage(source,ecosystem,slot,fetched_at,complete,stale,entry_json)
   VALUES (?,?,?,?,?,?,?) ON CONFLICT(source,ecosystem,slot) DO UPDATE SET fetched_at=excluded.fetched_at,
   complete=excluded.complete,stale=excluded.stale,entry_json=excluded.entry_json`);
  if(!current||coverage.fetchedAt>=current.fetched_at)put.run(source,ecosystem,'current',coverage.fetchedAt,coverage.complete?1:0,coverage.provenance?.stale===true?1:0,text(coverage));
  if(coverage.complete){
   const last=this.db.prepare("SELECT fetched_at FROM advisory_coverage WHERE source=? AND ecosystem=? AND slot='last_complete'").get(source,ecosystem);
   if(!last||coverage.fetchedAt>=last.fetched_at)put.run(source,ecosystem,'last_complete',coverage.fetchedAt,1,coverage.provenance?.stale===true?1:0,text(coverage));
  }
 }
 _commit({records=[],queries=[],coverages=[]}){
  for(const record of records)this._putRecord(record);
  for(const query of queries)this._putQuery(query);
  for(const coverage of coverages)this._putCoverage(coverage);
 }
 commit({records=[],queries=[],coverages=[]}={}){
  if(!Array.isArray(records)||!Array.isArray(queries)||!Array.isArray(coverages))throw Error('invalid advisory transaction');
  const transaction=parse(text({records,queries,coverages}));
  for(const record of transaction.records)validateRecord(record);
  for(const query of transaction.queries)validateQuery(query);
  for(const coverage of transaction.coverages)validateCoverage(coverage);
  if(!records.length&&!queries.length&&!coverages.length)return;
  return this.db.transaction(()=>{
   const incoming=new Set(transaction.records.map(record=>key(record.source,advisoryId(record))));
   for(const query of transaction.queries)for(const id of query.ids)if(!incoming.has(key(query.source,id))&&!this._rowRecord(query.source,id))throw Error(`missing advisory detail: ${id}`);
   this._commit(transaction);
  });
 }
 getRecord(source,id){return this._record(source,id)}
 getQuery(tuple,{now=Date.now(),ttlMs=DEFAULT_QUERY_TTL_MS}={}){
  if(!Number.isFinite(ttlMs)||ttlMs<0)throw Error('invalid advisory query TTL');
  const source=tuple.source||'osv',ecosystem=tuple.ecosystem,nameKey=ecosystem==='Maven'?tuple.name:packageName(ecosystem,tuple.name);
  const row=this.db.prepare('SELECT * FROM advisory_queries WHERE source=? AND ecosystem=? AND name_key=? AND version=?').get(source,ecosystem,nameKey,tuple.version);
  if(!row)return null;
  const ids=this.db.prepare('SELECT id FROM advisory_query_ids WHERE source=? AND ecosystem=? AND name_key=? AND version=? ORDER BY ordinal').all(source,ecosystem,nameKey,tuple.version).map(x=>x.id);
  if(ids.some(id=>!this._rowRecord(source,id)))return null;
  const provenance=parse(row.provenance_json);
  return {source,ecosystem,name:row.original_name,version:row.version,ids,fetchedAt:row.fetched_at,complete:true,provenance,fresh:provenance.stale!==true&&now>=row.fetched_at&&now-row.fetched_at<ttlMs};
 }
 getSourceCoverage(source,ecosystem='*',options={}){return this._coverage({source,ecosystem},options)}
 _coverage(tuple,{now=Date.now(),ttlMs=DEFAULT_QUERY_TTL_MS}={}){
  const source=tuple.source||'osv';
  let coverageEcosystem=tuple.ecosystem;
  let current=this.db.prepare("SELECT * FROM advisory_coverage WHERE source=? AND ecosystem=? AND slot='current'").get(source,coverageEcosystem);
  if(!current && source==='osv' && tuple.name){
   coverageEcosystem=require('./airgap-project').packageScope(tuple.ecosystem,tuple.name);
   current=this.db.prepare("SELECT * FROM advisory_coverage WHERE source=? AND ecosystem=? AND slot='current'").get(source,coverageEcosystem);
  }
  if(!current)return null;
  const baseline=this.db.prepare("SELECT * FROM advisory_coverage WHERE source=? AND ecosystem=? AND slot='last_complete'").get(source,coverageEcosystem);
  const unpack=row=>{const x=parse(row.entry_json);return {...x,fresh:x.provenance?.stale!==true&&now>=x.fetchedAt&&now-x.fetchedAt<ttlMs}};
  return {...unpack(current),lastComplete:baseline?unpack(baseline):null};
 }
 getQuerySummary(source='osv',{now=Date.now(),ttlMs=DEFAULT_QUERY_TTL_MS}={}){
  if(!Number.isFinite(ttlMs)||ttlMs<0)throw Error('invalid advisory query TTL');
  const row=this.db.prepare(`SELECT COUNT(*) count,MIN(fetched_at) oldestFetchedAt,MAX(fetched_at) newestFetchedAt,
   SUM(CASE WHEN stale=1 OR fetched_at>? OR fetched_at<=? THEN 1 ELSE 0 END) staleCount FROM advisory_queries WHERE source=?`).get(now,now-ttlMs,source);
  return {count:row.count,oldestFetchedAt:row.oldestFetchedAt,newestFetchedAt:row.newestFetchedAt,staleCount:row.staleCount||0,complete:false,scope:'consulted-package-versions'};
 }
 getPackageRecords(ecosystem,name,{source='osv',includeWithdrawn=false}={}){
  const pkgName=packageName(ecosystem,name);
  const rows=source==null
   ? this.db.prepare('SELECT source,id FROM advisory_packages WHERE ecosystem=? AND name_key=? ORDER BY source,id').all(ecosystem,pkgName)
   : this.db.prepare('SELECT source,id FROM advisory_packages WHERE ecosystem=? AND name_key=? AND source=? ORDER BY id').all(ecosystem,pkgName,source);
  return rows.map(x=>this._record(x.source,x.id)).filter(record=>record&&(includeWithdrawn||!isWithdrawn(record)));
 }
 getPackageView(tuple,options={}){
  const source=tuple.source||'osv',query=this.getQuery(tuple,options);
  const records=this.getPackageRecords(tuple.ecosystem,tuple.name,{source,includeWithdrawn:true});
  if(source==='osv'&&tuple.ecosystem==='Maven')for(const legacy of this.getPackageRecords(tuple.ecosystem,tuple.name,{source:'osv-legacy-maven',includeWithdrawn:true}))if(!this._rowRecord('osv',advisoryId(legacy)))records.push(legacy);
  const queryRecords=query?query.ids.map(id=>this._record(source,id)):[];
  const combined=new Map([...records,...queryRecords].filter(Boolean).map(record=>[key(record.source,advisoryId(record)),record]));
  return {query,coverage:this._coverage(tuple,options),records:[...combined.values()],queryRecords,
   querySuperseded:!!query&&[...combined.values()].some(record=>!queryCoversRecord(query,record))};
 }
 async importRecords(iterable,{source='osv',fetchedAt=Date.now(),provenance={transport:'seed'},batchSize=250,coverages=[],envelopes=false}={}){
  if(!Number.isSafeInteger(batchSize)||batchSize<1||batchSize>1000)throw Error('invalid advisory import batch size');
  for(const coverage of coverages)validateCoverage(coverage);
  let count=0,batch=[];
  this.db.exec('BEGIN IMMEDIATE');
  try{
   for await(const document of iterable){
    const record=envelopes?document:{source,document,fetchedAt,provenance};validateRecord(record);
    batch.push(record);count++;
    if(batch.length>=batchSize){this._commit({records:batch});batch=[]}
   }
   if(batch.length)this._commit({records:batch});
   for(const coverage of coverages)this._putCoverage(coverage);
   this.db.exec('COMMIT');return count;
  }catch(error){try{this.db.exec('ROLLBACK')}catch{}throw error}
 }
 importEnvelopes(iterable,options={}){return this.importRecords(iterable,{...options,envelopes:true})}
}

function openAdvisoryStore(options){return new SqliteAdvisoryStore(options)}
module.exports={SqliteAdvisoryStore,openAdvisoryStore};
