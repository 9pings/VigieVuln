'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = require('./helpers/isolated-cache')('nvd-bulk');
const bulk = require('../lib/nvd-bulk');
const nvd = require('../lib/nvd');
const id = 'CVE-2021-44228';
const body = marker => ({id, description:marker, cwes:['CWE-502']});

test('compact snapshots retain full enrichment and choose newest offline without changing online TTL', () => {
 const dir=path.join(root,'nvd-cache'), now=Date.now(), old=now-20000, newer=now-10000;
 const a=bulk.createWriter(dir,old);a.add(id,body('old snapshot'));a.finish();
 const b=bulk.createWriter(dir,newer);b.add(id,body('new snapshot'));const generation=b.finish();
 assert.deepEqual(bulk.validateAll(dir),{generations:2,records:2});
 assert.deepEqual(bulk.snapshotSummary(dir),{count:2,oldestFetchedAt:old,newestFetchedAt:newer,newestRecordCount:1});
 assert.deepEqual(bulk.readBulk(dir,id).body,body('new snapshot'));
 const db=require('../lib/cache-db').getCacheDb(root),bytes=Buffer.from(JSON.stringify(body('new snapshot')));
 db.prepare('INSERT INTO nvd_records(cve,kind,fetched_at,revision_ms,body_deflate,body_bytes,metadata_json) VALUES (?,?,?,?,?,?,?)').run(
  id,'bulk',newer,null,require('../lib/advisory-compression').compress(bytes),bytes.length,'{}');
 assert.equal(nvd.readCache(id,true).description,'new snapshot');
 assert.equal(nvd.readCache(id,false),null,'server projection must not be treated as fresh native NVD');
 nvd.writeCache(id,body('live'));
 assert.equal(nvd.readCache(id,true).description,'live');
 assert.equal(nvd.readCache(id,false).description,'live');
 db.prepare("DELETE FROM nvd_records WHERE cve=? AND kind='live'").run(id);
 assert.equal(nvd.readCache(id,true).description,'new snapshot');
 assert.ok(fs.readdirSync(path.join(dir,'_bulk',generation.generation)).length<=257);
});

test('corrupt shards or manifest never fabricate a result and fall back to older snapshots', () => {
 const dir=path.join(root,'corruption'), now=Date.now();
 const a=bulk.createWriter(dir,now-2000);a.add(id,body('safe'));a.finish();
 const b=bulk.createWriter(dir,now-1000);b.add(id,body('corrupt'));const out=b.finish();
 fs.writeFileSync(path.join(dir,'_bulk',out.generation,bulk.shardName(id)),'{}');
 assert.throws(()=>bulk.validateAll(dir),/checksum/);
 assert.equal(bulk.readBulk(dir,id).body.description,'safe');
 assert.equal(bulk.readBulk(dir,'CVE-2021-999999'),null);
});

test('aborted snapshot leaves no readable generation', () => {
 const dir=path.join(root,'aborted'), w=bulk.createWriter(dir,Date.now());
 w.add(id,body('temporary'));w.abort();assert.equal(bulk.readBulk(dir,id),null);
});
