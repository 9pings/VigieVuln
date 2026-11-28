'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {createCacheRepository}=require('../lib/cache/repository');
const {openCacheDb,closeCacheDbs}=require('../lib/cache/db');
const {exportCache,importCache}=require('../lib/cache/archive');
const {openAdvisoryStore}=require('../lib/advisories/store-sqlite');

function fixture(t){
 const base=fs.mkdtempSync(path.join(os.tmpdir(),'vigie-sqlite-archive-'));
 t.after(()=>{closeCacheDbs();fs.rmSync(base,{recursive:true,force:true})});
 return {source:path.join(base,'source'),target:path.join(base,'target'),archive:path.join(base,'cache.tar.gz')};
}
function lookup(dir){
 const db=openCacheDb({cacheDir:dir});
 try{return db.prepare("SELECT cve FROM cve_lookup WHERE kind='package'").all().map(r=>r.cve)}
 finally{db.close()}
}
function setLookup(dir,cve,stamp){
 const db=openCacheDb({cacheDir:dir});
 try{
  db.prepare("INSERT INTO cve_lookup VALUES ('package','maven:g:a','nvd',?,'a','{}')").run(cve);
  db.prepare("INSERT INTO cache_snapshots VALUES ('cve_lookup',?,1,0,1,'{}')").run(stamp);
 }finally{db.close()}
}

test('SQLite archive merges values, preserves local config and keeps the newer CVE index',async t=>{
 const f=fixture(t),source=createCacheRepository(f.source),target=createCacheRepository(f.target);
 source.put('fixture','shared','older',{fetchedAt:100});
 source.put('fixture','remote','remote value',{fetchedAt:100});
 target.put('fixture','shared','newer',{fetchedAt:200});
 target.put('fixture','local','local value',{fetchedAt:200});
 fs.writeFileSync(path.join(f.target,'config.json'),'secret');
 setLookup(f.source,'CVE-2026-0001',100);
 setLookup(f.target,'CVE-2026-0002',200);
 await exportCache(f.archive,{sourceDir:f.source});
 await importCache(f.archive,{targetDir:f.target});
 assert.equal(createCacheRepository(f.target).get('fixture','shared').value,'newer');
 assert.equal(createCacheRepository(f.target).get('fixture','remote').value,'remote value');
 assert.equal(createCacheRepository(f.target).get('fixture','local').value,'local value');
 assert.deepEqual(lookup(f.target),['CVE-2026-0002']);
 assert.equal(fs.readFileSync(path.join(f.target,'config.json'),'utf8'),'secret');
});

test('SQLite merge unions per-package Maven presence and discards unverified absences',async t=>{
 const f=fixture(t),name='maven-exists-cache.json';
 createCacheRepository(f.source).put('auxiliary',name,{meta:{fetchedAt:100},entries:{'g:remote':true,'g:shared':true,'g:legacy':false}},{fetchedAt:100});
 createCacheRepository(f.target).put('auxiliary',name,{meta:{fetchedAt:200},entries:{'g:local':true,'g:shared':false}},{fetchedAt:200});
 await exportCache(f.archive,{sourceDir:f.source});
 await importCache(f.archive,{targetDir:f.target});
 const result=createCacheRepository(f.target).get('auxiliary',name);
 assert.deepEqual(result.value.entries,{'g:remote':true,'g:shared':true,'g:local':true});
 assert.equal(result.value.meta.fetchedAt,100);
});

test('SQLite archive rejects a modified payload without changing the target',async t=>{
 const f=fixture(t),repo=createCacheRepository(f.source);
 repo.put('fixture','value','original');
 await exportCache(f.archive,{sourceDir:f.source});
 const stage=path.join(path.dirname(f.archive),'stage');fs.mkdirSync(stage);
 require('node:child_process').execFileSync('tar',['-xzf',f.archive,'-C',stage]);
 const dbfile=path.join(stage,'.vigie-vuln','cache.sqlite');
 const bytes=fs.readFileSync(dbfile);bytes[bytes.length-1]^=1;fs.writeFileSync(dbfile,bytes);
 require('node:child_process').execFileSync('tar',['-czf',f.archive,'-C',stage,'.vigie-vuln']);
 createCacheRepository(f.target).put('fixture','local','safe');
 await assert.rejects(importCache(f.archive,{targetDir:f.target}),/checksum/);
 assert.equal(createCacheRepository(f.target).get('fixture','local').value,'safe');
});

test('SQLite merge selects the newest CVE index as one snapshot',async t=>{
 const f=fixture(t);setLookup(f.source,'CVE-2026-0001',300);setLookup(f.target,'CVE-2026-0002',200);
 await exportCache(f.archive,{sourceDir:f.source});
 await importCache(f.archive,{targetDir:f.target});
 assert.deepEqual(lookup(f.target),['CVE-2026-0001']);
 assert.equal(createCacheRepository(f.target).getSnapshot('cve_lookup').fetchedAt,300);
});

test('SQLite merge retains a newer local advisory and imports unrelated records',async t=>{
 const f=fixture(t),first=openAdvisoryStore({cacheDir:f.source}),second=openAdvisoryStore({cacheDir:f.target});
 const record=(id,name,modified,fetchedAt)=>({source:'osv',document:{id,modified,affected:[{package:{ecosystem:'Maven',name}}]},fetchedAt,provenance:{transport:'seed'}});
 first.commit({records:[record('GHSA-shared','g:old','2026-01-01T00:00:00Z',100),record('GHSA-imported','g:other','2026-01-01T00:00:00Z',100)]});
 second.commit({records:[record('GHSA-shared','g:new','2026-02-01T00:00:00Z',200)]});
 first.close();second.close();
 await exportCache(f.archive,{sourceDir:f.source});
 await importCache(f.archive,{targetDir:f.target});
 const result=openAdvisoryStore({cacheDir:f.target});
 try{
  assert.deepEqual(result.getPackageRecords('Maven','g:new').map(r=>r.document.id),['GHSA-shared']);
  assert.deepEqual(result.getPackageRecords('Maven','g:other').map(r=>r.document.id),['GHSA-imported']);
  assert.deepEqual(result.getPackageRecords('Maven','g:old').map(r=>r.document.id),[]);
 }finally{result.close()}
});

test('newer withdrawal in an imported archive removes the old package binding',async t=>{
 const f=fixture(t),local=openAdvisoryStore({cacheDir:f.target}),incoming=openAdvisoryStore({cacheDir:f.source});
 local.commit({records:[{source:'osv',document:{id:'GHSA-withdrawn',modified:'2026-01-01T00:00:00Z',affected:[{package:{ecosystem:'Maven',name:'g:a'}}]},fetchedAt:100}]});
 incoming.commit({records:[{source:'osv',document:{id:'GHSA-withdrawn',modified:'2026-02-01T00:00:00Z',withdrawn:'2026-02-01T00:00:00Z',affected:[]},fetchedAt:200}]});
 local.close();incoming.close();
 await exportCache(f.archive,{sourceDir:f.source});
 await importCache(f.archive,{targetDir:f.target});
 const result=openAdvisoryStore({cacheDir:f.target});
 try{
  assert.deepEqual(result.getPackageRecords('Maven','g:a'),[]);
  assert.ok(result.getRecord('osv','GHSA-withdrawn').document.withdrawn);
 }finally{result.close()}
});

test('replace installs the archive and keeps local configuration and a backup',async t=>{
 const f=fixture(t);createCacheRepository(f.source).put('fixture','value','incoming');
 createCacheRepository(f.target).put('fixture','value','local');
 fs.writeFileSync(path.join(f.target,'config.json'),'private key');
 await exportCache(f.archive,{sourceDir:f.source});
 await importCache(f.archive,{targetDir:f.target,replace:true});
 assert.equal(createCacheRepository(f.target).get('fixture','value').value,'incoming');
 assert.equal(fs.readFileSync(path.join(f.target,'config.json'),'utf8'),'private key');
 assert.equal(fs.readdirSync(path.dirname(f.target)).filter(name=>name.startsWith('target.bak-')&&name.endsWith('.sqlite')).length,1);
});

test('cold import installs a SQLite database and old bundles are rejected',async t=>{
 const f=fixture(t);createCacheRepository(f.source).put('fixture','value','available offline');
 await exportCache(f.archive,{sourceDir:f.source});
 await importCache(f.archive,{targetDir:f.target});
 assert.equal(createCacheRepository(f.target).get('fixture','value').value,'available offline');
 const old=path.join(path.dirname(f.archive),'old.tar.gz');
 const stage=path.join(path.dirname(f.archive),'old');fs.mkdirSync(stage);
 fs.writeFileSync(path.join(stage,'legacy.json'),'{}');
 require('node:child_process').execFileSync('tar',['-czf',old,'-C',stage,'legacy.json']);
 await assert.rejects(importCache(old,{targetDir:f.target}),/unsupported cache bundle/);
 assert.equal(createCacheRepository(f.target).get('fixture','value').value,'available offline');
});

test('invalid archive errors are sanitized and cache transfer requires no PATH tools',async t=>{
 const f=fixture(t);fs.writeFileSync(f.archive,'not an archive');
 await assert.rejects(importCache(f.archive,{targetDir:f.target}),/unsupported cache bundle: invalid gzip or tar data/);
 createCacheRepository(f.source).put('fixture','key','value');
 const {spawnSync}=require('node:child_process'),modulePath=require.resolve('../lib/cache/archive');
 const script=`const a=require(${JSON.stringify(modulePath)}); (async()=>{await a.exportCache(${JSON.stringify(f.archive)},{sourceDir:${JSON.stringify(f.source)}});await a.importCache(${JSON.stringify(f.archive)},{targetDir:${JSON.stringify(f.target)}})})().catch(e=>{console.error(e.message);process.exitCode=1});`;
 const child=spawnSync(process.execPath,['-e',script],{env:{...process.env,PATH:''},encoding:'utf8'});
 assert.equal(child.status,0,child.stderr);assert.equal(createCacheRepository(f.target).get('fixture','key').value,'value');
});

test('export still rejects an uncheckpointed WAL introduced during native streaming',async t=>{
 const f=fixture(t),{spawnSync}=require('node:child_process');createCacheRepository(f.source).put('fixture','key','value');
 const modulePath=require.resolve('../lib/cache/archive');
 const script=`const fs=require('node:fs'), path=require('node:path'), original=fs.createReadStream;fs.createReadStream=function(file,...args){if(path.basename(String(file))==='cache.sqlite' && path.basename(path.dirname(String(file)))==='.vigie-vuln')fs.writeFileSync(file+'-wal','injected');return original.call(this,file,...args)};require(${JSON.stringify(modulePath)}).exportCache(${JSON.stringify(f.archive)},{sourceDir:${JSON.stringify(f.source)}}).catch(e=>{process.stdout.write(e.message);process.exitCode=1});`;
 const child=spawnSync(process.execPath,['-e',script],{encoding:'utf8',env:{...process.env,PATH:''}});
 assert.equal(child.status,1);assert.match(child.stdout,/uncheckpointed WAL/);assert.equal(fs.existsSync(f.archive),false);
});

test('native cache extraction rejects links, traversal and duplicate entries',async t=>{
 const f=fixture(t),tar=require('tar-stream'),zlib=require('node:zlib');
 async function bundle(entries){const pack=tar.pack(),chunks=[];const gzip=pack.pipe(zlib.createGzip());gzip.on('data',c=>chunks.push(c));const done=new Promise((r,j)=>{pack.on('error',j);gzip.on('error',j).on('end',r)});
  for(const header of entries) await new Promise((r,j)=>pack.entry(header,'',e=>e?j(e):r()));pack.finalize();await done;await new Promise(r=>setImmediate(r));fs.writeFileSync(f.archive,Buffer.concat(chunks));}
 for(const entry of [{name:'.vigie-vuln/cache.sqlite',type:'symlink',linkname:'/etc/passwd'},{name:'../escape',type:'file'},{name:'.vigie-vuln/cache.sqlite',type:'link',linkname:'elsewhere'}]){await bundle([entry]);await assert.rejects(importCache(f.archive,{targetDir:f.target}),/links or special|unexpected/);}
 await bundle([{name:'.vigie-vuln/cache.sqlite'},{name:'.vigie-vuln/cache.sqlite'}]);await assert.rejects(importCache(f.archive,{targetDir:f.target}),/duplicate/);
});
