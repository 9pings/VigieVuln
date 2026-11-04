'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {prepareDirectCache,prepareScopedCache}=require('../lib/cache-startup');

test('SQLite startup discards legacy cache contents while preserving configuration and account session',t=>{
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'vv-sqlite-start-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const legacy=path.join(home,'.fad-checker'),current=path.join(home,'.vigie-vuln'),session=path.join(home,'.vigievuln','account-session.json');
 fs.mkdirSync(legacy);fs.mkdirSync(current);fs.mkdirSync(path.dirname(session));
 fs.writeFileSync(path.join(legacy,'config.json'),'old private key');
 fs.writeFileSync(path.join(current,'config.json'),'current private key');
 fs.writeFileSync(path.join(current,'cache.sqlite'),'new database');
 fs.mkdirSync(path.join(current,'advisory-store'));fs.writeFileSync(path.join(current,'advisory-store','events.jsonl'),'old journal');
 fs.writeFileSync(session,'account token');
 prepareDirectCache({homeDir:home});
 assert.equal(fs.readFileSync(path.join(current,'config.json'),'utf8'),'current private key');
 assert.equal(fs.readFileSync(path.join(current,'cache.sqlite'),'utf8'),'new database');
 assert.equal(fs.readFileSync(session,'utf8'),'account token');
 assert.equal(fs.existsSync(path.join(current,'advisory-store')),false);
 assert.equal(fs.existsSync(legacy),false);
});

test('proxy scope keeps its origin marker outside the purged cache',t=>{
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'vv-sqlite-scope-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const scope=path.join(home,'scope'),cache=path.join(scope,'.vigie-vuln');fs.mkdirSync(cache,{recursive:true});
 fs.writeFileSync(path.join(scope,'origin.json'),'trusted origin');fs.writeFileSync(path.join(cache,'old.json'),'old cache');
 prepareScopedCache(cache);
 assert.equal(fs.readFileSync(path.join(scope,'origin.json'),'utf8'),'trusted origin');
 assert.equal(fs.existsSync(path.join(cache,'old.json')),false);
});
