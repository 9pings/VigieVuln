'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {stableRecord,METADATA_VERSION}=require('../lib/cache/record-freshness');
const {closeCacheDbs}=require('../lib/cache/db');
const nvd=require('../lib/providers/nvd/enrich');

test('stable individual records are reused by default and require trustworthy old source dates',()=>{
 const now=Date.parse('2026-11-05T00:00:00Z');
 const old={published:'2020-01-01T00:00:00Z',modified:'2024-01-01T00:00:00Z'};
 const opts={reuseStableAdvisories:true,now};
 assert.equal(METADATA_VERSION,1);
 assert.equal(stableRecord('osv',old,opts),true);
 assert.equal(stableRecord('osv',old,{now}),true);
 assert.equal(stableRecord('osv',old,{now,reuseStableAdvisories:false}),false);
 assert.equal(stableRecord('osv',old,{...opts,forceUpdate:true}),false);
 assert.equal(stableRecord('osv',{...old,modified:'2026-10-01'},opts),false);
 assert.equal(stableRecord('osv',{...old,modified:null},opts),false);
 assert.equal(stableRecord('osv',{...old,published:'2027-01-01'},opts),false);
 assert.equal(stableRecord('osv',{...old,modified:'invalid'},opts),false);
 assert.equal(stableRecord('osv',old,{...opts,stableAdvisoryAgeDays:2000}),false);
 assert.equal(stableRecord('catalogue',old,opts),false);
});

test('NVD stable cached record is reused by default and newer imports replace it',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-stable-'));
 try {
  const id='CVE-2020-12345',old={published:'2020-01-01',modified:'2021-01-01',description:'old'};
  nvd.writeCache(id,old,Date.now()-86400000,dir);
  assert.deepEqual(nvd.readCache(id,false,dir),old);
  assert.equal(nvd.readCache(id,false,dir,{reuseStableAdvisories:false}),null);
  assert.deepEqual(nvd.readCache(id,false,dir,{reuseStableAdvisories:true}),old);
  assert.equal(nvd.readCache(id,false,dir,{forceUpdate:true}),null);
  const updated={...old,modified:new Date().toISOString(),description:'updated'};
  nvd.writeCache(id,updated,Date.now(),dir);
  assert.deepEqual(nvd.readCache(id,false,dir,{reuseStableAdvisories:true}),updated);
 } finally {closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}
});

test('NVD proxy records are bound to their proxy origin',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-stable-proxy-'));
 const providers=require('../lib/providers');
 const old={published:'2020-01-01',modified:'2021-01-01'};
 try {
  providers.configureResourceRoute({proxyUrl:'https://one.example',hosted:true});
  nvd.writeCache('CVE-2020-12345',old,Date.now()-86400000,dir);
  assert.deepEqual(nvd.readCache('CVE-2020-12345',false,dir,{reuseStableAdvisories:true}),old);
  providers.configureResourceRoute({proxyUrl:'https://two.example',hosted:true});
  assert.equal(nvd.readCache('CVE-2020-12345',false,dir,{reuseStableAdvisories:true}),null);
  providers.configureResourceRoute({proxyUrl:null,hosted:false});
  assert.equal(nvd.readCache('CVE-2020-12345',false,dir,{reuseStableAdvisories:true}),null);
 } finally {providers.configureResourceRoute({proxyUrl:null,hosted:false});closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}
});

test('proxy OSV repeats package consultations but reuses bound stable details until forced or origin changes',async t=>{
 const {queryBatch}=require('../lib/providers/osv/query'); const providers=require('../lib/providers');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-stable-osv-'));let batch=0,details=0;
 t.after(()=>{providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});require('../lib/cache/db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const fetcher=async(_url,opts)=>{const req=JSON.parse(opts.body),headers={'x-fad-proxy-fetched-at':new Date().toISOString()};if(req.type==='packages'){batch++;return Response.json({results:[{vulns:[{id:'GHSA-test-1234'}]}]},{headers});}details++;return Response.json({id:'GHSA-test-1234',published:'2020-01-01',modified:'2021-01-01',affected:[]},{headers});};
 const dep={ecosystem:'Maven',groupId:'org.example',name:'demo',version:'1.0'};
 const opts={cacheDir:dir,fetcher,queryTtlMs:0};
 providers.configureResourceRoute({proxyUrl:'https://one.example',hosted:false,fetcher,store:null});
 await queryBatch([dep],opts);await queryBatch([dep],opts);assert.equal(batch,2);assert.equal(details,1);
 providers.configureResourceRoute({proxyUrl:'https://two.example',hosted:false,fetcher,store:null});
 await queryBatch([dep],opts);assert.equal(details,2);
 await queryBatch([dep],{...opts,forceUpdate:true});assert.equal(details,3);assert.equal(batch,4);
});

test('proxy EUVD stable details preserve their observation date and refresh on origin change or force',async t=>{
 const providers=require('../lib/providers'),{enrichEuropeanFindings}=require('../lib/findings/enrichment'),{createCacheRepository}=require('../lib/cache/repository');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-stable-euvd-')),repo=createCacheRepository(dir),id='CVE-2020-12345';let details=0,mappings=0;
 t.after(()=>{providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});require('../lib/cache/db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const fetcher=async(_url,opts)=>{const req=JSON.parse(opts.body),headers={'x-fad-proxy-fetched-at':new Date().toISOString()};if(req.type==='vulnerability'){details++;return Response.json({id:'EUVD-2020-1',aliases:id,datePublished:'2020-01-01',dateUpdated:'2021-01-01',description:'metadata'},{headers});}mappings++;return Response.json({items:[{cve:id,id:'EUVD-2020-1'}]},{headers});};
 const opts={cacheDir:dir,fetcher,certfr:false},make=()=>[{cve:{id}}];
 providers.configureResourceRoute({proxyUrl:'https://one.example',hosted:true,fetcher,store:null,hostedStore:null});
 await enrichEuropeanFindings(make(),opts);let stored=repo.get('catalogue','euvd-targeted').value;const observed=Date.now()-86400000;stored.entries[id].detailsFetchedAt=observed;repo.put('catalogue','euvd-targeted',stored);
 const next=make();await enrichEuropeanFindings(next,opts);assert.equal(details,1);assert.equal(next[0].cve.cveEvidence[0].euvdDetailsEvidence.fetchedAt,observed);assert.equal(next[0].cve.cveEvidence[0].euvdDetailsEvidence.reusedStable,true);
 providers.configureResourceRoute({proxyUrl:'https://two.example',hosted:true,fetcher,store:null,hostedStore:null});
 await enrichEuropeanFindings(make(),opts);assert.equal(details,2);
 await enrichEuropeanFindings(make(),{...opts,forceUpdate:true});assert.equal(details,3);assert.ok(mappings>=1);
});

test('EUVD mirror provenance preserves scope, observation and separate check dates offline',async t=>{
 const providers=require('../lib/providers'),{enrichEuropeanFindings}=require('../lib/findings/enrichment');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-euvd-provenance-')),id='CVE-2020-12345';
 t.after(()=>{providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});require('../lib/cache/db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const fetcher=async(_url,opts)=>{const req=JSON.parse(opts.body),headers={'x-fad-proxy-fetched-at':'2025-01-01T00:00:00Z','x-fad-proxy-checked-at':'2026-10-01T00:00:00Z','x-fad-proxy-scope':'euvd-search-record; relationships-incomplete'};return req.type==='vulnerability'?Response.json({id:'EUVD-2020-1',aliases:id,description:'record'},{headers}):Response.json({items:[{cve:id,id:'EUVD-2020-1'}]},{headers});};
 providers.configureResourceRoute({proxyUrl:'https://fleet.example',hosted:true,fetcher,hostedStore:null,store:null});
 const matches=[{cve:{id}}];await enrichEuropeanFindings(matches,{cacheDir:dir,fetcher,certfr:false});
 const provenance=matches[0].cve.euvdDetails.provenance;assert.equal(provenance.sourceScope,'euvd-search-record; relationships-incomplete');assert.equal(provenance.observedAt,'2025-01-01T00:00:00.000Z');assert.equal(provenance.checkedAt,'2026-10-01T00:00:00.000Z');assert.match(provenance.resource,/enisaid\?id=EUVD-2020-1/);
 const offline=[{cve:{id}}];await enrichEuropeanFindings(offline,{cacheDir:dir,offline:true,certfr:false,fetcher:()=>{throw Error('network')}});assert.deepEqual(offline[0].cve.euvdDetails.provenance,provenance);
});
