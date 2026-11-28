'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const {enrichEuropeanFindings}=require('../lib/findings/enrichment'),{exportCache,importCache}=require('../lib/cache/archive'),providers=require('../lib/providers');
test('EUVD mirror HTTP evidence survives cache bundle transfer and offline image-style enrichment',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-euvd-airgap-')),source=path.join(dir,'source'),target=path.join(dir,'target'),archive=path.join(dir,'cache.tar.gz'),id='CVE-2020-12345';let calls=0;
 const server=http.createServer((req,res)=>{let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{calls++;const q=JSON.parse(body),headers={'content-type':'application/json','x-fad-proxy-fetched-at':'2025-01-01T00:00:00Z','x-fad-proxy-checked-at':'2026-10-01T00:00:00Z','x-fad-proxy-scope':'euvd-search-record; relationships-incomplete'};res.writeHead(200,headers);res.end(JSON.stringify(q.type==='vulnerability'?{id:'EUVD-2020-1',aliases:id,description:'Mirror record',dateUpdated:'2021-01-01'}:{items:[{cve:id,id:'EUVD-2020-1'}]}));});});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin=`http://127.0.0.1:${server.address().port}`;
 t.after(async()=>{providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null,store:null,hostedStore:null});await new Promise(resolve=>server.close(resolve));require('../lib/cache/db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 providers.configureResourceRoute({proxyUrl:origin,hosted:true,store:null,hostedStore:null});
 const online=[{dep:{artifactTargetId:'image'},cve:{id}}];await enrichEuropeanFindings(online,{cacheDir:source,certfr:false});assert.equal(calls,2);
 await exportCache(archive,{sourceDir:source});await importCache(archive,{targetDir:target});
 const evidence=online[0].cve.euvdDetails.provenance;assert.equal(evidence.sourceScope,'euvd-search-record; relationships-incomplete');assert.equal(evidence.observedAt,'2025-01-01T00:00:00.000Z');assert.equal(evidence.checkedAt,'2026-10-01T00:00:00.000Z');
 const offline=[{dep:{artifactTargetId:'image'},cve:{id}}];await enrichEuropeanFindings(offline,{cacheDir:target,offline:true,certfr:false,fetcher:()=>{throw Error('network tripwire')}});assert.equal(calls,2);assert.deepEqual(offline[0].cve.euvdDetails.provenance,evidence);
});

test('stale mirror detail retains refresh failure as a real warning online and offline',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-euvd-failure-')),id='CVE-2020-12345';
 t.after(()=>{providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null,store:null,hostedStore:null});require('../lib/cache/db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const fetcher=async(_url,opts)=>{const q=JSON.parse(opts.body),headers={'x-fad-proxy-fetched-at':'2025-01-01T00:00:00Z'};if(q.type==='vulnerability')return Response.json({id:'EUVD-2020-1',aliases:id,description:'Cached record'},{headers:{...headers,'x-fad-proxy':'stale','x-fad-proxy-reason':'refresh-failed','x-fad-proxy-stale-reason':'upstream-http-503'}});return Response.json({items:[{cve:id,id:'EUVD-2020-1'}]},{headers});};
 providers.configureResourceRoute({proxyUrl:'https://fleet.example',hosted:true,fetcher,store:null,hostedStore:null});
 const online=[{dep:{artifactTargetId:'image'},cve:{id}}],result=await enrichEuropeanFindings(online,{cacheDir:dir,certfr:false,fetcher});const warnings=result.warnings.filter(w=>w.source==='euvd-details' && w.severity!=='info');assert.equal(warnings.length,1);assert.match(warnings[0].message,/upstream-http-503/);assert.equal(warnings[0].status,503);assert.equal(online[0].cve.euvdDetails.provenance.staleReason,'upstream-http-503');
 const offline=[{dep:{artifactTargetId:'image'},cve:{id}}],replay=await enrichEuropeanFindings(offline,{cacheDir:dir,offline:true,certfr:false,fetcher:()=>{throw Error('network')}});assert.equal(offline[0].cve.euvdDetails.provenance.staleReason,'upstream-http-503');assert.equal(replay.warnings.filter(w=>w.source==='euvd-details' && w.severity!=='info').length,1);assert.match(replay.warnings.find(w=>w.source==='euvd-details').message,/upstream-http-503/);
});
