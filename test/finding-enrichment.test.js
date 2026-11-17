'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {createCacheRepository}=require('../lib/cache-repository');const {enrichEuropeanFindings}=require('../lib/finding-enrichment');const {projectImageCves}=require('../lib/artifacts/cve-view');
function root(t){const d=fs.mkdtempSync(path.join(os.tmpdir(),'european-enrich-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(d,{recursive:true,force:true})});return d;}
test('offline caches enrich each explicit related CVE independently and project evidence',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),now=Date.now(),one='CVE-2024-12345',two='CVE-2024-56789';
 repo.put('catalogue','euvd',{_fetchedAt:now,body:{byCve:{[one]:'EUVD-2024-12'},exploited:{[one]:'2024-01-01'}}});
 repo.put('catalogue','certfr',{meta:{fetchedAt:now},entries:{'CERTFR-2024-AVI-001':{kind:'avis',title:'Example',cves:[two]}}});
 const matches=[{dep:{artifactTargetId:'a',ecosystem:'system',name:'p',version:'1'},cve:{id:'DLA-1',upstream:[one,two],related:['CVE-2024-99999']}}];
 const result=await enrichEuropeanFindings(matches,{cacheDir,offline:true,fetcher:()=>{throw Error('network tripwire')}});assert.ok(result.coverage.filter(x=>x.collector!=='euvd-details').every(x=>x.execution==='completed'));assert.equal(result.coverage.find(x=>x.collector==='euvd-details').execution,'partial');assert.equal(matches[0].cve.euvd,undefined);
 const evidence=matches[0].cve.cveEvidence;assert.deepEqual(evidence.find(e=>e.id===one).euvd,{id:'EUVD-2024-12',exploitedSince:'2024-01-01'});assert.equal(evidence.find(e=>e.id===two).certfr[0].ref,'CERTFR-2024-AVI-001');assert.equal(evidence.find(e=>e.id===one).gcveEvidence.kind,'derived-alias');assert.equal(evidence.some(e=>e.id==='CVE-2024-99999'),false);
 const rows=projectImageCves(matches);assert.equal(rows[0].cve.euvd.id,'EUVD-2024-12');assert.equal(rows[0].cve.certfr,undefined);assert.equal(rows[1].cve.certfr[0].ref,'CERTFR-2024-AVI-001');assert.equal(rows[1].cve.euvd,undefined);
});
test('missing, no-match and excluded coverage are distinct, and adapters fail independently',async t=>{
 const cacheDir=root(t),match=[{cve:{id:'CVE-2024-12345'}}];let result=await enrichEuropeanFindings(match,{cacheDir,offline:true,euvd:false});
 assert.equal(result.coverage.find(x=>x.collector==='euvd').result,'not-consulted');assert.equal(result.coverage.find(x=>x.collector==='certfr').result,'unavailable');assert.equal(result.coverage.find(x=>x.collector==='gcve').result,'derived-alias');
 assert.equal(result.warnings.find(w=>w.source==='certfr').severity,'info');
 const repo=createCacheRepository(cacheDir),now=Date.now();repo.put('catalogue','euvd',{_fetchedAt:now,body:{byCve:{},exploited:{}}});repo.put('catalogue','certfr',{meta:{fetchedAt:now},entries:{}});
 result=await enrichEuropeanFindings(match,{cacheDir,offline:true});assert.equal(result.coverage.find(x=>x.collector==='euvd').result,'no-match');assert.equal(result.coverage.find(x=>x.collector==='certfr').result,'no-match');
 let called=false;result=await enrichEuropeanFindings(match,{cacheDir,europeanAdapters:[{id:'bad',run:async()=>{throw Error('unavailable')}},{id:'good',run:async()=>{called=true;return {result:'no-match'}}}]});assert.equal(result.coverage[0].execution,'failed');assert.equal(result.coverage[1].execution,'completed');assert.ok(called);
});
test('hosted targeted records remain available in offline cache',async t=>{
 const cacheDir=root(t),providers=require('../lib/providers'),id='CVE-2024-12345',calls=[];
 const fetcher=async(url,opts)=>{const body=JSON.parse(opts.body);calls.push(body.provider);const value=body.type==='vulnerability'?{id:'EUVD-2024-1',aliases:id,baseScore:6.5,description:'EU context'}:{items:body.provider==='euvd'?[{cve:id,id:'EUVD-2024-1',exploitedSince:null}]:[{cve:id,advisories:[{ref:'CERTFR-2024-AVI-001',kind:'avis',title:'Test'}]}]};return Response.json(value,{headers:{'x-fad-proxy-fetched-at':new Date().toISOString()}})};
 providers.configureResourceRoute({proxyUrl:'https://fleet.invalid',hosted:true,fetcher,store:null,hostedStore:null});t.after(()=>providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null}));
 const online=[{cve:{id}}],offline=[{cve:{id}}];const a=await enrichEuropeanFindings(online,{cacheDir,fetcher});assert.deepEqual(calls,['euvd','euvd','certfr']);assert.ok(a.coverage.every(x=>x.execution==='completed'));
 providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});const b=await enrichEuropeanFindings(offline,{cacheDir,offline:true,fetcher:()=>{throw Error('network tripwire')}});assert.deepEqual(offline,online);assert.ok(b.coverage.every(x=>x.execution==='completed'));
});
test('stale and per-CVE unavailable states remain explicit',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),id='CVE-2024-12345',now=Date.now();
 repo.put('catalogue','euvd',{_fetchedAt:now,body:{byCve:{[id]:'EUVD-2024-12'},exploited:{}}},{stale:true});
 const matches=[{cve:{id}}],result=await enrichEuropeanFindings(matches,{cacheDir,offline:true});
 assert.equal(result.coverage.find(x=>x.collector==='euvd').execution,'partial');assert.equal(matches[0].cve.cveEvidence[0].euvdEvidence.stale,true);assert.equal(matches[0].cve.cveEvidence[0].certfrEvidence.status,'unavailable');
});
test('a broken cache does not block independent derived GCVE aliases',async t=>{
 const dir=root(t),bad=path.join(dir,'not-a-directory');fs.writeFileSync(bad,'x');const matches=[{cve:{id:'CVE-2024-12345'}}];
 const result=await enrichEuropeanFindings(matches,{cacheDir:bad,offline:true,fetcher:()=>{throw Error('network tripwire')}});
 assert.equal(matches[0].cve.gcve,'GCVE-0-2024-12345');assert.equal(result.coverage.find(c=>c.collector==='gcve').execution,'completed');assert.equal(result.coverage.find(c=>c.collector==='euvd').execution,'failed');assert.equal(result.coverage.find(c=>c.collector==='certfr').execution,'failed');
});
test('regional exclusions do not consult European sources or create derived aliases',async t=>{
 const cacheDir=root(t),matches=[{cve:{id:'CVE-2024-12345'}}];const result=await enrichEuropeanFindings(matches,{cacheDir,euvd:false,certfr:false,disableGcve:true,fetcher:()=>{throw Error('network tripwire')}});
 assert.ok(result.coverage.every(c=>c.result==='not-consulted'));assert.equal(matches[0].cve.gcve,undefined);assert.deepEqual(result.warnings,[]);assert.ok(result.coverage.every(c=>c.execution==='not-applicable' && c.expected===false));
});
test('derived GNA-0 alias never replaces original native nonzero GNA identity',async t=>{
 const cacheDir=root(t),native='GCVE-42-2024-12345',matches=[{dep:{artifactTargetId:'a',ecosystem:'system',name:'p',version:'1'},cve:{id:'CVE-2024-12345',gcve:native,gcveEvidence:{kind:'native-record'}}}];
 await enrichEuropeanFindings(matches,{cacheDir,offline:true,europeanAdapters:require('../lib/finding-enrichment').europeanAdapters.filter(a=>a.id==='gcve')});
 assert.equal(matches[0].cve.gcve,native);assert.equal(matches[0].cve.gcveEvidence.kind,'native-record');assert.equal(matches[0].cve.cveEvidence[0].gcveAlias,'GCVE-0-2024-12345');
 const projected=projectImageCves(matches)[0];assert.equal(projected.cve.gcve,native);assert.equal(projected.cve.gcveAlias,'GCVE-0-2024-12345');assert.equal(projected.cve.gcveEvidence.kind,'native-record');
});
test('ENISA metadata fills missing CVE context independently of detection and replays offline',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),id='CVE-2024-8096',now=Date.now();repo.put('catalogue','euvd',{_fetchedAt:now,body:{byCve:{[id]:'EUVD-2024-48936'},exploited:{}}});
 const fetcher=async(url)=>{assert.match(String(url),/enisaid\?id=EUVD-2024-48936/);return Response.json({id:'EUVD-2024-48936',aliases:`${id}\nGHSA-test`,baseScore:6.5,baseScoreVersion:'3.1',baseScoreVector:'CVSS:3.1/AV:N',description:'ENISA context',datePublished:'2024-09-11',references:'https://example.org/cve\njavascript:alert(1)'});};
 const make=()=>[{source:'gcve',dep:{artifactTargetId:'img',ecosystem:'system',name:'curl',version:'1'},cve:{id:'DLA-1',severity:'UNKNOWN',upstream:[id],description:'Distro advisory'}}];
 const online=make();const result=await enrichEuropeanFindings(online,{cacheDir,fetcher,certfr:false});assert.equal(online[0].source,'gcve');assert.equal(online[0].cve.id,'DLA-1');assert.equal(online[0].cve.score,6.5);assert.equal(online[0].cve.description,'Distro advisory');assert.deepEqual(online[0].cve.riskEvidence,{source:'euvd',id,relationship:'upstream'});assert.equal(result.coverage.find(x=>x.collector==='euvd-details').execution,'completed');
 const projected=projectImageCves(online)[0];assert.equal(projected.cve.id,id);assert.equal(projected.cve.score,6.5);assert.equal(projected.cve.description,'ENISA context');assert.deepEqual(projected.cve.euvdDetails.references,['https://example.org/cve']);
 const offline=make();await enrichEuropeanFindings(offline,{cacheDir,offline:true,certfr:false,fetcher:()=>{throw Error('network tripwire')}});assert.deepEqual(offline,online);
});
test('EUVD HTTP blockage is recorded per CVE and explained again offline',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),id='CVE-2024-8096';repo.put('catalogue','euvd',{_fetchedAt:Date.now(),body:{byCve:{[id]:'EUVD-2024-48936'},exploited:{}}});
 const online=[{cve:{id}}],a=await enrichEuropeanFindings(online,{cacheDir,certfr:false,fetcher:async()=>new Response('',{status:403})});
 const warning=a.warnings.find(w=>w.source==='euvd-details');assert.equal(warning.status,403);assert.notEqual(warning.severity,'info');assert.match(warning.message,/HTTP 403/);assert.deepEqual(warning.resources,['EUVD-2024-48936']);
 const saved=repo.get('catalogue','euvd-targeted').value.entries[id].detailsFailure;assert.equal(saved.status,403);assert.ok(saved.attemptedAt);
 const offline=[{cve:{id}}],b=await enrichEuropeanFindings(offline,{cacheDir,offline:true,certfr:false,fetcher:()=>{throw Error('network')}});assert.equal(b.warnings.find(w=>w.source==='euvd-details').status,403);assert.equal(offline[0].cve.cveEvidence[0].euvdDetailsEvidence.failure.status,403);
});
test('large EUVD documents fit default budget and explicit smaller budget is identified as internal',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),id='CVE-2024-8096';repo.put('catalogue','euvd',{_fetchedAt:Date.now(),body:{byCve:{[id]:'EUVD-2024-48936'},exploited:{}}});
 const fetcher=async()=>Response.json({id:'EUVD-2024-48936',aliases:id,description:'context',products:'x'.repeat(4*1024*1024)});
 const limited=await enrichEuropeanFindings([{cve:{id}}],{cacheDir,certfr:false,fetcher,maxEuvdMetadataBytes:1024});assert.equal(limited.warnings.find(w=>w.source==='euvd-details').code,'metadata-budget-exceeded');assert.match(limited.warnings.find(w=>w.source==='euvd-details').message,/scanner.*budget/);
 const matches=[{cve:{id}}],normal=await enrichEuropeanFindings(matches,{cacheDir,certfr:false,fetcher});assert.equal(normal.coverage.find(c=>c.collector==='euvd-details').execution,'completed');assert.equal(matches[0].cve.euvdDetails.description,'context');
});
test('ENISA details remain independent with NVD present and invalid identity is rejected',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),id='CVE-2024-12345';repo.put('catalogue','euvd',{_fetchedAt:Date.now(),body:{byCve:{[id]:'EUVD-2024-1'},exploited:{}}});let calls=0;
 const match={source:'gcve+nvd',cve:{id,severity:'HIGH',score:8.1,description:'NVD',nvdEvidence:{records:[{id,score:8.1,severity:'HIGH',description:'NVD',cvssVector:'vector'}]}}};
 const fetcher=async()=>{calls++;return Response.json({id:'EUVD-2024-1',aliases:id,baseScore:4.2,description:'ENISA'});};await enrichEuropeanFindings([match],{cacheDir,fetcher,certfr:false});assert.equal(calls,1);assert.equal(match.cve.score,8.1);assert.equal(match.cve.description,'NVD');assert.equal(match.cve.euvdDetails.score,4.2);
 const otherCache=root(t),otherRepo=createCacheRepository(otherCache);otherRepo.put('catalogue','euvd',{_fetchedAt:Date.now(),body:{byCve:{[id]:'EUVD-2024-1'},exploited:{}}});
 const bad={cve:{id,severity:'UNKNOWN'}};const r=await enrichEuropeanFindings([bad],{cacheDir:otherCache,certfr:false,fetcher:async()=>Response.json({id:'EUVD-2024-1',aliases:'CVE-2024-99999',baseScore:9.8})});assert.equal(bad.cve.score,undefined);assert.equal(r.coverage.find(x=>x.collector==='euvd-details').execution,'partial');
});
test('EUVD detail keeps exploited evidence, refreshes on origin change and then reuses that origin cache',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),now=Date.now(),id='CVE-2024-12345',providers=require('../lib/providers');repo.put('catalogue','euvd',{_fetchedAt:now,body:{byCve:{[id]:'EUVD-2024-1'},exploited:{[id]:'2024-02-01'}}});
 let detailCalls=0;const direct=async()=>{detailCalls++;return Response.json({id:'EUVD-2024-1',aliases:id,baseScore:6.5,description:'EU detail',datePublished:'Oct 2, 2026, 12:00:00 AM'});};
 const first=[{cve:{id}}];await enrichEuropeanFindings(first,{cacheDir,fetcher:direct,certfr:false});assert.equal(first[0].cve.euvdDetails.published,'2026-10-02T00:00:00');assert.equal(first[0].cve.euvd.exploitedSince,'2024-02-01');
 const offline=[{cve:{id}}];await enrichEuropeanFindings(offline,{cacheDir,offline:true,certfr:false,fetcher:()=>{throw Error('network')}});assert.equal(offline[0].cve.euvd.exploitedSince,'2024-02-01');assert.equal(offline[0].cve.euvdDetails.score,6.5);
 const hosted=async(url,opts)=>{const req=JSON.parse(opts.body);if(req.type==='vulnerability'){detailCalls++;return Response.json({id:'EUVD-2024-1',aliases:id,baseScore:6.5,description:'Hosted EU detail'},{headers:{'x-fad-proxy-fetched-at':new Date(now).toISOString()}});}return Response.json({items:[{cve:id,id:'EUVD-2024-1',exploitedSince:'2024-02-01'}]},{headers:{'x-fad-proxy-fetched-at':new Date(now).toISOString()}});};
 providers.configureResourceRoute({proxyUrl:'https://fleet.invalid',hosted:true,fetcher:hosted,store:null,hostedStore:null});t.after(()=>providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null}));
 const again=[{cve:{id}}];await enrichEuropeanFindings(again,{cacheDir,fetcher:hosted,certfr:false});assert.equal(detailCalls,2);assert.equal(again[0].cve.euvdDetails.description,'Hosted EU detail');assert.equal(again[0].cve.euvd.exploitedSince,'2024-02-01');
 const cached=[{cve:{id}}];await enrichEuropeanFindings(cached,{cacheDir,fetcher:hosted,certfr:false});assert.equal(detailCalls,2);assert.equal(cached[0].cve.euvdDetails.description,'Hosted EU detail');
});
test('self-hosted proxy stale metadata is not stamped as freshly fetched',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),id='CVE-2024-12345',providers=require('../lib/providers'),old=Date.now()-6*3600*1000;repo.put('catalogue','euvd',{_fetchedAt:Date.now(),body:{byCve:{[id]:'EUVD-2024-1'},exploited:{}}});
 const fetcher=async()=>Response.json({id:'EUVD-2024-1',aliases:id,baseScore:5.0},{headers:{'x-fad-proxy':'stale','x-fad-proxy-fetched-at':new Date(old).toISOString()}});
 providers.configureResourceRoute({proxyUrl:'https://fleet.invalid',hosted:false,fetcher,store:null});t.after(()=>providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null}));
 const result=await enrichEuropeanFindings([{cve:{id}}],{cacheDir,fetcher,certfr:false});assert.equal(result.coverage.find(x=>x.collector==='euvd-details').execution,'partial');const item=repo.get('catalogue','euvd-targeted').value.entries[id];assert.equal(item.detailsFetchedAt,old);assert.equal(item.detailsStale,true);
});
test('EUVD evidence never mixes its vector or severity with a different existing score',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),id='CVE-2024-12345';repo.put('catalogue','euvd',{_fetchedAt:Date.now(),body:{byCve:{[id]:'EUVD-2024-1'},exploited:{}}});
 const fetcher=async()=>Response.json({id:'EUVD-2024-1',aliases:id,baseScore:6.5,baseScoreVersion:'3.1',baseScoreVector:'CVSS:3.1/AV:N',description:'ENISA'});
 const match={dep:{artifactTargetId:'img',ecosystem:'system',name:'p',version:'1'},source:'osv',cve:{id,score:9,severity:'UNKNOWN'}};
 await enrichEuropeanFindings([match],{cacheDir,fetcher,certfr:false});assert.equal(match.cve.score,9);assert.equal(match.cve.severity,'UNKNOWN');assert.equal(match.cve.cvssVector,undefined);assert.equal(match.cve.euvdDetails.score,6.5);
 const projected=projectImageCves([match])[0];assert.equal(projected.cve.score,9);assert.equal(projected.cve.severity,'UNKNOWN');assert.equal(projected.cve.cvssVector,undefined);assert.equal(projected.cve.euvdDetails.score,6.5);
});
test('partial NVD score is never paired with EUVD vector or severity',()=>{
 const id='CVE-2024-12345',match={dep:{artifactTargetId:'img',ecosystem:'system',name:'p',version:'1'},cve:{id:'DLA-1',upstream:[id],severity:'UNKNOWN',nvdEvidence:{records:[{id,score:8.1,severity:'UNKNOWN'}]},cveEvidence:[{id,euvdDetails:{id:'EUVD-2024-1',source:'euvd',score:6.5,severity:'MEDIUM',cvssVector:'EU-VECTOR'}}]}};
 const projected=projectImageCves([match])[0];assert.equal(projected.cve.score,8.1);assert.equal(projected.cve.severity,'UNKNOWN');assert.equal(projected.cve.cvssVector,undefined);assert.equal(projected.cve.euvdDetails.cvssVector,'EU-VECTOR');
});
test('EUVD detail operation accepts only validated IDs and fixed official endpoint',()=>{
 const {validateResource}=require('../lib/resource-cache/validate'),provider=require('../lib/providers/euvd');
 const request=validateResource({provider:'euvd',type:'vulnerability',params:{id:'EUVD-2024-48936'}});assert.equal(provider.build(request.type,request.params).url,'https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2024-48936');
 for(const id of ['https://evil.test/','EUVD-2024-1&url=https://evil.test','../../x']){assert.throws(()=>validateResource({provider:'euvd',type:'vulnerability',params:{id}}));assert.throws(()=>provider.build('vulnerability',{id}));}
});
test('legacy EUVD cached timestamps are normalized without inventing a timezone',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),id='CVE-2022-1304',now=Date.now(),original='Apr 14, 2022, 8:05:47 PM';
 repo.put('catalogue','euvd-targeted',{entries:{[id]:{item:{id:'EUVD-2022-1',exploitedSince:null},fetchedAt:now,stale:false,details:{id:'EUVD-2022-1',source:'euvd',score:6.5,severity:'MEDIUM',published:original,modified:'Oct 14, 2026, 12:39:25 PM'},detailsFetchedAt:now,detailsStale:false}}});
 const matches=[{dep:{artifactTargetId:'img',ecosystem:'system',name:'p',version:'1'},cve:{id}}];await enrichEuropeanFindings(matches,{cacheDir,offline:true,certfr:false,fetcher:()=>{throw Error('network')}});
 assert.equal(matches[0].cve.euvdDetails.published,'2022-04-14T20:05:47');assert.equal(matches[0].cve.euvdDetails.publishedOriginal,original);
 const projected=projectImageCves(matches)[0];assert.equal(projected.cve.euvdDetails.modified,'2026-10-14T12:39:25');
 const html=require('../lib/artifacts/risk-report').renderEuvdEvidence(projected.cve,'en');assert.match(html,/<time datetime="2022-04-14T20:05:47">/);assert.match(html,/<time datetime="2026-10-14T12:39:25">/);assert.doesNotMatch(html,/2022-04-14T20:05:47Z/);
});
test('ENISA timestamp normalization retains floating time and validates the calendar',()=>{
 const {normalizeEuvdCalendarDate}=require('../lib/euvd');assert.equal(normalizeEuvdCalendarDate('Oct 2, 2026, 12:00:00 AM'),'2026-10-02T00:00:00');assert.equal(normalizeEuvdCalendarDate('Oct 2, 2026, 12:00:00 PM'),'2026-10-02T12:00:00');
 assert.equal(normalizeEuvdCalendarDate('Feb 30, 2026, 8:05:47 PM'),null);assert.equal(normalizeEuvdCalendarDate('Oct 2, 2026, 25:05:47 PM'),null);assert.equal(normalizeEuvdCalendarDate('2026-10-02T08:15:00+02:00'),'2026-10-02T08:15:00+02:00');
});
test('ordinary offline cache age alone does not produce false stale warnings',async t=>{
 const cacheDir=root(t),repo=createCacheRepository(cacheDir),old=Date.now()-30*24*3600*1000,id='CVE-2024-12345';
 repo.put('catalogue','euvd',{_fetchedAt:old,body:{byCve:{},exploited:{}}});repo.put('catalogue','certfr',{meta:{fetchedAt:old},entries:{}});
 const result=await enrichEuropeanFindings([{cve:{id}}],{cacheDir,offline:true,fetcher:()=>{throw Error('network tripwire')}});assert.deepEqual(result.warnings,[]);assert.ok(result.coverage.every(c=>['completed','not-applicable'].includes(c.execution)));
});

test('resource-specific health deduplication retains other endpoint outages and EUVD mapping coverage',async t=>{
 const cacheDir=root(t),providers=require('../lib/providers'),health=require('../lib/source-health').createSourceHealth(),id='CVE-2024-12345',euvd='EUVD-2024-123';
 createCacheRepository(cacheDir).put('catalogue','euvd',{_fetchedAt:Date.now(),body:{byCve:{[id]:euvd},exploited:{}}});
 const fetcher=async()=>new Response('',{status:503,headers:{'x-fad-proxy':'denied'}});
 providers.configureResourceRoute({proxyUrl:'https://fleet.invalid',hosted:false,fetcher,health,store:null,hostedStore:null,proxyRateLimitMaxRetries:0,resetRateLimit:true,sleep:async()=>{}});
 t.after(()=>providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null,health:null,proxyRateLimitMaxRetries:null,resetRateLimit:true,sleep:undefined}));
 const result=await enrichEuropeanFindings([{cve:{id}}],{cacheDir,certfr:false,disableGcve:true,fetcher});
 assert.equal(result.coverage.find(c=>c.collector==='euvd').execution,'completed','mapping remains complete');
 assert.equal(result.coverage.find(c=>c.collector==='euvd-details').execution,'partial');
 const keys=result.warnings.flatMap(w=>w.requestKeys||[]);assert.equal(keys.length,1);
 assert.equal(health.degraded().length,1);assert.equal(health.unreportedOutages(keys).length,0,'same request is already explained by detail warning');
 health.markOutage('euvd',{url:'https://euvdservices.enisa.europa.eu/api/search',code:'HTTP 503',requestKey:require('../lib/providers/common').failureKey('euvd','exploited',{page:0})});
 assert.equal(health.unreportedOutages(keys).length,1,'different endpoint remains a global alert');
});
