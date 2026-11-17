const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const {createCacheRepository}=require('../lib/cache-repository');const {enrichArtifactFindings}=require('../lib/artifacts/enrichment');const {evaluateGate}=require('../lib/gate');const {buildInventory}=require('../lib/unmanaged');
test('cached KEV and EPSS enrich artifact findings offline, including CVE aliases',async()=>{const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-enrich-'));try{const repo=createCacheRepository(cacheDir),now=Date.now();repo.put('catalogue','kev',{_fetchedAt:now,body:{byId:{'CVE-2024-12345':{dateAdded:'2024-01-01',dueDate:'2024-01-20',ransomware:true}}}});repo.put('catalogue','epss',{meta:{fetchedAt:now},entries:{'CVE-2024-10000':{score:.1,percentile:.5},'CVE-2024-12345':{score:.5,percentile:.9}}});const matches=[{dep:{name:'demo'},cve:{id:'GHSA-abcd-efgh-ijkl',aliases:['CVE-2024-10000','CVE-2024-12345'],severity:'HIGH'}}];const res=await enrichArtifactFindings(matches,{offline:true,cacheDir,enrich:['kev','epss'],fetcher:()=>{throw Error('network')}});assert(matches[0].cve.kev);assert.equal(matches[0].cve.epssScore,.5);assert(evaluateGate(matches,'kev').failed);assert(res.coverage.every(c=>c.execution==='completed'));assert.equal(matches[0].cve.id,'GHSA-abcd-efgh-ijkl');}finally{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})}});
test('missing KEV cache remains indeterminate and OS-owned binary is not unmanaged',async()=>{const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-enrich-'));try{const m=[{cve:{id:'CVE-2024-99999'}}];const r=await enrichArtifactFindings(m,{offline:true,cacheDir,enrich:['kev'],fetcher:()=>{throw Error('network')}});assert.equal(r.coverage[0].execution,'partial');assert.equal(m[0].cve.kev,undefined);assert.equal(buildInventory(new Map([['x',{provenance:'binary',artifactTargetId:'image',osPackageOwners:[{name:'pkg'}],hashes:{sha256:'abc'}}]])).length,0)}finally{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})}});
test('explicit upstream CVEs enrich without promoting relationships or guessing identifiers',async()=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-upstream-'));
 try {
  const repo=createCacheRepository(cacheDir),now=Date.now();
  repo.put('catalogue','kev',{_fetchedAt:now,body:{byId:{'CVE-2024-56789':{dateAdded:'2024-01-01',dueDate:'2024-01-20',ransomware:false}}}});
  repo.put('catalogue','epss',{meta:{fetchedAt:now},entries:{'CVE-2024-12345':{score:.1,percentile:.4},'CVE-2024-56789':{score:.7,percentile:.99}}});
  const matches=[{dep:{name:'pkg'},cve:{id:'DEBIAN-CVE-2024-12345',aliases:[],upstream:['CVE-2024-12345','CVE-2024-56789','GHSA-not-cve'],severity:'HIGH'}}];
  const result=await enrichArtifactFindings(matches,{cacheDir,offline:true,enrich:['kev','epss'],fetcher:()=>{throw Error('network')}});
  assert.equal(matches[0].cve.id,'DEBIAN-CVE-2024-12345');assert.deepEqual(matches[0].cve.aliases,[]);assert.equal(matches[0].cve.kev,true);assert.equal(matches[0].cve.epssScore,.7);assert.deepEqual(matches[0].cve.kevEvidence,{source:'kev',id:'CVE-2024-56789',relationship:'upstream'});assert.deepEqual(matches[0].cve.epssEvidence,{source:'epss',id:'CVE-2024-56789',relationship:'upstream'});assert.equal(result.coverage[1].execution,'completed');
  const guessed=[{cve:{id:'DEBIAN-CVE-2024-56789',aliases:[],upstream:[]}}];const unknown=await enrichArtifactFindings(guessed,{cacheDir,offline:true,enrich:['kev']});assert.equal(guessed[0].cve.kev,undefined);assert.equal(unknown.coverage[0].execution,'not-applicable');assert.deepEqual(unknown.warnings,[]);
 } finally {require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})}
});
test('NVD evidence tracks every explicit upstream CVE separately',async()=>{
 const nvd=require('../lib/nvd'),original=nvd.enrichMatches;
 try {nvd.enrichMatches=async copies=>{for(const x of copies){x.source='osv+nvd';x.cve.cwes=[x.cve.id];}};
 const match={source:'osv',cve:{id:'DIST-1',upstream:['CVE-2024-12345','CVE-2024-56789']}};
 const result=await enrichArtifactFindings([match],{offline:true,enrich:['nvd']});assert.equal(result.coverage[0].execution,'completed');assert.deepEqual(match.cve.nvdEvidence.records.map(x=>x.id),['CVE-2024-12345','CVE-2024-56789']);
 }finally{nvd.enrichMatches=original;}
});
test('source profiles cannot invoke disabled enrichment adapters',async()=>{
 const {enrichArtifactFindings}=require('../lib/artifacts/enrichment');let invoked=false;
 const result=await enrichArtifactFindings([{cve:{id:'CVE-2024-12345'}}],{enrich:['kev'],kev:false,enrichmentAdapters:[{id:'kev',run:async()=>{invoked=true;return {complete:true};}}]});
 assert.equal(invoked,false);assert.equal(result.coverage[0].execution,'not-applicable');assert.equal(result.coverage[0].expected,false);assert.deepEqual(result.warnings,[]);
});
test('default NVD enrichment preserves distro verdict and replays identically offline through direct and proxy sources',async()=>{
 const providers=require('../lib/providers'),now=Date.now(),id='CVE-2024-8096';
 const raw={id,descriptions:[{lang:'en',value:'NVD description'}],metrics:{cvssMetricV31:[{cvssData:{baseScore:9.1,baseSeverity:'CRITICAL',vectorString:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}}]},references:[{url:'https://example.test/advisory'}],weaknesses:[{description:[{lang:'en',value:'CWE-79'}]}],published:'2024-01-01T00:00:00.000Z'};
 for(const proxy of [false,true]){
  const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-nvd-route-')),calls=[];
  try{
   const repo=createCacheRepository(cacheDir);repo.put('catalogue','euvd',{_fetchedAt:now,body:{byCve:{},exploited:{}}});repo.put('catalogue','certfr',{meta:{fetchedAt:now},entries:{}});repo.put('catalogue','kev',{_fetchedAt:now,body:{byId:{}}});repo.put('catalogue','epss',{meta:{fetchedAt:now},entries:{[id]:{score:.1,percentile:.5}}});
   const fetcher=async(url,opts={})=>{calls.push(String(url));if(proxy){const request=JSON.parse(opts.body);assert.equal(request.provider,'nvd');assert.ok(['cve','cve-mirror'].includes(request.type));return new Response(JSON.stringify(raw),{headers:{'content-type':'application/json','x-fad-proxy-fetched-at':new Date().toISOString()}});}assert.match(String(url),/githubusercontent|nvd/);return new Response(JSON.stringify(raw),{headers:{'content-type':'application/json'}});};
   providers.configureResourceRoute({proxyUrl:proxy?'https://fleet.test':null,hosted:false,store:null,hostedStore:null,fetcher});
   const make=()=>[{source:'osv',dep:{name:'curl'},cve:{id:'DLA-3951-1',upstream:[id],severity:'UNKNOWN',score:null,fixVersion:'7.74.0-1.3+deb11u14'}}];
   const online=make(),onlineResult=await enrichArtifactFindings(online,{cacheDir,fetcher});assert.equal(online[0].cve.id,'DLA-3951-1');assert.equal(online[0].source,'nvd+osv');assert.equal(online[0].cve.severity,'CRITICAL');assert.equal(online[0].cve.score,9.1);assert.equal(online[0].cve.fixVersion,'7.74.0-1.3+deb11u14');assert.deepEqual(online[0].cve.riskEvidence,{source:'nvd',id,relationship:'upstream'});assert.equal(online[0].cve.nvdEvidence.records[0].relationship,'upstream');assert.ok(onlineResult.coverage.every(c=>['completed','not-applicable'].includes(c.execution)));assert.ok(calls.length>0);if(proxy)assert.ok(calls.every(x=>x.startsWith('https://fleet.test/')));
   providers.configureResourceRoute({proxyUrl:null,fetcher:null});const offline=make();await enrichArtifactFindings(offline,{cacheDir,offline:true,fetcher:()=>{throw Error('network tripwire')}});assert.deepEqual(offline,online);
  }finally{providers.configureResourceRoute({proxyUrl:null,fetcher:null,store:null,hostedStore:null});require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true});}
 }
});
test('multiple upstream CVEs retain independent NVD metadata without an aggregate severity',async()=>{
 const nvd=require('../lib/nvd'),original=nvd.enrichMatches;
 try {nvd.enrichMatches=async copies=>{for(const [i,x] of copies.entries()){x.source='osv+nvd';Object.assign(x.cve,{severity:i?'LOW':'CRITICAL',score:i?2.1:9.1,cvssVector:`vector-${i}`});}};
  const match={source:'osv',cve:{id:'DLA-1',severity:'UNKNOWN',upstream:['CVE-2024-12345','CVE-2024-56789']}};
  await enrichArtifactFindings([match],{enrich:['nvd'],offline:true});assert.equal(match.cve.severity,'UNKNOWN');assert.equal(match.cve.score,undefined);assert.equal(match.cve.riskEvidence,undefined);assert.deepEqual(match.cve.nvdEvidence.records.map(x=>[x.id,x.score,x.relationship]),[['CVE-2024-12345',9.1,'upstream'],['CVE-2024-56789',2.1,'upstream']]);
 } finally {nvd.enrichMatches=original;}
});
test('per-CVE KEV and EPSS observations never bleed across projected advisory CVEs',async()=>{
 const {projectImageCves}=require('../lib/artifacts/cve-view'),cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-metric-cves-'));
 try {const repo=createCacheRepository(cacheDir),now=Date.now(),one='CVE-2024-12345',two='CVE-2024-56789';repo.put('catalogue','kev',{_fetchedAt:now,body:{byId:{[one]:{dateAdded:'2024-01-01'}}}});repo.put('catalogue','epss',{meta:{fetchedAt:now},entries:{[one]:{score:.1,percentile:.2},[two]:{score:.8,percentile:.9}}});
  const matches=[{dep:{artifactTargetId:'a',ecosystem:'system',manager:'dpkg',name:'p',version:'1'},cve:{id:'DLA-1',upstream:[one,two],severity:'UNKNOWN'}}];
  await enrichArtifactFindings(matches,{offline:true,cacheDir,enrich:['kev','epss'],fetcher:()=>{throw Error('network')}});const rows=projectImageCves(matches);
  assert.equal(rows[0].cve.kev,true);assert.equal(rows[0].cve.epssScore,.1);assert.equal(rows[1].cve.kev,undefined);assert.equal(rows[1].cve.epssScore,.8);
 } finally {require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})}
});
test('non-CVE notices are inapplicable, not source failures, alongside eligible CVEs',async()=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-eligible-'));try{
  const now=Date.now(),repo=createCacheRepository(cacheDir),id='CVE-2024-12345';repo.put('catalogue','kev',{_fetchedAt:now,body:{byId:{}}});repo.put('catalogue','epss',{meta:{fetchedAt:now},entries:{[id]:{score:null,percentile:null}}});require('../lib/nvd').writeCache(id,{severity:'MEDIUM',score:5},now,cacheDir);
  const matches=[{cve:{id:'DLA-1'}},{cve:{id, severity:'UNKNOWN'}}];const r=await enrichArtifactFindings(matches,{cacheDir,offline:true,enrich:['nvd','kev','epss'],fetcher:()=>{throw Error('network')}});assert.deepEqual(r.warnings,[]);assert.ok(r.coverage.every(c=>c.execution==='completed'));assert.equal(matches[1].cve.score,5);
  const only=await enrichArtifactFindings([{cve:{id:'DLA-2'}}],{cacheDir,offline:true,enrich:['nvd','kev','epss'],fetcher:()=>{throw Error('network')}});assert.ok(only.coverage.every(c=>c.execution==='not-applicable'));assert.deepEqual(only.warnings,[]);
  const missing=await enrichArtifactFindings([{cve:{id:'CVE-2024-99999'}}],{cacheDir,offline:true,enrich:['nvd','epss']});assert.ok(missing.coverage.every(c=>c.execution==='partial'));assert.equal(missing.warnings.length,2);
 }finally{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})}
});
test('hosted targeted KEV stores positive and negative observations for offline replay',async()=>{
 const providers=require('../lib/providers'),cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-kev-target-')),one='CVE-2024-12345',two='CVE-2024-56789';let calls=0;
 try{
  const fetcher=async(url,opts)=>{calls++;const body=JSON.parse(opts.body);assert.equal(body.provider,'kev');assert.equal(body.type,'cves');return Response.json({items:[{cve:one,kev:{dateAdded:'2024-01-01',dueDate:'2024-02-01',ransomware:true}},{cve:two,kev:null}]},{headers:{'x-fad-proxy-fetched-at':new Date().toISOString()}});};
  providers.configureResourceRoute({proxyUrl:'https://fleet.invalid',hosted:true,fetcher,store:null,hostedStore:null});const make=()=>[{cve:{id:one}},{cve:{id:two}}],online=make();
  const result=await enrichArtifactFindings(online,{cacheDir,fetcher,enrich:['kev']});assert.equal(result.coverage[0].execution,'completed');assert.deepEqual(result.warnings,[]);assert.equal(online[0].cve.kev,true);assert.equal(online[1].cve.kev,undefined);assert.equal(calls,1);
  providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});const offline=make();const replay=await enrichArtifactFindings(offline,{cacheDir,offline:true,enrich:['kev'],fetcher:()=>{throw Error('network tripwire')}});assert.deepEqual(offline,online);assert.equal(replay.coverage[0].execution,'completed');assert.deepEqual(replay.warnings,[]);
 }finally{providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null,store:null,hostedStore:null});require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true});}
});
test('hosted KEV request failure and truly absent cache remain incomplete',async()=>{
 const providers=require('../lib/providers'),cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-kev-fail-'));
 try{const fetcher=async()=>new Response('unavailable',{status:503});providers.configureResourceRoute({proxyUrl:'https://fleet.invalid',hosted:true,fetcher,store:null,hostedStore:null});
  const result=await enrichArtifactFindings([{cve:{id:'CVE-2024-12345'}}],{cacheDir,fetcher,enrich:['kev']});assert.equal(result.coverage[0].execution,'partial');assert.match(result.warnings[0].message,/KEV/);
  providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null});const offline=await enrichArtifactFindings([{cve:{id:'CVE-2024-12345'}}],{cacheDir,offline:true,enrich:['kev'],fetcher:()=>{throw Error('network')}});assert.equal(offline.coverage[0].execution,'partial');assert.equal(offline.warnings.length,1);
 }finally{providers.configureResourceRoute({proxyUrl:null,hosted:false,fetcher:null,store:null,hostedStore:null});require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true});}
});
test('NVD confirmed absence is scoped and replayed offline; failed and missing lookups remain incomplete',async()=>{
 const nvd=require('../lib/nvd'),providers=require('../lib/providers'),original=providers.getResource;
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-nvd-absence-')),other=fs.mkdtempSync(path.join(os.tmpdir(),'artifact-nvd-other-')),id='CVE-2024-12345';
 try{
  providers.getResource=async()=>new Response('',{status:404});
  const run=opts=>enrichArtifactFindings([{cve:{id}}],{cacheDir,enrich:['nvd'],mirror:false,...opts});
  const online=await run({});assert.equal(online.coverage[0].execution,'completed');assert.equal(online.coverage[0].result,'no-match');assert.deepEqual(online.warnings,[]);
  const offline=await run({offline:true,fetcher:()=>{throw Error('network')}});assert.equal(offline.coverage[0].result,'no-match');assert.deepEqual(offline.warnings,[]);
  assert.equal(nvd.hasCachedAbsence(id,{cacheDir:other,offline:true}),false);
  providers.getResource=async()=>new Response('',{status:403});
  const failed=await run({});assert.equal(failed.coverage[0].execution,'partial');assert.equal(failed.warnings.length,1);
  const missing=await run({cacheDir:other,offline:true});assert.equal(missing.coverage[0].execution,'partial');assert.equal(missing.warnings.length,1);
 }finally{providers.getResource=original;require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true});fs.rmSync(other,{recursive:true,force:true});}
});
