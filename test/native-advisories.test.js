'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {openAdvisoryStore: openFixtureStore}=require('../lib/advisory-store');
const fixtureStores = new Set();
function openAdvisoryStore(options) {
 const store = openFixtureStore(options), close = store.close.bind(store);
 fixtureStores.add(store);
 store.close = () => { fixtureStores.delete(store); close(); };
 return store;
}
function removeFixture(root) {
 for (const store of fixtureStores) {
  const relative = path.relative(root, store.db.file);
  if (relative && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative)) store.close();
 }
 require('../lib/cache-db').closeCacheDbs();
 fs.rmSync(root, {recursive:true,force:true});
}

const {importCveDirectory,importGcveIndex,matchCveStore,matchGcveStore}=require('../lib/native-advisories');
const {buildGcveIndex}=require('../lib/gcve-index');
const {newIndex,addToIndex,extractMavenRelevantCve}=require('../lib/cve-download');
const {makeDepRecord}=require('../lib/dep-record');
function seedCveIndex(cache,index){
 const db=require('../lib/cache-db').getCacheDb(cache),crypto=require('node:crypto');
 index.meta.builtAt ||= new Date().toISOString();
 const put=db.prepare('INSERT INTO cve_lookup(kind,lookup_key,source,cve,affected_key,projection_json) VALUES (?,?,?,?,?,?)');
 for(const [kind,buckets] of [['package',index.byPackageName],['product',index.byProduct]])for(const [lookup,entries] of Object.entries(buckets))for(const entry of entries){
  const json=JSON.stringify(entry);put.run(kind,lookup,entry.source||'CVEProject',entry.id,crypto.createHash('sha256').update(json).digest('hex'),json);
 }
 db.prepare('INSERT INTO cache_snapshots(namespace,fetched_at,complete,stale,record_count,metadata_json) VALUES (?,?,?,?,?,?)').run(
  'cve_lookup',Date.parse(index.meta.builtAt),1,0,index.meta.cveCount||0,JSON.stringify(index.meta));
}

test('CVE native ingestion keeps raw data, native rejection beats legacy, coverage stays partial',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-native-cve-'));t.after(()=>removeFixture(root));
 const dir=path.join(root,'records');fs.mkdirSync(dir);const store=openAdvisoryStore({cacheDir:root});
 const raw=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/cve-samples/cve-with-packagename.json'),'utf8'));raw.cveMetadata.state='PUBLISHED';raw.cveMetadata.dateUpdated='2025-01-01T00:00:00Z';
 fs.writeFileSync(path.join(dir,raw.cveMetadata.cveId+'.json'),JSON.stringify(raw));
 await importCveDirectory(store,dir);
 assert.deepEqual(store.getRecord('cveproject',raw.cveMetadata.cveId).document,raw);
 assert.equal(store.getSourceCoverage('cveproject','*').complete,false);
 const dep=makeDepRecord({ecosystem:'maven',namespace:'org.apache.logging.log4j',name:'log4j-core',version:'2.14.1'});
 const deps=new Map([[dep.coordKey,dep]]),legacy=newIndex();addToIndex(legacy,extractMavenRelevantCve(raw));
 assert.equal(matchCveStore(deps,store,legacy).matches.length,1);
 const rejected={cveMetadata:{cveId:raw.cveMetadata.cveId,state:'REJECTED',dateUpdated:'2026-01-01T00:00:00Z'},containers:{cna:{rejectedReasons:[{lang:'en',value:'rejected'}]}}};
 fs.writeFileSync(path.join(dir,raw.cveMetadata.cveId+'.json'),JSON.stringify(rejected));await importCveDirectory(store,dir);
 assert.equal(matchCveStore(deps,store,legacy).matches.length,0);
});

test('GCVE stores independent native IDs, GNA provenance and rejection state',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-native-gcve-'));t.after(()=>removeFixture(root));
 const store=openAdvisoryStore({cacheDir:root});const at=new Date(Date.now()-2000).toISOString();
 const raw={cveMetadata:{vulnId:'GCVE-1-example',state:'PUBLISHED',dateUpdated:'2025-01-01T00:00:00Z'},containers:{cna:{affected:[{packageName:'com.example:lib',collectionURL:'https://repo.maven.apache.org/maven2',versions:[{version:'1.0',status:'affected'}]}],x_gcve:[{vulnId:'GCVE-1-example',recordType:'advisory'}]}}};
 const source={gna:1,sourceUrl:'https://example.org/gna-1.ndjson',collectedAt:at,complete:true,records:[raw]};
 const index=buildGcveIndex([source]);index.directory={verified:true,notCollected:1};await importGcveIndex(store,index);
 const stored=store.getRecord('gcve','GCVE-1-example');assert.deepEqual(stored.document,raw);assert.equal(stored.provenance.gna,1);
 assert.equal(store.getPackageRecords('Maven','com.example:lib',{source:'gcve'}).length,1);
 assert.equal(store.getSourceCoverage('gcve','*').complete,false);
 const dep=makeDepRecord({ecosystem:'maven',namespace:'com.example',name:'lib',version:'1.0'}), deps=new Map([[dep.coordKey,dep]]);
 assert.equal(matchGcveStore(deps,store,index).matches.length,1);
 const rejected=structuredClone(raw);rejected.cveMetadata.state='REJECTED';rejected.cveMetadata.dateUpdated='2026-01-01T00:00:00Z';
 const later=buildGcveIndex([{...source,records:[rejected]}]);later.directory={verified:true,notCollected:1};await importGcveIndex(store,later);
 assert.equal(store.getRecord('gcve','GCVE-1-example').document.cveMetadata.state,'REJECTED');
 assert.equal(store.getPackageRecords('Maven','com.example:lib',{source:'gcve'}).length,0);
 assert.equal(matchGcveStore(deps,store,index).matches.length,0);
});

test('native product-only CVE remains uncertain without a package binding',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cve-product-'));t.after(()=>removeFixture(root));
 const dir=path.join(root,'records');fs.mkdirSync(dir);const store=openAdvisoryStore({cacheDir:root});
 const raw={cveMetadata:{cveId:'CVE-2024-43210',state:'PUBLISHED',dateUpdated:'2025-01-01T00:00:00Z'},containers:{cna:{affected:[{vendor:'example',product:'unusual-product',versions:[{version:'1.0',lessThan:'2.0',versionType:'maven',status:'affected'}]}]}}};
 fs.writeFileSync(path.join(dir,'CVE-2024-43210.json'),JSON.stringify(raw));await importCveDirectory(store,dir);
 const dep=makeDepRecord({ecosystem:'maven',namespace:'org.example',name:'unusual-product',version:'1.5'});
 const deps=new Map([[dep.coordKey,dep]]),legacy=newIndex();addToIndex(legacy,extractMavenRelevantCve(raw));
 assert.equal(store.getPackageRecords('Maven','org.example:unusual-product',{source:'cveproject'}).length,0);
 const result=matchCveStore(deps,store,legacy);
 assert.equal(result.matches.length,0);assert.equal(result.identityUncertain,true);
 assert.equal(matchCveStore(deps,store,null).matches.length,0);
});

test('offline CLI reads GCVE from journal without a legacy GCVE index',async t=>{
 const {spawnSync}=require('node:child_process');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-gcve-journal-cli-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),src=path.join(root,'src'),out=path.join(root,'out');fs.mkdirSync(home);fs.mkdirSync(src);
 fs.writeFileSync(path.join(src,'package.json'),JSON.stringify({name:'app',version:'1.0.0',dependencies:{'gcve-test':'1.0.0'}}));
 const store=openAdvisoryStore({cacheDir:path.join(home,'.vigie-vuln')});
 const raw={cveMetadata:{vulnId:'GCVE-1-test-cli',state:'PUBLISHED',dateUpdated:'2026-01-01T00:00:00Z'},containers:{cna:{affected:[{packageURL:'pkg:npm/gcve-test',versions:[{version:'1.0.0',status:'affected'}]}],x_gcve:[{vulnId:'GCVE-1-test-cli',recordType:'advisory'}]}}};
 const index=buildGcveIndex([{gna:1,sourceUrl:'https://example.org/feed',collectedAt:new Date().toISOString(),complete:true,records:[raw]}]);index.directory={verified:true,notCollected:0};
 await importGcveIndex(store,index);
 assert.equal(store.getSourceCoverage('gcve','*').complete,false);
 const args=[path.join(__dirname,'../vigievuln.js'),'-s',src,'--ecosystem','npm','--offline','-d','osv,nvd,eol,epss,kev,euvd,certfr,retire,transitive,all-libs','--no-binaries','--no-certs','--report-json','-o',out];
 const run=spawnSync(process.execPath,args,{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home,FORCE_COLOR:'0'},encoding:'utf8',timeout:30000});
 assert.equal(run.status,0,run.stdout+run.stderr);const report=JSON.parse(fs.readFileSync(path.join(out,'findings.json'),'utf8'));
 assert.ok(report.cve.some(c=>c.id==='GCVE-1-test-cli'),JSON.stringify(report.warnings));
 assert.ok(!report.warnings.some(w=>/no GCVE advisory data/.test(w.message)));
});

test('CVEProject proxy projection replays offline as partial and native rejection supersedes it',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cve-proxy-'));t.after(()=>removeFixture(root));
 const store=openAdvisoryStore({cacheDir:root});const at=Date.now()-2000;
 const raw=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/cve-samples/cve-with-packagename.json'),'utf8'));raw.cveMetadata.state='PUBLISHED';raw.cveMetadata.dateUpdated='2025-01-01T00:00:00Z';
 const projection=extractMavenRelevantCve(raw), {projectedCveEnvelope,cveEnvelope}=require('../lib/native-advisories');
 store.commit({records:[projectedCveEnvelope(projection,at)],coverages:[{source:'cveproject-legacy',ecosystem:'*',fetchedAt:at,complete:false}]});
 const dep=makeDepRecord({ecosystem:'maven',namespace:'org.apache.logging.log4j',name:'log4j-core',version:'2.14.1'}), deps=new Map([[dep.coordKey,dep]]);
 assert.equal(matchCveStore(deps,store).matches.length,1);
 const rejected={cveMetadata:{cveId:raw.cveMetadata.cveId,state:'REJECTED',dateUpdated:'2026-01-01T00:00:00Z'},containers:{cna:{}}};
 store.commit({records:[cveEnvelope(rejected,{fetchedAt:at+1000})]});
 assert.equal(matchCveStore(deps,store).matches.length,0);
});

test('zero advisory TTL retries stale GCVE online and retains cached findings on failure',async t=>{
 const {spawnSync}=require('node:child_process');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-gcve-zero-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),src=path.join(root,'src'),out=path.join(root,'out');fs.mkdirSync(home);fs.mkdirSync(src);
 fs.writeFileSync(path.join(src,'package.json'),JSON.stringify({name:'app',version:'1.0.0',dependencies:{'gcve-test':'1.0.0'}}));
 const store=openAdvisoryStore({cacheDir:path.join(home,'.vigie-vuln')});
 const raw={cveMetadata:{vulnId:'GCVE-1-test-zero',state:'PUBLISHED',dateUpdated:'2026-01-01T00:00:00Z'},containers:{cna:{affected:[{packageURL:'pkg:npm/gcve-test',versions:[{version:'1.0.0',status:'affected'}]}],x_gcve:[{vulnId:'GCVE-1-test-zero',recordType:'advisory'}]}}};
 const index=buildGcveIndex([{gna:1,sourceUrl:'https://example.org/feed',collectedAt:new Date().toISOString(),complete:true,records:[raw]}]);index.directory={verified:true,notCollected:0};await importGcveIndex(store,index);
 const hook=path.join(root,'hook.cjs'), marker=path.join(root,'requests');
 fs.writeFileSync(hook,`globalThis.fetch=async u=>{require('fs').appendFileSync(${JSON.stringify(marker)},String(u)+'\\n');return new Response('',{status:503})}`);
 const args=['--require',hook,path.join(__dirname,'../vigievuln.js'),'-s',src,'--ecosystem','npm','--advisory-query-ttl','0','-d','osv,nvd,eol,epss,kev,euvd,certfr,retire,transitive,all-libs','--no-binaries','--no-certs','--report-json','-o',out];
 const run=spawnSync(process.execPath,args,{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home,FORCE_COLOR:'0'},encoding:'utf8',timeout:30000});
 assert.equal(run.status,0,run.stdout+run.stderr);assert.match(fs.readFileSync(marker,'utf8'),/gcve\.eu/);
 const report=JSON.parse(fs.readFileSync(path.join(out,'findings.json'),'utf8'));
 assert.ok(report.cve.some(c=>c.id==='GCVE-1-test-zero'));assert.ok(report.warnings.some(w=>/GCVE refresh failed/.test(w.message)));
});

test('CVEProject TTL uses cached index until expiry and zero forces refresh',t=>{
 const {spawnSync}=require('node:child_process');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cve-ttl-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),cache=path.join(home,'.vigie-vuln');fs.mkdirSync(cache,{recursive:true});
 seedCveIndex(cache,{meta:{indexVersion:require('../lib/cve-download').MAVEN_INDEX_VERSION,builtAt:new Date().toISOString()},byPackageName:{},byProduct:{}});
 const modulePath=path.join(__dirname,'../lib/cve-download.js');
 const script=`let calls=0;globalThis.fetch=async()=>{calls++;return new Response('',{status:503})};const m=require(${JSON.stringify(modulePath)});(async()=>{await m.ensureCveIndex({ttlMs:3600000});if(calls!==0)throw Error('fresh index revalidated');try{await m.ensureCveIndex({ttlMs:0});throw Error('zero TTL did not revalidate')}catch(e){if(!/HTTP 503/.test(e.message))throw e;}if(calls<1)throw Error('refresh did not fetch')})().catch(e=>{console.error(e);process.exit(1)});`;
 const run=spawnSync(process.execPath,['-e',script],{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home},encoding:'utf8',timeout:30000});
 assert.equal(run.status,0,run.stdout+run.stderr);
});

test('obsolete fresh CVE projection refreshes online and preserves only native proof offline',t=>{
 const {spawnSync}=require('node:child_process');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cve-old-projection-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),cache=path.join(home,'.vigie-vuln');fs.mkdirSync(cache,{recursive:true});
 const raw=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/cve-samples/cve-with-packagename.json'),'utf8'));raw.cveMetadata.state='PUBLISHED';
 const store=openAdvisoryStore({cacheDir:cache});store.commit({records:[require('../lib/native-advisories').cveEnvelope(raw,{fetchedAt:Date.now()})],coverages:[{source:'cveproject',ecosystem:'*',fetchedAt:Date.now(),complete:false}]});
 const index=require('../lib/cve-download').newIndex();require('../lib/cve-download').addToIndex(index,require('../lib/cve-download').extractMavenRelevantCve(raw));delete index.meta.indexVersion;
 for(const entries of Object.values(index.byPackageName))for(const entry of entries)delete entry.coordinateEvidence;
 seedCveIndex(cache,index);
 const codec=path.join(__dirname,'../lib/codecs/maven.codec.js'),depRecord=path.join(__dirname,'../lib/dep-record.js');
 const script=`let calls=0;globalThis.fetch=async()=>{calls++;return new Response('',{status:503})};const c=require(${JSON.stringify(codec)}),d=require(${JSON.stringify(depRecord)}).makeDepRecord({ecosystem:'maven',namespace:'org.apache.logging.log4j',name:'log4j-core',version:'2.14.1'}),deps=new Map([[d.coordKey,d]]);(async()=>{let r=await c.nativeScanners[0].scan(deps,{offline:true});if(calls||!r.matches.some(m=>m.cve.id==='CVE-2021-44228')||!r.meta.identityUncertain)throw Error('offline evidence or warning missing');r=await c.nativeScanners[0].scan(deps,{queryTtlMs:3600000});if(!calls||!r.matches.some(m=>m.cve.id==='CVE-2021-44228')||!/503/.test(r.meta.refreshError))throw Error('old index was not refreshed or native evidence lost')})().catch(e=>{console.error(e);process.exit(1)})`;
 const run=spawnSync(process.execPath,['-e',script],{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home},encoding:'utf8',timeout:30000});assert.equal(run.status,0,run.stdout+run.stderr);
});

test('failed CVEProject TTL refresh retains native findings and signals failure',t=>{
 const {spawnSync}=require('node:child_process');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cve-stale-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),store=openAdvisoryStore({cacheDir:path.join(home,'.vigie-vuln')});
 const raw=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/cve-samples/cve-with-packagename.json'),'utf8'));raw.cveMetadata.state='PUBLISHED';raw.cveMetadata.dateUpdated='2025-01-01T00:00:00Z';
 store.commit({records:[require('../lib/native-advisories').cveEnvelope(raw,{fetchedAt:Date.now()})],coverages:[{source:'cveproject',ecosystem:'*',fetchedAt:Date.now(),complete:false}]});
 const codec=path.join(__dirname,'../lib/codecs/maven.codec.js'),depRecord=path.join(__dirname,'../lib/dep-record.js');
 const script=`globalThis.fetch=async()=>new Response('',{status:503});const c=require(${JSON.stringify(codec)}),d=require(${JSON.stringify(depRecord)}).makeDepRecord({ecosystem:'maven',namespace:'org.apache.logging.log4j',name:'log4j-core',version:'2.14.1'});c.nativeScanners[0].scan(new Map([[d.coordKey,d]]),{queryTtlMs:0}).then(r=>{if(!r.matches.some(m=>m.cve.id==='CVE-2021-44228')||!/503/.test(r.meta.refreshError))throw Error('cached CVE lost or failure missing')}).catch(e=>{console.error(e);process.exit(1)})`;
 const run=spawnSync(process.execPath,['-e',script],{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home},encoding:'utf8',timeout:30000});
 assert.equal(run.status,0,run.stdout+run.stderr);
});

test('complete native CVE corpus is not marked partial solely because a legacy index exists',t=>{
 const {spawnSync}=require('node:child_process');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cve-complete-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),cache=path.join(home,'.vigie-vuln'),store=openAdvisoryStore({cacheDir:cache});
 const raw=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/cve-samples/cve-with-packagename.json'),'utf8'));raw.cveMetadata.state='PUBLISHED';raw.cveMetadata.dateUpdated='2025-01-01T00:00:00Z';
 const fetchedAt=Date.now();store.commit({records:[require('../lib/native-advisories').cveEnvelope(raw,{fetchedAt})],coverages:[{source:'cveproject',ecosystem:'*',fetchedAt,complete:true}]});
 const legacy=newIndex();addToIndex(legacy,extractMavenRelevantCve(raw));fs.mkdirSync(path.join(cache,'cve-data'),{recursive:true});fs.writeFileSync(path.join(cache,'cve-data','maven-cve-index.json'),JSON.stringify(legacy));
 const codec=path.join(__dirname,'../lib/codecs/maven.codec.js'),depRecord=path.join(__dirname,'../lib/dep-record.js');
 const script=`const c=require(${JSON.stringify(codec)}),d=require(${JSON.stringify(depRecord)}).makeDepRecord({ecosystem:'maven',namespace:'org.apache.logging.log4j',name:'log4j-core',version:'2.14.1'});c.nativeScanners[0].scan(new Map([[d.coordKey,d]]),{offline:true}).then(r=>{if(r.meta.incomplete||r.matches.length!==1)throw Error('incorrect completeness')}).catch(e=>{console.error(e);process.exit(1)})`;
 const run=spawnSync(process.execPath,['-e',script],{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home},encoding:'utf8',timeout:30000});assert.equal(run.status,0,run.stdout+run.stderr);
});

test('a complete current Maven index covers the scan even when native journal coverage is partial', t=>{
 const {spawnSync}=require('node:child_process');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cve-index-complete-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),cache=path.join(home,'.vigie-vuln');
 const store=openAdvisoryStore({cacheDir:cache}),at=Date.now();
 store.commit({coverages:[{source:'cveproject',ecosystem:'*',fetchedAt:at,complete:false}]});store.close();
 const download=path.join(__dirname,'../lib/cve-download.js'),codec=path.join(__dirname,'../lib/codecs/maven.codec.js'),depRecord=path.join(__dirname,'../lib/dep-record.js'),cacheDb=path.join(__dirname,'../lib/cache-db.js');
 const script=`const c=require(${JSON.stringify(download)}),i=c.newIndex();i.meta.builtAt=new Date().toISOString();i.meta.cveCount=0;require(${JSON.stringify(cacheDb)}).getCacheDb().prepare("INSERT INTO cache_snapshots(namespace,fetched_at,complete,stale,record_count,metadata_json) VALUES('cve_lookup',?,1,0,0,?)").run(Date.now(),JSON.stringify(i.meta));const codec=require(${JSON.stringify(codec)}),d=require(${JSON.stringify(depRecord)}).makeDepRecord({ecosystem:'maven',namespace:'org.example',name:'demo',version:'1.0'}),deps=new Map([[d.coordKey,d]]);(async()=>{let r=await codec.nativeScanners[0].scan(deps,{offline:true});if(r.meta.incomplete)throw Error('complete index marked partial');require(${JSON.stringify(cacheDb)}).getCacheDb().prepare("UPDATE cache_snapshots SET complete=0 WHERE namespace='cve_lookup'").run();r=await codec.nativeScanners[0].scan(deps,{offline:true});if(!r.meta.incomplete)throw Error('partial index marked complete')})().catch(e=>{console.error(e);process.exit(1)})`;
 const run=spawnSync(process.execPath,['-e',script],{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home},encoding:'utf8',timeout:30000});
 assert.equal(run.status,0,run.stdout+run.stderr);
});

test('hosted CVE batch wins over older cached native findings and preserves upstream timestamp',t=>{
 const {spawnSync}=require('node:child_process');const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-hosted-cve-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),store=openAdvisoryStore({cacheDir:path.join(home,'.vigie-vuln')});
 const raw=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/cve-samples/cve-with-packagename.json'),'utf8'));raw.cveMetadata.state='PUBLISHED';raw.cveMetadata.dateUpdated='2025-01-01T00:00:00Z';
 const now=Date.now(),fetchedAt=now-7200000;store.commit({records:[require('../lib/native-advisories').cveEnvelope(raw,{fetchedAt:now-1000})],coverages:[{source:'cveproject',ecosystem:'*',fetchedAt:now-1000,complete:false}]});
 const codec=path.join(__dirname,'../lib/codecs/maven.codec.js'),provider=path.join(__dirname,'../lib/providers'),depRecord=path.join(__dirname,'../lib/dep-record.js');
 const script=`const p=require(${JSON.stringify(provider)});p.getResource=async(i,t,v,o)=>{if(!o.forceRefresh)throw Error('cache bypass missing');return Response.json({cves:[],builtAt:${JSON.stringify(new Date(now).toISOString())}},{headers:{'x-fad-proxy':'stale','x-fad-proxy-fetched-at':${JSON.stringify(new Date(fetchedAt).toISOString())}}})};const c=require(${JSON.stringify(codec)}),d=require(${JSON.stringify(depRecord)}).makeDepRecord({ecosystem:'maven',namespace:'org.apache.logging.log4j',name:'log4j-core',version:'2.14.1'});c.nativeScanners[0].scan(new Map([[d.coordKey,d]]),{hostedProxy:true,queryTtlMs:3600000}).then(r=>{if(r.matches.length||!r.meta.stale)throw Error('proxy batch not authoritative or stale signal missing');const s=require(${JSON.stringify(path.join(__dirname,'../lib/advisory-store.js'))}).openAdvisoryStore().getSourceCoverage('cveproject-legacy','*');if(s.fetchedAt!==${fetchedAt})throw Error('upstream timestamp lost')}).catch(e=>{console.error(e);process.exit(1)})`;
 const run=spawnSync(process.execPath,['-e',script],{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home},encoding:'utf8',timeout:30000});assert.equal(run.status,0,run.stdout+run.stderr);
});

test('hosted CVE batch reports a demonstrably newer native revision as a conflict',t=>{
 const {spawnSync}=require('node:child_process');const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-hosted-conflict-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),store=openAdvisoryStore({cacheDir:path.join(home,'.vigie-vuln')});
 const raw=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/cve-samples/cve-with-packagename.json'),'utf8'));raw.cveMetadata.state='PUBLISHED';raw.cveMetadata.dateUpdated='2025-01-01T00:00:00Z';
 store.commit({records:[require('../lib/native-advisories').cveEnvelope(raw,{fetchedAt:Date.now()})]});
 const codec=path.join(__dirname,'../lib/codecs/maven.codec.js'),provider=path.join(__dirname,'../lib/providers'),depRecord=path.join(__dirname,'../lib/dep-record.js');
 const script=`const p=require(${JSON.stringify(provider)});p.getResource=async()=>Response.json({cves:[],builtAt:'2024-01-01T00:00:00Z'},{headers:{'x-fad-proxy-fetched-at':new Date().toISOString()}});const c=require(${JSON.stringify(codec)}),d=require(${JSON.stringify(depRecord)}).makeDepRecord({ecosystem:'maven',namespace:'org.apache.logging.log4j',name:'log4j-core',version:'2.14.1'});c.nativeScanners[0].scan(new Map([[d.coordKey,d]]),{hostedProxy:true,queryTtlMs:3600000}).then(r=>{if(r.matches.length!==1||!r.meta.conflict)throw Error('newer native conflict missed')}).catch(e=>{console.error(e);process.exit(1)})`;
 const run=spawnSync(process.execPath,['-e',script],{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home},encoding:'utf8',timeout:30000});assert.equal(run.status,0,run.stdout+run.stderr);
});

test('hosted CVE response without timestamp does not create fresh cached evidence',t=>{
 const {spawnSync}=require('node:child_process');const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cve-no-stamp-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home');fs.mkdirSync(home);
 const codec=path.join(__dirname,'../lib/codecs/maven.codec.js'),provider=path.join(__dirname,'../lib/providers'),depRecord=path.join(__dirname,'../lib/dep-record.js'),store=path.join(__dirname,'../lib/advisory-store.js');
 const script=`require(${JSON.stringify(provider)}).getResource=async()=>Response.json({cves:[],builtAt:new Date().toISOString()});const c=require(${JSON.stringify(codec)}),d=require(${JSON.stringify(depRecord)}).makeDepRecord({ecosystem:'maven',namespace:'org.example',name:'lib',version:'1'});c.nativeScanners[0].scan(new Map([[d.coordKey,d]]),{hostedProxy:true,queryTtlMs:3600000}).then(r=>{if(!r.meta.timestampUnknown)throw Error('unknown freshness not signaled');if(require(${JSON.stringify(store)}).openAdvisoryStore().getSourceCoverage('cveproject-legacy','*'))throw Error('unknown timestamp cached')}).catch(e=>{console.error(e);process.exit(1)})`;
 const run=spawnSync(process.execPath,['-e',script],{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home},encoding:'utf8',timeout:30000});assert.equal(run.status,0,run.stdout+run.stderr);
});

test('GCVE per-GNA complete snapshots prove absence without inventing rejection; partial reappearance survives',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-gcve-membership-'));t.after(()=>removeFixture(root));
 const store=openAdvisoryStore({cacheDir:root}), base=Date.now()-10000;
 const raw=gna=>({cveMetadata:{vulnId:`GCVE-${gna}-shared`,state:'PUBLISHED',dateUpdated:'2025-01-01T00:00:00Z'},containers:{cna:{affected:[{packageURL:'pkg:npm/gcve-test',versions:[{version:'1.0',status:'affected'}]}],x_gcve:[{vulnId:`GCVE-${gna}-shared`,recordType:'advisory'}]}}});
 const source=(gna,offset,records,complete=true)=>({gna,sourceUrl:`https://example.org/gna-${gna}`,collectedAt:new Date(base+offset).toISOString(),complete,records});
 const ingest=async sources=>{const index=buildGcveIndex(sources);index.directory={verified:true,notCollected:0};await importGcveIndex(store,index);};
 const dep=makeDepRecord({ecosystem:'npm',name:'gcve-test',version:'1.0'}),deps=new Map([[dep.coordKey,dep]]);
 const ids=()=>matchGcveStore(deps,store).matches.map(x=>x.cve.gcve).sort();
 await ingest([source(1,0,[raw(1)]),source(2,0,[raw(2)])]);assert.deepEqual(ids(),['GCVE-1-shared','GCVE-2-shared']);
 await ingest([source(1,1000,[],false)]);assert.deepEqual(ids(),['GCVE-1-shared','GCVE-2-shared']);
 await ingest([source(1,2000,[])]);assert.deepEqual(ids(),['GCVE-2-shared']);
 assert.equal(store.getRecord('gcve','GCVE-1-shared').document.cveMetadata.state,'PUBLISHED');
 await ingest([source(1,3000,[raw(1)],false)]);assert.deepEqual(ids(),['GCVE-1-shared','GCVE-2-shared']);
});

for (const builtAt of [null,'2026-10-01T00:00:00Z']) test(`hosted positive cannot resurrect native rejection when corpus date is ${builtAt || 'unknown'}`,t=>{
 const {spawnSync}=require('node:child_process');const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cve-tombstone-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),store=openAdvisoryStore({cacheDir:path.join(home,'.vigie-vuln')});
 const raw=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/cve-samples/cve-with-packagename.json'),'utf8'));raw.cveMetadata.state='PUBLISHED';raw.cveMetadata.dateUpdated='2025-01-01T00:00:00Z';
 const rejected={cveMetadata:{cveId:raw.cveMetadata.cveId,state:'REJECTED',dateUpdated:'2025-11-01T00:00:00Z'},containers:{cna:{}}};
 store.commit({records:[require('../lib/native-advisories').cveEnvelope(rejected,{fetchedAt:Date.now()-1000})]});
 const projection=extractMavenRelevantCve(raw);projection.modified='2026-09-01T00:00:00Z';
 const codec=path.join(__dirname,'../lib/codecs/maven.codec.js'),provider=path.join(__dirname,'../lib/providers'),depRecord=path.join(__dirname,'../lib/dep-record.js'),advisory=path.join(__dirname,'../lib/advisory-store.js'),native=path.join(__dirname,'../lib/native-advisories.js');
 const script=`const p=require(${JSON.stringify(provider)});p.getResource=async()=>Response.json({cves:[${JSON.stringify(projection)}],builtAt:${JSON.stringify(builtAt)}},{headers:{'x-fad-proxy-fetched-at':new Date().toISOString()}});const c=require(${JSON.stringify(codec)}),d=require(${JSON.stringify(depRecord)}).makeDepRecord({ecosystem:'maven',namespace:'org.apache.logging.log4j',name:'log4j-core',version:'2.14.1'}),deps=new Map([[d.coordKey,d]]);(async()=>{let r=await c.nativeScanners[0].scan(deps,{hostedProxy:true,queryTtlMs:3600000});if(r.matches.length||!r.meta.conflict)throw Error('rejected CVE resurrected');r=await c.nativeScanners[0].scan(deps,{offline:true});if(r.matches.length)throw Error('offline CVE resurrected');const native=require(${JSON.stringify(native)}),store=require(${JSON.stringify(advisory)}).openAdvisoryStore(),restored=${JSON.stringify(raw)};restored.cveMetadata.dateUpdated='2026-01-01T00:00:00Z';store.commit({records:[native.cveEnvelope(restored,{fetchedAt:Date.now()})]});r=await c.nativeScanners[0].scan(deps,{hostedProxy:true,queryTtlMs:3600000});if(r.matches.length!==1)throw Error('native reinstatement lost')})().catch(e=>{console.error(e);process.exit(1)})`;
 const run=spawnSync(process.execPath,['-e',script],{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home},encoding:'utf8',timeout:30000});assert.equal(run.status,0,run.stdout+run.stderr);
});

test('--gcve-offline uses stale local GCVE data during an online scan without refreshing it',async t=>{
 const {spawnSync}=require('node:child_process'),root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-gcve-local-'));t.after(()=>removeFixture(root));
 const home=path.join(root,'home'),src=path.join(root,'src'),out=path.join(root,'out'),cache=path.join(home,'.vigie-vuln');fs.mkdirSync(home);fs.mkdirSync(src);
 fs.writeFileSync(path.join(src,'package.json'),JSON.stringify({name:'fixture',version:'1.0.0',dependencies:{'gcve-test':'1.0.0'}}));
 const at=new Date(Date.now()-86400000).toISOString(),raw={cveMetadata:{vulnId:'GCVE-1-stale-fixture',state:'PUBLISHED'},containers:{cna:{affected:[{packageURL:'pkg:npm/gcve-test',versions:[{version:'1.0.0',status:'affected'}]}],x_gcve:[{vulnId:'GCVE-1-stale-fixture',recordType:'advisory'}]}}};
 const index=buildGcveIndex([{gna:1,sourceUrl:'https://example.org/feed',collectedAt:at,complete:true,records:[raw]}]);index.directory={verified:true,notCollected:0};const store=openAdvisoryStore({cacheDir:cache});await importGcveIndex(store,index);store.close();require('../lib/cache-repository').createCacheRepository(cache).put('catalogue','gcve',index,{fetchedAt:Date.parse(at)});
 const hook=path.join(root,'network.cjs'),marker=path.join(root,'network');fs.writeFileSync(hook,`globalThis.fetch=async u=>{require('node:fs').appendFileSync(${JSON.stringify(marker)},String(u)+'\\n');return new Response('',{status:503})}`);
 const args=['--require',hook,path.join(__dirname,'../vigievuln.js'),'-s',src,'--ecosystem','npm','--gcve-offline','--advisory-query-ttl','0','-d','osv,nvd,eol,epss,kev,euvd,certfr,retire,transitive,all-libs','--no-binaries','--no-certs','--report-json','-o',out];
 const r=spawnSync(process.execPath,args,{cwd:root,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home,FORCE_COLOR:'0'},encoding:'utf8',timeout:30000});assert.equal(r.status,0,r.stdout+r.stderr);
 const report=JSON.parse(fs.readFileSync(path.join(out,'findings.json')));assert.ok(report.cve.some(x=>x.id==='GCVE-1-stale-fixture'));assert.ok(report.provenance.freshnessNotices.some(w=>w.message.startsWith('GCVE')));assert.ok(!report.warnings.some(w=>w.type==='source-stale'));
 if(fs.existsSync(marker))assert.doesNotMatch(fs.readFileSync(marker,'utf8'),/gcve\.eu|vulnerability\.circl\.lu/);
});
