'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {openAdvisoryStore}=require('../lib/advisory-store');
const {openCacheDb}=require('../lib/cache-db');
const {buildProjectScope,buildProjectSnapshot}=require('../lib/airgap-project');
const {queryBatch}=require('../lib/osv');
const {makeDepRecord}=require('../lib/dep-record');

test('project snapshot keeps all versions of selected packages without claiming global coverage',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-project-snapshot-')),source=path.join(root,'source'),target=path.join(root,'target');
 t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const dep=makeDepRecord({ecosystem:'maven',namespace:'example',name:'kept',version:'1.0'});
 const unrelated=makeDepRecord({ecosystem:'maven',namespace:'example',name:'other',version:'1.0'});
 const store=openAdvisoryStore({cacheDir:source}),at=Date.now();
 const doc=(id,name)=>({id,aliases:[id==='GHSA-kept'?'CVE-2020-12345':'CVE-2020-54321'],affected:[{package:{ecosystem:'Maven',name},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0'}]}]}]});
 store.commit({records:[{source:'osv',document:doc('GHSA-kept','example:kept'),fetchedAt:at},{source:'osv',document:doc('GHSA-other','example:other'),fetchedAt:at}],coverages:[{source:'osv',ecosystem:'Maven',complete:true,fetchedAt:at,provenance:{transport:'seed'}}]});
 store.close();
 const db=openCacheDb({cacheDir:source});const ins=db.prepare("INSERT INTO nvd_records VALUES(?,'bulk',?,NULL,?,1,'{}')");ins.run('CVE-2020-12345',at,Buffer.from([1]));ins.run('CVE-2020-54321',at,Buffer.from([1]));db.close();
 const project=buildProjectScope(new Map([['kept',dep]]));
 assert.equal(require('../lib/cache-repository').createCacheRepository(source).get('airgap-project','latest'),null,'project scope is not persisted');
 buildProjectSnapshot(source,target,project);
 const {exportCache,importCache}=require('../lib/cache-archive-sqlite');
 // An obsolete marker from an older build cannot change full-cache export.
 require('../lib/cache-repository').createCacheRepository(source).put('airgap-project','latest',project);
 const archive=path.join(root,'full.tar.gz');
 assert.equal((await exportCache(archive,{sourceDir:source})).scope,'full');
 const restored=path.join(root,'restored');await importCache(archive,{targetDir:restored});
 const full=openAdvisoryStore({cacheDir:restored});assert.ok(full.getRecord('osv','GHSA-other'));full.close();
 const out=openAdvisoryStore({cacheDir:target});
 assert.equal(out.getSourceCoverage('osv','Maven'),null);
 assert.equal(out.getPackageView({source:'osv',ecosystem:'Maven',name:'example:kept',version:'1.5'}).coverage.complete,true);
 assert.equal(out.getPackageView({source:'osv',ecosystem:'Maven',name:'example:other',version:'1.0'}).coverage,null);
 assert.equal(out.getRecord('osv','GHSA-other'),null);
 assert.deepEqual(out.db.prepare('SELECT cve FROM nvd_records').all().map(x=>x.cve),['CVE-2020-12345']);
 out.close();
 const warnings=[];
 const newer={...dep,version:'1.5'};
 assert.equal((await queryBatch([newer],{cacheDir:target,offline:true,onWarning:w=>warnings.push(w)})).length,1);
 assert.equal(warnings.filter(w=>w.type==='osv-coverage').length,0);
 await queryBatch([unrelated],{cacheDir:target,offline:true,onWarning:w=>warnings.push(w)});
 assert.equal(warnings.filter(w=>w.type==='osv-coverage').length,1);
});

test('native binaries retain NVD and do not become Maven package identities',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-project-native-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const dep=makeDepRecord({ecosystem:'maven',namespace:'example',name:'kept',version:'1.0'});
 const binary=makeDepRecord({ecosystem:'binary',name:'example.dll',provenance:'binary'});
 const project=buildProjectScope(new Map([['dep',dep],['binary',binary]]));
 assert.equal(project.retainAllNvd,true);assert.equal(project.packages.length,1);
 const descriptor=require('../lib/deps-descriptor').serializeDeps(new Map([['dep',dep],['binary',binary]]));
 assert.equal([...require('../lib/deps-descriptor').deserializeDeps(descriptor).resolved.values()].find(d=>d.ecosystem==='binary').provenance,'binary');
});

test('project export retains bulk NVD records for findings without package advisory records', t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-project-finding-nvd-')),source=path.join(root,'online'),target=path.join(root,'offline');
 t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const at=Date.now(),db=openCacheDb({cacheDir:source});
 const insert=db.prepare("INSERT INTO nvd_records VALUES(?,'bulk',?,NULL,?,1,'{}')");
 insert.run('CVE-2026-10001',at,Buffer.from([1]));insert.run('CVE-2026-10002',at,Buffer.from([1]));db.close();
 const dep=makeDepRecord({ecosystem:'npm',name:'example',version:'1.0.0'});
 buildProjectSnapshot(source,target,buildProjectScope(new Map([['example',dep]]),{cves:['CVE-2026-10001']}));
 const output=openCacheDb({cacheDir:target});
 try { assert.deepEqual(output.prepare('SELECT cve FROM nvd_records').all().map(row=>row.cve),['CVE-2026-10001']); }
 finally {output.close()}
});

test('project export keeps relevant native records, not the global CVE corpus',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-project-native-cve-')),source=path.join(root,'online'),target=path.join(root,'offline');
 t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const {cveEnvelope,matchNativeNpmCves}=require('../lib/native-advisories'),at=Date.now();
 const raw=(id,name)=>({cveMetadata:{cveId:id,state:'PUBLISHED',dateUpdated:'2026-01-01T00:00:00Z'},containers:{cna:{affected:[{packageURL:`pkg:npm/${name}`,defaultStatus:'unaffected',versions:[{version:'0',lessThan:'2.0.0',versionType:'semver',status:'affected'}]}]}}});
 const dep=makeDepRecord({ecosystem:'npm',name:'kept',version:'1.0.0'}),resolved=new Map([[dep.coordKey,dep]]),store=openAdvisoryStore({cacheDir:source});
 store.commit({records:[cveEnvelope(raw('CVE-2026-10001','kept'),{fetchedAt:at}),cveEnvelope(raw('CVE-2026-10002','other'),{fetchedAt:at}),cveEnvelope(raw('CVE-2026-10003','other'),{fetchedAt:at})]});
 assert.equal(matchNativeNpmCves(resolved,store).matches.length,1);store.close();
 const db=openCacheDb({cacheDir:source});
 db.prepare('INSERT INTO cve_lookup VALUES(?,?,?,?,?,?)').run('product','other','CVEProject','CVE-2026-10003','a','{}');
 const insert=db.prepare("INSERT INTO nvd_records VALUES(?,'live',?,NULL,?,1,'{}')");
 for(const id of ['CVE-2026-10001','CVE-2026-10002','CVE-2026-10003'])insert.run(id,at,Buffer.from([1]));db.close();
 buildProjectSnapshot(source,target,buildProjectScope(resolved));
 const offline=openAdvisoryStore({cacheDir:target});
 try{
  assert.equal(matchNativeNpmCves(resolved,offline).matches.length,1);
  assert.ok(offline.getRecord('cveproject','CVE-2026-10001'));
  assert.equal(offline.getRecord('cveproject','CVE-2026-10002'),null);
  assert.equal(offline.getRecord('cveproject','CVE-2026-10003'),null);
  assert.deepEqual(offline.db.prepare('SELECT cve FROM nvd_records ORDER BY cve').all().map(row=>row.cve),['CVE-2026-10001']);
 }finally{offline.close()}
});

test('project indexes merge by covered bucket without pretending to be global',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-project-index-')),source=path.join(root,'source'),target=path.join(root,'target');
 t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const db=openCacheDb({cacheDir:source}),at=Date.now();
 db.prepare("INSERT INTO cache_snapshots VALUES('cve_lookup',?,1,0,2,'{}')").run(at);
 const put=db.prepare('INSERT INTO cve_lookup VALUES(?,?,?,?,?,?)');
 put.run('package','example:one','CVEProject','CVE-2026-10001','a','{}');
 put.run('package','example:two','CVEProject','CVE-2026-10002','b','{}');db.close();
 const {exportCache,importCache}=require('../lib/cache-archive-sqlite');
 for(const name of ['one','two']){
  const dep=makeDepRecord({ecosystem:'maven',namespace:'example',name,version:'1.0'}),archive=path.join(root,`${name}.tar.gz`);
  await exportCache(archive,{sourceDir:source,project:buildProjectScope(new Map([[name,dep]]))});
  await importCache(archive,{targetDir:target});
 }
 const result=openCacheDb({cacheDir:target});
 try{
  assert.deepEqual(result.prepare('SELECT lookup_key FROM cve_lookup ORDER BY lookup_key').all().map(r=>r.lookup_key),['example:one','example:two']);
  assert.equal(result.prepare("SELECT complete FROM cache_snapshots WHERE namespace='cve_lookup'").get().complete,0);
  assert.deepEqual(result.prepare("SELECT key FROM cache_entries WHERE namespace='airgap-cve-index' AND key LIKE 'p:%' ORDER BY key").all().map(r=>r.key),['p:example:one','p:example:two']);
 }finally{result.close()}
});

test('project export excludes other projects from prewarmed EPSS and EUVD enrichments',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-project-enrichment-')),source=path.join(root,'online'),target=path.join(root,'offline');t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const repo=require('../lib/cache-repository').createCacheRepository(source),kept='CVE-2026-10001',other='CVE-2026-10002',at=Date.now()-3600000;
 repo.put('catalogue','epss',{meta:{fetchedAt:at},entries:{[kept]:{score:0.3},[other]:{score:0.8}}},{fetchedAt:at});
 repo.put('catalogue','euvd-targeted',{entries:{[kept]:{item:{id:'EUVD-2026-1'},fetchedAt:at,stale:true},[other]:{item:{id:'EUVD-2026-2'},fetchedAt:at,stale:false}}},{fetchedAt:at});
 const d=makeDepRecord({ecosystem:'npm',name:'example',version:'1.0.0'});
 buildProjectSnapshot(source,target,buildProjectScope(new Map([['example',d]]),{cves:[kept]}));
 const out=require('../lib/cache-repository').createCacheRepository(target);
 for(const key of ['epss','euvd-targeted']){const r=out.get('catalogue',key);assert.deepEqual(Object.keys(r.value.entries),[kept]);assert.equal(r.fetchedAt,at)}
 assert.equal(out.get('catalogue','euvd-targeted').value.entries[kept].stale,true);
});

test('targeted online consultations survive project export without a seed; later discoveries remain unknown',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-targeted-airgap-')),source=path.join(root,'online'),target=path.join(root,'offline');
 t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const dep=(name,version)=>makeDepRecord({ecosystem:'maven',namespace:'example',name,version});
 const direct=dep('direct','1.0'),transitive=dep('transitive','2.0'),later=dep('later','3.0');
 const resolved=new Map([['direct',direct],['transitive',transitive]]);
 const document={id:'GHSA-airgap-test',affected:[{package:{ecosystem:'Maven',name:'example:transitive'},versions:['2.0']}]};
 let calls=0;
 const fetcher=async(url,init)=>{
  calls++;
  if(url.endsWith('/querybatch'))return Response.json({results:JSON.parse(init.body).queries.map(q=>q.package.name==='example:transitive'?{vulns:[{id:document.id}]}:{})});
  return Response.json(document);
 };
 assert.equal((await queryBatch([...resolved.values()],{cacheDir:source,fetcher})).length,1);
 assert.equal(calls,2);
 const store=openAdvisoryStore({cacheDir:source});assert.equal(store.getSourceCoverage('osv','Maven'),null);store.close();
 buildProjectSnapshot(source,target,buildProjectScope(resolved));
 const warnings=[];
 const offlineFetch=()=>assert.fail('offline consultation contacted the network');
 assert.equal((await queryBatch([direct,transitive],{cacheDir:target,offline:true,fetcher:offlineFetch,onWarning:w=>warnings.push(w)})).length,1);
 assert.equal(warnings.filter(w=>w.type==='osv-coverage').length,0);
 await queryBatch([later,{...direct,version:'1.1'}],{cacheDir:target,offline:true,fetcher:offlineFetch,onWarning:w=>warnings.push(w)});
 assert.match(warnings.find(w=>w.type==='osv-coverage').message,/2 Maven package\/version/);
});
