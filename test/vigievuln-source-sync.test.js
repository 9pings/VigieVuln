'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {openAdvisoryStore}=require('../lib/advisory-store-sqlite'),{makeDepRecord}=require('../lib/dep-record');
const {refreshReviewed,isCurrentForPackage}=require('../lib/vigievuln-advisories');
const {queryBatch,queryReviewedForDeps}=require('../lib/osv');
const pkg=(ecosystem,name,version,namespace)=>makeDepRecord({ecosystem,name,version,...(namespace?{namespace}: {})});
const doc=(id,ecosystem,name)=>({id,aliases:['CVE-2026-103387'],affected:[{package:{ecosystem,name},versions:['4.4.0','4.4.1'],ranges:[],database_specific:{vigievuln_partial_versions:true}}],references:[{type:'ORIGINAL',url:'https://www.cve.org/CVERecord?id=CVE-2026-103387'}],curation:{method:'AI-assisted reconciliation',sources:[{url:'https://github.com/garycourt/uri-js/issues/103'}]},modifiedAt:'2026-01-01T00:00:00Z'});
const mkstore=t=>{const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-sync-'));const store=openAdvisoryStore({cacheDir:root});t.after(()=>{store.close();require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});return {root,store}};
const response=(records,now)=>Response.json({records,complete:true},{headers:{'x-fad-proxy-fetched-at':new Date(now).toISOString()}});

test('targeted reviewed consultation persists, matches offline, and honours a later withdrawal',async t=>{
 const {root,store}=mkstore(t),now=Date.now()-2000,npm=pkg('npm','uri-js','4.4.1'),maven=pkg('maven','example','4.4.1','org.test'),resolved=new Map([[npm.coordKey,npm],[maven.coordKey,maven]]),v=doc('VV:CVE-2026-103387','npm','uri-js');let calls=0;
 const getResource=async(id,type,p,opts)=>{calls++;assert.equal(id,'vigievuln');assert.equal(type,'advisories');assert.equal(opts.forceRefresh,true);assert.deepEqual(p.packages,[{ecosystem:'Maven',name:'org.test:example'},{ecosystem:'npm',name:'uri-js'}]);return response([v],now)};
 await refreshReviewed(resolved,store,{getResource});await refreshReviewed(resolved,store,{getResource});assert.equal(calls,1);
 const warnings=[],withoutOsv=queryReviewedForDeps(resolved,{store,onWarning:w=>warnings.push(w)});assert.equal(withoutOsv.length,1);assert.equal(withoutOsv[0].cve.curation.method,'AI-assisted reconciliation');assert.equal(withoutOsv[0].dep.name,'uri-js');
 store.commit({coverages:[{source:'osv',ecosystem:'npm',complete:true,fetchedAt:now},{source:'osv',ecosystem:'Maven',complete:true,fetchedAt:now}]});const output=await queryBatch([npm,maven],{offline:true,store,cacheDir:root});assert.equal(output.length,1);assert.equal(output[0].source,'vigievuln');
 const unrelated=doc('vv:CVE-2026-103387:def456','npm','other');store.commit({records:[{source:'vigievuln',document:unrelated,packages:[{ecosystem:'npm',name:'other'}],fetchedAt:now}]});
 const {buildProjectScope}=require('../lib/airgap-project'),{exportCache,importCache}=require('../lib/cache-archive-sqlite');const archive=path.join(root,'project.tar.gz');await exportCache(archive,{sourceDir:root,project:buildProjectScope(resolved)});const target=path.join(root,'offline');await importCache(archive,{targetDir:target});const offline=openAdvisoryStore({cacheDir:target});assert.equal(queryReviewedForDeps(resolved,{store:offline}).length,1);assert.equal(offline.getRecord('vigievuln',unrelated.id),null);offline.close();
 await refreshReviewed(resolved,store,{ttlMs:0,getResource:async()=>response([],now+1000)});assert.equal(queryReviewedForDeps(resolved,{store}).length,0);
});

test('one VV advisory matches each package using its own evidence and versions',async t=>{
 const {store}=mkstore(t),now=Date.now()-1000,alpha=pkg('maven','alpha','1.5','org.test'),beta=pkg('maven','beta','1.5','org.test'),deps=new Map([[alpha.coordKey,alpha],[beta.coordKey,beta]]);
 const v=doc('VV:CVE-2026-103387','Maven','org.test:alpha');
 v.affected=[{package:{ecosystem:'Maven',name:'org.test:alpha'},versions:[],ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0'}]}],database_specific:{vigievuln_curation:{method:'AI-assisted reconciliation',confidence:'high'}}},{package:{ecosystem:'Maven',name:'org.test:beta'},versions:[],ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1.0'}]}],database_specific:{vigievuln_curation:{method:'AI-assisted reconciliation',confidence:'uncertain'}}}];
 await refreshReviewed(deps,store,{getResource:async()=>response([v],now)});
 const matches=queryReviewedForDeps(deps,{store});assert.equal(matches.length,1);assert.equal(matches[0].dep.name,'alpha');assert.equal(matches[0].cve.curation.confidence,'high');assert.ok(matches[0].cve.aliases.includes('VV:CVE-2026-103387'));
 const providers=require('../lib/providers'),original=providers.getResource;providers.getResource=async(provider,type,p)=>{assert.equal(provider,'kev');assert.deepEqual(p.ids,['CVE-2026-103387']);return Response.json({items:[{cve:'CVE-2026-103387',kev:{dateAdded:'2026-01-01'}}]})};
 try{await require('../lib/kev').enrichKev(matches,{hostedProxy:true});assert.equal(matches[0].cve.kev,true);assert.equal(matches[0].cve.kevDateAdded,'2026-01-01')}finally{providers.getResource=original}
});

test('failed or unrelated response cannot replace an earlier complete consultation',async t=>{
 const {store}=mkstore(t),now=Date.now()-1000,d=pkg('npm','uri-js','4.4.1'),deps=new Map([[d.coordKey,d]]),v=doc('vv:CVE-2026-103387:abc123','npm','uri-js');
 await refreshReviewed(deps,store,{getResource:async()=>response([v],now)});
 await assert.rejects(refreshReviewed(deps,store,{ttlMs:0,getResource:async()=>response([doc('vv:CVE-2026-103387:def456','npm','other')],now+1)}),/unrelated/);
 assert.equal(queryReviewedForDeps(deps,{store}).length,1);
 await assert.rejects(refreshReviewed(deps,store,{ttlMs:0,getResource:async()=>new Response('',{status:503})}),/HTTP 503/);
 assert.equal(queryReviewedForDeps(deps,{store}).length,1);
});

test('a slightly fast server clock does not make a new consultation stale',async t=>{
 const {store}=mkstore(t),d=pkg('npm','uri-js','4.4.1'),deps=new Map([[d.coordKey,d]]),v=doc('vv:CVE-2026-103387:abc123','npm','uri-js');let calls=0;
 const getResource=async()=>{calls++;return response([v],Date.now()+15000)};
 await refreshReviewed(deps,store,{getResource});
 const q=store.getQuery({source:'vigievuln',ecosystem:'npm',name:'uri-js',version:'*'});
 assert.equal(q.fresh,true);assert.ok(q.fetchedAt<=Date.now());
 const warnings=[];assert.equal(queryReviewedForDeps(deps,{store,onWarning:w=>warnings.push(w)}).length,1);assert.deepEqual(warnings,[]);
 await refreshReviewed(deps,store,{getResource});assert.equal(calls,1);
 await assert.rejects(refreshReviewed(deps,store,{ttlMs:0,getResource:async()=>response([],Date.now()+301000)}),/trustworthy timestamp/);
});
