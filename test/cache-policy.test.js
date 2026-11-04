'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const policy=require('../lib/cache-policy');

test('local freshness is four hours and force bypasses it',t=>{
 t.after(()=>policy.setForceUpdate(false));
 const now=Date.now(),ttl=4*3600000;
 assert.equal(policy.fresh(now-ttl+1,7*24*3600000,now),true);
 assert.equal(policy.fresh(now-ttl,7*24*3600000,now),false);
 policy.setForceUpdate(true);
 assert.equal(policy.fresh(now,ttl,now),false);
});

test('refresh preserves unqueried entries and transient failures without restamping them',()=>{
 const cache={meta:{fetchedAt:200},entries:{refreshed:{latest:'2'},failed:{error:'timeout'},absent:{error:'404',absent:true}}};
 const previous={fetchedAt:100,entries:{refreshed:{latest:'1'},failed:{latest:'1'},untouched:{latest:'1'},absent:{latest:'1'}}};
 policy.preserveEntries(cache,previous);
 assert.equal(cache.entries.refreshed.latest,'2');assert.equal(cache.entries.failed.latest,'1');
 assert.equal(cache.entries.untouched.latest,'1');assert.equal(cache.entries.absent.absent,true);
 assert.equal(cache.meta.fetchedAt,100);
});

test('force-update revalidates a fresh provider response while retaining conditional requests',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-force-provider-'));
 const {createCacheStore}=require('../lib/proxy-cache');const {configureResourceRoute,getResource}=require('../lib/providers');
 const store=createCacheStore(root);let calls=0,validator=null;
 t.after(()=>{policy.setForceUpdate(false);configureResourceRoute({proxyUrl:null,hosted:false,store:null,fetcher:null});require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});
 configureResourceRoute({proxyUrl:null,hosted:false,store,fetcher:async(_url,init)=>{calls++;validator=init?.headers?.['if-none-match'];return calls===1?new Response('{"vulnerabilities":[]}',{status:200,headers:{etag:'"one"','content-type':'application/json'}}):new Response(null,{status:304});}});
 assert.equal((await getResource('kev','catalog',{})).status,200);
 assert.equal((await getResource('kev','catalog',{})).status,200);assert.equal(calls,1);
 policy.setForceUpdate(true);
 assert.equal((await getResource('kev','catalog',{})).status,200);assert.equal(calls,2);assert.equal(validator,'"one"');
 assert.equal((await getResource('kev','catalog',{},{offline:true})).status,200);assert.equal(calls,2);
});

test('force-update revalidates cached Maven POMs and preserves them offline',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-force-pom-'));
 t.after(()=>{policy.setForceUpdate(false);require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});
 const {fetchPom}=require('../lib/transitive');let calls=0;
 const fetcher=async()=>{calls++;return new Response('<project/>',{status:200});};
 assert.equal(await fetchPom('org.example','test','1',{cacheDir:root,fetcher}),'<project/>');
 assert.equal(await fetchPom('org.example','test','1',{cacheDir:root,fetcher}),'<project/>');assert.equal(calls,1);
 policy.setForceUpdate(true);
 assert.equal(await fetchPom('org.example','test','1',{cacheDir:root,fetcher}),'<project/>');assert.equal(calls,2);
 assert.equal(await fetchPom('org.example','test','1',{cacheDir:root,offline:true,fetcher:()=>assert.fail('network')}),'<project/>');
});

test('force-update and offline are rejected together',()=>{
 const r=spawnSync(process.execPath,[path.join(__dirname,'../vigievuln.js'),'-s','.','--offline','--force-update'],{encoding:'utf8'});
 assert.equal(r.status,2);assert.match(r.stderr,/requires an online scan/);
});

test('force-update rechecks a fresh OSV consultation without making the new result stale',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-force-osv-'));
 const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir:root});
 t.after(()=>{policy.setForceUpdate(false);store.close();require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});
 const dep=require('../lib/dep-record').makeDepRecord({ecosystem:'npm',name:'example',version:'1.0.0'});
 const query={source:'osv',ecosystem:'npm',name:'example',version:'1.0.0'};
 store.commit({queries:[{...query,ids:[],fetchedAt:Date.now()-1000,complete:true}]});
 let calls=0;const warnings=[];const fetcher=async()=>{calls++;return Response.json({results:[{}]});};
 const {queryBatch}=require('../lib/osv');
 await queryBatch([dep],{store,fetcher,onWarning:w=>warnings.push(w)});assert.equal(calls,0);
 policy.setForceUpdate(true);
 await queryBatch([dep],{store,fetcher,onWarning:w=>warnings.push(w)});assert.equal(calls,1);
 assert.equal(store.getQuery(query).fresh,true);assert.ok(!warnings.some(w=>w.type==='source-stale'));
});

test('force-update checks the CVE release tag without redownloading an unchanged archive',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-force-cve-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const lib=path.resolve(__dirname,'../lib');
 const script=`const policy=require(${JSON.stringify(path.join(lib,'cache-policy'))}),db=require(${JSON.stringify(path.join(lib,'cache-db'))}).getCacheDb(),c=require(${JSON.stringify(path.join(lib,'cve-download'))}),idx=c.newIndex();idx.meta.builtAt=new Date(Date.now()-10*3600000).toISOString();idx.meta.releaseTag='cve_same';idx.meta.cveCount=0;db.prepare("INSERT INTO cache_snapshots VALUES('cve_lookup',?,1,0,0,?)").run(Date.parse(idx.meta.builtAt),JSON.stringify(idx.meta));let calls=0;require(${JSON.stringify(path.join(lib,'providers'))}).getResource=async(id,type)=>{if(id!=='github'||type!=='cve-release')throw Error('archive downloaded');calls++;return Response.json({tag_name:'cve_same',assets:[{name:'all.zip',browser_download_url:'https://example.test/all.zip'}]})};policy.setForceUpdate(true);c.ensureCveIndex().then(out=>{if(calls!==1||out.meta.builtAt!==idx.meta.builtAt||!out.meta.checkedAt)throw Error('release not revalidated')}).catch(e=>{console.error(e);process.exit(1)})`;
 const r=spawnSync(process.execPath,['-e',script],{cwd:root,env:{...process.env,HOME:root,USERPROFILE:root},encoding:'utf8'});
 assert.equal(r.status,0,r.stderr);
});
