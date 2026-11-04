'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-euvd-airgap-'));
require('../lib/cache-directory').setActiveCacheDir(root);
const {enrichEuvd}=require('../lib/euvd'),{configureResourceRoute}=require('../lib/providers');
test('hosted EUVD matches and source freshness are preserved offline',async t=>{
 t.after(()=>{configureResourceRoute({proxyUrl:null,hosted:false,store:null});require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null});
 const date=new Date(Date.now()-3600000).toISOString(),id='CVE-2026-10001';
 const fetcher=async()=>Response.json({items:[{cve:id,id:'EUVD-2026-123',exploitedSince:'2026-01-01'}]},{headers:{'x-fad-proxy':'stale','x-fad-proxy-fetched-at':date}});
 const online=[{cve:{id}}];await enrichEuvd(online,{hostedProxy:true,fetcher});assert.equal(online[0].cve.euvd.id,'EUVD-2026-123');
 const offline=[{cve:{id}}],stale=[];await enrichEuvd(offline,{offline:true,fetcher:()=>{throw Error('unexpected network')},onStale:at=>stale.push(at)});
 assert.deepEqual(offline[0].cve.euvd,online[0].cve.euvd);assert.deepEqual(stale,[date]);
 const data=require('../lib/cache-repository').createCacheRepository(root).get('catalogue','euvd-targeted').value;
 assert.equal(data.entries[id].fetchedAt,Date.parse(date));assert.equal(data.entries[id].stale,true);
});
