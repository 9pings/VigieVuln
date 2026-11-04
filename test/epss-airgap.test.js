'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-epss-airgap-'));
require('../lib/cache-directory').setActiveCacheDir(root);
const {enrichEpss}=require('../lib/epss'),{configureResourceRoute}=require('../lib/providers');
test('hosted EPSS observations survive offline while online queries still revalidate',async t=>{
 t.after(()=>{configureResourceRoute({proxyUrl:null,hosted:false,store:null});require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null});
 let calls=0;const fetcher=async()=>{calls++;return Response.json({data:[{cve:'CVE-2026-10001',epss:'0.42',percentile:'0.9'}]})};
 const first=[{cve:{id:'CVE-2026-10001'}}];await enrichEpss(first,{fetcher});assert.equal(first[0].cve.epssScore,0.42);
 const offline=[{cve:{id:'CVE-2026-10001'}}];await enrichEpss(offline,{offline:true,fetcher:()=>{throw Error('unexpected network')}});assert.equal(offline[0].cve.epssScore,0.42);assert.equal(offline[0].cve.epssPercentile,0.9);
 await enrichEpss([{cve:{id:'CVE-2026-10001'}}],{fetcher});assert.equal(calls,2);
});
