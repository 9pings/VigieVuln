'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {resolveReleaseEvidence,parsePage}=require('../lib/system-inventory/freexian-release-evidence');const providers=require('../lib/providers');
const id='CVE-2026-76642',distribution={id:'debian',versionId:'11',codename:'bullseye'},input={id,sourceName:'util-linux',sourceVersion:'1:2.36.1-8',distribution};
const page=(fixed='(not affected)',extra='')=>`<html><h1>${id}</h1><table><tr><th>Package</th><th>Type</th><th>Release</th><th>Fixed Version</th><th>Urgency</th><th>Origin</th></tr><tr><td><a>util-linux</a></td><td>source</td><td>bullseye</td><td>${fixed}</td><td></td><td>ELA</td></tr>${extra}</table><h2>Notes</h2><pre>[bullseye] &lt;not-affected&gt; explained</pre></html>`;
function fixture(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-freexian-proof-'));t.after(()=>{providers.configureResourceRoute({proxyUrl:null,hosted:false});require('../lib/cache-db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});return dir;}
test('release table verifies CVE, exact source and distribution; matching page replays offline',async t=>{const dir=fixture(t);let calls=0;const fetchResource=async()=>{calls++;return new Response(page())};const first=await resolveReleaseEvidence(input,{cacheDir:dir,fetchResource});assert.equal(first.status,'not-affected');assert.equal(first.evidence.row.release,'bullseye');assert.match(first.evidence.notes,/<not-affected>/);assert.match(first.evidence.sha256,/^[a-f0-9]{64}$/);const offline=await resolveReleaseEvidence(input,{cacheDir:dir,offline:true,fetchResource:()=>assert.fail('network')});assert.equal(offline.status,'not-affected');assert.equal(calls,1);assert.deepEqual(offline.evidence,first.evidence);assert.equal((await resolveReleaseEvidence({...input,distribution:{...distribution,codename:'buster'}},{cacheDir:dir,offline:true})).status,'unknown');assert.throws(()=>parsePage(page(),'CVE-2026-9999'),/identity/);});
test('numeric fixes require installed version at least fixed and ambiguity remains unknown',async t=>{const dir=fixture(t),fetchResource=async()=>new Response(page('1:2.40-1'));assert.equal((await resolveReleaseEvidence(input,{cacheDir:dir,fetchResource})).status,'unknown');assert.equal((await resolveReleaseEvidence({...input,sourceVersion:'1:2.40-1'},{cacheDir:dir,offline:true})).status,'fixed');const duplicate=page('(not affected)','<tr><td>util-linux</td><td>source</td><td>bullseye</td><td>(not affected)</td><td></td><td></td></tr>');assert.equal((await resolveReleaseEvidence(input,{cacheDir:fixture(t),fetchResource:async()=>new Response(duplicate)})).status,'unknown');});
test('malformed pages, HTTP failure and changed proxy origin retain uncertainty',async t=>{const dir=fixture(t);providers.configureResourceRoute({proxyUrl:'https://one.example',hosted:true});const fetchResource=async()=>new Response(page(),{headers:{'x-fad-proxy-fetched-at':new Date().toISOString()}});assert.equal((await resolveReleaseEvidence(input,{cacheDir:dir,fetchResource})).status,'not-affected');providers.configureResourceRoute({proxyUrl:'https://two.example',hosted:true});const failed=await resolveReleaseEvidence(input,{cacheDir:dir,fetchResource:async()=>new Response('',{status:503})});assert.equal(failed.status,'unknown');assert.match(failed.evidence.failure,/503/);assert.throws(()=>parsePage(page('(not affected)').replace('<td>source</td>','<td rowspan="2">source</td>'),id),/unsupported/);});
test('rate limiting retries within shared budget and forced failed refresh persists offline',async t=>{const dir=fixture(t);let calls=0,now=0;const throttle=require('../lib/proxy-throttle').createProxyThrottle({intervalMs:0,maxWaitMs:45000,now:()=>now,sleep:async ms=>{now+=ms;},warn:()=>{},subscribeSkip:()=>null});const fetchResource=async()=>{calls++;return calls===1?new Response('',{status:429,headers:{'retry-after':'3'}}):new Response(page())};const first=await resolveReleaseEvidence(input,{cacheDir:dir,fetchResource,freexianReleaseThrottle:throttle});assert.equal(first.status,'not-affected');assert.equal(calls,2);assert.equal(now,3000);const failed=await resolveReleaseEvidence(input,{cacheDir:dir,forceUpdate:true,fetchResource:async()=>new Response('',{status:503}),freexianReleaseThrottle:throttle});assert.match(failed.evidence.failure,/503/);const offline=await resolveReleaseEvidence(input,{cacheDir:dir,offline:true});assert.equal(offline.status,'not-affected');assert.match(offline.evidence.failure,/503/);});
test('user abort does not publish successful evidence',async t=>{const dir=fixture(t),controller=new AbortController();controller.abort();await assert.rejects(resolveReleaseEvidence(input,{cacheDir:dir,signal:controller.signal,fetchResource:()=>assert.fail('network')}),{name:'AbortError'});const offline=await resolveReleaseEvidence(input,{cacheDir:dir,offline:true});assert.equal(offline.status,'unknown');});
test('an adapter deadline during rate limiting does not abort the audit',async t=>{
 const dir=fixture(t);
 const timedOut=await resolveReleaseEvidence(input,{cacheDir:dir,fetchResource:async()=>{
  throw Object.assign(Error('Proxy request aborted while waiting for rate limit.'),{name:'AbortError'});
 }});
 assert.equal(timedOut.status,'unknown');
 assert.match(timedOut.evidence.failure,/rate limit/);
});

test('Retry-After waits do not consume the next Freexian request timeout',async t=>{
 const dir=fixture(t),signals=[],messages=[];let time=0;
 const throttle=require('../lib/proxy-throttle').createProxyThrottle({
  intervalMs:0,now:()=>time,sleep:async ms=>{time+=ms;await new Promise(r=>setTimeout(r,20));},
  warn:m=>messages.push(m),subscribeSkip:()=>null
 });
 const result=await resolveReleaseEvidence(input,{cacheDir:dir,freexianReleaseTimeoutMs:5,freexianReleaseThrottle:throttle,
  fetchResource:async(type,params,signal)=>{
   signals.push(signal);assert.equal(signal.aborted,false);
   return signals.length===1?new Response(null,{status:429,headers:{'retry-after':'6'}}):new Response(page());
  }});
 assert.equal(result.status,'not-affected');
 assert.equal(signals.length,2);assert.notEqual(signals[0],signals[1]);assert.equal(time,6000);
 assert.match(messages[0],/freexian.vulnerability.*429.*6s/);
});
