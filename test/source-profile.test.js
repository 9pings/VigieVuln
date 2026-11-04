const { test } = require('node:test');
const assert = require('node:assert/strict');
const { applySourceProfile, proxyOnlyFetch, officialAccountFetch } = require('../lib/source-profile');

test('default profile preserves legacy behaviour', () => {
 const base = {osv:true, nvd:true, euvd:true, certfr:true, appPlugins:'auto', binaries:true};
 assert.deepEqual(applySourceProfile(base).options, {...base,sourceProfile:'all'});
});

test('regional profiles exclude the opposite vulnerability sources and ambiguous cached feeds', () => {
 const base = {osv:true,osvDb:true,nvd:true,epss:true,kev:true,euvd:true,certfr:true,retire:true,appPlugins:'auto',binaries:true};
 const eu = applySourceProfile({...base,sourceProfile:'eu'});
 assert.equal(eu.options.osv,false); assert.equal(eu.options.osvDb,false);assert.equal(eu.options.nvd,false);
 assert.equal(eu.options.euvd,true);assert.equal(eu.options.disableCveProject,true);
 assert.equal(eu.options.appPlugins,'none');assert.equal(eu.options.binaries,true);assert.equal(eu.options.disableBinaryId,true);assert.equal(eu.warnings.length,1);
 const us = applySourceProfile({...base,sourceProfile:'us'});
 assert.equal(us.options.euvd,false);assert.equal(us.options.certfr,false);assert.equal(us.options.packagistAudit,false);
 assert.equal(us.options.osv,true);assert.equal(us.options.disableGcve,true);
 assert.throws(()=>applySourceProfile({...base,sourceProfile:'eu'}, {explicit:name=>name==='osvDb'}), /unavailable/);
 assert.throws(()=>applySourceProfile({...base,sourceProfile:'eu',wordfenceFeed:'custom.json'}), /origin cannot be verified/);
});

test('proxy-only transport refuses different hosts and redirects', async () => {
 const calls = [];
 const guarded = proxyOnlyFetch(async (url, init)=>{calls.push([url,init]);return new Response('ok');}, 'https://proxy.example');
 await guarded('https://proxy.example/v1/resource');
 assert.equal(calls[0][1].redirect,'error');
 assert.throws(()=>guarded('https://other.example/v1/resource'), /blocked/);
 assert.throws(()=>guarded('https://proxy.example.evil.test/v1/resource'), /blocked/);
 assert.equal(applySourceProfile({sourceProfile:'proxy',proxyCache:'https://proxy.example',offline:true}).options.offline,true);
});

test('official account bootstrap transport allows only exact routes and methods without redirects', async () => {
 const calls=[];const fetcher=officialAccountFetch(async (url,init)=>{calls.push({url,init});return new Response('ok');});
 await fetcher('https://www.vigievuln.fr/v1/accounts/me',{method:'GET'});
 await fetcher('https://www.vigievuln.fr/v1/accounts/proxy-keys',{method:'POST'});
 assert.equal(calls.length,2);assert.ok(calls.every(x=>x.init.redirect==='error'));
 for(const [url,method] of [['https://other.example/v1/accounts/me','GET'],['https://www.vigievuln.fr/v1/accounts/me?x=1','GET'],['https://www.vigievuln.fr/v1/accounts/me','POST'],['https://www.vigievuln.fr/v1/accounts/delete','POST'],['https://api.vigievuln.fr/v1/accounts/me','GET']])
  assert.throws(()=>fetcher(url,{method}),/blocked/);
});
