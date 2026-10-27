const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { resolveHostedProxy, checkHostedProxy } = require('../lib/hosted-proxy');

test('hosted proxy selects only the two official origins and requires an account key online', () => {
  assert.equal(resolveHostedProxy({vigievulnProxy:true}, {VIGIEVULN_PROXY_CACHE_TOKEN:'secret'}).proxyCache, 'https://api.vigievuln.fr');
  assert.equal(resolveHostedProxy({vigievulnProxy:'com',proxyCacheToken:'explicit'}, {}).proxyCache, 'https://api.vigievuln.com');
  assert.throws(()=>resolveHostedProxy({vigievulnProxy:'https://evil.invalid'}, {}), /fr or com/);
  assert.throws(()=>resolveHostedProxy({vigievulnProxy:true}, {}), /requires a proxy key/);
  assert.throws(()=>resolveHostedProxy({vigievulnProxy:true,proxyCache:'http://localhost'}, {}), /not both/);
  assert.equal(resolveHostedProxy({vigievulnProxy:true,offline:true}, {}).proxyCacheToken, null);
});

test('preflight authenticates without redirects and fails clearly on expired keys', async () => {
  await checkHostedProxy('https://api.vigievuln.fr', 'secret', async (url, options) => {
    assert.equal(url, 'https://api.vigievuln.fr/v1/proxy/status');
    assert.equal(options.headers.authorization, 'Bearer secret');
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal);
    return Response.json({ok:true,service:'vigievuln-proxy'});
  });
  for (const status of [401,403]) await assert.rejects(checkHostedProxy('https://api.vigievuln.fr', 'secret', async()=>new Response('',{status})), /invalid, expired or revoked/);
  await assert.rejects(checkHostedProxy('https://api.vigievuln.fr','secret',async()=>Response.json({ok:true})), /unexpected/);
});

test('CLI rejects missing hosted credentials before starting a scan', () => {
  const env = {...process.env, VIGIEVULN_PROXY_CACHE_TOKEN:'', FAD_PROXY_CACHE_TOKEN:'', VIGIEVULN_ENV:'', FAD_CHECKER_ENV:'', FORCE_COLOR:'0'};
  const result=spawnSync(process.execPath,[path.join(__dirname,'../vigievuln.js'),'-s',__dirname,'--vigievuln-proxy'],{env,encoding:'utf8'});
  assert.equal(result.status,2);assert.match(result.stderr,/requires a proxy key/);assert.doesNotMatch(result.stdout,/Collection/);
});
