'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createAccountClient, ACCOUNT_ORIGIN, DEFAULT_TIMEOUT_MS } = require('../lib/account-client');
const { createAccountSessionStore } = require('../lib/account-session');

const NOW = 1800000000000;
const SESSION = { token: 'fad_account-session', expiresAt: NOW + 60000 };
const ACCOUNT = { id: 'account-id', email: 'alice@example.test', projectLimit: 10 };
const LOGIN = { ...SESSION, tokenType: 'Bearer', account: ACCOUNT };
const CREDENTIALS = { email: ACCOUNT.email, password: 'never-store-this-password' };

function memoryStore(initial = null) {
  let value = initial;
  return { read: () => value, write: session => { value = session; }, clear: () => { value = null; } };
}

function client(fetcher, sessionStore = memoryStore(), options = {}) {
  return createAccountClient({ fetcher, sessionStore, now: () => NOW, ...options });
}

test('login/me/logout use only the fixed account API and never create proxy keys', async () => {
  const calls = [];
  const store = memoryStore();
  const api = client(async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/login')) return Response.json(LOGIN);
    if (url.endsWith('/me')) return Response.json({ account: ACCOUNT });
    return Response.json({ revoked: 1 });
  }, store, { origin: 'https://evil.invalid', proxyCacheToken: 'proxy-secret' });
  assert.equal(ACCOUNT_ORIGIN, 'https://www.vigievuln.fr');
  assert.equal(DEFAULT_TIMEOUT_MS, 15000);
  assert.deepEqual(await api.login({ ...CREDENTIALS, proxyCacheToken: 'proxy-secret' }), { account: ACCOUNT, expiresAt: SESSION.expiresAt });
  assert.deepEqual(store.read(), SESSION);
  assert.deepEqual(await api.me(), { account: ACCOUNT });
  assert.deepEqual(await api.logout(), { revoked: 1 });
  assert.equal(store.read(), null);
  assert.deepEqual(calls.map(c => [c.url, c.init.method]), [
    [ACCOUNT_ORIGIN + '/v1/accounts/login', 'POST'],
    [ACCOUNT_ORIGIN + '/v1/accounts/me', 'GET'],
    [ACCOUNT_ORIGIN + '/v1/accounts/logout', 'POST'],
  ]);
  assert.deepEqual(JSON.parse(calls[0].init.body), CREDENTIALS);
  assert.equal(calls[0].init.headers.authorization, undefined);
  assert.equal(calls[1].init.body, undefined);
  assert.equal(calls[2].init.body, '{}');
  for (const { init } of calls) {
    assert.equal(init.redirect, 'error');
    assert.equal(init.credentials, 'omit');
    assert.equal(init.cache, 'no-store');
    assert.ok(init.signal instanceof AbortSignal);
    assert.doesNotMatch(JSON.stringify(init), /proxy-secret/);
  }
  for (const { init } of calls.slice(1)) assert.equal(init.headers.authorization, 'Bearer ' + SESSION.token);
});

test('a signed-in account can explicitly create a separate proxy key', async () => {
  let call;
  const api=client(async (url,init)=>{call={url,init};return Response.json({key:{token:'proxy-key'}},{status:201})},memoryStore(SESSION));
  assert.deepEqual(await api.createProxyKey(),{token:'proxy-key'});
  assert.equal(call.url,ACCOUNT_ORIGIN+'/v1/accounts/proxy-keys');
  assert.equal(call.init.headers.authorization,'Bearer '+SESSION.token);
});

test('real private store survives client recreation without retaining a password', { skip: typeof process.getuid !== 'function' }, async t => {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-account-client-'));
  t.after(() => fs.rmSync(homeDir, { recursive: true, force: true }));
  const store = createAccountSessionStore({ homeDir, now: () => NOW });
  await client(async () => Response.json(LOGIN), store).login(CREDENTIALS);
  assert.deepEqual(JSON.parse(fs.readFileSync(store.filePath)), SESSION);
  const reopened = createAccountSessionStore({ homeDir, now: () => NOW });
  await client(async (_, init) => {
    assert.equal(init.headers.authorization, 'Bearer ' + SESSION.token);
    return Response.json({ account: ACCOUNT });
  }, reopened).me();
  await client(async () => { throw Error('network unavailable'); }, reopened).logout().catch(error => {
    assert.equal(error.code, 'NETWORK_ERROR');
  });
  assert.equal(fs.existsSync(store.filePath), false);
  assert.equal(fs.existsSync(path.join(homeDir, '.fad-checker')), false);
});

test('missing, expired and unsafe sessions never reach the transport', async () => {
  let calls = 0;
  for (const [session, code] of [[null, 'NOT_AUTHENTICATED'], [{ ...SESSION, expiresAt: NOW }, 'SESSION_EXPIRED'],
    [{ ...SESSION, token: 'bad\r\nAuthorization: injected' }, 'INVALID_SESSION']]) {
    await assert.rejects(client(async () => { calls++; }, memoryStore(session)).me(), { code });
  }
  assert.equal(calls, 0);
  assert.deepEqual(await client(async () => { calls++; }).logout(), { revoked: 0 });
  const expired = memoryStore({ ...SESSION, expiresAt: NOW });
  assert.deepEqual(await client(async () => { calls++; }, expired).logout(), { revoked: 0 });
  assert.equal(expired.read(), null);
  assert.equal(calls, 0);
});

test('invalid credentials and timeouts are rejected locally', async () => {
  let calls = 0;
  const api = client(async () => { calls++; });
  for (const credentials of [undefined, null, {}, { ...CREDENTIALS, email: ' ' }, { ...CREDENTIALS, password: '' },
    { ...CREDENTIALS, password: 'x'.repeat(513) }, { ...CREDENTIALS, email: 'x'.repeat(255) }]) {
    await assert.rejects(api.login(credentials), { code: 'INVALID_CREDENTIALS' });
  }
  assert.equal(calls, 0);
  for (const timeoutMs of [0, -1, 1.5, Infinity, 2147483648]) {
    assert.throws(() => client(async () => {}, memoryStore(), { timeoutMs }), { code: 'INVALID_OPTIONS' });
  }
});

test('HTTP errors are typed and never reflect server secrets; failed login preserves the previous session', async () => {
  for (const [status, code] of [[400, 'HTTP_ERROR'], [401, 'UNAUTHORIZED'], [403, 'FORBIDDEN'], [429, 'RATE_LIMITED'], [500, 'HTTP_ERROR'], [503, 'HTTP_ERROR']]) {
    const store = memoryStore(SESSION);
    const api = client(async () => Response.json({ error: CREDENTIALS.password, token: SESSION.token }, { status }), store);
    await assert.rejects(api.login(CREDENTIALS), error => {
      assert.equal(error.code, code);
      assert.equal(error.status, status);
      assert.doesNotMatch(error.stack + JSON.stringify(error), /never-store-this-password|fad_account-session/);
      return true;
    });
    assert.deepEqual(store.read(), SESSION);
  }
});

test('me clears rejected sessions only on 401, retaining them on transient errors and forbidden responses', async () => {
  for (const status of [401, 403, 429, 500]) {
    const store = memoryStore(SESSION);
    await assert.rejects(client(async () => new Response('', { status }), store).me(), { status });
    assert.deepEqual(store.read(), status === 401 ? null : SESSION);
  }
});

test('redirects and already-followed responses are refused without persisting a session', async () => {
  for (const status of [301, 302, 303, 307, 308]) {
    const store = memoryStore();
    let calls = 0;
    await assert.rejects(client(async () => {
      calls++;
      return new Response(null, { status, headers: { location: 'https://evil.invalid/steal' } });
    }, store).login(CREDENTIALS), { code: 'REDIRECT_REFUSED' });
    assert.equal(calls, 1);
    assert.equal(store.read(), null);
  }
  for (const property of [{ redirected: true }, { url: 'https://evil.invalid/steal' }]) {
    const response = Response.json(LOGIN);
    for (const [name, value] of Object.entries(property)) Object.defineProperty(response, name, { value });
    await assert.rejects(client(async () => response).login(CREDENTIALS), { code: 'REDIRECT_REFUSED' });
  }
});

test('malformed login responses cannot replace a valid session', async () => {
  for (const value of [null, [], {}, { ...LOGIN, token: '' }, { ...LOGIN, token: 'bad\nheader' },
    { ...LOGIN, expiresAt: NOW }, { ...LOGIN, expiresAt: String(SESSION.expiresAt) },
    { ...LOGIN, tokenType: 'Basic' }, { ...LOGIN, account: {} }]) {
    const store = memoryStore(SESSION);
    await assert.rejects(client(async () => Response.json(value), store).login(CREDENTIALS), { code: 'INVALID_RESPONSE' });
    assert.deepEqual(store.read(), SESSION);
  }
  for (const response of [new Response('secret-not-json', { headers: { 'content-type': 'application/json' } }),
    new Response('<html>secret</html>'), Response.json({ value: 'x'.repeat(65536) }), new Response(null, { status: 204 })]) {
    await assert.rejects(client(async () => response).login(CREDENTIALS), error => {
      assert.equal(error.code, 'INVALID_RESPONSE');
      assert.doesNotMatch(error.stack, /secret-not-json/);
      return true;
    });
  }
});

test('malformed me and logout responses are reported; logout still clears the local session', async () => {
  await assert.rejects(client(async () => Response.json({ account: {} }), memoryStore(SESSION)).me(), { code: 'INVALID_RESPONSE' });
  for (const value of [{}, { revoked: -1 }, { revoked: '1' }, { revoked: 1.5 }]) {
    const store = memoryStore(SESSION);
    await assert.rejects(client(async () => Response.json(value), store).logout(), { code: 'INVALID_RESPONSE' });
    assert.equal(store.read(), null);
  }
});

test('network exceptions are sanitized; logout clears locally for every HTTP/network failure', async () => {
  const failing = async () => { throw new Error(CREDENTIALS.password + SESSION.token); };
  await assert.rejects(client(failing).login(CREDENTIALS), error => {
    assert.equal(error.code, 'NETWORK_ERROR');
    assert.doesNotMatch(error.stack + JSON.stringify(error), /never-store-this-password|fad_account-session/);
    assert.equal(error.cause, undefined);
    return true;
  });
  for (const fetcher of [failing, ...[401, 403, 429, 500].map(status => async () => new Response('', { status }))]) {
    const store = memoryStore(SESSION);
    await assert.rejects(client(fetcher, store).logout());
    assert.equal(store.read(), null);
  }
});

test('timeout covers fetch even when the injected transport ignores abort; late login cannot save', async () => {
  let signal;
  let resolveFetch;
  const store = memoryStore();
  const api = client((_, init) => {
    signal = init.signal;
    return new Promise(resolve => { resolveFetch = resolve; });
  }, store, { timeoutMs: 20 });
  await assert.rejects(api.login(CREDENTIALS), { code: 'TIMEOUT' });
  assert.equal(signal.aborted, true);
  let cancelled = false;
  resolveFetch(new Response(new ReadableStream({ cancel() { cancelled = true; } })));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(store.read(), null);
  assert.equal(cancelled, true);
});

test('timeout also covers a stalled response body and logout still clears locally', async () => {
  let signal;
  const store = memoryStore(SESSION);
  let cancelled = false;
  const stream = new ReadableStream({ cancel() { cancelled = true; } });
  const api = client(async (_, init) => {
    signal = init.signal;
    return new Response(stream, { headers: { 'content-type': 'application/json' } });
  }, store, { timeoutMs: 20 });
  await assert.rejects(api.logout(), { code: 'TIMEOUT' });
  assert.equal(signal.aborted, true);
  assert.equal(store.read(), null);
  assert.equal(cancelled, true);
});

test('an abort-aware transport reports TIMEOUT without exposing its exception', async () => {
  await assert.rejects(client((_, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(new Error(CREDENTIALS.password)), { once: true });
  }), memoryStore(), { timeoutMs: 20 }).login(CREDENTIALS), error => {
    assert.equal(error.code, 'TIMEOUT');
    assert.doesNotMatch(error.stack, /never-store-this-password/);
    return true;
  });
});

test('failed local persistence attempts to revoke the newly issued session and reports the storage error', async () => {
  const calls = [];
  const error = Object.assign(new Error('Unable to save session'), { code: 'SESSION_IO' });
  const store = memoryStore(SESSION);
  store.write = () => { throw error; };
  await assert.rejects(client(async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/login')) return Response.json(LOGIN);
    throw Error('revocation unavailable');
  }, store).login(CREDENTIALS), { code: 'SESSION_IO' });
  assert.equal(calls.length, 2);
  assert.equal(calls[1].url, ACCOUNT_ORIGIN + '/v1/accounts/logout');
  assert.equal(calls[1].init.headers.authorization, 'Bearer ' + SESSION.token);
  assert.deepEqual(store.read(), SESSION);
});

test('local cleanup errors remain visible instead of reporting a successful logout', async () => {
  const store = memoryStore(SESSION);
  store.clear = () => { throw Object.assign(new Error('Unable to clear session'), { code: 'SESSION_IO' }); };
  await assert.rejects(client(async () => Response.json({ revoked: 1 }), store).logout(), { code: 'SESSION_IO' });
});
