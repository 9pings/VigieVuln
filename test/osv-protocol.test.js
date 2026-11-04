const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
// Module loading resolves cache defaults, so isolate that work as well as the
// explicit query cache and resource stores created by each test below.
const fallbackCache = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-osv-protocol-root-'));
const realHomedir = os.homedir;
os.homedir = () => fallbackCache;
require('../lib/cache-directory').setActiveCacheDir(fallbackCache);
after(() => { os.homedir = realHomedir; require('../lib/cache-db').closeCacheDbs(); fs.rmSync(fallbackCache, { recursive: true, force: true }); });
const { queryBatch, cacheKey } = require('../lib/osv');
const { makeDepRecord } = require('../lib/dep-record');
const { configureResourceRoute } = require('../lib/providers');
const { createSourceHealth } = require('../lib/source-health');
const { createCacheStore } = require('../lib/resource-cache/fs-store');
const { openAdvisoryStore: openStore } = require('../lib/advisory-store');
const stores = new Set();
function openAdvisoryStore(options) { const store = openStore(options); stores.add(store); return store; }
function closeStores() { for (const store of stores) store.close(); stores.clear(); require('../lib/cache-db').closeCacheDbs(); }


const dep = makeDepRecord({ ecosystem: 'maven', namespace: 'org.example', name: 'widget', version: '1.0' });
const record = { id: 'GHSA-protocol-1', summary: 'Fixture', affected: [{
  package: { ecosystem: 'Maven', name: 'org.example:widget' }, versions: ['1.0'],
}] };
const tuple = { source: 'osv', ecosystem: 'Maven', name: 'org.example:widget', version: '1.0' };
function setup(t) {
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-osv-protocol-'));
  configureResourceRoute({ proxyUrl: null, hosted: false, token: null, store: null, hostedStore: null, health: null, fetcher: null });
  t.after(() => {
    configureResourceRoute({ proxyUrl: null, hosted: false, token: null, store: null, hostedStore: null, health: null, fetcher: null });
    closeStores(); fs.rmSync(cacheDir, { recursive: true, force: true });
  });
  return cacheDir;
}
const key = () => cacheKey(dep.groupId, dep.artifactId, dep.version, dep.ecosystem);
const query = (cacheDir, fetcher, extra = {}) => queryBatch([dep], { cacheDir, fetcher, onProgress() {}, ...extra });

test('a complete empty object is cached as an authoritative clean answer and reused offline', async t => {
  const cacheDir = setup(t); let calls = 0;
  assert.deepEqual(await query(cacheDir, async () => { calls++; return Response.json({ results: [{}] }); }), []);
  const warnings = [];
  assert.deepEqual(await query(cacheDir, async () => assert.fail('offline network'), { offline: true, onWarning: w => warnings.push(w) }), []);
  assert.equal(calls, 1);
  assert.deepEqual(warnings, [], 'confirmed empty differs from an absent lookup');
});

test('truncated, invalid and unfinished querybatch results never publish a clean package lookup', async t => {
  const badResults = [
    {}, { results: [] }, { results: [{}, {}] }, { results: [null] }, { results: [[]] },
    { results: [{ error: 'unavailable' }] }, { results: [{ vulns: null }] },
    { results: [{ vulns: [{ id: '../escape' }] }] }, { results: [{ vulns: [{}] }] },
    { results: [{ vulns: 'invalid' }] },
  ];
  for (const [i, body] of badResults.entries()) await t.test(`invalid result ${i}`, async t => {
    const cacheDir = setup(t);
    await assert.rejects(query(cacheDir, async () => Response.json(body)), error => error.code === 'OSV_INCOMPLETE');
    assert.equal(fs.existsSync(path.join(cacheDir, key())), false);
    assert.equal(openAdvisoryStore({ cacheDir }).getQuery(tuple), null, 'invalid responses cannot publish coverage in the common store');
  });
  await t.test('a repeated page token terminates with incomplete coverage', async t => {
    const cacheDir = setup(t); let calls = 0;
    await assert.rejects(query(cacheDir, async () => {
      calls++; return Response.json({ results: [{ vulns: [{ id: record.id }], next_page_token: 'same-token' }] });
    }), error => error.code === 'OSV_INCOMPLETE');
    assert.equal(calls, 2);
    assert.equal(fs.existsSync(path.join(cacheDir, key())), false);
    assert.equal(openAdvisoryStore({ cacheDir }).getQuery(tuple), null);
  });
});

test('querybatch paginates each dependency independently and deduplicates advisory details', async t => {
  const cacheDir = setup(t), other = { ...dep, version: '2.0' }, requests = [], details = [];
  const fetcher = async (url, init) => {
    if (!url.endsWith('/querybatch')) { details.push(url); return Response.json(record); }
    const queries = JSON.parse(init.body).queries; requests.push(queries);
    return Response.json({ results: queries.map(q => q.version === '2.0' ? {} : q.page_token
      ? { vulns: [{ id: record.id }] }
      : { vulns: [{ id: record.id }], next_page_token: 'page-two' }) });
  };
  const matches = await queryBatch([dep, other], { cacheDir, fetcher, onProgress() {} });
  assert.equal(matches.length, 1);
  assert.deepEqual(requests.map(batch => batch.map(q => [q.version, q.page_token])),
    [[['1.0', undefined], ['2.0', undefined]], [['1.0', 'page-two']]]);
  assert.equal(details.length, 1, 'same ID on both pages needs one detail request');
});

test('detail failures do not replace the previous package lookup with a partial ID list', async t => {
  for (const failure of ['http', 'mismatched-id', 'invalid-json']) await t.test(failure, async t => {
    const cacheDir = setup(t);
    const fetchedAt = Date.now() - 48 * 3600000;
    const old = JSON.stringify({ _schema: 2, _fetchedAt: fetchedAt, body: ['GHSA-old'] });
    fs.writeFileSync(path.join(cacheDir, key()), old);
    const store = openAdvisoryStore({ cacheDir });
    store.commit({ records: [{ source: 'osv', document: { ...record, id: 'GHSA-old' }, fetchedAt }],
      queries: [{ ...tuple, ids: ['GHSA-old'], fetchedAt, complete: true }] });
    const fetcher = async url => {
      if (url.endsWith('/querybatch')) return Response.json({ results: [{ vulns: [{ id: record.id }] }] });
      if (failure === 'http') return new Response('', { status: 503 });
      if (failure === 'mismatched-id') return Response.json({ id: 'GHSA-other' });
      return new Response('{');
    };
    await assert.rejects(query(cacheDir, fetcher), error => error.code === 'OSV_INCOMPLETE');
    assert.equal(fs.readFileSync(path.join(cacheDir, key()), 'utf8'), old);
    assert.equal(fs.existsSync(path.join(cacheDir, `vuln_${record.id}.json`)), false);
    assert.deepEqual(store.getQuery(tuple).ids, ['GHSA-old'], 'the previous common-store proof survives a failed detail refresh');
    assert.equal(store.getQuery(tuple).fetchedAt, fetchedAt, 'a failure cannot rejuvenate the previous proof');
    assert.equal(store.getRecord('osv', record.id), null);
  });
});

test('an unverified legacy offline snapshot reports unknown coverage without contacting the network', async t => {
  const cacheDir = setup(t), warnings = [];
  fs.writeFileSync(path.join(cacheDir, key()), JSON.stringify({ _schema: 2, _fetchedAt: Date.now(), body: [record.id] }));
  assert.deepEqual(await query(cacheDir, async () => assert.fail('offline network'),
    { offline: true, onWarning: w => warnings.push(w) }), []);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0].type, 'osv-coverage');
  assert.match(warnings[0].message, /not been checked|incomplete|unavailable/i);
});

test('stale proxy findings remain usable and preserve the declared source freshness', async t => {
  const cacheDir = setup(t), health = createSourceHealth();
  const fetchedAt = '2026-01-01T00:00:00.000Z';
  configureResourceRoute({ proxyUrl: 'https://proxy.example.test', hosted: true, token: 'fixture', health });
  const fetcher = async (_url, init) => {
    const payload = JSON.parse(init.body);
    assert.equal(payload.provider, 'osv');
    assert.equal(init.redirect, 'error');
    assert.equal(init.headers['x-fad-proxy-token'], 'fixture');
    assert.ok(init.headers['x-vigievuln-client-version']);
    return Response.json(payload.type === 'packages' ? { results: [{ vulns: [{ id: record.id }] }] } : record,
      { headers: { 'x-fad-proxy': 'stale', 'x-fad-proxy-fetched-at': fetchedAt } });
  };
  const matches = await query(cacheDir, fetcher);
  assert.equal(matches.length, 1);
  assert.deepEqual(health.stale(), [{ id: 'osv', at: Date.parse(fetchedAt) }]);
  const saved = openAdvisoryStore({ cacheDir });
  assert.equal(saved.getQuery(tuple).fetchedAt, Date.parse(fetchedAt));
  assert.equal(saved.getRecord('osv', record.id).fetchedAt, Date.parse(fetchedAt));
  assert.equal(saved.getQuery(tuple).fresh, false);
  // A stale reply must never create a newly fresh package proof. Switching to
  // direct mode must still refresh instead of silently reusing that stale reply.
  configureResourceRoute({ proxyUrl: null, hosted: false, health: null });
  let refreshes = 0;
  assert.deepEqual(await query(cacheDir, async () => {
    refreshes++; return Response.json({ results: [{}] });
  }), []);
  assert.equal(refreshes, 1, 'the original upstream date, not receive time, controls freshness');
});

test('queryTtlMs zero refreshes both the OSV proof and the underlying local HTTP cache', async t => {
  const cacheDir = setup(t), store = createCacheStore(path.join(cacheDir, 'resources'));
  configureResourceRoute({ store });
  let batchCalls = 0;
  const fetcher = async url => {
    if (!url.endsWith('/querybatch')) return Response.json(record);
    batchCalls++;
    return Response.json({ results: [batchCalls === 1 ? { vulns: [{ id: record.id }] } : {}] });
  };
  assert.equal((await query(cacheDir, fetcher)).length, 1);
  assert.equal(batchCalls, 1);
  assert.deepEqual(await query(cacheDir, fetcher, { queryTtlMs: 0 }), [], 'forced refresh sees the new empty answer');
  assert.equal(batchCalls, 2, 'a still-fresh HTTP response must not override TTL zero');
});
