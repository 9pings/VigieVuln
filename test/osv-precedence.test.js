const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const fallbackCache = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-osv-precedence-root-'));
const realHomedir = os.homedir;
os.homedir = () => fallbackCache;
require('../lib/cache-directory').setActiveCacheDir(fallbackCache);
after(() => { os.homedir = realHomedir; require('../lib/cache-db').closeCacheDbs(); fs.rmSync(fallbackCache, { recursive: true, force: true }); });
const { openAdvisoryStore } = require('../lib/advisory-store');
const { queryBatch } = require('../lib/osv');
const { makeDepRecord } = require('../lib/dep-record');
const { configureResourceRoute } = require('../lib/providers');

const dep = makeDepRecord({ ecosystem: 'maven', namespace: 'org.example', name: 'widget', version: '1.5' });
const tuple = { source: 'osv', ecosystem: 'Maven', name: 'org.example:widget', version: '1.5' };
const resetRoute = () => configureResourceRoute({ proxyUrl: null, hosted: false, token: null,
  store: null, hostedStore: null, health: null, fetcher: null });
function fixture(t) {
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-osv-precedence-'));
  resetRoute();
  const now = Date.now(), earlier = now - 2 * 3600000, consulted = now - 3600000, later = now - 1800000;
  const store = openAdvisoryStore({ cacheDir });
  t.after(() => { resetRoute(); store.close(); require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); });
  const document = (extra = {}) => ({ id: 'GHSA-precedence',
    published: new Date(earlier - 2 * 86400000).toISOString(), modified: new Date(earlier - 86400000).toISOString(),
    affected: [{ package: { ecosystem: 'Maven', name: tuple.name },
      ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.0' }, { fixed: '2.0' }] }] }], ...extra });
  const put = (doc, fetchedAt, transport = 'seed') => store.commit({ records: [
    { source: 'osv', document: doc, fetchedAt, provenance: { transport } },
  ] });
  const proof = (ids, fetchedAt = consulted) => store.commit({ queries: [
    { ...tuple, ids, fetchedAt, complete: true, provenance: { transport: 'direct' } },
  ] });
  const coverage = (complete, fetchedAt = consulted) => store.commit({ coverages: [
    { source: 'osv', ecosystem: 'Maven', complete, fetchedAt, provenance: { transport: 'seed' } },
  ] });
  const scan = (extra = {}) => {
    const warnings = [];
    return queryBatch([dep], { cacheDir, store, offline: true,
      fetcher: async () => assert.fail('offline network'), onWarning: warning => warnings.push(warning), ...extra })
      .then(matches => ({ matches, warnings }));
  };
  return { store, now, earlier, consulted, later, document, put, proof, coverage, scan };
}

test('a newer exact empty query takes precedence over an older seed finding without deleting the advisory', async t => {
  const f = fixture(t), doc = f.document();
  f.put(doc, f.earlier); f.proof([]); f.coverage(true, f.earlier);
  const result = await f.scan();
  assert.deepEqual(result.matches, []);
  assert.deepEqual(result.warnings, []);
  assert.deepEqual(f.store.getRecord('osv', doc.id).document, doc);
});

test('reobserving the same source document after a clean query does not supersede that query', async t => {
  const f = fixture(t), doc = f.document();
  f.put(doc, f.earlier); f.proof([]); f.put(doc, f.later);
  assert.equal(f.store.getRecord('osv', doc.id).contentChangedAt, f.earlier);
  const offline = await f.scan();
  assert.deepEqual(offline.matches, [], 'an observation date cannot override a later consultation about unchanged content');
  const online = await f.scan({ offline: false, fetcher: async () => assert.fail('the unchanged document must not force an online refresh') });
  assert.deepEqual(online.matches, []);
});

test('a new source revision imported after a clean query can add an offline finding and forces online revalidation', async t => {
  const f = fixture(t), old = f.document({ affected: [] });
  f.put(old, f.earlier); f.proof([]);
  const newer = f.document({ modified: new Date(f.later - 1000).toISOString() });
  f.put(newer, f.later);
  assert.equal((await f.scan()).matches.length, 1, 'new seed content supersedes the earlier exact answer');
  let batches = 0;
  const result = await f.scan({ offline: false, fetcher: async url => {
    if (url.endsWith('/querybatch')) { batches++; return Response.json({ results: [{}] }); }
    assert.fail(`unexpected detail request ${url}`);
  } });
  assert.equal(batches, 1, 'the prior query remains inside its TTL but is superseded by new source content');
  assert.deepEqual(result.matches, []);
});

test('a fresh exact query and newer advisory are not made stale by an older seed', async t => {
  const f = fixture(t), old = f.document({affected: []});
  f.put(old, f.earlier); f.proof([]); f.coverage(true, Date.now() - 48 * 3600000);
  f.put(f.document({modified:new Date(f.later - 1000).toISOString()}), f.later);
  const result = await f.scan();
  assert.equal(result.matches.length, 1, 'newer evidence remains applicable');
  assert.equal(result.warnings.filter(w => w.type === 'source-stale').length, 0);
});

test('a withdrawal imported after a positive query remains authoritative against a later stale active document', async t => {
  const f = fixture(t), active = f.document();
  f.put(active, f.earlier); f.proof([active.id]);
  const withdrawn = f.document({ modified: new Date(f.later - 1000).toISOString(), withdrawn: new Date(f.later - 1000).toISOString() });
  f.put(withdrawn, f.later); f.put(active, f.now - 1000, 'proxy');
  assert.ok(f.store.getRecord('osv', active.id).document.withdrawn);
  assert.deepEqual((await f.scan()).matches, []);
  let batches = 0;
  const result = await f.scan({ offline: false, fetcher: async url => {
    assert.ok(url.endsWith('/querybatch'));
    batches++; return Response.json({ results: [{}] });
  } });
  assert.deepEqual(result.matches, []);
  assert.equal(batches, 1, 'withdrawal supersedes the old positive consultation');
});

test('expiring a clean query keeps its offline meaning while online refreshes independently of seed freshness', async t => {
  const f = fixture(t), doc = f.document();
  f.put(doc, f.earlier); f.proof([]); f.coverage(true, f.now - 1000);
  const offline = await f.scan({ queryTtlMs: 60000 });
  assert.deepEqual(offline.matches, []);
  assert.ok(offline.warnings.some(w => w.type === 'source-stale'));
  assert.deepEqual(f.store.getRecord('osv', doc.id).document, doc, 'TTL cannot erase the advisory');
  let batches = 0;
  const online = await f.scan({ offline: false, queryTtlMs: 60000, fetcher: async url => {
    assert.ok(url.endsWith('/querybatch'));
    batches++; return Response.json({ results: [{}] });
  } });
  assert.equal(batches, 1, 'a recent complete seed cannot extend an expired exact query TTL');
  assert.deepEqual(online.matches, []);
});

test('a full seed certifies clean offline coverage while a partial seed leaves coverage unknown', async t => {
  for (const complete of [false, true]) await t.test(`complete=${complete}`, async t => {
    const f = fixture(t); f.coverage(complete);
    const { matches, warnings } = await f.scan();
    assert.deepEqual(matches, []);
    assert.equal(warnings.some(w => w.type === 'osv-coverage'), !complete);
    assert.equal(f.store.getQuery(tuple), null, 'ecosystem coverage never manufactures an exact consultation');
  });
});

test('TTL zero preserves offline findings and timestamps while requiring a fresh online query', async t => {
  const f = fixture(t), doc = f.document();
  f.put(doc, f.earlier); f.proof([doc.id]);
  const offline = await f.scan({ queryTtlMs: 0 });
  assert.equal(offline.matches.length, 1);
  assert.ok(offline.warnings.some(w => w.type === 'source-stale'));
  assert.equal(f.store.getQuery(tuple).fetchedAt, f.consulted);
  let batches = 0;
  const online = await f.scan({ offline: false, queryTtlMs: 0, fetcher: async url => {
    if (url.endsWith('/querybatch')) { batches++; return Response.json({ results: [{ vulns: [{ id: doc.id }] }] }); }
    return Response.json(doc);
  } });
  assert.equal(batches, 1);
  assert.equal(online.matches.length, 1);
  assert.ok(f.store.getQuery(tuple).fetchedAt >= f.now);
  assert.equal(f.store.getRecord('osv', doc.id).contentChangedAt, f.earlier, 'refetching unchanged content only adds an observation');
});
