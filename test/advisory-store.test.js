'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openAdvisoryStore, DEFAULT_QUERY_TTL_MS } = require('../lib/advisory-store');
const now = Date.now() - 1000;
const document = (id, modified = '2026-01-01T00:00:00Z', extra = {}) => ({
  id, modified, published: '2025-01-01T00:00:00Z', details: 'Full native document ' + 'x'.repeat(3000),
  affected: [{ package: { ecosystem: 'npm', name: 'demo' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }], ecosystem_specific: { custom: true } }], ...extra,
});
const record = (doc, extra = {}) => ({ source: 'osv', document: doc, fetchedAt: now, provenance: { transport: 'direct' }, ...extra });
const tuple = { source: 'osv', ecosystem: 'npm', name: 'demo', version: '1.0.0' };
const proof = (ids, extra = {}) => ({ ...tuple, ids, complete: true, fetchedAt: now, provenance: { transport: 'direct' }, ...extra });
function fixture(t) {
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-advisory-store-'));
  const store = openAdvisoryStore({ cacheDir });
  t.after(() => { store.close(); fs.rmSync(cacheDir, { recursive: true, force: true }); });
  return { cacheDir, store };
}
test('native documents, arbitrary fields and multi-version ranges survive persistent merge', t => {
  const { store, cacheDir } = fixture(t), first = document('A');
  store.commit({ records: [record(first)], queries: [proof(['A'])] });
  store.commit({ records: [record(document('B'))], queries: [proof(['B'], { fetchedAt: now + 1 })] });
  const reopened = openAdvisoryStore({ cacheDir });
  assert.deepEqual(reopened.getRecord('osv', 'A').document, first);
  assert.deepEqual(reopened.getPackageRecords('npm', 'demo').map(r => r.document.id).sort(), ['A', 'B']);
  assert.deepEqual(reopened.getQuery(tuple).ids, ['B'], 'exact query proof is independent from stored package advisories');
  assert.equal(reopened.getQuery({ ...tuple, version: '1.1.0' }), null, 'ranges never imply query completeness');
  reopened.close();
});
test('TTL changes revalidation only and zero TTL retains exact offline evidence', t => {
  const { store } = fixture(t);
  store.commit({ queries: [proof([])] });
  assert.equal(store.getQuery(tuple, { now, ttlMs: DEFAULT_QUERY_TTL_MS }).fresh, true);
  assert.equal(store.getQuery(tuple, { now: now + DEFAULT_QUERY_TTL_MS }).fresh, false);
  assert.equal(store.getQuery(tuple, { now, ttlMs: 0 }).fresh, false);
  assert.deepEqual(store.getQuery(tuple, { now: now + DEFAULT_QUERY_TTL_MS }).ids, []);
  assert.throws(() => store.getQuery(tuple, { ttlMs: -1 }), /TTL/);
});
test('source revisions win over arrival order and tombstones resist stale resurrection', t => {
  const { store } = fixture(t);
  store.commit({ records: [record(document('A', '2026-02-01T00:00:00Z', { withdrawn: '2026-02-01T00:00:00Z' }))] });
  store.commit({ records: [record(document('A'), { fetchedAt: now + 2 })] });
  assert.equal(store.getPackageRecords('npm', 'demo').length, 0);
  assert.ok(store.getRecord('osv', 'A').document.withdrawn);
  store.commit({ records: [record(document('A', '2026-02-01T00:00:00Z'), { fetchedAt: now + 3 })] });
  assert.ok(store.getRecord('osv', 'A').document.withdrawn, 'same revision cannot resurrect a withdrawal');
  store.commit({ records: [record(document('A', '2026-03-01T00:00:00Z'))] });
  assert.equal(store.getPackageRecords('npm', 'demo').length, 1, 'strictly newer upstream revision may reinstate advisory');
});
test('native source identities and provenance remain independent for identical IDs', t => {
  const { store } = fixture(t);
  store.commit({ records: [record(document('CVE-2026-1')), record({ id: 'CVE-2026-1', native: { vendor: 'GCVE' } }, { source: 'gcve', packages: [{ ecosystem: 'npm', name: 'demo' }], provenance: { transport: 'proxy', origin: 'https://proxy.example' } })] });
  assert.equal(store.getRecord('gcve', 'CVE-2026-1').document.native.vendor, 'GCVE');
  assert.equal(store.getRecord('osv', 'CVE-2026-1').provenance.transport, 'direct');
  assert.equal(store.getPackageRecords('npm', 'demo').length, 1);
  assert.equal(store.getPackageRecords('npm', 'demo', { source: null }).length, 2);
});
test('package renames replace index membership without erasing unrelated advisories', t => {
  const { store } = fixture(t);
  store.commit({ records: [record(document('A')), record(document('B'))] });
  const updated = document('A', '2026-02-01T00:00:00Z'); updated.affected[0].package.name = 'renamed';
  store.commit({ records: [record(updated)] });
  assert.deepEqual(store.getPackageRecords('npm', 'demo').map(r => r.document.id), ['B']);
  assert.deepEqual(store.getPackageRecords('npm', 'renamed').map(r => r.document.id), ['A']);
});
test('incomplete/malformed transactions never publish records or verified queries', t => {
  const { store } = fixture(t);
  assert.throws(() => store.commit({ records: [record(document('A'))], queries: [proof(['MISSING'])] }), /missing advisory detail/);
  assert.equal(store.getRecord('osv', 'A'), null);
  assert.throws(() => store.commit({ queries: [proof([], { complete: false })] }), /incomplete/);
  assert.throws(() => store.commit({ records: [record(document('A', 'not-a-date'))] }), /modified/);
  assert.equal(store.getQuery(tuple), null);
});
test('a failed SQLite transaction publishes neither records nor query proof', t => {
  const { store, cacheDir } = fixture(t);
  assert.throws(() => store.commit({records:[record(document('A'))],queries:[proof(['missing'])]}),/missing advisory detail/);
  const reopened=openAdvisoryStore({cacheDir});
  assert.equal(reopened.getRecord('osv','A'),null);
  assert.equal(reopened.getQuery(tuple),null);
  reopened.close();
});
test('late query response cannot replace newer authoritative tuple proof', t => {
  const { store } = fixture(t);
  store.commit({ records: [record(document('A'))], queries: [proof([], { fetchedAt: now + 10 })] });
  store.commit({ queries: [proof(['A'])] });
  assert.deepEqual(store.getQuery(tuple).ids, []);
});
test('targeted reads do not decode unrelated advisory bodies', t => {
  const { store } = fixture(t);
  store.commit({ records: [record(document('A')),record(document('B'))] });
  store.db.prepare('UPDATE advisory_records SET envelope_deflate=? WHERE source=? AND id=?').run(Buffer.from('broken'),'osv','B');
  assert.equal(store.getRecord('osv', 'A').document.id, 'A');
  assert.throws(()=>store.getRecord('osv','B'));
});
test('streamed seed imports preserve withdrawals and never create query coverage', async t => {
  const { store } = fixture(t);
  async function* records() { yield document('A'); yield document('B', '2026-01-01T00:00:00Z', { withdrawn: '2026-01-01T00:00:00Z' }); }
  assert.equal(await store.importRecords(records(), { fetchedAt: now, batchSize: 1 }), 2);
  assert.equal(store.getPackageRecords('npm', 'demo').length, 1);
  assert.equal(store.getPackageRecords('npm', 'demo', { includeWithdrawn: true }).length, 2);
  assert.equal(store.getQuery(tuple), null);
});
test('verified complete seed coverage is separate from exact query evidence', async t => {
  const { store } = fixture(t);
  await store.importRecords([document('A')], { fetchedAt: now, coverages: [{ source: 'osv', ecosystem: 'npm', fetchedAt: now, complete: true }] });
  const view = store.getPackageView({ ...tuple, name: 'unlisted' });
  assert.equal(view.query, null);
  assert.equal(view.coverage.complete, true);
  assert.deepEqual(view.records, []);
  assert.equal(store.getPackageView({ ...tuple, ecosystem: 'Go' }).coverage, null);
});
test('failed streamed seed never publishes partial records or completeness', async t => {
  const { store } = fixture(t);
  async function* failing() { yield document('A'); throw new Error('checksum failed'); }
  await assert.rejects(store.importRecords(failing(), { batchSize: 1, coverages: [{ source: 'osv', ecosystem: 'npm', fetchedAt: now, complete: true }] }), /checksum/);
  assert.equal(store.getRecord('osv', 'A'), null);
  assert.equal(store.getPackageView(tuple).coverage, null);
});
test('package view preserves API hits without affected coordinates and detects newer data', t => {
  const { store } = fixture(t);
  store.commit({ records: [record({ id: 'A', affected: [{ ranges: [] }] })], queries: [proof(['A'])] });
  let view = store.getPackageView(tuple);
  assert.equal(view.queryRecords[0].document.id, 'A');
  assert.equal(view.querySuperseded, false);
  store.commit({ records: [record(document('B'), { fetchedAt: now + 1 })] });
  view = store.getPackageView(tuple);
  assert.equal(view.querySuperseded, true);
  assert.equal(view.records.length, 2);
});
test('native CVEProject records need no invented OSV id field', t => {
  const { store } = fixture(t);
  const native = { cveMetadata: { cveId: 'CVE-2026-1234' }, containers: { cna: { title: 'Original' } } };
  store.commit({ records: [record(native, { source: 'cveproject' })] });
  assert.deepEqual(store.getRecord('cveproject', 'CVE-2026-1234').document, native);
});
test('co-observed document hashes preserve authoritative API evidence without refreshing TTL', t => {
  const { store } = fixture(t), crypto = require('node:crypto'), doc = document('A');
  store.commit({ records: [record(doc, { fetchedAt: now + 50 })], queries: [proof(['A'], { provenance: { documentHashes: { A: crypto.createHash('sha256').update(JSON.stringify(doc)).digest('hex') } } })] });
  let view = store.getPackageView(tuple);
  assert.equal(view.querySuperseded, false);
  assert.equal(view.query.fetchedAt, now);
  store.commit({ records: [record(doc, { fetchedAt: now + 100, provenance: { transport: 'proxy' } })] });
  view = store.getPackageView(tuple);
  assert.equal(view.querySuperseded, false, 'identical document refresh does not invalidate every version query');
  assert.equal(view.records[0].observations.length, 2);
  store.commit({ records: [record(document('A', '2026-02-01T00:00:00Z'), { fetchedAt: now + 200 })] });
  assert.equal(store.getPackageView(tuple).querySuperseded, true, 'changed document supersedes old fingerprint');
});
test('native OSV tombstone overrides projected Maven legacy record', t => {
  const { store } = fixture(t), doc = document('A');
  doc.affected[0].package = { ecosystem: 'Maven', name: 'g:a' };
  store.commit({ records: [record(doc, { source: 'osv-legacy-maven' })] });
  const maven = { ...tuple, ecosystem: 'Maven', name: 'g:a' };
  assert.equal(store.getPackageView(maven).records[0].source, 'osv-legacy-maven');
  store.commit({ records: [record({ id: 'A', withdrawn: '2026-02-01T00:00:00Z' })] });
  assert.deepEqual(store.getPackageView(maven).records, []);
});
test('a newer partial snapshot retains the date of the complete baseline', t => {
  const { store } = fixture(t), coverage = { source: 'osv', ecosystem: 'npm', fetchedAt: now, complete: true };
  store.commit({ coverages: [coverage] });
  store.commit({ coverages: [{ ...coverage, fetchedAt: now + 1, complete: false }] });
  const coverageView = store.getPackageView(tuple).coverage;
  assert.equal(coverageView.complete, false, 'latest partial collection is visible');
  assert.equal(coverageView.fetchedAt, now + 1);
  assert.equal(coverageView.lastComplete.complete, true);
  assert.equal(coverageView.lastComplete.fetchedAt, now);
});
test('concurrent writers preserve disjoint updates under the store lock', async t => {
  const { store, cacheDir } = fixture(t), { spawn } = require('node:child_process');
  const modulePath = require.resolve('../lib/advisory-store');
  const code = `const {openAdvisoryStore}=require(process.argv[1]); const store=openAdvisoryStore({cacheDir:process.argv[2]}); for(let i=0;i<12;i++)store.commit({records:[{source:'osv',document:{id:process.argv[3]+'-'+i,affected:[{package:{ecosystem:'npm',name:'demo'},versions:['1.0.0']}]},fetchedAt:Date.now()}]});`;
  await Promise.all(['LEFT', 'RIGHT'].map(prefix => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', code, modulePath, cacheDir, prefix], { stdio: ['ignore', 'ignore', 'pipe'] });
    let error = ''; child.stderr.on('data', chunk => { error += chunk; });
    child.on('error', reject); child.on('exit', status => status === 0 ? resolve() : reject(new Error(error)));
  })));
  assert.equal(store.getPackageRecords('npm', 'demo').length, 24);
});
test('native CVEProject and GCVE revisions keep REJECTED tombstones isolated', async t => {
  const { store } = fixture(t), { isWithdrawn } = require('../lib/advisory-store');
  const native = (source, state, updated) => ({ source, id: 'CVE-2026-1234', fetchedAt: now,
    packages: [{ ecosystem: 'npm', name: 'demo' }], document: { cveMetadata: { cveId: 'CVE-2026-1234', state, dateUpdated: updated } } });
  await store.importEnvelopes([
    native('gcve', 'PUBLISHED', '2026-01-01T00:00:00Z'),
    native('cveproject', 'REJECTED', '2026-02-01T00:00:00Z'),
  ], { coverages: [{ source: 'cveproject', ecosystem: '*', fetchedAt: now, complete: false }] });
  store.commit({ records: [{ ...native('cveproject', 'PUBLISHED', '2026-01-01T00:00:00Z'), fetchedAt: now + 20 }] });
  assert.equal(isWithdrawn(store.getRecord('cveproject', 'CVE-2026-1234')), true);
  assert.equal(isWithdrawn(store.getRecord('gcve', 'CVE-2026-1234')), false);
  assert.equal(store.getPackageRecords('npm', 'demo', { source: 'cveproject' }).length, 0);
  assert.equal(store.getSourceCoverage('cveproject').complete, false);
});
test('query summary reports exact consulted tuples and explicit upstream staleness', t => {
  const { store } = fixture(t);
  store.commit({ queries: [proof([]), proof([], { version: '2.0.0', provenance: { transport: 'proxy', stale: true } })] });
  assert.equal(store.getQuery({ ...tuple, version: '2.0.0' }, { now }).fresh, false);
  assert.deepEqual(store.getQuerySummary('osv', { now }), { count: 2, oldestFetchedAt: now, newestFetchedAt: now, staleCount: 1, complete: false, scope: 'consulted-package-versions' });
  assert.equal(store.getSourceCoverage('osv', 'npm'), null, 'consulted tuples never imply complete ecosystem coverage');
});
