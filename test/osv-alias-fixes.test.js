require('./helpers/isolated-cache')('osv-alias-fixes');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openAdvisoryStore } = require('../lib/advisory-store');
const { queryBatch } = require('../lib/osv');
const { makeDepRecord } = require('../lib/dep-record');
const { mergeBySource } = require('../lib/merge-sources');
const { configureResourceRoute } = require('../lib/providers');
const { generateHtmlReport } = require('../lib/cve-report');
const { buildFindings } = require('../lib/json-export');

// Native fields from the live Express 4.17.1 comparison. Both source documents
// share CVE aliases, but the older document's 0.1.10 target remains vulnerable
// through the newer document until 0.1.13. No live network is used by this test.
const older = {
  id: 'GHSA-9wv6-86v2-598j', modified: '2026-09-10T03:50:18.832560863Z',
  aliases: ['CVE-2024-45296', 'CVE-2026-4867', 'GHSA-37ch-88jc-xwx2'],
  affected: [['0.2.0', '1.9.0'], ['0', '0.1.10'], ['7.0.0', '8.0.0'], ['2.0.0', '3.3.0'], ['4.0.0', '6.3.0']]
    .map(([introduced, fixed]) => ({ package: { ecosystem: 'npm', name: 'path-to-regexp' },
      ranges: [{ type: 'SEMVER', events: [{ introduced }, { fixed }] }],
      database_specific: { source: 'https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2024/09/GHSA-9wv6-86v2-598j/GHSA-9wv6-86v2-598j.json' } })),
};
const newer = {
  id: 'GHSA-37ch-88jc-xwx2', modified: '2026-09-10T03:50:36.768786245Z',
  aliases: ['CVE-2024-45296', 'CVE-2026-4867', 'GHSA-9wv6-86v2-598j'],
  affected: [{ package: { ecosystem: 'npm', name: 'path-to-regexp' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.1.13' }] }],
    database_specific: { source: 'https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2026/03/GHSA-37ch-88jc-xwx2/GHSA-37ch-88jc-xwx2.json' } }],
};

test('Express path-to-regexp aliases cannot merge into a fix still affected by a native OSV document', async t => {
  for (const order of [[newer, older], [older, newer]]) for (const offline of [false, true]) {
    await t.test(`${offline ? 'seed' : 'direct'} / first ${order[0].id}`, async t => {
      const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-osv-alias-fix-'));
      const resetRoute = () => configureResourceRoute({ proxyUrl: null, hosted: false, token: null,
        store: null, hostedStore: null, health: null, fetcher: null });
      resetRoute();
      const store = openAdvisoryStore({ cacheDir });
      t.after(() => { resetRoute(); store.close(); require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); });
      if (offline) await store.importRecords(order, { source: 'osv', fetchedAt: Date.now() - 1000,
        provenance: { transport: 'seed' } });
      const dep = makeDepRecord({ ecosystem: 'npm', name: 'path-to-regexp', version: '0.1.7' });
      const fetcher = async (url) => {
        if (offline) assert.fail('offline network');
        if (url.endsWith('/querybatch')) return Response.json({ results: [{ vulns: order.map(v => ({ id: v.id })) }] });
        const document = order.find(v => url.endsWith('/' + v.id));
        assert.ok(document); return Response.json(document);
      };
      const raw = await queryBatch([dep], { cacheDir, store, offline, fetcher, onProgress() {} });
      const merged = mergeBySource([], raw);
      assert.equal(merged.length, 1);
      assert.equal(merged[0].cve.id, 'CVE-2024-45296');
      assert.equal(merged[0].cve.fixVersion, null, 'divergent advisory targets require review before proposing an upgrade');
      assert.equal(merged[0].cve.fixConflict, 'inconsistent-advisory-targets');
      assert.equal(merged[0].cve.branchFix, undefined);
      const json = buildFindings({ cveMatches: merged, resolvedDeps: new Map([[dep.coordKey, dep]]), projectInfo: { name: 'fixture' } });
      assert.equal(json.cve.length, 1, 'conflicting fixes must never erase the vulnerability finding');
      assert.equal(json.cve[0].fixVersion, null);
      assert.equal(json.cve[0].fixConflict, 'inconsistent-advisory-targets');
      // Report rendering performs another merge through its internal mergeMatches.
      const html = generateHtmlReport({ cveMatches: raw, devCveMatches: [], embeddedMatches: [], retireMatches: [],
        eolResults: [], obsoleteResults: [], outdatedResults: [], resolvedDeps: new Map([[dep.coordKey, dep]]),
        projectInfo: { name: 'fixture' }, warnings: [] });
      assert.match(html, /manual triage/);
      assert.doesNotMatch(html, /0\.1\.10/, 'the report must not revive an unsafe upgrade while merging duplicate rows');
    });
  }
});
