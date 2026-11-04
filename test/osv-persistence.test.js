'use strict';
require('./helpers/isolated-cache')('osv-persistence');
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { openAdvisoryStore } = require('../lib/advisory-store');
const { queryBatch } = require('../lib/osv');
const { makeDepRecord } = require('../lib/dep-record');
const dep = makeDepRecord({ ecosystem: 'maven', namespace: 'g', name: 'a', version: '1.0' });
const document = (modified, extra = {}) => ({ id: 'GHSA-persistence', modified, summary: 'Fetched old advisory', affected: [{ package: { ecosystem: 'Maven', name: 'g:a' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.0' }] }] }], ...extra });

for (const scenario of ['withdrawn', 'same-revision-withdrawn', 'newer-exclusion', 'equal-revision-newer-observation']) {
  test(`failed persistence retains source revision precedence: ${scenario}`, async t => {
    const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-osv-persistence-'));
    const store = openAdvisoryStore({ cacheDir });
    t.after(() => { store.close(); require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); });
    const incoming = document('2026-01-01T00:00:00Z');
    let previous = document('2026-02-01T00:00:00Z'), fetchedAt = Date.now() - 1000;
    if (scenario.includes('withdrawn')) previous = document(scenario === 'same-revision-withdrawn' ? incoming.modified : previous.modified, { withdrawn: '2026-01-01T00:00:00Z' });
    if (scenario === 'newer-exclusion') previous.affected[0].ranges[0].events = [{ introduced: '2.0' }, { fixed: '3.0' }];
    if (scenario === 'equal-revision-newer-observation') { previous = document(incoming.modified, { summary: 'Known newer observation' }); fetchedAt = Date.now() + 10000; }
    store.commit({ records: [{ source: 'osv', document: previous, fetchedAt }] });
    store.importEnvelopes = async () => { throw Object.assign(new Error('disk full'), { code: 'ENOSPC' }); };
    const warnings = [];
    const result = await queryBatch([dep], { cacheDir, store, queryTtlMs: 0, onWarning: warning => warnings.push(warning), fetcher: async url => ({ ok: true, json: async () => url.includes('querybatch') ? { results: [{ vulns: [{ id: incoming.id }] }] } : incoming }) });
    if (scenario === 'equal-revision-newer-observation') {
      assert.equal(result.length, 1);
      assert.equal(result[0].cve.summary, 'Known newer observation');
    } else assert.deepEqual(result, []);
    assert.ok(warnings.some(warning => warning.type === 'source-unavailable' && /could not be saved/.test(warning.message)));
    assert.deepEqual(store.getRecord('osv', incoming.id).document, previous);
    assert.equal(store.getQuery({ source: 'osv', ecosystem: 'Maven', name: 'g:a', version: '1.0' }), null);
  });
}
for (const scenario of ['older-negative', 'older-positive', 'negative-proof-with-later-advisory']) {
  test(`live stale query preserves newer tuple evidence: ${scenario}`, async t => {
    const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-osv-stale-proof-'));
    const store = openAdvisoryStore({ cacheDir });
    t.after(() => { store.close(); require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); });
    const at = Date.now();
    const doc = document('2026-02-01T00:00:00Z');
    const query = { source: 'osv', ecosystem: 'Maven', name: 'g:a', version: '1.0', ids: scenario === 'older-negative' ? [doc.id] : [], complete: true, fetchedAt: at - 1000 };
    store.commit({ records: [{ source: 'osv', document: doc, fetchedAt: at - 2000 }], queries: [query] });
    if (scenario === 'negative-proof-with-later-advisory') store.commit({ records: [{ source: 'osv', document: { ...doc, modified: '2026-03-01T00:00:00Z' }, fetchedAt: at - 100 }] });
    const warnings = [], headers = new Headers({ 'x-fad-proxy': 'stale', 'x-fad-proxy-fetched-at': new Date(at - 5000).toISOString() });
    const result = await queryBatch([dep], { cacheDir, store, queryTtlMs: 0, onWarning: warning => warnings.push(warning), fetcher: async url => ({ ok: true, headers, json: async () => url.includes('querybatch') ? { results: [scenario === 'older-negative' ? {} : { vulns: [{ id: doc.id }] }] } : document('2026-01-01T00:00:00Z') }) });
    assert.equal(result.length, scenario === 'older-positive' ? 0 : 1);
    assert.deepEqual(store.getQuery(query).ids, query.ids);
    assert.equal(store.getQuery(query).fetchedAt, query.fetchedAt);
    assert.ok(warnings.some(warning => warning.type === 'source-stale' && /predates/.test(warning.message)));
  });
}
test('an older proxy response does not warn when newer saved evidence is fresh', async t => {
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-osv-fresh-proof-'));
  const store = openAdvisoryStore({ cacheDir });
  t.after(() => { store.close(); require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); });
  const at = Date.now(), doc = document('2026-02-01T00:00:00Z');
  const query = { source: 'osv', ecosystem: 'Maven', name: 'g:a', version: '1.0', ids: [doc.id], complete: true, fetchedAt: at - 1000 };
  store.commit({records:[{source:'osv',document:doc,fetchedAt:at-2000}],queries:[query]});
  store.commit({records:[{source:'osv',document:{...doc,modified:'2026-03-01T00:00:00Z'},fetchedAt:at-100}]});
  const warnings=[], headers=new Headers({'x-fad-proxy':'stale','x-fad-proxy-fetched-at':new Date(at-5000).toISOString()});
  const result=await queryBatch([dep],{cacheDir,store,onWarning:w=>warnings.push(w),fetcher:async url=>({ok:true,headers,json:async()=>url.includes('querybatch')?{results:[{}]}:doc})});
  assert.equal(result.length,1);
  assert.equal(store.getQuery(query).fetchedAt,query.fetchedAt);
  assert.equal(warnings.filter(w=>w.type==='source-stale').length,0);
});
