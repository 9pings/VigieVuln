const root = require('./helpers/isolated-cache')('osv-ruby-versions');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { rangeVerdict, vulnVerdict, newOsvIndex, addOsvRecord, matchOsvDbDeps, matchOsvDbRecords } = require('../lib/osv-db');
const { queryBatch } = require('../lib/osv');
const { makeDepRecord } = require('../lib/dep-record');

test('Ruby OSV ranges honor inclusive introductions, exclusive fixes, last affected and limits', () => {
  const range = { type: 'ECOSYSTEM', events: [{ fixed: '2.0' }, { introduced: '1.0.rc1' }] };
  for (const [v, expected] of [['1.0.beta9', false], ['1.0.rc1', true], ['1.0', true], ['1.9.9', true], ['2.0.0', false]])
    assert.equal(rangeVerdict(v, range, 'RubyGems'), expected, v);
  const last = { type: 'ECOSYSTEM', events: [{ introduced: '1' }, { last_affected: '1.9' }] };
  assert.equal(rangeVerdict('1.9.0', last, 'RubyGems'), true);
  assert.equal(rangeVerdict('1.9.1', last, 'RubyGems'), false);
  const limit = { type: 'ECOSYSTEM', events: [{ introduced: '0' }, { limit: '2' }] };
  assert.equal(rangeVerdict('0.a', limit, 'RubyGems'), true);
  assert.equal(rangeVerdict('2.0', limit, 'RubyGems'), false);
  assert.equal(vulnVerdict('1.0.0', { affected: [{ versions: ['1.0'] }] }, 'RubyGems'), true);
  assert.equal(vulnVerdict('1.0.1', { affected: [{ versions: ['1.0'] }] }, 'RubyGems'), false);
  for (const bad of ['v1.2', '1.0+build', 'main', '1.*']) assert.equal(rangeVerdict(bad, range, 'RubyGems'), null);
  assert.equal(rangeVerdict('1.0', { type: 'GIT', events: [{ introduced: '0' }] }, 'RubyGems'), null);
  assert.equal(rangeVerdict('1.0', { type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: 'v2.0' }] }, 'RubyGems'), null);
});

test('Ruby range results agree online, warm offline, index and streamed seed including fixed negatives', async () => {
  // Fixed answers: the online oracle does not call the production comparator.
  const answers = new Map([['0.9', false], ['1.0.beta1', false], ['1.0.rc1', true], ['1.0', true], ['1.9', true], ['2.0', false], ['2.1', false]]);
  const record = { id: 'GHSA-ruby-range', aliases: ['CVE-2099-91002'], affected: [{
    package: { ecosystem: 'RubyGems', name: 'widget' },
    ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.0.rc1' }, { fixed: '2.0' }] }],
  }] };
  const deps = [...answers.keys()].map(version => makeDepRecord({ ecosystem: 'ruby', name: 'widget', version }));
  const cacheDir = path.join(root, 'query');
  const live = await queryBatch(deps, { cacheDir, onProgress() {}, fetcher: async (url, init) => {
    if (url.endsWith('/querybatch')) return Response.json({ results: JSON.parse(init.body).queries.map(q => {
      assert.deepEqual(q.package, { name: 'widget', ecosystem: 'RubyGems' });
      assert.ok(answers.has(q.version));
      return answers.get(q.version) ? { vulns: [{ id: record.id }] } : {};
    }) });
    return Response.json(record);
  } });
  const versions = matches => matches.map(m => m.dep.version).sort();
  assert.deepEqual(versions(live), [...answers].filter(([, hit]) => hit).map(([v]) => v).sort());
  const warm = await queryBatch(deps, { cacheDir, offline: true, fetcher: async () => assert.fail('offline attempted network') });
  const index = newOsvIndex('RubyGems'); addOsvRecord(index, record);
  const combined = { ...deps[0], versions: [...answers.keys()] };
  const inventory = new Map([[combined.coordKey, combined]]);
  const bytes = Buffer.from(JSON.stringify(record) + '\n'), recordsFile = path.join(root, 'records.jsonl');
  fs.writeFileSync(recordsFile, bytes);
  const seed = { recordsFile, ecosystem: 'RubyGems', recordCount: 1, sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  for (const result of [warm, matchOsvDbDeps(inventory, index), await matchOsvDbRecords(inventory, seed)])
    assert.deepEqual(versions(result), versions(live));
  const wrongPackage = { ...combined, name: 'other', coordKey: 'ruby:other' };
  assert.deepEqual(await matchOsvDbRecords(new Map([[wrongPackage.coordKey, wrongPackage]]), seed), []);
  const unknown = [], unsupported = { ...combined, version: 'v1.0', versions: ['v1.0'] };
  assert.deepEqual(await matchOsvDbRecords(new Map([[unsupported.coordKey, unsupported]]), seed, { onUnknown: x => unknown.push(x) }), []);
  assert.equal(unknown.length, 1);
});
