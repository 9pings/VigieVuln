const root = require('./helpers/isolated-cache')('osv-packagist-versions');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { vulnVerdict, rangeVerdict, newOsvIndex, addOsvRecord, matchOsvDbDeps, matchOsvDbRecords } = require('../lib/osv-db');
const { queryBatch } = require('../lib/osv');
const { makeDepRecord } = require('../lib/dep-record');

const affectedVersion = version => ({ affected: [{ versions: [version] }] });

test('Packagist explicit numeric releases recognize the optional VCS v prefix only', () => {
  for (const [a, b] of [['2.13.1', 'v2.13.1'], ['v4.4.25', '4.4.25'], ['V1.2.3.4', '1.2.3.4'], ['1.2', 'v1.2']]) {
    assert.equal(vulnVerdict(a, affectedVersion(b), 'Packagist'), true);
    assert.equal(vulnVerdict(b, affectedVersion(a), 'Packagist'), true);
  }
  for (const [a, b] of [['2.13.1', 'v2.13.2'], ['1.2', 'v1.2.0'], ['dev-main', 'vdev-main'],
    ['1.x-dev', 'v1.x-dev'], ['1.2.3-RC1', 'v1.2.3-RC1'], ['1.2.3+meta', 'v1.2.3+meta'],
    ['1.2.3', 'vv1.2.3'], ['1.2.3.4.5', 'v1.2.3.4.5']]) {
    assert.equal(vulnVerdict(a, affectedVersion(b), 'Packagist'), null, `${a} / ${b} remains unknown`);
  }
  assert.equal(vulnVerdict('1.2.3', affectedVersion('v1.2.3'), 'RubyGems'), null);
  assert.equal(vulnVerdict('1.2.3', affectedVersion('v1.2.3'), 'PyPI'), null);
  assert.equal(rangeVerdict('2.13.1', { type: 'ECOSYSTEM', events: [{ introduced: '2.0.0' }, { fixed: '2.15.3' }] }, 'Packagist'), null);
});

test('explicit Composer versions agree online, warm offline, index and streamed seed without widening ranges', async () => {
  // Shape observed for twig/twig in the real Composer benchmark. The online
  // oracle's answers are fixed, independent of the offline version evaluator.
  const record = { id: 'GHSA-packagist-prefix', aliases: ['CVE-2099-91001'], affected: [{
    package: { ecosystem: 'Packagist', name: 'twig/twig' }, versions: ['v2.13.1'],
    ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.0.0' }, { fixed: '2.15.3' }] }],
  }] };
  const dep = makeDepRecord({ ecosystem: 'composer', namespace: 'twig', name: 'twig', version: '2.13.1' });
  const deps = new Map([[dep.coordKey, dep]]);
  const cacheDir = path.join(root, 'query');
  const live = await queryBatch([dep], { cacheDir, onProgress() {}, fetcher: async (url, init) => {
    if (url.endsWith('/querybatch')) {
      assert.deepEqual(JSON.parse(init.body).queries, [{ package: { name: 'twig/twig', ecosystem: 'Packagist' }, version: '2.13.1' }]);
      return Response.json({ results: [{ vulns: [{ id: record.id }] }] });
    }
    return Response.json(record);
  } });
  assert.equal(live.length, 1);
  const warm = await queryBatch([dep], { cacheDir, offline: true, fetcher: async () => assert.fail('offline attempted network') });
  const index = newOsvIndex('Packagist');
  addOsvRecord(index, record);
  const bytes = Buffer.from(JSON.stringify(record) + '\n');
  const recordsFile = path.join(root, 'records.jsonl');
  fs.writeFileSync(recordsFile, bytes);
  const seed = { recordsFile, ecosystem: 'Packagist', recordCount: 1, sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  const unknown = [];
  const streamed = await matchOsvDbRecords(deps, seed, { onUnknown: x => unknown.push(x) });
  const compact = matches => matches.map(m => ({ id: m.cve.id, version: m.dep.version, coord: m.dep.coordKey }));
  for (const result of [warm, matchOsvDbDeps(deps, index), streamed]) assert.deepEqual(compact(result), compact(live));
  assert.deepEqual(unknown, [], 'an explicit affected version is conclusive without range inference');
  const different = { ...dep, version: '2.13.2', versions: ['2.13.2'] };
  assert.equal((await matchOsvDbRecords(new Map([[different.coordKey, different]]), seed, { onUnknown: x => unknown.push(x) })).length, 0);
  assert.equal(unknown.length, 1, 'a different release is still unknown, not guessed vulnerable');
});
