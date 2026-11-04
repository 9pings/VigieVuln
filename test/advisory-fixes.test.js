'use strict';
require('./helpers/isolated-cache')('advisory-fixes');
const test = require('node:test'), assert = require('node:assert/strict');
const { mergeBySource } = require('../lib/merge-sources');
const { mergeMatches } = require('../lib/cve-report');
const dep = { ecosystem: 'npm', coordKey: 'npm:demo', groupId: '', artifactId: 'demo', name: 'demo', version: '1.0.0' };
const match = (id, fixVersion, aliases = [], source = 'osv', extra = {}) => ({ dep, source, cve: { id, aliases, fixVersion, fixEvaluation: fixVersion ? 'verified' : 'unknown', ...(fixVersion ? { branchFix: { fixed: fixVersion } } : {}), ...extra } });

test('an alias bridge merges every group and suppresses targets independently of order', () => {
  const a = match('CVE-A', '2.0.0', ['GHSA-left']);
  const b = match('CVE-B', '3.0.0', ['GHSA-right']);
  const bridge = match('GCVE-1-bridge', null, ['GHSA-left', 'GHSA-right'], 'GCVE:GNA-1');
  for (const sequence of [[a, b, bridge], [bridge, b, a], [b, bridge, a]]) {
    const result = mergeBySource([], sequence);
    assert.equal(result.length, 1);
    assert.equal(result[0].cve.fixVersion, null);
    assert.equal(result[0].cve.branchFix, undefined);
    assert.ok(result[0].cve.fixConflict);
    assert.ok(result[0].cve.aliases.includes('GHSA-left'));
    assert.ok(result[0].cve.aliases.includes('GHSA-right'));
    const later = mergeBySource(result, [match('CVE-A', '2.0.0')]);
    assert.equal(later[0].cve.fixVersion, null, 'later sources cannot silently reinstate a conflicted target');
  }
});
test('an explicit unknown target assessment from CVEProject or GCVE blocks an OSV auto-fix', () => {
  for (const source of ['CVEProject', 'GCVE:GNA-1']) {
    const verified = match('CVE-A', '2.0.0'), unknown = match('CVE-A', null, [], source);
    for (const records of [[verified, unknown], [unknown, verified]]) {
      const result = mergeBySource([], records)[0];
      assert.equal(result.cve.fixVersion, null);
      assert.equal(result.cve.branchFix, undefined);
      assert.equal(result.cve.fixConflict, 'unverified-advisory');
    }
  }
});
test('agreeing evaluated targets survive while enrichment without an assessment adds no safety claim', () => {
  const verified = match('CVE-A', '2.0.0'), agreed = match('CVE-A', '2.0.0', [], 'CVEProject');
  const enrichment = { dep, source: 'nvd', cve: { id: 'CVE-A', description: 'Enrichment only' } };
  const result = mergeBySource([], [verified, agreed, enrichment])[0];
  assert.equal(result.cve.fixVersion, '2.0.0');
  assert.equal(result.cve.fixConflict, undefined);
});
test('report duplicate reduction cannot retain a target discarded by conflicting evidence', () => {
  for (const records of [[match('CVE-A', '2.0.0'), match('CVE-A', '3.0.0')], [match('CVE-A', '2.0.0'), match('CVE-A', null, [], 'GCVE:GNA-1')]]) {
    for (const ordered of [records, [...records].reverse()]) {
      const result = mergeMatches(ordered)[0];
      assert.equal(result.cve.fixVersion, null);
      assert.equal(result.cve.branchFix, undefined);
      assert.ok(result.cve.fixConflict);
    }
  }
});
