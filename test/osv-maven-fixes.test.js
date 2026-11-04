require('./helpers/isolated-cache')('osv-maven-fixes');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { vulnToMatch } = require('../lib/osv');
const { makeDepRecord } = require('../lib/dep-record');

const pkg = { ecosystem: 'Maven', name: 'org.example:widget' };
const range = (introduced, fixed) => ({ type: 'ECOSYSTEM', events: [{ introduced }, { fixed }] });
const affected = (ranges, extra = {}) => ({ package: pkg, ranges, ...extra });
const match = (entries, version = '1.5', ecosystem = 'maven') => vulnToMatch(
  makeDepRecord({ ecosystem, namespace: 'org.example', name: 'widget', version }),
  { id: 'GHSA-maven-fix', affected: entries }).cve;

test('Maven fix proposals leave every overlapping range and their branch target is also safe', () => {
  for (const ecosystem of ['maven', 'gradle']) {
    const result = match([affected([range('1.0', '2.0'), range('1.2', '3.0')])], '1.5', ecosystem);
    assert.equal(result.fixVersion, '3.0', `${ecosystem}: 2.0 remains vulnerable through the second interval`);
    assert.deepEqual(result.branchFix, { fixed: '3.0' });
  }
});

test('Maven explicit affected versions, including equivalent spellings, invalidate a fixed boundary', () => {
  const result = match([affected([range('1.0', '2.0'), range('2.5', '3.0')], { versions: ['2.0.0'] })]);
  assert.equal(result.fixVersion, '3.0');
  assert.equal(result.branchFix, undefined, 'the old branch target 2.0 is explicitly affected');
});

test('all affected entries for one Maven package participate in fix validation', () => {
  const result = match([affected([range('1.0', '2.0')]), affected([{ type: 'ECOSYSTEM', events: [{ introduced: '1.8' }] }])]);
  assert.equal(result.fixVersion, null, 'the second entry remains affected after the only published fix');
  assert.equal(result.branchFix, undefined);
});

test('Maven unknown, malformed or imprecise ranges cannot certify a correction', async t => {
  for (const [label, unknown] of [
    ['GIT', { type: 'GIT', events: [{ introduced: '0' }] }],
    ['unknown kind', { type: 'FUTURE', events: [{ introduced: '0' }] }],
    ['missing introduced', { type: 'ECOSYSTEM', events: [{ fixed: '4.0' }] }],
    ['malformed event', { type: 'ECOSYSTEM', events: [{ introduced: '0', fixed: '4.0' }] }],
    ['null range', null],
    ['non-array events', { type: 'ECOSYSTEM', events: { introduced: '0' } }],
    ['null event', { type: 'ECOSYSTEM', events: [null] }],
    ['invalid semver', { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.0' }] }],
    ['numeric precision', range('1.0', '9007199254740993')],
  ]) await t.test(label, () => {
    const result = match([affected([range('1.0', '2.0'), unknown])]);
    assert.equal(result.fixVersion, null);
    assert.equal(result.branchFix, undefined);
  });
  const unsafeCurrent = match([affected([range('0', '9007199254740993')])], '9007199254740992');
  assert.equal(unsafeCurrent.fixVersion, null);
  assert.equal(unsafeCurrent.branchFix, undefined);
  assert.equal(match([affected([range('1.0', '2.0')])], '${revision}').fixVersion, null);
});

test('Maven fix validation binds both the package name and ecosystem', () => {
  const irrelevant = { type: 'GIT', events: [{ introduced: '0' }] };
  const result = match([
    affected([range('1.0', '2.0')]),
    { package: { ecosystem: 'Maven', name: 'org.other:widget' }, ranges: [irrelevant] },
    { package: { ecosystem: 'npm', name: pkg.name }, ranges: [range('1.0', '9.0')] },
  ]);
  assert.equal(result.fixVersion, '2.0');
  assert.deepEqual(result.branchFix, { fixed: '2.0' });
  const foreignOnly = match([{ package: { ecosystem: 'npm', name: pkg.name }, ranges: [range('1.0', '2.0')] }]);
  assert.equal(foreignOnly.fixVersion, null, 'a similarly named package in another ecosystem supplies no Maven fix');
  assert.equal(foreignOnly.branchFix, undefined);
  const differentlyCased = match([{ package: { ecosystem: 'Maven', name: 'Org.Example:widget' }, ranges: [range('1.0', '2.0')] }]);
  assert.equal(differentlyCased.fixVersion, null, 'Maven package identity must match exactly');
});

test('verified Maven branch fixes preserve ordering of qualifiers and maintained branches', () => {
  const entries = [affected([{ type: 'ECOSYSTEM', events: [
    { introduced: '11.0.0-M1' }, { fixed: '11.0.22' },
    { fixed: '9.0.118' }, { introduced: '0' },
    { fixed: '10.1.55' }, { introduced: '10.1.0-M1' },
  ] }])];
  for (const [current, fixed] of [['9.0.100', '9.0.118'], ['10.1.50', '10.1.55'], ['11.0.21', '11.0.22']]) {
    const result = match(entries, current);
    assert.equal(result.fixVersion, fixed);
    assert.deepEqual(result.branchFix, { fixed });
  }
});

test('a Maven last_affected boundary alone is not a concrete verified correction', () => {
  const result = match([affected([{ type: 'ECOSYSTEM', events: [{ introduced: '1.0' }, { last_affected: '2.0' }] }])]);
  assert.equal(result.fixVersion, null);
  assert.equal(result.branchFix, undefined, 'do not suggest every version after a boundary without a concrete safe target');
});
