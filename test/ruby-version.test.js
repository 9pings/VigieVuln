const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { compareRubyVersions: compare } = require('../lib/ruby-version');

test('RubyGems ordering preserves padding, prereleases, case and arbitrary numeric precision', () => {
  for (const [a, b] of [['1', '1.0.0'], ['1.0.a1', '1.a.1'], ['1.0-a1', '1.pre.a.1'],
    ['1.0.a.0', '1.a'], ['01.002', '1.2']]) assert.equal(compare(a, b), 0, `${a} = ${b}`);
  for (const [a, b] of [['1.0.a9', '1.0.a10'], ['1.0.a1', '1.0'], ['1.0', '1.0.1'],
    ['1.0.RC1', '1.0.rc1'], ['1.0.1', '1.1'], ['9007199254740992', '9007199254740993'],
    ['1.0-1', '1.0']]) {
    assert.equal(compare(a, b), -1, `${a} < ${b}`);
    assert.equal(compare(b, a), 1);
  }
});

test('nonliteral Ruby versions remain unknown rather than being coerced', () => {
  for (const invalid of ['', ' ', ' 1.0', '1.0 ', 'v1.0', '1.0+build', 'main', '>=1.0', '1.*',
    '1..0', '1.0/', '1.0\n', '1.é', null, 1, '1'.repeat(1025)]) {
    assert.equal(compare(invalid, '1.0'), null, String(invalid));
    assert.equal(compare('1.0', invalid), null);
  }
});

test('RubyGems comparator agrees with the independent native Gem::Version oracle', t => {
  const probe = spawnSync('ruby', ['-rrubygems', '-e', 'print Gem::VERSION'], { encoding: 'utf8' });
  if (probe.error?.code === 'ENOENT') { t.skip('Ruby is unavailable; fixed boundary cases still run'); return; }
  assert.equal(probe.status, 0, probe.stderr);
  const versions = new Set(['0', '0.a', '1', '1.0', '1.0.0', '1.0.a', '1.a.0', '1.0-a',
    '1.0.RC1', '1.0.rc1', '01.02', '9007199254740993.0', '9007199254740992.0']);
  for (const major of [0, 1, 2, 10]) for (const minor of [0, 2, 10]) {
    for (const suffix of ['', '.0', '.1', '.a1', '.a9', '.a10', '-beta.2', '.pre.0', '.rc1'])
      versions.add(`${major}.${minor}${suffix}`);
  }
  const inputs = [...versions];
  const result = spawnSync('ruby', ['-rjson', '-rrubygems', '-e',
    'v = JSON.parse(STDIN.read).map { |s| Gem::Version.new(s) }; puts JSON.generate(v.map { |a| v.map { |b| a <=> b } })'],
  { input: JSON.stringify(inputs), encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  const expected = JSON.parse(result.stdout);
  for (let i = 0; i < inputs.length; i++) for (let j = 0; j < inputs.length; j++)
    assert.equal(compare(inputs[i], inputs[j]), expected[i][j], `${inputs[i]} <=> ${inputs[j]}`);
});
