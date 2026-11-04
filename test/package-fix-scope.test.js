'use strict';
require('./helpers/isolated-cache')('package-fix-scope');
const test = require('node:test'), assert = require('node:assert/strict');
const { generateHtmlReport } = require('../lib/cve-report');
const { buildFindings } = require('../lib/json-export');
const { vulnToMatch } = require('../lib/osv');
const { vulnVerdict } = require('../lib/osv-db');
const { makeDepRecord } = require('../lib/dep-record');
function advisory(id, name, events) {
  return { id, aliases: [`CVE-2099-${id === 'GHSA-a' ? '1001' : '1002'}`], affected: [{ package: { ecosystem: 'npm', name }, ranges: [{ type: 'SEMVER', events }] }] };
}
function report(matches) {
  return generateHtmlReport({ cveMatches: matches, resolvedDeps: new Map(matches.map(m => [m.dep.coordKey, m.dep])), projectInfo: { name: 'scope-test' }, warnings: [], outdatedResults: [] });
}
for (const scope of ['prod', 'transitive']) {
  test(`advisory candidates never become a package-wide ${scope} pin through numeric maximum`, () => {
    const dep = makeDepRecord({ ecosystem: 'npm', name: 'demo', version: '1.0.0', scope });
    if (scope === 'transitive') dep.via = ['npm:parent'];
    const a = advisory('GHSA-a', 'demo', [{ introduced: '0' }, { fixed: '2.0.0' }, { introduced: '3.0.0' }, { fixed: '4.0.0' }]);
    const b = advisory('GHSA-b', 'demo', [{ introduced: '0' }, { fixed: '3.0.0' }]);
    const matches = [vulnToMatch(dep, a), vulnToMatch(dep, b)];
    assert.deepEqual(matches.map(m => m.cve.fixVersion), ['2.0.0', '3.0.0']);
    assert.equal(vulnVerdict('3.0.0', a, 'npm'), true, 'the numeric maximum reintroduces another matched advisory');
    const html = report(matches), actions = html.slice(html.indexOf('id="ch8"'));
    assert.match(html, /Advisory-specific candidate/);
    assert.match(actions, /manual triage/);
    assert.doesNotMatch(actions, /class="fix-recipe"|&quot;overrides&quot;|&quot;resolutions&quot;/);
    assert.doesNotMatch(html, /Pin demo ≥|Pin to ≥/);
    const json = buildFindings({ cveMatches: matches, projectInfo: { name: 'scope-test' } });
    assert.deepEqual(json.cve.map(c => c.fixVersion), ['2.0.0', '3.0.0'], 'individual advisory candidates remain available');
    for (const finding of json.cve) { assert.equal(finding.fixScope, 'advisory'); assert.equal(finding.packageFixVerified, false); }
  });
}
test('an advisory affecting only the target version prevents inferring safety from current findings alone', () => {
  const dep = makeDepRecord({ ecosystem: 'npm', name: 'demo', version: '1.0.0', scope: 'transitive' });
  dep.via = ['npm:parent'];
  const current = advisory('GHSA-a', 'demo', [{ introduced: '0' }, { fixed: '2.0.0' }]);
  const future = advisory('GHSA-b', 'demo', [{ introduced: '2.0.0' }, { fixed: '3.0.0' }]);
  assert.equal(vulnVerdict(dep.version, future, 'npm'), false);
  assert.equal(vulnVerdict('2.0.0', future, 'npm'), true);
  const finding = vulnToMatch(dep, current);
  assert.equal(finding.cve.fixVersion, '2.0.0');
  const html = report([finding]), actions = html.slice(html.indexOf('id="ch8"'));
  assert.match(html, /Package-wide safety has not been verified/);
  assert.match(actions, /manual triage/);
  assert.doesNotMatch(actions, /class="fix-recipe"/);
});
