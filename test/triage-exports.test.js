const { test } = require('node:test');
const assert = require('node:assert/strict');
const { buildCsaf } = require('../lib/csaf-export');
const { buildCycloneDx } = require('../lib/sbom-export');
const { buildFindings } = require('../lib/json-export');
const { parseVex, applySuppressions } = require('../lib/suppress');
const { makeDepRecord } = require('../lib/dep-record');
const a = makeDepRecord({ ecosystem: 'npm', name: 'a', version: '1.0.0' });
const b = makeDepRecord({ ecosystem: 'npm', name: 'b', version: '1.0.0' });
const deps = new Map([[a.coordKey, a], [b.coordKey, b]]);
const match = (dep, extra = {}) => ({ dep, cve: { id: 'CVE-2026-12345', severity: 'HIGH' }, ...extra });

test('accepted risk is retained as affected with scoped triage notes in CSAF and SBOM', () => {
	const matches = [match(a, { suppressed: true, suppressedReason: 'accepted risk' }), match(b)];
	const csaf = buildCsaf(deps, matches);
	assert.deepEqual(csaf.vulnerabilities[0].product_status, { known_affected: ['PROD-0', 'PROD-1'] });
	const note = JSON.parse(csaf.vulnerabilities[0].notes.find(n => n.title === 'VigieVuln triage').text);
	assert.deepEqual(note.product_ids, ['PROD-0']);
	assert.equal(note.reason, 'accepted risk');
	assert.equal(note.suppressed, true);
	assert.deepEqual(parseVex(csaf), [], 'accepted risk is not a VEX assertion of non-affectation');
	const vuln = buildCycloneDx(deps, matches).vulnerabilities[0];
	const triage = JSON.parse(vuln.properties.find(p => p.name === 'vigievuln:triage').value);
	assert.deepEqual(triage.refs, ['pkg:npm/a@1.0.0']);
	assert.equal(triage.reason, 'accepted risk');
	assert.equal(triage.status, undefined);
	assert.equal(vuln.analysis, undefined, 'must not globally clear the other product');
});

test('explicit VEX exemptions round trip by product without clearing other affected products', () => {
	for (const status of ['fixed', 'known_not_affected']) {
		const matches = [match(a, { suppressed: true, suppressedReason: `VEX: ${status}`, suppressionStatus: status }), match(b)];
		const csaf = buildCsaf(deps, matches);
		assert.deepEqual(csaf.vulnerabilities[0].product_status, { known_affected: ['PROD-1'], [status]: ['PROD-0'] });
		const fresh = [match(a), match(b)];
		assert.equal(applySuppressions(fresh, parseVex(csaf)), 1);
		assert.equal(fresh[0].suppressionStatus, status);
		assert.equal(fresh[1].suppressed, undefined);
		assert.equal(buildFindings({ cveMatches: matches }).cve[0].suppressionStatus, status);
		const allCleared = buildCsaf(deps, [matches[0]]).vulnerabilities[0];
		assert.deepEqual(allCleared.product_status, { [status]: ['PROD-0'] });
	}
});

test('contradictory duplicate product assertions remain affected with deduplicated scores and flags', () => {
	const affected = { ...match(a), cve: { id: 'CVE-2026-12345', severity: 'HIGH', kev: true, score: 8, cvssVersion: '3.1' } };
	const fixed = { ...affected, suppressed: true, suppressionStatus: 'fixed' };
	const notAffected = { ...affected, suppressed: true, suppressionStatus: 'known_not_affected' };
	for (const matches of [[affected, fixed], [fixed, affected], [fixed, notAffected], [notAffected, fixed], [affected, affected]]) {
		const v = buildCsaf(deps, matches).vulnerabilities[0];
		assert.deepEqual(v.product_status, { known_affected: ['PROD-0'] });
		assert.deepEqual(v.scores[0].products, ['PROD-0']);
		assert.deepEqual(v.flags[0].product_ids, ['PROD-0']);
	}
	assert.equal(buildCsaf(deps, [fixed]).vulnerabilities[0].flags, undefined);
});
