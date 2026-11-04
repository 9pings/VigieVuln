const { test } = require("node:test");
const assert = require("node:assert");

const { diffFindings, summarizeDiff, findingKey, newProductionCveCount } = require("../lib/diff");

function cve(id, coord, version, extra = {}) {
	return { id, severity: extra.severity || "HIGH", suppressed: !!extra.suppressed, cpeFiltered: !!extra.cpeFiltered, dep: { ecosystem: extra.ecosystem || "maven", coord, version } };
}
function doc(cveArr, extra = {}) {
	return { cve: cveArr, eol: extra.eol || [], obsolete: [], outdated: extra.outdated || [], licenses: [] };
}

test("findingKey is stable on id + ecosystem + coord + version", () => {
	const k1 = findingKey(cve("CVE-1", "g:a", "1.0.0"));
	const k2 = findingKey(cve("CVE-1", "g:a", "1.0.0", { severity: "LOW" }));
	assert.strictEqual(k1, k2, "severity does not affect identity");
	assert.notStrictEqual(k1, findingKey(cve("CVE-1", "g:a", "2.0.0")), "version changes identity");
});

test("diffFindings classifies added / removed / unchanged CVEs", () => {
	const base = doc([cve("CVE-1", "g:a", "1.0.0"), cve("CVE-2", "g:b", "2.0.0")]);
	const cur = doc([cve("CVE-1", "g:a", "1.0.0"), cve("CVE-3", "g:c", "3.0.0")]);
	const d = diffFindings(base, cur);
	assert.deepStrictEqual(d.cve.added.map(f => f.id), ["CVE-3"]);
	assert.deepStrictEqual(d.cve.removed.map(f => f.id), ["CVE-2"]);
	assert.deepStrictEqual(d.cve.unchanged.map(f => f.id), ["CVE-1"]);
});

test("a version bump shows the old finding removed and the new one added", () => {
	const base = doc([cve("CVE-9", "g:a", "1.0.0")]);
	const cur = doc([cve("CVE-9", "g:a", "1.0.1")]);
	const d = diffFindings(base, cur);
	assert.strictEqual(d.cve.added.length, 1);
	assert.strictEqual(d.cve.removed.length, 1);
});

test("diffFindings diffs EOL and outdated categories by dep identity", () => {
	const base = { cve: [], eol: [{ product: "java", dep: { ecosystem: "maven", coord: "g:a", version: "8" } }], obsolete: [], outdated: [], licenses: [] };
	const cur = { cve: [], eol: [], obsolete: [], outdated: [{ latest: "2.0", dep: { ecosystem: "npm", coord: "left-pad", version: "1.0" } }], licenses: [] };
	const d = diffFindings(base, cur);
	assert.strictEqual(d.eol.removed.length, 1);
	assert.strictEqual(d.outdated.added.length, 1);
});

test("summarizeDiff counts; new production CVEs exclude suppressed and cpe-filtered", () => {
	const base = doc([]);
	const cur = doc([
		cve("CVE-A", "g:a", "1.0.0", { severity: "CRITICAL" }),
		cve("CVE-B", "g:b", "1.0.0", { suppressed: true }),
		cve("CVE-C", "g:c", "1.0.0", { cpeFiltered: true }),
	]);
	const d = diffFindings(base, cur);
	assert.strictEqual(newProductionCveCount(d), 1, "only CVE-A is a new production finding");
	const s = summarizeDiff(d);
	assert.strictEqual(s.cve.added, 3);
	assert.strictEqual(s.cve.addedProduction, 1);
	assert.strictEqual(s.cve.addedBySeverity.CRITICAL, 1);
});

test("diffFindings tolerates a baseline document missing a category", () => {
	const base = { cve: [cve("CVE-1", "g:a", "1.0.0")] }; // no eol/outdated keys
	const cur = doc([cve("CVE-1", "g:a", "1.0.0")]);
	const d = diffFindings(base, cur);
	assert.strictEqual(d.cve.unchanged.length, 1);
	assert.strictEqual(d.eol.added.length, 0);
});

const { eolKey } = require("../lib/diff");

test("eol identity includes status: unsupported → eol on the same dep is a CHANGE, legacy docs default to eol", () => {
	const dep = { ecosystem: "composer", coord: "symfony/framework-bundle", version: "5.4.45" };
	const base = doc([], { eol: [{ product: "Symfony", status: "unsupported", dep }] });
	const cur = doc([], { eol: [{ product: "Symfony", status: "eol", dep }] });
	const d = diffFindings(base, cur);
	assert.strictEqual(d.eol.added.length, 1);
	assert.strictEqual(d.eol.removed.length, 1);
	assert.strictEqual(d.eol.unchanged.length, 0);
	assert.strictEqual(eolKey({ dep }), eolKey({ status: "eol", dep }), "a pre-status baseline entry equals a status:eol entry");
});

test("physical Composer copies have distinct diff identities", () => {
	const first = { ...cve("CVE-1", "vendor/lib", "1.0", { ecosystem: "composer" }), findingId: "fad-cve-first" };
	const second = { ...first, findingId: "fad-cve-second" };
	const d = diffFindings(doc([first]), doc([first, second]));
	assert.deepStrictEqual(d.cve.added.map(f => f.findingId), ["fad-cve-second"]);
	assert.strictEqual(d.cve.unchanged.length, 1);
});

test("missing advisory coverage marks an absent application finding unassessed, not resolved", () => {
	const old = { ...cve("CVE-1", "vendor/lib", "1.0", { ecosystem: "composer" }),
		findingId: "fad-cve-first", applicationIds: ["wordpress:site"] };
	const cur = { ...doc([]), coverage: [{ applicationId: "wordpress:site", capability: "advisories",
		execution: "not-run", result: "indeterminate" }] };
	const d = diffFindings(doc([old]), cur);
	assert.strictEqual(d.cve.removed.length, 0);
	assert.deepStrictEqual(d.cve.unassessed, [old]);
	assert.strictEqual(summarizeDiff(d).cve.unassessed, 1);
});

test("ordinary findings remain unassessed when advisory or inventory coverage is incomplete", () => {
	const old = cve('CVE-1', 'lodash', '1.0', { ecosystem: 'npm' });
	for (const type of ['source-unavailable', 'source-stale', 'osv-coverage', 'parse-error', 'dependency-coverage', 'no-lockfile']) {
		const d = diffFindings(doc([old]), { ...doc([]), warnings: [{ type, message: 'gap' }] });
		assert.deepStrictEqual(d.cve.removed, []);
		assert.deepStrictEqual(d.cve.unassessed, [old]);
	}
	assert.equal(diffFindings(doc([old]), { ...doc([]), warnings: [{ type: 'suppressed' }] }).cve.removed.length, 1);
});

test("new production gate excludes dev/test/provided but includes embedded findings", () => {
	const findings = [
		{ ...cve('DEV', 'dev', '1'), dep: { isDev: true } },
		{ ...cve('TEST', 'test', '1'), dep: { scope: 'test' } },
		{ ...cve('PROVIDED', 'provided', '1'), dep: { scope: 'provided' } },
		{ ...cve('EMBEDDED', 'binary', '1'), dep: { isDev: true, provenance: 'embedded' } },
		cve('PROD', 'prod', '1'),
	];
	const s = summarizeDiff(diffFindings(doc([]), doc(findings)));
	assert.equal(s.cve.added, 5);
	assert.equal(s.cve.addedProduction, 2);
	assert.equal(s.cve.addedBySeverity.HIGH, 2);
});

test("baseline validation rejects unrelated JSON and malformed findings but permits legacy exports", () => {
	const { validateFindingsDocument } = require('../lib/diff');
	for (const invalid of [null, [], {}, { schema: 'other', cve: [] }, { cve: {} }, { cve: [null] }, { cve: [{ id: 'CVE-1' }] }])
		assert.throws(() => validateFindingsDocument(invalid));
	assert.deepStrictEqual(validateFindingsDocument({ cve: [] }), { cve: [] });
	assert.equal(validateFindingsDocument({ schema: 'fad-findings/1', cve: [cve('CVE-1', 'g:a', '1')] }).cve.length, 1);
});

test('provenance freshness and source limits survive JSON export and prevent false remediation', () => {
	const { buildFindings } = require('../lib/json-export');
	const { freshnessNotice } = require('../lib/cve-report');
	const old = cve('CVE-1', 'lodash', '1.0', { ecosystem: 'npm' });
	const notice = freshnessNotice({ type: 'source-stale', message: 'osv: cached data from 2026-01-01T00:00:00Z was used and may be outdated.' });
	assert.ok(notice);
	for (const provenance of [
		{ freshnessNotices: [notice] },
		{ sourceLimitations: [{ source: 'CVEProject', message: 'partial projection' }] },
		{ mavenDepthLimitReached: true },
	]) {
		const current = buildFindings({ cveMatches: [], projectInfo: { provenance }, warnings: [] });
		const d = diffFindings(doc([old]), current);
		assert.deepStrictEqual(d.cve.removed, []);
		assert.deepStrictEqual(d.cve.unassessed, [old]);
	}
	const healthy = buildFindings({ cveMatches: [], projectInfo: { provenance: {
		freshnessNotices: [], sourceLimitations: [], dataSources: [{ id: 'osv', status: 'cached', asOf: '2026-11-04T00:00:00Z' }],
	} } });
	assert.equal(diffFindings(doc([old]), healthy).cve.removed.length, 1);
});

test('baseline project mismatch is a warning hint, never a reason to refuse a diff', () => {
 const {baselineProjectWarning}=require('../lib/diff');
 const base={...doc([cve('CVE-1','g:a','1')]),project:{name:'old-project'}};
 const current={...doc([cve('CVE-1','g:a','1')]),project:{name:'renamed-project'}};
 assert.equal(baselineProjectWarning(base,current).type,'baseline-project-mismatch');
 assert.match(baselineProjectWarning(base,current).message,/comparison continues/);
 assert.equal(diffFindings(base,current).cve.unchanged.length,1);
 for(const project of [undefined,{}, {name:''},{name:'old-project'},{name:' old-project '}])
  assert.equal(baselineProjectWarning(base,{project}),null);
 assert.doesNotMatch(baselineProjectWarning(base,{project:{name:'malicious\nname\x1b'}}).message,/[\r\n\x1b]/);
});
