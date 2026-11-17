const { test } = require("node:test");
const assert = require("node:assert/strict");
const { summarizeFindings, coalescePhysicalFindings } = require("../lib/finding-summary");

const match = (findingId, applicationIds, relation = "indirect") => ({ findingId, applicationIds,
	applicationRelation: relation, dep: { ecosystem: "composer", coordKey: "composer:vendor/lib", version: "1.0" },
	cve: { id: "CVE-1", severity: "HIGH" } });

test("finding summary counts physical findings once and marks application exposure as overlapping", () => {
	const summary = summarizeFindings([match("a", ["site-a", "site-b"]), match("a", ["site-a", "site-b"]),
		match("b", ["site-b"], "direct")]);
	assert.equal(summary.total, 2);
	assert.equal(summary.applicationUnique, 2);
	assert.deepEqual(summary.bySeverity, { critical: 0, high: 2, medium: 0, low: 0, none: 0, unknown: 0 });
	assert.deepEqual(summary.byApplication, { "site-a": 1, "site-b": 2 });
	assert.deepEqual(summary.byApplicationRelation, { direct: 1, indirect: 1, unknown: 0 });
	assert.equal(summary.applicationExposureOverlaps, true);
});

test("suppressed and CPE filtered matches are excluded from active totals", () => {
	const summary = summarizeFindings([{ ...match("a", ["site"]), suppressed: true },
		{ ...match("b", ["site"]), cpeFiltered: true }, match("c", [])]);
	assert.equal(summary.total, 1);
	assert.equal(summary.excluded.suppressed, 1);
	assert.equal(summary.excluded.cpeFiltered, 1);
});

test("Composer CVE from Drupal and OSV merges on one physical lock occurrence", () => {
	const dep = { ecosystem: "composer", coordKey: "composer:drupal/core", version: "10.3.1",
		manifestPaths: ["/audit/site/composer.lock"] };
	const merged = coalescePhysicalFindings([
		{ findingId: "osv-id", dep, source: "osv", cve: { id: "CVE-2099-1234", severity: "HIGH", score: 7.5 } },
		{ findingId: "drupal-id", dep: { ...dep, provenance: "application" }, source: "drupal-security-advisories",
			advisoryId: "SA-CORE-2099-001", applicationIds: ["drupal:site"], ownerComponentIds: ["drupal:site:core"],
			applicationRelation: "direct", cve: { id: "CVE-2099-1234", aliases: ["SA-CORE-2099-001"],
				severityOriginal: "Critical", osvRefs: [{ url: "https://www.drupal.org/sa-core-2099-001" }] } },
	], "/audit");
	assert.equal(merged.length, 1);
	assert.deepEqual(merged[0].applicationIds, ["drupal:site"]);
	assert.equal(merged[0].applicationRelation, "direct");
	assert.deepEqual(merged[0].cve.aliases, ["SA-CORE-2099-001"]);
	assert.match(merged[0].source, /osv/);
	assert.match(merged[0].source, /drupal-security-advisories/);
	assert.match(merged[0].findingId, /^fad-cve-/);
});

test("the same advisory on two physical installations keeps one line and one count per occurrence", () => {
	const occurrence = (site, source, extra = {}) => ({
		dep: { ecosystem: "composer", coordKey: "composer:drupal/core", version: "10.3.1",
			manifestPaths: [`/audit/${site}/composer.lock`], ...(source === "drupal-security-advisories" ? { provenance: "application" } : {}) },
		source, ...extra });
	const osv = site => occurrence(site, "osv",
		{ cve: { id: "CVE-2099-1234", severity: "HIGH", score: 7.5, nvdRefs: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2099-1234" }] } });
	const drupal = site => occurrence(site, "drupal-security-advisories",
		{ advisoryId: "SA-CORE-2099-001", applicationIds: [`drupal:${site}`], ownerComponentIds: [`drupal:${site}:core`],
			applicationRelation: "direct",
			cve: { id: "CVE-2099-1234", aliases: ["SA-CORE-2099-001"], severityOriginal: "Critical",
				osvRefs: [{ url: "https://www.drupal.org/sa-core-2099-001" }] } });
	const merged = coalescePhysicalFindings([osv("a"), drupal("a"), osv("b"), drupal("b")], "/audit");
	assert.equal(merged.length, 2, "one finding per physical lock occurrence, never a global merge");
	assert.equal(new Set(merged.map(f => f.findingId)).size, 2);
	const paths = merged.map(f => f.dep.manifestPaths[0]).sort();
	assert.deepEqual(paths, ["/audit/a/composer.lock", "/audit/b/composer.lock"]);
	for (const finding of merged) {
		assert.match(finding.source, /osv/);
		assert.match(finding.source, /drupal-security-advisories/);
		assert.equal(finding.applicationRelation, "direct");
		assert.equal(finding.cve.score, 7.5, "NVD/OSV enrichment survives the Drupal merge");
		assert.equal(finding.cve.severity, "HIGH");
	}
	const summary = summarizeFindings(merged);
	assert.equal(summary.total, 2);
	assert.deepEqual(summary.byApplication, { "drupal:a": 1, "drupal:b": 1 });
	assert.deepEqual(summary.byApplicationRelation, { direct: 2, indirect: 0, unknown: 0 });
});

test("a Drupal advisory without a CVE never merges into the CVE line of the same occurrence", () => {
	const dep = { ecosystem: "composer", coordKey: "composer:drupal/webform", version: "6.2.0",
		manifestPaths: ["/audit/site/composer.lock"] };
	const merged = coalescePhysicalFindings([
		{ dep: { ...dep }, source: "osv", cve: { id: "CVE-2099-4242", severity: "HIGH", score: 8.1 } },
		{ dep: { ...dep, provenance: "application" }, source: "drupal-security-advisories",
			advisoryId: "SA-CONTRIB-2099-002", applicationIds: ["drupal:site"], ownerComponentIds: ["drupal:site:module:webform"],
			applicationRelation: "direct", cve: { id: "SA-CONTRIB-2099-002", aliases: ["SA-CONTRIB-2099-002"],
				severity: "MEDIUM", severityScheme: "drupal-rating", severityOriginal: "Moderately critical" } },
	], "/audit");
	assert.equal(merged.length, 2, "no alias in common means no merge: the two advisories stay distinct");
	const cveLine = merged.find(f => f.cve.id === "CVE-2099-4242");
	const advisoryLine = merged.find(f => f.cve.id === "SA-CONTRIB-2099-002");
	assert.ok(cveLine && advisoryLine);
	assert.deepEqual(cveLine.cve.aliases || [], [], "no CVE is fabricated for the advisory without one");
	assert.equal(advisoryLine.cve.severityScheme, "drupal-rating");
	assert.equal(summarizeFindings(merged).total, 2);
});
test('image findings remain distinct across targets even without serialized coordinate keys',()=>{
 const one={dep:{ecosystem:'system',name:'libfoo',version:'1',artifactTargetId:'img-a',artifactPath:'/var/lib/dpkg/status'},cve:{id:'CVE-2024-12345',severity:'HIGH'}};
 const two={...one,dep:{...one.dep,artifactTargetId:'img-b'}};
 assert.equal(summarizeFindings([one,two]).total,2);
 const composer={...one,dep:{ecosystem:'composer',coordKey:'composer:vendor/lib',version:'1',artifactTargetId:'img-a',manifestPaths:['/app/vendor/composer/installed.json']}};
 const second={...composer,dep:{...composer.dep,artifactTargetId:'img-b'}};
 const rows=coalescePhysicalFindings([composer,second]);assert.equal(rows.length,2);assert.notEqual(rows[0].findingId,rows[1].findingId);
});
