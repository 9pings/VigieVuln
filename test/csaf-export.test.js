const { test } = require("node:test");
const assert = require("node:assert/strict");
const { buildCsaf } = require("../lib/csaf-export");
const { makeDepRecord } = require("../lib/dep-record");

function resolvedFixture() {
	const m = new Map();
	for (const r of [
		makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1", manifestPath: "pom.xml" }),
		makeDepRecord({ ecosystem: "pypi", namespace: "", name: "django", version: "2.2.0", manifestPath: "pyproject.toml" }),
	]) m.set(r.coordKey, r);
	return m;
}

test("buildCsaf emits a csaf_vex document with product_tree + vulnerabilities", () => {
	const resolved = resolvedFixture();
	const matches = [{
		dep: resolved.get("org.apache.logging.log4j:log4j-core"),
		cve: { id: "CVE-2021-44228", severity: "CRITICAL", score: 10, cvssVersion: "CVSS:3.1", cvssVector: "AV:N", description: "RCE", kev: true, kevDueDate: "2021-12-24", priority: { band: "exploited", score: 100 } },
	}];
	const doc = buildCsaf(resolved, matches, { projectInfo: { name: "demo" }, toolVersion: "1.0.0", timestamp: "2026-06-01T00:00:00Z" });

	assert.equal(doc.document.category, "csaf_vex");
	assert.equal(doc.document.csaf_version, "2.0");
	assert.equal(doc.document.tracking.id, "vigievuln-demo-2026-06-01");
	assert.equal(doc.product_tree.full_product_names.length, 2);
	const log4jProd = doc.product_tree.full_product_names.find(p => p.name.includes("log4j-core"));
	assert.equal(log4jProd.product_identification_helper.purl, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");

	assert.equal(doc.vulnerabilities.length, 1);
	const v = doc.vulnerabilities[0];
	assert.equal(v.cve, "CVE-2021-44228");
	assert.deepEqual(v.product_status.known_affected, [log4jProd.product_id]);
	assert.equal(v.scores[0].cvss_v3.version, "3.1");
	assert.equal(v.scores[0].cvss_v3.baseScore, 10);
	assert.deepEqual(v.scores[0].products, [log4jProd.product_id]);
	assert.equal(v.flags[0].label, "exploited");
	assert.ok(v.notes.some(n => n.category === "other" && /KEV/.test(n.text)));
});

test("buildCsaf omits cvss_v3 scores for non-v3 metrics", () => {
	const resolved = resolvedFixture();
	const matches = [{ dep: resolved.get("pypi:django"), cve: { id: "CVE-2019-0001", severity: "HIGH", score: 7.5, cvssVersion: "CVSS:2.0" } }];
	const doc = buildCsaf(resolved, matches, {});
	assert.equal(doc.vulnerabilities[0].scores, undefined);
});

// Regression: CSAF must stay schema-valid for awkward inputs. (audit fix #5)
//  - a match whose dep isn't in resolvedDeps (Snyk-only) gets registered as a
//    product so known_affected is never the (invalid) empty array;
//  - an "UNKNOWN" severity is mapped to a valid CVSS-v3 baseSeverity enum;
//  - a non-v3 (e.g. v4) vector string is dropped rather than failing the v3 schema.
test("buildCsaf keeps schema-valid output for snyk-only + UNKNOWN + v4-vector", () => {
	const doc = buildCsaf(new Map(), [
		{ dep: { ecosystem: "npm", name: "ghost", version: "1.0.0", coordKey: "npm:ghost" }, source: "snyk", cve: { id: "CVE-X", severity: "HIGH", score: 7 } },
		{ dep: { ecosystem: "npm", name: "foo", version: "2.0.0", coordKey: "npm:foo" }, cve: { id: "CVE-Y", severity: "UNKNOWN", score: 5, cvssVersion: "3.1", cvssVector: "CVSS:4.0/AV:N" } },
	]);
	for (const v of doc.vulnerabilities) {
		assert.ok(v.product_status.known_affected.length >= 1, `${v.cve} has affected products`);
		const sev = v.scores?.[0]?.cvss_v3?.baseSeverity;
		if (sev) assert.ok(["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(sev), `${sev} is a valid enum`);
		const vec = v.scores?.[0]?.cvss_v3?.vectorString;
		if (vec) assert.match(vec, /^CVSS:3\.[01]\//);
	}
	// the unresolved snyk-only dep was registered as a product
	assert.ok(doc.product_tree.full_product_names.some(p => p.name.includes("ghost")));
});

test("Wordfence advisory without CVE uses CSAF ids and retains affected product", () => {
	const dep = { ecosystem: "wordpress", namespace: "wordpress/plugin", name: "example", version: "1.2",
		coordKey: "wordpress:plugin:example", provenance: "application", manifestPaths: ["site/plugin.php"] };
	const doc = buildCsaf(new Map(), [{ dep, source: "wordfence-v3", cve: {
		id: "WF-123e4567-e89b-12d3-a456-426614174000", severity: "HIGH", score: 7.5,
	} }]);
	const finding = doc.vulnerabilities[0];
	assert.equal(finding.cve, undefined);
	assert.deepEqual(finding.ids, [{ system_name: "Wordfence", text: "123e4567-e89b-12d3-a456-426614174000" }]);
	assert.equal(finding.product_status.known_affected.length, 1);
	assert.equal(doc.product_tree.full_product_names[0].product_identification_helper.purl,
		"pkg:generic/wordpress/plugin/example@1.2");
});

test("a CSAF vulnerability keeps every physical occurrence as its own affected product", () => {
	const { makeDepRecord } = require("../lib/dep-record");
	const resolved = new Map();
	const mk = (version, findingId) => {
		const dep = makeDepRecord({ ecosystem: "composer", namespace: "v", name: "lib", version, manifestPath: "/p/composer.lock" });
		dep.occurrences = [{ version, manifestPath: "/p/composer.lock", scope: "prod", isDev: false, requires: {} }];
		resolved.set(dep.coordKey, dep);
		return { dep: { ...dep, version }, cve: { id: "CVE-2099-0001", severity: "HIGH" },
			findingId, applicationIds: ["wordpress:site"], applicationRelation: "direct" };
	};
	const doc = buildCsaf(resolved, [mk("1.0.0", "f-1"), mk("1.1.0", "f-2")],
		{ projectInfo: { name: "demo", src: "/p" }, toolVersion: "1.0.0", timestamp: "2026-06-01T00:00:00Z" });
	assert.equal(doc.vulnerabilities.length, 1);
	assert.ok(doc.vulnerabilities[0].product_status.known_affected.length >= 2,
		"two physical occurrences of one CVE stay two affected products, never merged into one");
});
