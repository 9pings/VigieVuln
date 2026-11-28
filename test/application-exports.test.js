const { test } = require("node:test");
const assert = require("node:assert/strict");
const { makeDepRecord } = require("../lib/inventory/dep-record");
const { buildCycloneDx } = require("../lib/reports/sbom-export");
const { buildCsaf } = require("../lib/reports/csaf-export");
const { buildSarif } = require("../lib/reports/sarif-export");

function fixture() {
	const dep = makeDepRecord({ ecosystem: "composer", namespace: "vendor", name: "lib", version: "1.0.0",
		manifestPath: "/audit/site-a/composer.lock", scope: "prod" });
	dep.occurrences = [
		{ version: "1.0.0", manifestPath: "/audit/site-a/composer.lock", scope: "prod" },
		{ version: "2.0.0", manifestPath: "/audit/site-b/composer.lock", scope: "prod" },
	];
	const match = { findingId: "fad-cve-site-a", dep: { ...dep, version: "1.0.0",
		occurrences: [dep.occurrences[0]], manifestPaths: [dep.occurrences[0].manifestPath] },
		cve: { id: "CVE-2099-0001", severity: "HIGH", score: 7.5 } };
	return { resolved: new Map([[dep.coordKey, dep]]), match };
}

test("SBOM and CSAF preserve Composer versions and affect only the matching occurrence", () => {
	const { resolved, match } = fixture();
	const opts = { projectInfo: { name: "audit", src: "/audit" } };
	const bom = buildCycloneDx(resolved, [match], opts);
	const libs = bom.components.filter(c => c.name === "lib");
	assert.deepEqual(new Set(libs.map(c => c.version)), new Set(["1.0.0", "2.0.0"]));
	assert.equal(new Set(libs.map(c => c["bom-ref"])).size, 2);
	assert.deepEqual(bom.vulnerabilities[0].affects.map(a => a.ref), [libs.find(c => c.version === "1.0.0")["bom-ref"]]);
	const csaf = buildCsaf(resolved, [match], opts);
	const products = csaf.product_tree.full_product_names.filter(p => p.name.startsWith("vendor/lib"));
	assert.equal(products.length, 2);
	assert.deepEqual(csaf.vulnerabilities[0].product_status.known_affected,
		[products.find(p => p.name.includes("@1.0.0")).product_id]);
});

test("SARIF fingerprints distinguish two physical copies", () => {
	const { match } = fixture();
	const second = { ...match, findingId: "fad-cve-site-b", dep: { ...match.dep,
			occurrences: [{ version: "1.0.0", manifestPath: "/audit/site-b/composer.lock" }],
			manifestPaths: ["/audit/site-b/composer.lock"] } };
	const result = buildSarif([match, second], { projectInfo: { src: "/audit" } }).runs[0].results;
	assert.equal(new Set(result.map(r => r.partialFingerprints.fadKey)).size, 2);
});

test("CSAF names two same-version Composer copies by their relative location", () => {
	const { resolved, match } = fixture();
	const dep = resolved.values().next().value;
	dep.occurrences[1].version = "1.0.0";
	const doc = buildCsaf(resolved, [match], { projectInfo: { src: "/audit" } });
	const names = doc.product_tree.full_product_names.map(p => p.name);
	assert.ok(names.some(n => n.includes("site-a/composer.lock")));
	assert.ok(names.some(n => n.includes("site-b/composer.lock")));
	assert.equal(doc.vulnerabilities[0].product_status.known_affected.length, 1);
});
