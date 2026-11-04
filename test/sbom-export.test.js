const { test } = require("node:test");
const assert = require("node:assert/strict");
const { buildCycloneDx, cvssMethod, cdxSeverity } = require("../lib/sbom-export");
const { makeDepRecord } = require("../lib/dep-record");

function resolvedFixture() {
	const m = new Map();
	for (const r of [
		makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1", manifestPath: "pom.xml" }),
		makeDepRecord({ ecosystem: "npm", namespace: "", name: "lodash", version: "4.17.20", manifestPath: "package.json" }),
	]) m.set(r.coordKey, r);
	return m;
}

test("buildCycloneDx produces a valid 1.6 skeleton with components + vulnerabilities", () => {
	const resolved = resolvedFixture();
	const matches = [{
		dep: resolved.get("org.apache.logging.log4j:log4j-core"),
		cve: { id: "CVE-2021-44228", severity: "CRITICAL", score: 10, cvssVersion: "CVSS:3.1", cvssVector: "AV:N", cwes: ["CWE-502"], epssPercentile: 0.99, kev: true, priority: { band: "exploited", score: 100 } },
		source: "osv+nvd",
	}];
	const bom = buildCycloneDx(resolved, matches, { projectInfo: { name: "demo" }, toolVersion: "1.2.3", timestamp: "2026-06-01T00:00:00Z" });

	assert.equal(bom.bomFormat, "CycloneDX");
	assert.equal(bom.specVersion, "1.6");
	assert.equal(bom.components.length, 2);
	const log4j = bom.components.find(c => c.name === "log4j-core");
	assert.equal(log4j.purl, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
	assert.equal(log4j.group, "org.apache.logging.log4j");

	assert.equal(bom.vulnerabilities.length, 1);
	const v = bom.vulnerabilities[0];
	assert.equal(v.id, "CVE-2021-44228");
	assert.equal(v.ratings[0].severity, "critical");
	assert.equal(v.ratings[0].method, "CVSSv31");
	assert.deepEqual(v.cwes, [502]);
	assert.equal(v.affects[0].ref, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
	assert.ok(v.properties.some(p => p.name === "fad:kev" && p.value === "true"));
	assert.ok(v.properties.some(p => p.name === "fad:priorityBand" && p.value === "exploited"));
});

test("buildCycloneDx dedups one CVE across multiple affected components", () => {
	const resolved = resolvedFixture();
	const dep = resolved.get("npm:lodash");
	const matches = [
		{ dep, cve: { id: "CVE-2020-8203", severity: "HIGH", score: 7.4 } },
		{ dep: { ...dep, version: "4.17.20" }, cve: { id: "CVE-2020-8203", severity: "HIGH", score: 7.4 } },
	];
	const bom = buildCycloneDx(resolved, matches, {});
	assert.equal(bom.vulnerabilities.length, 1);
	assert.equal(bom.vulnerabilities[0].affects.length, 1);
});

test("buildCycloneDx attaches component licenses from licenseResults", () => {
	const resolved = resolvedFixture();
	const dep = resolved.get("npm:lodash");
	const licenseResults = { assessed: [{ dep, ids: ["MIT"], raw: [], category: "permissive" }] };
	const bom = buildCycloneDx(resolved, [], { licenseResults });
	const lodash = bom.components.find(c => c.name === "lodash");
	assert.deepEqual(lodash.licenses, [{ license: { id: "MIT" } }]);
});

test("cvssMethod + cdxSeverity map NVD shapes to CycloneDX enums", () => {
	assert.equal(cvssMethod("CVSS:3.1"), "CVSSv31");
	assert.equal(cvssMethod("CVSS:2.0"), "CVSSv2");
	assert.equal(cvssMethod(null), "other");
	assert.equal(cdxSeverity("CRITICAL"), "critical");
	assert.equal(cdxSeverity("WAT"), "unknown");
});

// Regression: tolerate both the clean "CVSS:3.1" label and the legacy "CVSS:V31"
// left in pre-fix NVD caches; an OSV/GHSA id must not get a dead NVD url. (#B/#C)
test("cvssMethod tolerates legacy CVSS:V31 cache labels", () => {
	assert.equal(cvssMethod("CVSS:3.1"), "CVSSv31");
	assert.equal(cvssMethod("CVSS:V31"), "CVSSv31");
	assert.equal(cvssMethod("CVSS:V40"), "CVSSv4");
});

test("buildCycloneDx points GHSA/OSV ids at the right advisory db", () => {
	const dep = makeDepRecord({ ecosystem: "npm", namespace: "", name: "x", version: "1.0.0", manifestPath: "package.json" });
	const resolved = new Map([[dep.coordKey, dep]]);
	const bom = buildCycloneDx(resolved, [
		{ dep, source: "osv", cve: { id: "GHSA-aaaa-bbbb-cccc", severity: "HIGH", score: 7 } },
		{ dep, source: "nvd", cve: { id: "CVE-2021-1", severity: "HIGH", score: 7 } },
	]);
	const ghsa = bom.vulnerabilities.find(v => v.id.startsWith("GHSA"));
	const cve = bom.vulnerabilities.find(v => v.id.startsWith("CVE"));
	assert.match(ghsa.source.url, /osv\.dev\/vulnerability/);
	assert.equal(ghsa.source.name, 'OSV');
	assert.match(cve.source.url, /nvd\.nist\.gov/);
});

test('SBOM preserves advisory provenance instead of inferring NVD from a CVE id', () => {
	const dep = makeDepRecord({ ecosystem:'npm', name:'x', version:'1.0.0', manifestPath:'package.json' });
	const bom = buildCycloneDx(new Map([[dep.coordKey, dep]]), [
		{dep, source:'CVEProject+osv', cve:{id:'CVE-2024-1234',severity:'HIGH',score:7}},
		{dep, cve:{id:'CVE-2024-5678',severity:'LOW',score:2}},
	]);
	const a = bom.vulnerabilities.find(v=>v.id==='CVE-2024-1234');
	assert.equal(a.source.name,'CVEProject');
	assert.deepEqual(a.properties.filter(p=>p.name==='vigievuln:source').map(p=>p.value),['CVEProject','osv']);
	assert.equal(a.ratings[0].source, undefined, 'do not guess which source supplied a merged score');
	assert.equal(bom.vulnerabilities.find(v=>v.id==='CVE-2024-5678').source.name,'cache');
});

test("Wordfence-only advisory registers its application component in CycloneDX", () => {
	const dep = { ecosystem: "wordpress", namespace: "wordpress/plugin", name: "example", version: "1.2",
		coordKey: "wordpress:plugin:example", provenance: "application", manifestPaths: ["site/wp-content/plugins/example/plugin.php"] };
	const bom = buildCycloneDx(new Map(), [{ dep, source: "wordfence-v3", cve: {
		id: "WF-123e4567-e89b-12d3-a456-426614174000", severity: "HIGH", score: 7.5,
	} }]);
	assert.equal(bom.components.length, 1);
	assert.equal(bom.components[0].purl, "pkg:generic/wordpress/plugin/example@1.2");
	assert.deepEqual(bom.vulnerabilities[0].affects, [{ ref: bom.components[0]["bom-ref"] }]);
	assert.equal(bom.vulnerabilities[0].source.name, "Wordfence");
});

test("the SBOM carries each occurrence's finding identity and application relation", () => {
	const { buildCycloneDx } = require("../lib/sbom-export");
	const mk = (version, relation, findingId) => ({
		dep: { ecosystem: "composer", namespace: "v", name: "lib", groupId: "v", artifactId: "lib",
			version, scope: "prod", coordKey: "composer:v/lib", manifestPaths: ["/p/composer.lock"] },
		cve: { id: "CVE-2099-0001", severity: "HIGH", score: 7.5 },
		findingId, applicationIds: ["wordpress:site"], applicationRelation: relation,
	});
	const bom = buildCycloneDx(new Map(), [mk("1.0.0", "direct", "f-1"), mk("1.1.0", "indirect", "f-2")],
		{ projectInfo: { name: "p", src: "/p" } });
	const props = bom.vulnerabilities[0].properties.filter(p => p.name === "fad:finding");
	assert.deepEqual(props.map(p => p.value).sort(), ["f-1=direct", "f-2=indirect"],
		"every physical occurrence keeps its findingId and its application relation");
	assert.ok(bom.vulnerabilities[0].affects.length >= 1);
});
