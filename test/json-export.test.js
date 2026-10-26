const { test } = require("node:test");
const assert = require("node:assert/strict");
const { buildFindings } = require("../lib/json-export");
const { makeDepRecord } = require("../lib/dep-record");

test("buildFindings produces a flat findings document with summary counts", () => {
	const log4j = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1", manifestPath: "/proj/pom.xml" });
	const lodash = makeDepRecord({ ecosystem: "npm", name: "lodash", version: "4.17.20", manifestPath: "/proj/package.json" });
	const resolvedDeps = new Map([[log4j.coordKey, log4j], [lodash.coordKey, lodash]]);

	const doc = buildFindings({
		cveMatches: [
			{ dep: log4j, cve: { id: "CVE-2021-44228", severity: "CRITICAL", score: 10, kev: true }, source: "osv" },
			{ dep: lodash, cve: { id: "CVE-2020-8203", severity: "HIGH", score: 7.4 }, cpeFiltered: true },
		],
		eolResults: [{ product: "log4j", eol: true, dep: log4j }],
		outdatedResults: [{ dep: lodash, latest: "4.17.21" }],
		licenseResults: { assessed: [{ dep: lodash, ids: ["MIT"], raw: [], category: "permissive" }], flagged: [] },
		resolvedDeps,
		projectInfo: { name: "demo", src: "/proj", generatedAt: "2026-06-01T00:00:00Z" },
		toolVersion: "2.0.2",
	});

	assert.equal(doc.tool.name, "VigieVuln");
	assert.equal(doc.summary.dependencies, 2);
	assert.equal(doc.summary.cve.critical, 1);
	assert.equal(doc.summary.cve.kev, 1);
	assert.equal(doc.summary.cve.total, 1); // cpeFiltered excluded from total
	assert.equal(doc.summary.eol, 1);
	assert.equal(doc.summary.outdated, 1);

	assert.equal(doc.cve.length, 2);
	const c = doc.cve[0];
	assert.equal(c.id, "CVE-2021-44228");
	assert.equal(c.kev, true);
	assert.equal(c.dep.purl, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
	assert.equal(doc.cve[1].cpeFiltered, true);

	assert.equal(doc.licenses[0].licenses[0], "MIT");
});

test("buildFindings carries the ignored-directories appendix (array + summary count)", () => {
	const doc = buildFindings({
		excludedDirs: [
			{ dir: "a/b/c/node_modules", type: "default", reason: "default-exclude (node_modules)" },
			{ dir: "legacy", type: "exclude-path", reason: "--exclude-path (legacy)" },
		],
		projectInfo: { name: "demo", src: "/proj" },
		toolVersion: "2.0.2",
	});
	assert.equal(doc.summary.excludedDirs, 2);
	assert.equal(doc.excludedDirs.length, 2);
	assert.equal(doc.excludedDirs[0].dir, "a/b/c/node_modules");
	assert.equal(doc.excludedDirs[1].type, "exclude-path");
	// absent input → empty, not undefined
	assert.deepEqual(buildFindings({}).excludedDirs, []);
});

test("buildFindings carries dep.versionSource (BOM provenance) when backfilled, null otherwise", () => {
	const batch = makeDepRecord({ ecosystem: "maven", namespace: "org.springframework.batch", name: "spring-batch-integration", version: "6.0.3", manifestPath: "/proj/build.gradle.kts" });
	batch.versionSource = { via: "bom", bom: "org.springframework.boot:spring-boot-dependencies:4.0.6" };
	const lodash = makeDepRecord({ ecosystem: "npm", name: "lodash", version: "4.17.20", manifestPath: "/proj/package.json" });
	const doc = buildFindings({
		cveMatches: [
			{ dep: batch, cve: { id: "CVE-2099-0001", severity: "HIGH", score: 7.5 }, source: "osv" },
			{ dep: lodash, cve: { id: "CVE-2020-8203", severity: "HIGH", score: 7.4 }, source: "osv" },
		],
		projectInfo: { name: "demo", src: "/proj" },
		toolVersion: "2.0.2",
	});
	assert.deepEqual(doc.cve[0].dep.versionSource, { via: "bom", bom: "org.springframework.boot:spring-boot-dependencies:4.0.6" });
	assert.equal(doc.cve[1].dep.versionSource, null);
});

test("buildFindings counts suppressed matches separately", () => {
	const dep = makeDepRecord({ ecosystem: "npm", name: "x", version: "1.0.0", manifestPath: "p" });
	const doc = buildFindings({
		cveMatches: [
			{ dep, cve: { id: "CVE-A", severity: "HIGH", score: 7 }, suppressed: true, suppressedReason: "accepted risk" },
			{ dep, cve: { id: "CVE-B", severity: "LOW", score: 2 } },
		],
		resolvedDeps: new Map([[dep.coordKey, dep]]),
	});
	assert.equal(doc.summary.suppressed, 1);
	assert.equal(doc.summary.cve.total, 1); // suppressed excluded
	assert.equal(doc.cve.find(c => c.id === "CVE-A").suppressed, true);
});

test("buildFindings carries EOL origin (productSlug/via/viaKey) for traceability", () => {
	const dep = makeDepRecord({ ecosystem: "maven", namespace: "org.springframework.boot", name: "spring-boot", version: "2.1.0" });
	const doc = buildFindings({
		cveMatches: [],
		eolResults: [{ dep, product: "Spring Boot", productSlug: "spring-boot", via: "group-prefix", viaKey: "org.springframework.boot", eol: "2020-11-05" }],
		resolvedDeps: new Map([[dep.coordKey, dep]]),
		projectInfo: { name: "x", src: "/x" },
	});
	assert.equal(doc.eol[0].productSlug, "spring-boot");
	assert.equal(doc.eol[0].via, "group-prefix");
	assert.equal(doc.eol[0].viaKey, "org.springframework.boot");
});

test("buildFindings includes the embedded inventory (coords with and without CVE)", () => {
	const clean = makeDepRecord({ ecosystem: "maven", namespace: "com.google.guava", name: "guava", version: "30.1-jre", manifestPath: "dist/app.jar!/BOOT-INF/lib/guava-30.1-jre.jar", provenance: "embedded" });
	const vuln = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.0", manifestPath: "dist/app.jar!/BOOT-INF/lib/log4j-core-2.14.0.jar", provenance: "embedded" });
	const doc = buildFindings({
		cveMatches: [{ dep: vuln, source: "osv", cve: { id: "CVE-2021-44228", severity: "CRITICAL" } }],
		resolvedDeps: new Map([[clean.coordKey, clean], [vuln.coordKey, vuln]]),
		projectInfo: { name: "x", src: "/x" },
	});
	assert.equal(doc.summary.embedded, 2);
	assert.equal(doc.embedded.length, 2);
	assert.ok(doc.embedded.some(e => e.artifactId === "guava" && e.vulnCount === 0));
	assert.ok(doc.embedded.some(e => e.artifactId === "log4j-core" && e.vulnCount === 1));
});

test("eol entries carry status / cycle / support / anchor / components; summary splits unsupported", () => {
	const sf = makeDepRecord({ ecosystem: "composer", namespace: "symfony", name: "framework-bundle", version: "5.4.45", manifestPath: "/proj/composer.lock" });
	const doc = buildFindings({
		eolResults: [
			{ product: "Symfony", productSlug: "symfony", via: "composer-framework", viaKey: "symfony/framework-bundle", cycle: "5.4", status: "unsupported", eol: "2029-02-28", support: "2024-11-30", anchor: "symfony/framework-bundle", components: [{ name: "symfony/framework-bundle", version: "5.4.45" }, { name: "symfony/yaml", version: "5.4.45" }], dep: sf },
			{ product: "log4j", eol: true, dep: sf },   // legacy shape: no status → "eol"
		],
		resolvedDeps: new Map(), projectInfo: { name: "demo", src: "/proj", generatedAt: "2026-09-02T00:00:00Z" },
	});
	assert.equal(doc.summary.eol, 2);
	assert.equal(doc.summary.unsupported, 1);
	assert.equal(doc.eol[0].status, "unsupported");
	assert.equal(doc.eol[0].cycle, "5.4");
	assert.equal(doc.eol[0].support, "2024-11-30");
	assert.equal(doc.eol[0].anchor, "symfony/framework-bundle");
	assert.deepEqual(doc.eol[0].components.map(c => c.name), ["symfony/framework-bundle", "symfony/yaml"]);
	assert.equal(doc.eol[1].status, "eol");
	assert.equal(doc.eol[1].cycle, null);
	assert.equal(doc.eol[1].anchor, null);
	assert.equal(doc.eol[1].components, null);
});

test("findings JSON carries application inventory, warnings and coverage even without findings", () => {
	const applications = [{ id: "wordpress:site-a", type: "wordpress", root: "site-a" }];
	const applicationInventory = [{ applicationId: "wordpress:site-a", kind: "plugin", name: "example", version: null }];
	const coverage = [{ applicationId: "wordpress:site-a", capability: "advisories", execution: "not-run", result: "indeterminate", diagnostic: "CMS_PROVIDER_UNCONFIGURED" }];
	const warnings = [{ type: "cms-version-unknown", message: "Version unavailable" }];
	const doc = buildFindings({ applications, applicationInventory, coverage, warnings });
	assert.equal(doc.schema, "fad-findings/1");
	assert.deepEqual(doc.applications, applications);
	assert.deepEqual(doc.applicationInventory, applicationInventory);
	assert.deepEqual(doc.coverage, coverage);
	assert.deepEqual(doc.warnings, warnings);
	assert.equal(doc.summary.applications, 1);
	assert.equal(doc.summary.applicationComponents, 1);
	assert.equal(doc.summary.coverageIncomplete, 1);
});

test("findings JSON retains physical finding ID and proven private-plugin ownership", () => {
	const match = { findingId: "fad-cve-copy-a", applicationIds: ["wordpress:site"],
		ownerComponentIds: ["wordpress:site:plugin:acme"], applicationRelation: "indirect",
		attributionStatus: "confirmed", dependencyPaths: [["acme/plugin", "vendor/lib"]],
		dep: { ecosystem: "composer", namespace: "vendor", name: "lib", version: "1.0.0",
			manifestPaths: ["site/wp-content/plugins/acme/composer.lock"] },
		cve: { id: "CVE-2099-0001", severity: "HIGH" } };
	const finding = buildFindings({ cveMatches: [match] }).cve[0];
	assert.equal(finding.findingId, "fad-cve-copy-a");
	assert.deepEqual(finding.ownerComponentIds, ["wordpress:site:plugin:acme"]);
	assert.equal(finding.applicationRelation, "indirect");
	assert.deepEqual(finding.dependencyPaths, [["acme/plugin", "vendor/lib"]]);
});

test("JSON headline counts unique physical findings while application exposure can overlap", () => {
	const dep = { ecosystem: "composer", namespace: "vendor", name: "lib", version: "1.0" };
	const one = { findingId: "copy-a", applicationIds: ["site-a", "site-b"],
		applicationRelation: "indirect", dep, cve: { id: "CVE-1", severity: "HIGH", kev: true } };
	const doc = buildFindings({ cveMatches: [one, { ...one }] });
	assert.equal(doc.summary.cve.total, 1);
	assert.equal(doc.summary.cve.high, 1);
	assert.equal(doc.summary.cve.kev, 1);
	assert.deepEqual(doc.findingSummary.byApplication, { "site-a": 1, "site-b": 1 });
});
