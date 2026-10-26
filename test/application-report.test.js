const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { generateHtmlReport, generateWordReport, writeReports } = require("../lib/cve-report");

const projectInfo = { name: "audit", src: "/audit", generatedAt: "2026-09-23" };
const apps = [{ id: "wordpress:site", type: "wordpress", root: "site" }];
const inventory = [{ id: "wordpress:site:plugin:acme", applicationId: "wordpress:site", kind: "plugin",
  name: "Acme Private", visibility: "private", path: "site/wp-content/plugins/acme", version: "1.0" }];
const match = file => ({ findingId: `finding:${file}`, applicationIds: ["wordpress:site"],
  ownerComponentIds: [inventory[0].id], applicationRelation: "indirect", attributionStatus: "confirmed",
  dep: { ecosystem: "composer", groupId: "vendor", artifactId: "lib", namespace: "vendor", name: "lib",
    version: "1.0.0", scope: "prod", manifestPaths: [`/audit/${file}`] },
  cve: { id: "CVE-2099-0001", severity: "HIGH", score: 7.5, description: "fixture" } });

test("HTML and Word group private plugin dependency CVEs without losing physical copies", () => {
  const payload = { cveMatches: [match("site/a/composer.lock"), match("site/b/composer.lock")],
    applications: apps, applicationInventory: inventory, projectInfo };
  for (const render of [generateHtmlReport, generateWordReport]) {
    const report = render(payload);
    assert.match(report, /Acme Private/);
    assert.match(report, /plugin Acme Private 1\.0/, "the owner group header carries the component's observed version");
    assert.match(report, /Private \/ custom components/);
    assert.match(report, /private/i);
    assert.match(report, /indirect/i);
    assert.equal((report.match(/class="cve-row/g) || []).length, 2);
    assert.match(report, /site\/a\/composer\.lock/);
    assert.match(report, /site\/b\/composer\.lock/);
  }
});

test("executive CVE links reach the application section", () => {
	const report = generateHtmlReport({ cveMatches: [{ ...match("site/a/composer.lock"),
		cve: { ...match("site/a/composer.lock").cve, severity: "CRITICAL", score: 10 } }],
		applications: apps, applicationInventory: inventory, projectInfo });
	assert.match(report, /class="exec-cve-link" href="#chapps">CVE-2099-0001<\/a>/);
	assert.match(report, /id="chapps"/);
});

test("reports show application inventory and incomplete coverage even without CVEs", () => {
	const payload = { cveMatches: [], applications: apps, applicationInventory: inventory,
		coverage: [{ applicationId: apps[0].id, capability: "advisories", sourceId: "wordfence-v3",
			execution: "not-run", result: "indeterminate", diagnostic: "CMS_PROVIDER_UNCONFIGURED" }], projectInfo };
	for (const render of [generateHtmlReport, generateWordReport]) {
		const report = render(payload);
		assert.match(report, /Acme Private/);
		assert.match(report, /wordfence-v3/);
		assert.match(report, /not-run/);
		assert.match(report, /CMS_PROVIDER_UNCONFIGURED/);
	}
});

test("a shared occurrence is detailed in each exposed instance section, with its own origins", () => {
	const shared = { ...match("site/shared/composer.lock"), findingId: "finding:shared",
		applicationIds: ["wordpress:site", "wordpress:site-b"],
		ownerComponentIds: ["wordpress:site:plugin:acme", "wordpress:site-b:plugin:acme-b"] };
	const applications = [...apps, { id: "wordpress:site-b", type: "wordpress", root: "site-b" }];
	const inventoryB = [...inventory, { id: "wordpress:site-b:plugin:acme-b", applicationId: "wordpress:site-b",
		kind: "plugin", name: "Acme B", visibility: "private", path: "site-b/wp-content/plugins/acme-b", version: "1.0" }];
	const relations = [
		{ applicationId: "wordpress:site", ownerComponentId: "wordpress:site:plugin:acme",
			depCoordKey: "composer:vendor/lib", version: "1.0.0", manifestPath: "/audit/site/shared/composer.lock",
			applicationRelation: "indirect", attributionStatus: "confirmed", proof: "physical-containment", dependencyPath: ["acme", "vendor/lib"] },
		{ applicationId: "wordpress:site-b", ownerComponentId: "wordpress:site-b:plugin:acme-b",
			depCoordKey: "composer:vendor/lib", version: "1.0.0", manifestPath: "/audit/site/shared/composer.lock",
			applicationRelation: "indirect", attributionStatus: "confirmed", proof: "physical-containment", dependencyPath: ["acme-b", "vendor/lib"] },
	];
	const payload = { cveMatches: [shared], applications, applicationInventory: inventoryB,
		applicationRelations: relations, projectInfo };
	for (const render of [generateHtmlReport, generateWordReport]) {
		const report = render(payload);
		// one physical finding, one detail row per exposed instance section
		assert.equal((report.match(/class="cve-row/g) || []).length, 2);
		assert.match(report, /Acme Private/);
		assert.match(report, /Acme B/);
		// each section references the other exposure
		assert.equal((report.match(/Also exposed in/g) || []).length, 2);
		// global counters stay a union of findings, not the sum of displayed rows
		assert.match(report, /1\.1 CMS & Frameworks \(1\)/);
		assert.match(report, /Production \(1\)/);
	}
});

test("distinct sets of shared owners keep separate application sections", () => {
	const app = { id: "wordpress:site", type: "wordpress", root: "site" };
	const owners = ["A", "B", "C"].map(name => ({ id: `wordpress:site:plugin:${name}`,
		applicationId: app.id, kind: "plugin", name, visibility: "public", path: `site/wp-content/plugins/${name}` }));
	const finding = (id, ownerIds) => ({ ...match(`site/${id}/composer.lock`), findingId: `finding:${id}`,
		applicationIds: [app.id], applicationExposures: [{ applicationId: app.id,
			ownerComponentIds: ownerIds, applicationRelation: "indirect" }],
		cve: { id, severity: "HIGH", score: 7.5, description: "fixture" } });
	const a = finding("CVE-2099-0101", [owners[0].id, owners[1].id]);
	const b = finding("CVE-2099-0102", [owners[0].id, owners[2].id]);
	for (const render of [generateHtmlReport, generateWordReport]) {
		const report = render({ cveMatches: [a, b], applications: [app], applicationInventory: owners, projectInfo });
		assert.match(report, /plugin A, plugin B \(1\)/);
		assert.match(report, /plugin A, plugin C \(1\)/);
	}
});

test("application dev dependency CVEs stay in the dev count and private owner section", () => {
	const dev = { ...match("site/dev/composer.lock"), dep: { ...match("site/dev/composer.lock").dep,
		scope: "dev", isDev: true } };
	const html = generateHtmlReport({ cveMatches: [], devCveMatches: [dev], applications: apps,
		applicationInventory: inventory, projectInfo });
	assert.equal((html.match(/class="cve-row/g) || []).length, 1);
	assert.match(html, /Acme Private/);
	assert.match(html, /Private \/ custom components/);
	assert.match(html, /Dev dependencies.*?\(1\)/s);
});

test("the application synthesis lists every instance with counts, priority and coverage", () => {
	const apps = [
		{ id: "wordpress:site-a", type: "wordpress", root: "site-a" },
		{ id: "drupal:site-b", type: "drupal", root: "site-b" },
		{ id: "wordpress:site-c", type: "wordpress", root: "site-c" },
	];
	const inventory = [
		{ id: "wordpress:site-a:core", applicationId: "wordpress:site-a", kind: "core", name: "WordPress", version: "6.5", visibility: "public", path: "site-a" },
		{ id: "wordpress:site-a:plugin:acme", applicationId: "wordpress:site-a", kind: "plugin", name: "Acme", version: "1.0", visibility: "public", path: "site-a/wp-content/plugins/acme" },
	];
	const direct = { ...match("site-a/composer.lock"), applicationRelation: "direct",
		ownerComponentIds: [inventory[1].id], cve: { id: "CVE-2099-0002", severity: "CRITICAL", score: 9.8, description: "fixture" } };
	const coverage = [
		{ applicationId: "wordpress:site-a", capability: "advisories", sourceId: "wordfence-v3", execution: "completed", result: "affected", expected: 2, executed: 2 },
		{ applicationId: "drupal:site-b", capability: "advisories", sourceId: "drupal-security-advisories", execution: "completed", result: "no-match", expected: 1, executed: 1 },
		{ applicationId: "wordpress:site-c", capability: "advisories", sourceId: "wordfence-v3", execution: "not-run", result: "indeterminate", diagnostic: "CMS_PROVIDER_UNCONFIGURED" },
	];
	const html = generateHtmlReport({ cveMatches: [direct], applications: apps, applicationInventory: inventory, coverage, projectInfo });
	assert.match(html, /Instance synthesis/);
	// site-a: observed core version, direct count, worst priority band and score
	assert.match(html, /site-a/);
	assert.match(html, /6\.5/);
	assert.match(html, /CRITICAL/);
	assert.match(html, /9\.8/);
	// site-b completed advisory search with no match is stated, never implied
	assert.match(html, /No matching advisory in the consulted data\./);
	// site-c was never checked: an incomplete evaluation, not a clean bill
	assert.match(html, /Evaluation incomplete\./);
	// the synthesis adds no CVE rows and no fabricated counts
	assert.equal((html.match(/class="cve-row/g) || []).length, 1);
	const word = generateWordReport({ cveMatches: [direct], applications: apps, applicationInventory: inventory, coverage, projectInfo });
	assert.match(word, /Instance synthesis/);
	assert.match(word, /Evaluation incomplete\./);
});

test("a mixed-coverage instance reads as partial even when a core advisory matched", () => {
	const apps = [{ id: "wordpress:wp", type: "wordpress", root: "wp" }];
	const inventory = [
		{ id: "wordpress:wp:core", applicationId: "wordpress:wp", kind: "core", name: "WordPress", version: "6.4.2", visibility: "public", path: "wp" },
		...["a", "b"].map(s => ({ id: `wordpress:wp:theme:${s}`, applicationId: "wordpress:wp", kind: "theme",
			name: `Theme ${s}`, version: "1.0", visibility: "public", path: `wp/wp-content/themes/${s}` })),
	];
	const coreHit = { ...match("wp/composer.lock"), applicationRelation: "direct", ownerComponentIds: [inventory[0].id],
		cve: { id: "CVE-2099-0099", severity: "CRITICAL", score: 9.8, description: "fixture" } };
	const coverage = [
		{ applicationId: "wordpress:wp", capability: "inventory", execution: "completed", result: "not-applicable", expected: 3, executed: 3 },
		{ applicationId: "wordpress:wp", capability: "advisories", sourceId: "wordfence-v3", occurrenceId: "wordpress:wp:core",
			execution: "completed", result: "affected", expected: 1, executed: 1 },
		{ applicationId: "wordpress:wp", capability: "advisories", sourceId: "wordfence-v3", occurrenceId: "wordpress:wp:theme:a",
			execution: "not-run", result: "indeterminate", expected: 1, executed: 0, diagnostic: "CMS_IDENTITY_UNVERIFIED" },
		{ applicationId: "wordpress:wp", capability: "advisories", sourceId: "wordfence-v3", occurrenceId: "wordpress:wp:theme:b",
			execution: "not-run", result: "indeterminate", expected: 1, executed: 0, diagnostic: "CMS_IDENTITY_UNVERIFIED" },
	];
	for (const render of [generateHtmlReport, generateWordReport]) {
		const report = render({ cveMatches: [coreHit], applications: apps, applicationInventory: inventory, coverage, projectInfo });
		// the mixed advisories lane must never claim completed
		assert.doesNotMatch(report, /wordfence-v3\): completed/, "a lane with unassessed components is not completed");
		assert.match(report, /advisories \(wordfence-v3\): partial/);
		assert.match(report, /1\/3/, "executed/expected is shown for the lane");
		assert.match(report, /2 not evaluated/, "the number of unassessed components is shown");
		assert.match(report, /CMS_IDENTITY_UNVERIFIED/);
		// a finding on the core does not silence the incomplete-evaluation note
		assert.match(report, /Evaluation incomplete\./);
	}
});

test("lane aggregation keeps failed visible and separates providers", () => {
	const apps = [{ id: "drupal:site", type: "drupal", root: "site" }];
	const coverage = [
		{ applicationId: "drupal:site", capability: "advisories", sourceId: "drupal-security-advisories",
			execution: "failed", result: "indeterminate", expected: 1, executed: 0, diagnostic: "CMS_PLUGIN_FAILED" },
		{ applicationId: "drupal:site", capability: "advisories", sourceId: "application-advisories",
			execution: "completed", result: "no-match", expected: 4, executed: 4 },
	];
	const html = generateHtmlReport({ cveMatches: [], applications: apps, applicationInventory: [], coverage, projectInfo });
	assert.match(html, /1\.1 CMS & Frameworks \(0\)/, "a zero-finding instance still gets its chapter");
	assert.match(html, /Instance synthesis/, "the synthesis shows even with no application CVE");
	assert.match(html, /No application CVE on the inventoried instances/);
	assert.match(html, /drupal-security-advisories/);
	assert.match(html, /CMS_PLUGIN_FAILED/);
	assert.match(html, /application-advisories/);
});

test("6.4 coverage rows name the component each check is about", () => {
	const apps = [{ id: "wordpress:wp", type: "wordpress", root: "wp" }];
	const inventory = [
		{ id: "wordpress:wp:core", applicationId: "wordpress:wp", kind: "core", name: "WordPress", version: "6.4.2", visibility: "public", path: "wp" },
		{ id: "wordpress:wp:theme:a", applicationId: "wordpress:wp", kind: "theme", name: "Theme A", version: "1.0", visibility: "public", path: "wp/wp-content/themes/a" },
	];
	const coverage = [
		{ applicationId: "wordpress:wp", capability: "inventory", execution: "completed", result: "not-applicable", expected: 2, executed: 2 },
		{ applicationId: "wordpress:wp", capability: "advisories", sourceId: "wordfence-v3", occurrenceId: "wordpress:wp:theme:a",
			execution: "not-run", result: "indeterminate", expected: 1, executed: 0, diagnostic: "CMS_IDENTITY_UNVERIFIED" },
	];
	for (const render of [generateHtmlReport, generateWordReport]) {
		const report = render({ cveMatches: [], applications: apps, applicationInventory: inventory, coverage, projectInfo });
		const section = report.slice(report.indexOf("Application coverage"));
		assert.match(section, /theme · Theme A/, "the coverage row names the checked component");
		assert.match(section, /wp\/wp-content\/themes\/a/, "the coverage row carries the component path");
		assert.match(section, /wordpress:wp:theme:a/, "the occurrence id stays visible for traceability");
	}
});

test("application subsections group coverage diagnostics by cause", () => {
	const apps = [{ id: "wordpress:wp", type: "wordpress", root: "wp" }];
	const inventory = [
		{ id: "wordpress:wp:theme:a", applicationId: "wordpress:wp", kind: "theme", name: "Theme A", version: "1.0", visibility: "public", path: "wp/wp-content/themes/a" },
		{ id: "wordpress:wp:theme:b", applicationId: "wordpress:wp", kind: "theme", name: "Theme B", version: "1.0", visibility: "public", path: "wp/wp-content/themes/b" },
		{ id: "wordpress:wp:module:acme", applicationId: "wordpress:wp", kind: "module", name: "Acme", version: "1.0", visibility: "private", path: "wp/modules/acme" },
	];
	const coverage = [
		{ applicationId: "wordpress:wp", capability: "advisories", sourceId: "wordfence-v3", occurrenceId: "wordpress:wp:theme:a",
			execution: "not-run", result: "indeterminate", expected: 1, executed: 0, diagnostic: "CMS_IDENTITY_UNVERIFIED" },
		{ applicationId: "wordpress:wp", capability: "advisories", sourceId: "wordfence-v3", occurrenceId: "wordpress:wp:theme:b",
			execution: "not-run", result: "indeterminate", expected: 1, executed: 0, diagnostic: "CMS_IDENTITY_UNVERIFIED" },
		{ applicationId: "wordpress:wp", capability: "advisories", sourceId: "wordfence-v3", occurrenceId: "wordpress:wp:module:acme",
			execution: "not-run", result: "indeterminate", expected: 1, executed: 0, diagnostic: "CMS_PRIVATE_COMPONENT" },
	];
	// What vigievuln.js passes for the same scan: one structured group per
	// (application, capability, source, diagnostic) cause, each listing its components.
	const warnings = [
		{ type: "cms-coverage", code: "CMS_IDENTITY_UNVERIFIED", applicationId: "wordpress:wp",
			capability: "advisories", sourceId: "wordfence-v3", execution: "not-run", diagnostic: "CMS_IDENTITY_UNVERIFIED", count: 2,
			items: [{ id: "theme Theme A", manifestPaths: ["/audit/wp/wp-content/themes/a"] },
				{ id: "theme Theme B", manifestPaths: ["/audit/wp/wp-content/themes/b"] }] },
		{ type: "cms-coverage", code: "CMS_PRIVATE_COMPONENT", applicationId: "wordpress:wp",
			capability: "advisories", sourceId: "wordfence-v3", execution: "not-run", diagnostic: "CMS_PRIVATE_COMPONENT", count: 1,
			items: [{ id: "module Acme", manifestPaths: ["/audit/wp/modules/acme"] }] },
	];
	for (const render of [generateHtmlReport, generateWordReport]) {
		const report = render({ cveMatches: [], applications: apps, applicationInventory: inventory, coverage, warnings, projectInfo });
		// one block per cause — not one identical message per unassessed component
		assert.equal((report.match(/warn-block warn-cms-coverage/g) || []).length, 2);
		assert.doesNotMatch(report, /id="ch0"/, "application diagnostics are not global alerts");
		assert.match(report, /2 component\(s\) not evaluated/);
		assert.match(report, /warn-items[\s\S]*?Theme A[\s\S]*?Theme B/, "both themes are listed inside the group");
		assert.match(report, /Declare a verified catalogue identity/, "the group states the expected action");
		assert.match(report, /CMS_IDENTITY_UNVERIFIED/);
	}
});

test("WordPress file diagnostics form one local warning subsection with a scrolling full path list", () => {
	const files = Array.from({ length: 7 }, (_, i) => `wp-includes/js/copy-${i + 1}.js`);
	const warnings = [
		{ type: "no-lockfile", message: "global descriptor warning" },
		...files.map(file => ({ type: "cms-coverage", code: "CMS_FILE_MISSING", applicationId: "wordpress:site",
			path: file, message: `wordpress:site: ${file} is absent` })),
		{ type: "cms-coverage", code: "CMS_INTEGRITY_LIST_TRUNCATED", applicationId: "wordpress:site",
			message: "more official files were absent" },
	];
	const payload = { cveMatches: [match("site/a/composer.lock")], applications: apps,
		applicationInventory: inventory, warnings, projectInfo };
	const html = generateHtmlReport(payload);
	const global = html.slice(html.indexOf('id="ch0"'), html.indexOf('id="chcve"'));
	assert.match(global, /global descriptor warning/);
	assert.doesNotMatch(global, /copy-1\.js|CMS_FILE_MISSING/);
	assert.equal((html.match(/class="warnings app-warnings"/g) || []).length, 1);
	assert.match(html, /wordpress · site[\s\S]*?<summary><h3>Warnings \(8\)<\/h3><\/summary>/);
	assert.match(html, /app-warning-files \{ max-height: 240px; overflow-y: auto/);
	for (const file of files) assert.match(html, new RegExp(file.replaceAll(".", "\\.")));
	assert.match(html, /more official files were absent/);
	const word = generateWordReport(payload);
	for (const file of files) assert.match(word, new RegExp(file.replaceAll(".", "\\.")));
	const empty = generateHtmlReport({ ...payload, cveMatches: [] });
	assert.match(empty, /id="chapps"/, "the zero-finding instance keeps its chapter");
	assert.match(empty, /Instance synthesis \(1\)/);
	assert.match(empty, /Application inventory &amp; coverage[\s\S]*?wordpress · site[\s\S]*?Warnings \(8\)/);
});

test("fix recommendations carry no orphan 7.0 numbering", () => {
	const direct = { dep: { ecosystem: "composer", groupId: "v", artifactId: "lib", namespace: "v", name: "lib",
		version: "1.0.0", scope: "prod" }, cve: { id: "CVE-2099-0001", severity: "HIGH", fixVersion: "1.1.0", description: "fixture" } };
	for (const render of [generateHtmlReport, generateWordReport]) {
		const report = render({ cveMatches: [direct], projectInfo });
		assert.doesNotMatch(report, /7\.0/, "no section 7.0 may appear — the report has no section 7");
		assert.match(report, /5\.1 Direct deps to update/);
	}
	const fr = generateHtmlReport({ cveMatches: [direct], projectInfo, locale: "fr" });
	assert.match(fr, /Dépendances directes à mettre à jour/);
	assert.doesNotMatch(fr, /Deps directes/);
});

test("coverage chrome translates in both directions (synthesis, inventory and app warnings)", () => {
	const apps = [{ id: "wordpress:wp", type: "wordpress", root: "wp" }];
	const inventory = [
		{ id: "wordpress:wp:core", applicationId: "wordpress:wp", kind: "core", name: "WordPress", version: "6.4.2", visibility: "public", path: "wp" },
		{ id: "wordpress:wp:theme:a", applicationId: "wordpress:wp", kind: "theme", name: "Theme A", version: "1.0", visibility: "public", path: "wp/wp-content/themes/a" },
	];
	const coverage = [
		{ applicationId: "wordpress:wp", capability: "inventory", execution: "completed", result: "not-applicable", expected: 2, executed: 2 },
		{ applicationId: "wordpress:wp", capability: "advisories", sourceId: "wordfence-v3", occurrenceId: "wordpress:wp:core",
			execution: "completed", result: "affected", expected: 1, executed: 1 },
		{ applicationId: "wordpress:wp", capability: "advisories", sourceId: "wordfence-v3", occurrenceId: "wordpress:wp:theme:a",
			execution: "not-run", result: "indeterminate", expected: 1, executed: 0, diagnostic: "CMS_IDENTITY_UNVERIFIED" },
	];
	const warnings = [{ type: "cms-coverage", code: "CMS_IDENTITY_UNVERIFIED", applicationId: "wordpress:wp",
		capability: "advisories", sourceId: "wordfence-v3", execution: "not-run", diagnostic: "CMS_IDENTITY_UNVERIFIED", count: 1,
		items: [{ id: "theme Theme A", manifestPaths: ["/audit/wp/wp-content/themes/a"] }] }];
	const payload = { cveMatches: [], applications: apps, applicationInventory: inventory, coverage, warnings, projectInfo };
	const en = generateHtmlReport(payload);
	const fr = generateHtmlReport({ ...payload, locale: "fr" });
	// EN chrome stays English
	assert.match(en, /1\.1 CMS & Frameworks \(0\)/, "the chapter shows the zero-finding synthesis");
	assert.match(en, /No application CVE on the inventoried instances/);
	assert.match(en, /wordfence-v3/);
	assert.match(en, /not evaluated/);
	// FR chrome is French in the synthesis, the 6.4 table and chapter 0
	assert.match(fr, /Inventaire applicatif et couverture/);
	assert.match(fr, /wordfence-v3/);
	assert.match(fr, /non évalué\(s\)/);
	assert.match(fr, /Avertissements/);
	assert.match(fr, /1 composant\(s\) non évalué\(s\)/);
	assert.doesNotMatch(fr, /id="ch0"/, "application diagnostics stay in the application subsection");
	assert.doesNotMatch(fr, /inventory: completed/);
	assert.doesNotMatch(fr, /: partial/);
	assert.doesNotMatch(fr, /<td>not-run</);
	assert.doesNotMatch(en, /inventaire|non évalué|partiel|terminé/);
});

test("the French application synthesis translates its chrome and its notes", () => {
	const apps = [{ id: "drupal:site-b", type: "drupal", root: "site-b" },
		{ id: "wordpress:site-c", type: "wordpress", root: "site-c" }];
	const coverage = [{ applicationId: "drupal:site-b", capability: "advisories", execution: "not-run", result: "indeterminate", diagnostic: "CMS_PROVIDER_UNCONFIGURED" }];
	const fr = generateHtmlReport({ cveMatches: [], applications: apps, applicationInventory: [], coverage, projectInfo, locale: "fr" });
	assert.match(fr, /Synthèse des instances/, "the zero-finding synthesis shows — translated");
	assert.match(fr, /Aucune CVE applicative sur les instances inventoriées/);
	assert.match(fr, /Inventaire applicatif et couverture/);
	assert.match(fr, /CMS_PROVIDER_UNCONFIGURED/);
	assert.doesNotMatch(fr, /Evaluation incomplete\./);
	assert.doesNotMatch(fr, /Instance synthesis/);
});

test("report numbers only populated subsections and keeps the contents links valid", () => {
	const generic = { ...match("plain/composer.lock"), findingId: "generic",
		applicationIds: [], ownerComponentIds: [], cve: { id: "CVE-2099-0002", severity: "HIGH", description: "fixture" } };
	const payload = { cveMatches: [match("site/composer.lock"), generic], applications: apps,
		applicationInventory: inventory, projectInfo };
	for (const render of [generateHtmlReport, generateWordReport]) {
		const report = render(payload);
		assert.match(report, /1\.1 CMS & Frameworks \(1\)/);
		assert.match(report, /1\.2 Production \(1\)/);
		assert.doesNotMatch(report, /1\.3 (?:Vendored JS|Dev dependencies)/);
		assert.match(report, /6\.1 Methodology, data sources & limitations/);
		assert.match(report, /6\.2 Application inventory & coverage/);
		for (const [, id] of report.matchAll(/href="#(ch[^" ]+)"/g))
			assert.match(report, new RegExp(`id="${id}"`), `missing chapter ${id}`);
	}
	const empty = generateHtmlReport({ applications: apps, applicationInventory: inventory, projectInfo });
	assert.match(empty, /1\. CVE \(0 direct, 0 indirect, 0 dev\)/);
	assert.match(empty, /1\.1 CMS & Frameworks \(0\)/, "an inventoried instance keeps its chapter even with zero findings");
	assert.match(empty, /Instance synthesis \(1\)/);
	assert.match(empty, /Application inventory & coverage/);
	const orphan = generateHtmlReport({ cveMatches: [match("site/composer.lock")], projectInfo });
	assert.match(orphan, /1\.1 CMS & Frameworks \(1\)/);
	assert.doesNotMatch(orphan, /Instance synthesis \(0\)/);
});

test("report writer preserves per-application ownership relations", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-app-report-"));
	try {
		const dep = { ...match("site/composer.lock").dep, coordKey: "composer:vendor/lib" };
		const finding = { ...match("site/composer.lock"), dep, applicationRelation: "unknown", ownerComponentIds: [] };
		const applicationRelations = [{ applicationId: apps[0].id, ownerComponentId: inventory[0].id,
			depCoordKey: dep.coordKey, version: dep.version, manifestPath: dep.manifestPaths[0],
			applicationRelation: "indirect" }];
		const htmlPath = path.join(dir, "report.html");
		await writeReports({ cveMatches: [finding], applications: apps, applicationInventory: inventory,
			applicationRelations, projectInfo, htmlPath, docPath: null });
		const html = fs.readFileSync(htmlPath, "utf8");
		assert.match(html, /Acme Private/);
		assert.match(html, /Indirect \(1\)/);
		assert.doesNotMatch(html, /Unknown origin \(1\)/);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
