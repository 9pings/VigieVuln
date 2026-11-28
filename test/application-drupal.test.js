const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const composer = require("../lib/codecs/composer.codec");
const drupal = require("../lib/applications/plugins/drupal");
const { runApplicationPlugins } = require("../lib/applications/plugins/runner");
const { buildApplicationRelations, expandComposerFindings } = require("../lib/applications/inventory");

test("Drupal local advisory snapshot assesses core while keeping a custom module separate", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal-feed-"));
	try {
		const feed = path.join(temp, "advisories.json");
		fs.writeFileSync(feed, JSON.stringify({ queriedPackages: ["drupal/core"], advisories: { "drupal/core": [
			{ advisoryId: "SA-CORE-2099-001", packageName: "drupal/core", title: "Drupal core - Critical - Fixture",
				link: "https://www.drupal.org/sa-core-2099-001", cve: null, affectedVersions: ">=10.3.0 <10.3.2" },
		] } }));
		const root = path.join(__dirname, "fixtures", "drupal-custom");
		const { deps } = await composer.collect(root);
		const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal",
			resolvedDeps: deps, activeCodecIds: ["composer"], drupalAdvisoriesPath: feed });
		assert.equal(result.findings.length, 1);
		assert.equal(result.findings[0].cve.id, "SA-CORE-2099-001");
		assert.equal(result.findings[0].cve.severityScheme, "drupal-rating");
		assert.equal(result.findings[0].cve.fixVersion, "10.3.2", "the affected range's exclusive upper bound is the publisher's fix");
		assert.equal(result.coverage.find(c => c.occurrenceId?.endsWith(":core")).result, "affected");
		assert.match(result.coverage.find(c => c.occurrenceId?.endsWith(":core")).sourceSnapshot.sha256, /^[a-f0-9]{64}$/);
		assert.equal(result.coverage.find(c => c.occurrenceId?.includes(":module:")).diagnostic, "CMS_PRIVATE_COMPONENT");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("Drupal custom module is private and its local dependency CVE is attributed to it", async () => {
	const root = path.join(__dirname, "fixtures", "drupal-custom");
	const { deps } = await composer.collect(root);
	const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal", resolvedDeps: deps, activeCodecIds: ["composer"] });
	assert.deepEqual(result.applications.map(a => a.id), ["drupal:site"]);
	const core = result.inventory.find(c => c.kind === "core");
	const mod = result.inventory.find(c => c.kind === "module");
	assert.equal(core.version, "10.3.1");
	assert.equal(mod.visibility, "private");
	assert.equal(mod.version, "1.0.0");
	assert.equal(mod.coord, "acme/payments");
	assert.equal(mod.coreVersionRequirement, "^10");
	const vulnerable = deps.get("composer:vendor/vulnerable-lib");
	const relations = buildApplicationRelations(root, result.applications, result.inventory, deps);
	const findings = expandComposerFindings([{ dep: vulnerable, cve: { id: "CVE-2099-0002" } }], root, relations);
	assert.deepEqual(findings[0].ownerComponentIds, [mod.id]);
	assert.equal(findings[0].applicationRelation, "indirect");
	const symfonyInsideDrupal = relations.find(r => r.depCoordKey === "composer:symfony/http-kernel" && r.ownerComponentId === core.id);
	assert.ok(symfonyInsideDrupal, "Symfony used by Drupal belongs under the Drupal core");
	assert.equal(result.applications.some(a => a.type === "symfony"), false);
	assert.equal(result.coverage.find(c => c.capability === "advisories").execution, "not-run");
	assert.equal(result.coverage.find(c => c.capability === "advisories").expected, result.inventory.length);
});

test("Drupal 7 is recognized without Composer and custom .info modules remain private", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal7-"));
	try {
		const site = path.join(root, "site");
		for (const dir of ["includes", "modules/system", "sites/all/modules/custom/acme"])
			fs.mkdirSync(path.join(site, dir), { recursive: true });
		fs.writeFileSync(path.join(site, "includes/bootstrap.inc"), "<?php define('VERSION', '7.104');");
		fs.writeFileSync(path.join(site, "modules/system/system.module"), "<?php");
		fs.writeFileSync(path.join(site, "sites/all/modules/custom/acme/acme.info"), 'name = "Acme"\nversion = "7.x-1.2"\ncore = "7.x"\n');
		const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal", activeCodecIds: [] });
		assert.deepEqual(result.applications.map(a => [a.id, a.layout]), [["drupal:site", "drupal7"]]);
		assert.equal(result.inventory.find(c => c.kind === "core").version, "7.104");
		assert.equal(result.inventory.find(c => c.kind === "module").visibility, "private");
		assert.ok(result.diagnostics.some(d => d.code === "CMS_UNSUPPORTED_BRANCH"));
		assert.equal(result.coverage.find(c => c.capability === "advisories").execution, "not-run");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("distributed Drupal project groups nested submodules under the project that carries the advisory identity", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal-submodule-"));
	try {
		const site = path.join(temp, "site");
		for (const dir of ["web/core/lib", "web/modules/contrib/webform/modules/webform_something"])
			fs.mkdirSync(path.join(site, dir), { recursive: true });
		fs.writeFileSync(path.join(site, "composer.json"), JSON.stringify({ require: { "drupal/core": "10.3.1", "drupal/webform": "^6.2" } }));
		fs.writeFileSync(path.join(site, "composer.lock"), JSON.stringify({ packages: [
			{ name: "drupal/core", version: "10.3.1" },
			{ name: "drupal/webform", version: "6.2.0" }], "packages-dev": [] }));
		fs.writeFileSync(path.join(site, "web/core/lib/Drupal.php"), "<?php\nclass Drupal {}\n");
		fs.writeFileSync(path.join(site, "web/core/core.services.yml"), "services: {}\n");
		fs.writeFileSync(path.join(site, "web/modules/contrib/webform/webform.info.yml"),
			"name: Webform\ntype: module\nproject: webform\ncore_version_requirement: ^10\n");
		fs.writeFileSync(path.join(site, "web/modules/contrib/webform/modules/webform_something/webform_something.info.yml"),
			"name: Webform Something\ntype: module\ncore_version_requirement: ^10\n");
		const { deps } = await composer.collect(temp);
		const result = await runApplicationPlugins(temp, { plugins: [drupal], selection: "drupal",
			resolvedDeps: deps, activeCodecIds: ["composer"] });
		const parent = result.inventory.find(c => c.machineName === "webform");
		const sub = result.inventory.find(c => c.machineName === "webform_something");
		assert.ok(parent && sub, "both the project and its submodule are inventoried");
		assert.equal(parent.coord, "drupal/webform");
		assert.equal(parent.version, "6.2.0");
		assert.equal(sub.parentComponentId, parent.id);
		assert.equal(sub.coord, "drupal/webform");
		assert.equal(sub.identityStatus, "probable");
		assert.equal(sub.version, "6.2.0");
		assert.ok(sub.evidence.some(e => e.relation === "submodule-of"),
			"the inherited identity must carry its own evidence");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("Drupal 7 nested submodules inherit the distributed project identity without inventing advisories", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal7-submodule-"));
	try {
		const site = path.join(temp, "site");
		for (const dir of ["includes", "modules/system", "sites/all/modules/contrib/foo/modules/foo_bar"])
			fs.mkdirSync(path.join(site, dir), { recursive: true });
		fs.writeFileSync(path.join(site, "includes/bootstrap.inc"), "<?php define('VERSION', '7.104');");
		fs.writeFileSync(path.join(site, "modules/system/system.module"), "<?php");
		fs.writeFileSync(path.join(site, "sites/all/modules/contrib/foo/foo.info"),
			'name = "Foo"\nproject = "foo"\nversion = "7.x-1.2"\ncore = "7.x"\n');
		fs.writeFileSync(path.join(site, "sites/all/modules/contrib/foo/modules/foo_bar/foo_bar.info"),
			'name = "Foo Bar"\nversion = "7.x-1.2"\ncore = "7.x"\n');
		const result = await runApplicationPlugins(temp, { plugins: [drupal], selection: "drupal", activeCodecIds: [] });
		const parent = result.inventory.find(c => c.machineName === "foo");
		const sub = result.inventory.find(c => c.machineName === "foo_bar");
		assert.ok(parent && sub);
		assert.equal(parent.coord, "drupal/foo");
		assert.equal(sub.parentComponentId, parent.id);
		assert.equal(sub.coord, "drupal/foo");
		assert.equal(sub.identityStatus, "probable");
		assert.ok(result.diagnostics.some(d => d.code === "CMS_UNSUPPORTED_BRANCH"),
			"the inherited identity still belongs to an unsupported branch");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("a Drupal 8 core tree is not misread as an extra Drupal 7 application", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal8-notd7-"));
	try {
		const site = path.join(temp, "site");
		for (const dir of ["core/lib", "core/includes", "core/modules/system"])
			fs.mkdirSync(path.join(site, dir), { recursive: true });
		fs.writeFileSync(path.join(site, "composer.json"), JSON.stringify({ require: { "drupal/core": "^8.5" } }));
		fs.writeFileSync(path.join(site, "core/lib/Drupal.php"), "<?php\nclass Drupal { const VERSION = '8.5.0'; }\n");
		fs.writeFileSync(path.join(site, "core/core.services.yml"), "services: {}\n");
		// Drupal 8 ships core/includes/bootstrap.inc and core/modules/system/system.module too,
		// but its bootstrap.inc carries no 7.x VERSION define — that define is the D7 evidence.
		fs.writeFileSync(path.join(site, "core/includes/bootstrap.inc"), "<?php\ndefine('DRUPAL_ROOT', getcwd());\n");
		fs.writeFileSync(path.join(site, "core/modules/system/system.module"), "<?php\n");
		const result = await runApplicationPlugins(temp, { plugins: [drupal], selection: "drupal", activeCodecIds: [] });
		assert.deepEqual(result.applications.map(a => [a.root, a.layout]), [["site", "composer"]],
			"the D8 core directory must not become a second, phantom Drupal 7 application");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("a source tree without a lock reads the observed core version from core/lib/Drupal.php", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal-observed-"));
	try {
		const feed = path.join(temp, "advisories.json");
		fs.writeFileSync(feed, JSON.stringify({ queriedPackages: ["drupal/core"], advisories: { "drupal/core": [
			{ advisoryId: "SA-CORE-2018-002", packageName: "drupal/core", title: "Drupal core - Fixture",
				link: "https://www.drupal.org/sa-core-2018-002", cve: "CVE-2018-7600",
				affectedVersions: ">=8.5.0 <8.5.1", reportedAt: "2018-03-28 18:14:10" }] } }));
		const site = path.join(temp, "site");
		fs.mkdirSync(path.join(site, "core/lib"), { recursive: true });
		fs.writeFileSync(path.join(site, "composer.json"), JSON.stringify({ require: { "drupal/core": "^8.5" } }));
		fs.writeFileSync(path.join(site, "core/lib/Drupal.php"), "<?php\nclass Drupal { const VERSION = '8.5.0'; }\n");
		fs.writeFileSync(path.join(site, "core/core.services.yml"), "services: {}\n");
		const result = await runApplicationPlugins(site, { plugins: [drupal], selection: "drupal",
			activeCodecIds: [], drupalAdvisoriesPath: feed });
		const core = result.inventory.find(c => c.kind === "core");
		assert.equal(core.version, "8.5.0", "the on-disk core marker is the observed version of the tree");
		assert.equal(core.versionStatus, "observed");
		assert.ok(core.evidence.some(e => e.field === "VERSION"), "the version must cite its evidence");
		assert.equal(result.findings.length, 1);
		assert.equal(result.findings[0].cve.id, "CVE-2018-7600");
		const coreCoverage = result.coverage.find(c => c.occurrenceId === core.id);
		assert.equal(coreCoverage.execution, "completed");
		assert.equal(coreCoverage.result, "affected");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("a lock and a diverging core marker produce a conflict, never a silent choice", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal-conflict-"));
	try {
		const site = path.join(temp, "site");
		fs.mkdirSync(path.join(site, "web/core/lib"), { recursive: true });
		fs.writeFileSync(path.join(site, "composer.json"), JSON.stringify({ require: { "drupal/core": "^10.3" } }));
		fs.writeFileSync(path.join(site, "composer.lock"), JSON.stringify({ packages: [
			{ name: "drupal/core", version: "10.3.1" }], "packages-dev": [] }));
		fs.writeFileSync(path.join(site, "web/core/lib/Drupal.php"), "<?php\nclass Drupal { const VERSION = '10.2.0'; }\n");
		fs.writeFileSync(path.join(site, "web/core/core.services.yml"), "services: {}\n");
		const { deps } = await composer.collect(temp);
		const result = await runApplicationPlugins(temp, { plugins: [drupal], selection: "drupal",
			resolvedDeps: deps, activeCodecIds: ["composer"] });
		const core = result.inventory.find(c => c.kind === "core");
		assert.equal(core.version, "10.3.1", "the lock stays the installed-version authority");
		assert.equal(core.versionStatus, "conflict");
		assert.ok(result.diagnostics.some(d => d.code === "CMS_VERSION_CONFLICT" &&
			/10\.3\.1/.test(d.message) && /10\.2\.0/.test(d.message)), "the divergence is stated, both values named");
		assert.equal(result.coverage.find(c => c.capability === "inventory").execution, "partial");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});
