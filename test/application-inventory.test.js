const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { makeDepRecord } = require("../lib/inventory/dep-record");
const { buildApplicationRelations, expandComposerFindings } = require("../lib/applications/inventory");

function composerDep(name, version, manifestPath, requires = {}) {
	const [namespace, pkg] = name.split("/");
	const dep = makeDepRecord({ ecosystem: "composer", namespace, name: pkg, version, manifestPath, scope: "prod" });
	dep.occurrences = [{ version, manifestPath, scope: "prod", isDev: false, requires }];
	return dep;
}

test("a private custom plugin owns CVEs in its own Composer dependencies", () => {
	const root = "/audit";
	const app = { id: "wordpress:site", type: "wordpress", root: "site" };
	const custom = { id: "wordpress:site:plugin:acme", applicationId: app.id, kind: "plugin", path: "site/wp-content/plugins/acme", visibility: "private" };
	const lock = path.join(root, "site/wp-content/plugins/acme/composer.lock");
	const dep = composerDep("vendor/vulnerable-lib", "1.0.0", lock);
	const relations = buildApplicationRelations(root, [app], [custom], new Map([[dep.coordKey, dep]]));
	assert.equal(relations.length, 1);
	assert.equal(relations[0].ownerComponentId, custom.id);
	assert.equal(relations[0].applicationRelation, "indirect");
	const findings = expandComposerFindings([{ dep, cve: { id: "CVE-2099-0001", severity: "HIGH" } }], root, relations);
	assert.equal(findings.length, 1);
	assert.deepEqual(findings[0].ownerComponentIds, [custom.id]);
	assert.equal(findings[0].applicationRelation, "indirect");
	assert.equal(findings[0].dep.version, "1.0.0");
});

test("two physical copies yield two finding IDs and keep each version's location", () => {
	const root = "/audit";
	const a = composerDep("vendor/lib", "1.0.0", path.join(root, "site-a/composer.lock"));
	a.versions.push("2.0.0");
	a.versionPaths["2.0.0"] = [path.join(root, "site-b/composer.lock")];
	a.manifestPaths.push(path.join(root, "site-b/composer.lock"));
	a.occurrences.push({ version: "2.0.0", manifestPath: path.join(root, "site-b/composer.lock"), scope: "prod", isDev: false, requires: {} });
	const matches = [
		{ dep: { ...a, version: "1.0.0" }, cve: { id: "CVE-2099-0001" } },
		{ dep: { ...a, version: "2.0.0" }, cve: { id: "CVE-2099-0001" } },
	];
	const findings = expandComposerFindings(matches, root, []);
	assert.equal(findings.length, 2);
	assert.notEqual(findings[0].findingId, findings[1].findingId);
	assert.deepEqual(findings.map(f => f.dep.manifestPaths[0]), [path.join(root, "site-a/composer.lock"), path.join(root, "site-b/composer.lock")]);
	assert.deepEqual(findings.map(f => f.dep.version), ["1.0.0", "2.0.0"]);
});

test("a shared library can have two proven plugin origins but remains one finding", () => {
	const root = "/audit";
	const app = { id: "wordpress:site", type: "wordpress", root: "site" };
	const lock = path.join(root, "site/composer.lock");
	const plugA = { id: "plugin:a", applicationId: app.id, kind: "plugin", path: "site/wp-content/plugins/a", coord: "acme/a", visibility: "private" };
	const plugB = { id: "plugin:b", applicationId: app.id, kind: "plugin", path: "site/wp-content/plugins/b", coord: "acme/b", visibility: "private" };
	const a = composerDep("acme/a", "1.0.0", lock, { "vendor/shared": "^1" });
	const b = composerDep("acme/b", "1.0.0", lock, { "vendor/shared": "^1" });
	const shared = composerDep("vendor/shared", "1.0.0", lock);
	const deps = new Map([[a.coordKey, a], [b.coordKey, b], [shared.coordKey, shared]]);
	const relations = buildApplicationRelations(root, [app], [plugA, plugB], deps);
	const findings = expandComposerFindings([{ dep: shared, cve: { id: "CVE-SHARED" } }], root, relations);
	assert.equal(findings.length, 1);
	assert.deepEqual(new Set(findings[0].ownerComponentIds), new Set([plugA.id, plugB.id]));
	assert.equal(findings[0].applicationRelation, "indirect");
	assert.equal(findings[0].dependencyPaths.length, 2);
});

test("unresolved Composer origin stays explicitly unknown", () => {
	const root = "/audit";
	const app = { id: "wordpress:site", type: "wordpress", root: "site" };
	const dep = composerDep("vendor/loose", "1.0.0", path.join(root, "site/composer.lock"));
	const relations = buildApplicationRelations(root, [app], [], new Map([[dep.coordKey, dep]]));
	const finding = expandComposerFindings([{ dep, cve: { id: "CVE-1" } }], root, relations)[0];
	assert.equal(relations[0].applicationRelation, "unknown");
	assert.equal(finding.applicationRelation, "unknown");
	assert.equal(finding.attributionStatus, "unknown");
});

test("a Composer manifest outside the scan root is not attributed to a root application", () => {
	const root = "/audit";
	const app = { id: "symfony:.", type: "symfony", root: "." };
	const dep = composerDep("vendor/outside", "1.0.0", "/other/composer.lock");
	const relations = buildApplicationRelations(root, [app], [], new Map([[dep.coordKey, dep]]));
	assert.deepEqual(relations, []);
});

test("advisory-targetable kinds stay direct; lock libraries never self-own as origins", () => {
	const root = "/audit";
	const app = { id: "symfony:.", type: "symfony", root: "." };
	const lock = path.join(root, "composer.lock");
	const framework = { id: "symfony:.:framework", applicationId: app.id, kind: "framework", coord: "symfony/framework-bundle", version: "7.1.1" };
	const httpFoundation = { id: "symfony:.:http-foundation", applicationId: app.id, kind: "framework-component", coord: "symfony/http-foundation", version: "7.1.1" };
	const fooBundle = { id: "symfony:.:foo-bundle", applicationId: app.id, kind: "bundle", coord: "acme/foo-bundle", version: "1.0" };
	const lib = { id: "symfony:.:vendor-lib", applicationId: app.id, kind: "library", coord: "vendor/lib", version: "1.0" };
	const twig = { id: "symfony:.:twig", applicationId: app.id, kind: "library", coord: "twig/twig", version: "3.0" };
	const fb = composerDep("symfony/framework-bundle", "7.1.1", lock, { "symfony/http-foundation": "^7.1" });
	const hf = composerDep("symfony/http-foundation", "7.1.1", lock);
	const foo = composerDep("acme/foo-bundle", "1.0", lock, { "vendor/lib": "^1" });
	const libDep = composerDep("vendor/lib", "1.0", lock);
	const twigDep = composerDep("twig/twig", "3.0", lock);
	const deps = new Map([[fb.coordKey, fb], [hf.coordKey, hf], [foo.coordKey, foo], [libDep.coordKey, libDep], [twigDep.coordKey, twigDep]]);
	const relations = buildApplicationRelations(root, [app], [framework, httpFoundation, fooBundle, lib, twig], deps);
	const find = (dep, cve) => expandComposerFindings([{ dep, cve: { id: cve } }], root, relations)[0];
	// the framework, an official framework component and a bundle are direct targets
	assert.equal(find(fb, "CVE-1").applicationRelation, "direct");
	assert.equal(find(hf, "CVE-2").applicationRelation, "direct");
	assert.equal(find(foo, "CVE-3").applicationRelation, "direct");
	// a library under a proven bundle origin is indirect — never direct by self-ownership
	const vendorLib = find(libDep, "CVE-4");
	assert.equal(vendorLib.applicationRelation, "indirect");
	assert.deepEqual(vendorLib.ownerComponentIds, [fooBundle.id]);
	assert.ok(vendorLib.dependencyPaths.some(p => p.join("→") === "acme/foo-bundle→vendor/lib"),
		"the introduction path follows the lock's require graph");
	// a library with no target-kind origin stays indirect under the application's own
	// root manifest (the framework owns the application's dependencies), never unknown here
	const twigFinding = find(twigDep, "CVE-5");
	assert.equal(twigFinding.applicationRelation, "indirect");
	assert.deepEqual(twigFinding.ownerComponentIds, [framework.id]);
});

test("a root project that replaces drupal/core attributes its lock to the core", () => {
	const root = "/audit";
	const app = { id: "drupal:drupal-8.5.0", type: "drupal", root: "drupal-8.5.0" };
	const core = { id: "drupal:drupal-8.5.0:core", applicationId: app.id, kind: "core", coord: "drupal/core", version: "8.5.0" };
	const lock = path.join(root, "drupal-8.5.0/composer.lock");
	const hf = composerDep("symfony/http-foundation", "3.4.4", lock);
	const dev = composerDep("phpunit/phpunit", "9.0.0", lock);
	dev.occurrences[0].scope = "dev";
	dev.occurrences[0].isDev = true;
	const relations = buildApplicationRelations(root, [app], [core], new Map([[hf.coordKey, hf], [dev.coordKey, dev]]));
	const prod = expandComposerFindings([{ dep: hf, cve: { id: "CVE-2019-10913" } }], root, relations)[0];
	assert.equal(prod.applicationRelation, "indirect", "the core's own lock dependencies are indirect under the core");
	assert.deepEqual(prod.ownerComponentIds, [core.id]);
	assert.deepEqual(prod.dependencyPaths, [["drupal/core", "symfony/http-foundation"]]);
	// dev-scope occurrences of the same root manifest are attributed too, scope intact
	const devFinding = expandComposerFindings([{ dep: dev, cve: { id: "CVE-DEV" } }], root, relations)[0];
	assert.equal(devFinding.applicationRelation, "indirect");
	assert.equal(devFinding.dep.scope, "dev");
	assert.equal(devFinding.dep.isDev, true);
	assert.deepEqual(devFinding.ownerComponentIds, [core.id]);
});
