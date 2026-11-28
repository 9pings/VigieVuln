const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const composer = require("../lib/codecs/composer.codec");
const drupal = require("../lib/applications/plugins/drupal");
const { runApplicationPlugins } = require("../lib/applications/plugins/runner");
const { buildApplicationRelations, expandComposerFindings } = require("../lib/applications/inventory");

test("component context inventories a standalone private Drupal module and owns its dependency", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal-component-"));
	try {
		fs.writeFileSync(path.join(root, "checkout.info.yml"), "name: Checkout Internal\ntype: module\nversion: 1.2.0\ncore_version_requirement: ^10\n");
		fs.writeFileSync(path.join(root, "composer.json"), JSON.stringify({ name: "acme/checkout", require: { "vendor/vulnerable-lib": "1.0.0" } }));
		fs.writeFileSync(path.join(root, "composer.lock"), JSON.stringify({ packages: [
			{ name: "vendor/vulnerable-lib", version: "1.0.0" }], "packages-dev": [] }));
		const { deps } = await composer.collect(root);
		const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal", scanContext: "component",
			resolvedDeps: deps, activeCodecIds: ["composer"] });
		assert.deepEqual(result.applications.map(a => [a.id, a.layout]), [["drupal:.", "component"]]);
		assert.deepEqual(result.inventory.map(c => c.kind), ["module"]);
		assert.equal(result.inventory[0].visibility, "private");
		assert.ok(result.applications[0].evidence.some(e => e.path === "checkout.info.yml" && e.field === "type"),
			"discovery evidence must cite validated content, not a bare file name");
		const relations = buildApplicationRelations(root, result.applications, result.inventory, deps);
		const finding = expandComposerFindings([{ dep: deps.get("composer:vendor/vulnerable-lib"),
			cve: { id: "CVE-2099-0010" } }], root, relations)[0];
		assert.deepEqual(finding.ownerComponentIds, [result.inventory[0].id]);
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("component context discovers a standalone legacy .info module with positive name evidence", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal-component-legacy-"));
	try {
		fs.writeFileSync(path.join(root, "legacy.info"), 'name = "Legacy Internal"\nversion = "7.x-1.2"\ncore = "7.x"\n');
		const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal", scanContext: "component", activeCodecIds: [] });
		assert.deepEqual(result.applications.map(a => a.layout), ["component"]);
		assert.equal(result.inventory.length, 1);
		assert.equal(result.inventory[0].kind, "module");
		assert.equal(result.inventory[0].version, "7.x-1.2");
		assert.ok(result.applications[0].evidence.some(e => e.path === "legacy.info" && e.field === "name"),
			"legacy discovery must cite the name field it validated");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("component context rejects info file names without valid Drupal metadata and announces the failure", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal-false-marker-"));
	try {
		fs.writeFileSync(path.join(root, "notes.info.yml"), "title: Internal release notes\ntype: content\n");
		fs.writeFileSync(path.join(root, "changelog.info"), "Release notes for 1.0\nnothing structured here\n");
		const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal", scanContext: "component", activeCodecIds: [] });
		assert.deepEqual(result.applications, []);
		assert.deepEqual(result.inventory, []);
		assert.ok(result.diagnostics.some(d => d.code === "CMS_INFO_INVALID" && d.path === "notes.info.yml"),
			"an .info.yml without a valid extension type must be announced, not inventoried");
		assert.ok(result.diagnostics.some(d => d.code === "CMS_INFO_INVALID" && d.path === "changelog.info"),
			"an .info without a name field must be announced, not inventoried");
		assert.ok(result.diagnostics.some(d => d.code === "CMS_COMPONENT_NOT_RECOGNIZED"),
			"a component scan that recognizes nothing must never look like a successful empty scan");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});
