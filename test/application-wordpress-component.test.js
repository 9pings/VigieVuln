const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const composer = require("../lib/codecs/composer.codec");
const wordpress = require("../lib/applications/plugins/wordpress");
const { runApplicationPlugins } = require("../lib/applications/plugins/runner");
const { buildApplicationRelations, expandComposerFindings } = require("../lib/applications/inventory");

test("component context inventories a standalone private WordPress plugin and owns its Composer dependency CVE", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wp-component-"));
	try {
		fs.writeFileSync(path.join(root, "checkout.php"), "<?php /* Plugin Name: Checkout Internal\nVersion: 2.0.0\nUpdate URI: https://internal.invalid/checkout\n */");
		fs.writeFileSync(path.join(root, "composer.json"), JSON.stringify({ name: "acme/checkout", require: { "vendor/vulnerable-lib": "1.0.0" } }));
		fs.writeFileSync(path.join(root, "composer.lock"), JSON.stringify({ packages: [
			{ name: "vendor/vulnerable-lib", version: "1.0.0" }], "packages-dev": [] }));
		const { deps } = await composer.collect(root);
		const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
			scanContext: "component", resolvedDeps: deps, activeCodecIds: ["composer"] });
		assert.deepEqual(result.applications.map(a => [a.id, a.layout]), [["wordpress:.", "component"]]);
		assert.equal(result.inventory.length, 1);
		assert.equal(result.inventory[0].kind, "plugin");
		assert.equal(result.inventory[0].visibility, "private");
		assert.equal(result.inventory[0].version, "2.0.0");
		const relations = buildApplicationRelations(root, result.applications, result.inventory, deps);
		const finding = expandComposerFindings([{ dep: deps.get("composer:vendor/vulnerable-lib"),
			cve: { id: "CVE-2099-0009" } }], root, relations)[0];
		assert.deepEqual(finding.ownerComponentIds, [result.inventory[0].id]);
		assert.equal(finding.applicationRelation, "indirect");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("component context with no recognizable WordPress header announces instead of scanning empty", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wp-false-marker-"));
	try {
		fs.writeFileSync(path.join(root, "index.php"), "<?php\necho 'nothing wordpress here';\n");
		fs.writeFileSync(path.join(root, "style.css"), "/* a plain stylesheet without any theme header */\nbody { margin: 0; }\n");
		const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
			scanContext: "component", activeCodecIds: [] });
		assert.deepEqual(result.applications, []);
		assert.deepEqual(result.inventory, []);
		assert.ok(result.diagnostics.some(d => d.code === "CMS_COMPONENT_NOT_RECOGNIZED"),
			"a component scan that recognizes nothing must be announced, never silent");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});
