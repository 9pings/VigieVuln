const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const composer = require("../lib/codecs/composer.codec");
const wordpress = require("../lib/application-plugins/wordpress");
const { runApplicationPlugins } = require("../lib/application-plugins/runner");
const { buildApplicationRelations, expandComposerFindings } = require("../lib/application-inventory");
const WORD_FENCE_FEED = { "123e4567-e89b-12d3-a456-426614174000": {
	id: "123e4567-e89b-12d3-a456-426614174000", title: "Acme public issue", cve: "CVE-2099-12345",
	software: [{ type: "plugin", slug: "acme", affected_versions: { "1-3": {
		from_version: "1", from_inclusive: true, to_version: "3", to_inclusive: true,
	} }, patched_versions: ["3.1"] }],
} };

test("Wordfence snapshot only matches an explicitly declared public plugin identity", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wordfence-feed-"));
	const root = path.join(temp, "scan");
	fs.cpSync(path.join(__dirname, "fixtures", "wordpress-custom"), root, { recursive: true });
	const pluginFile = path.join(root, "site/wp-content/plugins/acme/acme.php");
	fs.writeFileSync(pluginFile, fs.readFileSync(pluginFile, "utf8").replace(/^Update URI:.*\r?\n/m, ""));
	const feedFile = path.join(temp, "feed.json");
	fs.writeFileSync(feedFile, JSON.stringify(WORD_FENCE_FEED));
	try {
		const options = { plugins: [wordpress], selection: "wordpress", offline: true, wordfenceFeedPath: feedFile };
		const unverified = await runApplicationPlugins(root, options);
		assert.equal(unverified.findings.length, 0);
		const plugin = unverified.inventory.find(c => c.kind === "plugin");
		assert.equal(unverified.coverage.find(c => c.occurrenceId === plugin.id).execution, "not-run");
		const verified = await runApplicationPlugins(root, { ...options,
			publicComponents: ["site/wp-content/plugins/acme=acme"] });
		assert.equal(verified.findings.length, 1);
		assert.equal(verified.findings[0].cve.id, "CVE-2099-12345");
		assert.equal(verified.inventory.find(c => c.kind === "plugin").catalogueStatus, "user-declared");
		assert.equal(verified.findings[0].confidence, "user-declared");
		assert.equal(verified.coverage.find(c => c.occurrenceId === plugin.id).result, "affected");
		assert.match(verified.coverage.find(c => c.occurrenceId === plugin.id).sourceSnapshot.sha256, /^[a-f0-9]{64}$/);
		const privateResult = await runApplicationPlugins(root, { ...options,
			privateComponentPaths: ["site/wp-content/plugins/acme"] });
		assert.equal(privateResult.findings.length, 0);
		assert.equal(privateResult.coverage.find(c => c.occurrenceId === plugin.id).diagnostic, "CMS_PRIVATE_COMPONENT");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("third-party Update URI marks a WordPress plugin private even when a public slug is declared", async () => {
	const root = path.join(__dirname, "fixtures", "wordpress-custom");
	const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress", offline: true,
		publicComponents: ["site/wp-content/plugins/acme=acme"] });
	const plugin = result.inventory.find(c => c.kind === "plugin");
	assert.equal(plugin.visibility, "private");
	assert.equal(plugin.catalogueStatus, "not-queried");
	assert.ok(result.diagnostics.some(d => d.code === "CMS_PRIVATE_COMPONENT" && d.componentId === plugin.id));
	assert.ok(result.diagnostics.some(d => d.code === "CMS_IDENTITY_CONFLICT" && d.componentId === plugin.id));
	assert.equal(JSON.stringify(result).includes("intranet.example.invalid"), false);
});

test("private WordPress plugin remains distinct from the public catalogue and owns its dependency CVE", async () => {
	const root = path.join(__dirname, "fixtures", "wordpress-custom");
	const { deps } = await composer.collect(root);
	const result = await runApplicationPlugins(root, {
		plugins: [wordpress], selection: "wordpress", offline: true, resolvedDeps: deps, activeCodecIds: ["composer"],
		privateComponentPaths: ["./site/wp-content/plugins/acme"],
	});
	assert.deepEqual(result.applications.map(a => a.id), ["wordpress:site"]);
	const core = result.inventory.find(c => c.kind === "core");
	const plugin = result.inventory.find(c => c.kind === "plugin");
	const theme = result.inventory.find(c => c.kind === "theme");
	assert.equal(core.version, "6.6.2");
	assert.equal(plugin.version, "2.3.0");
	assert.equal(plugin.visibility, "private");
	assert.ok(result.diagnostics.some(d => d.code === "CMS_PRIVATE_COMPONENT" && d.componentId === plugin.id));
	assert.equal(plugin.catalogueStatus, "not-queried");
	assert.equal(theme.version, "1.4.2");
	assert.equal(JSON.stringify(result).includes("intranet.example.invalid"), false, "private update URLs stay local");
	const vulnerable = deps.get("composer:vendor/vulnerable-lib");
	const relations = buildApplicationRelations(root, result.applications, result.inventory, deps);
	const findings = expandComposerFindings([{ dep: vulnerable, cve: { id: "CVE-2099-0001", severity: "HIGH" } }], root, relations);
	assert.deepEqual(findings[0].ownerComponentIds, [plugin.id]);
	assert.equal(findings[0].applicationRelation, "indirect");
	assert.equal(findings[0].dep.version, "1.0.0");
	assert.equal(result.coverage.find(c => c.occurrenceId === plugin.id && c.capability === "advisories").execution, "not-run");
	assert.equal(result.coverage.find(c => c.occurrenceId === plugin.id && c.capability === "advisories").expected, 1);
});

test("Bedrock maps web/wp core and web/app private plugins to one application", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-bedrock-"));
	try {
		const site = path.join(root, "site");
		for (const dir of ["web/wp/wp-includes", "web/wp/wp-admin", "web/app/plugins/acme"])
			fs.mkdirSync(path.join(site, dir), { recursive: true });
		fs.writeFileSync(path.join(site, "composer.json"), '{"name":"roots/bedrock"}');
		fs.writeFileSync(path.join(site, "web/wp/wp-includes/version.php"), '<?php $wp_version = "6.6.2";');
		fs.writeFileSync(path.join(site, "web/wp/wp-admin/index.php"), '<?php');
		fs.writeFileSync(path.join(site, "web/wp/wp-load.php"), '<?php');
		fs.writeFileSync(path.join(site, "web/app/plugins/acme/acme.php"), '<?php /* Plugin Name: Acme\n Version: 1.2.0 */');
		const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress", offline: true,
			privateComponentPaths: ["site/web/app/plugins/acme"] });
		assert.deepEqual(result.applications.map(a => [a.id, a.layout]), [["wordpress:site", "bedrock"]]);
		assert.equal(result.inventory.find(c => c.kind === "core").version, "6.6.2");
		assert.equal(result.inventory.find(c => c.kind === "plugin").visibility, "private");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("WordPress inventories drop-ins and flags a missing parent theme", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wp-extras-"));
	try {
		const site = path.join(root, "site");
		for (const dir of ["wp-includes", "wp-admin", "wp-content/themes/child", "wp-content/mu-plugins/loader"])
			fs.mkdirSync(path.join(site, dir), { recursive: true });
		fs.writeFileSync(path.join(site, "wp-includes/version.php"), '<?php $wp_version = "6.6.2";');
		fs.writeFileSync(path.join(site, "wp-admin/index.php"), '<?php');
		fs.writeFileSync(path.join(site, "wp-load.php"), '<?php');
		fs.writeFileSync(path.join(site, "wp-content/object-cache.php"), '<?php /* Plugin Name: Cache Layer\n Version: 1.0 */');
		fs.writeFileSync(path.join(site, "wp-content/themes/child/style.css"), '/* Theme Name: Child\n Version: 1.0\n Template: absent-parent */');
		fs.writeFileSync(path.join(site, "wp-content/mu-plugins/loader/loader.php"), '<?php /* Plugin Name: Loader\n Version: 1.0 */');
		const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress", offline: true });
		assert.ok(result.inventory.some(c => c.kind === "drop-in" && c.name === "Cache Layer"));
		assert.ok(result.inventory.some(c => c.kind === "mu-plugin" && c.name === "Loader" && c.activation === "unknown"));
		assert.ok(result.diagnostics.some(d => d.code === "CMS_PARENT_MISSING"));
		assert.equal(result.coverage.find(c => c.capability === "inventory").execution, "partial");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});
