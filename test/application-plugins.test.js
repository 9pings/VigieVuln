const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { assertPluginShape } = require("../lib/applications/plugins/plugin.interface");
const { selectPlugins } = require("../lib/applications/plugins/select");
const { runApplicationPlugins } = require("../lib/applications/plugins/runner");

function fakePlugin(overrides = {}) {
	return {
		id: "fake", version: "1.0.0", apiVersion: 1, label: "Fake",
		supportedLayouts: ["source"], capabilities: { inventory: "qualified", advisories: "experimental" },
		requiredCodecs: [], providerIds: [],
		discover(ctx) { return ctx.index.hasFile("app/marker.txt") ? [{ root: "app", evidence: [{ path: "app/marker.txt" }] }] : []; },
		collect(app, ctx) { return { components: [{ id: `${app.id}:core`, applicationId: app.id, kind: "core", version: ctx.readText("app/marker.txt").trim() }], coverage: [
			{ applicationId: app.id, capability: "inventory", execution: "completed", result: "not-applicable", expected: 1, executed: 1 },
		] }; },
		assess() { return []; }, remediation() { return null; },
		...overrides,
	};
}

test("plugin contract rejects incompatible APIs and missing hooks", () => {
	assert.equal(assertPluginShape(fakePlugin()), true);
	assert.throws(() => assertPluginShape(fakePlugin({ apiVersion: 2 })), /apiVersion/);
	assert.throws(() => assertPluginShape(fakePlugin({ collect: null })), /collect/);
});

test("auto activates every plugin on detection; explicit selection rejects unknown IDs", () => {
	// User decision (2026-09-23, 6e session): a present CMS/framework MUST be activated —
	// `auto` inventories any recognized layout, qualified or still experimental. The
	// detection markers themselves are conjunctive positive evidence (kernel + lock,
	// artisan + bootstrap/app.php, wp-load.php + version.php, …), so an unrelated PHP
	// package never becomes an application (asserted by the wave-2 suite).
	const qualified = fakePlugin();
	const experimental = fakePlugin({ id: "experimental", capabilities: { inventory: "experimental" } });
	assert.deepEqual(selectPlugins([qualified, experimental], "auto").map(p => p.id), ["fake", "experimental"]);
	assert.deepEqual(selectPlugins([qualified, experimental], "none"), []);
	assert.deepEqual(selectPlugins([qualified, experimental], "all").map(p => p.id), ["fake", "experimental"]);
	assert.deepEqual(selectPlugins([qualified, experimental], "experimental").map(p => p.id), ["experimental"]);
	assert.throws(() => selectPlugins([qualified], "missing"), /unknown application plugin/);
});

test("auto inventories a recognized application layout instead of only announcing it", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-plugin-auto-"));
	try {
		fs.mkdirSync(path.join(root, "app")); fs.writeFileSync(path.join(root, "app", "marker.txt"), "1");
		const plugin = fakePlugin({ capabilities: { inventory: "experimental" } });
		const result = await runApplicationPlugins(root, { plugins: [plugin], selection: "auto" });
		assert.equal(result.applications.length, 1);
		assert.deepEqual(result.applications.map(a => a.id), ["fake:app"]);
		assert.ok(!result.diagnostics.some(d => d.code === "CMS_PLUGIN_UNQUALIFIED"));
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("a plugin joins the runner without a CLI-specific branch and yields relative application IDs", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-plugin-contract-"));
	try {
		fs.mkdirSync(path.join(root, "app"));
		fs.writeFileSync(path.join(root, "app", "marker.txt"), "1.2.3\n");
		const result = await runApplicationPlugins(root, { plugins: [fakePlugin()], selection: "auto" });
		assert.deepEqual(result.applications.map(a => a.id), ["fake:app"]);
		assert.equal(result.inventory[0].version, "1.2.3");
		assert.equal(result.coverage[0].execution, "completed");
		assert.deepEqual(result.diagnostics, []);
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("plugin failures and disabled required codecs are coverage gaps, not empty successful scans", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-plugin-fail-"));
	try {
		fs.mkdirSync(path.join(root, "app")); fs.writeFileSync(path.join(root, "app", "marker.txt"), "1");
		const broken = fakePlugin({ collect() { throw new Error("broken parser"); } });
		const failed = await runApplicationPlugins(root, { plugins: [broken], selection: "auto" });
		assert.equal(failed.coverage[0].execution, "failed");
		assert.equal(failed.coverage[0].result, "indeterminate");
		assert.equal(failed.diagnostics[0].code, "CMS_PLUGIN_FAILED");
		const missing = await runApplicationPlugins(root, { plugins: [fakePlugin({ requiredCodecs: ["composer"] })], selection: "auto", activeCodecIds: [] });
		assert.equal(missing.coverage[0].execution, "not-run");
		assert.equal(missing.diagnostics[0].code, "CMS_CODEC_DISABLED");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("assessment failure preserves completed inventory and records advisory failure", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-plugin-assess-"));
	try {
		fs.mkdirSync(path.join(root, "app")); fs.writeFileSync(path.join(root, "app", "marker.txt"), "1");
		const plugin = fakePlugin({ assess() { throw new Error("provider failed"); } });
		const result = await runApplicationPlugins(root, { plugins: [plugin], selection: "auto" });
		assert.equal(result.inventory.length, 1);
		assert.deepEqual(result.coverage.map(c => [c.capability, c.execution]),
			[["inventory", "completed"], ["advisories", "failed"]]);
		assert.equal(result.diagnostics[0].code, "CMS_PLUGIN_FAILED");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("private component paths cannot escape the scan root", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-plugin-path-"));
	try {
		await assert.rejects(runApplicationPlugins(root, { plugins: [fakePlugin()], selection: "auto",
			privateComponentPaths: ["../outside"] }), /private component path/i);
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("unmatched private and public component declarations are diagnosed", async () => {
	const root = path.join(__dirname, "fixtures", "wordpress-custom");
	const wordpress = require("../lib/applications/plugins/wordpress");
	const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
		privateComponentPaths: ["site/wp-content/plugins/missing"],
		publicComponents: ["site/wp-content/themes/missing=missing"] });
	assert.ok(result.diagnostics.some(d => d.code === "CMS_PRIVATE_PATH_UNMATCHED"));
	assert.ok(result.diagnostics.some(d => d.code === "CMS_PUBLIC_PATH_UNMATCHED"));
});

test("component scan context announces when no selected plugin recognizes a component", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-plugin-component-empty-"));
	try {
		const empty = await runApplicationPlugins(root, { plugins: [fakePlugin()], selection: "fake", scanContext: "component" });
		assert.deepEqual(empty.applications, []);
		assert.ok(empty.diagnostics.some(d => d.code === "CMS_COMPONENT_NOT_RECOGNIZED"));
		const source = await runApplicationPlugins(root, { plugins: [fakePlugin()], selection: "fake" });
		assert.ok(!source.diagnostics.some(d => d.code === "CMS_COMPONENT_NOT_RECOGNIZED"),
			"the announcement belongs to the explicit component context only");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("discover may return diagnostics alongside candidates", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-plugin-discover-diag-"));
	try {
		fs.mkdirSync(path.join(root, "app")); fs.writeFileSync(path.join(root, "app", "marker.txt"), "1\n");
		const plugin = fakePlugin({ discover() {
			return { candidates: [{ root: "app", evidence: [{ path: "app/marker.txt" }] }],
				diagnostics: [{ code: "CMS_DISCOVER_NOTE", message: "fixture note" }] };
		} });
		const result = await runApplicationPlugins(root, { plugins: [plugin], selection: "fake" });
		assert.deepEqual(result.applications.map(a => a.id), ["fake:app"]);
		assert.ok(result.diagnostics.some(d => d.code === "CMS_DISCOVER_NOTE"));
		assert.equal(result.inventory.length, 1);
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});
