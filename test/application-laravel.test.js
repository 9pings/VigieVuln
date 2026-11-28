const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const composer = require("../lib/codecs/composer.codec");
const laravel = require("../lib/applications/plugins/laravel");
const { runApplicationPlugins } = require("../lib/applications/plugins/runner");

test("Laravel application requires framework dependency and app markers, then inventories lock versions", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-laravel-"));
	try {
		fs.mkdirSync(path.join(root, "bootstrap"));
		fs.writeFileSync(path.join(root, "artisan"), "<?php");
		fs.writeFileSync(path.join(root, "bootstrap/app.php"), "<?php");
		fs.writeFileSync(path.join(root, "composer.json"), JSON.stringify({ name: "acme/app", require: {
			"laravel/framework": "^11.0", "acme/private-package": "^2.0" } }));
		fs.writeFileSync(path.join(root, "composer.lock"), JSON.stringify({ packages: [
			{ name: "laravel/framework", version: "v11.2.1", require: { "symfony/console": "^7.0" } },
			{ name: "symfony/console", version: "v7.0.8" },
			{ name: "acme/private-package", version: "2.1.0" },
		], "packages-dev": [] }));
		const { deps } = await composer.collect(root);
		const result = await runApplicationPlugins(root, { plugins: [laravel], selection: "laravel",
			resolvedDeps: deps, activeCodecIds: ["composer"] });
		assert.deepEqual(result.applications.map(a => a.id), ["laravel:."]);
		const byCoord = Object.fromEntries(result.inventory.map(c => [c.coord, c]));
		assert.equal(byCoord["laravel/framework"].version, "11.2.1");
		assert.equal(byCoord["laravel/framework"].kind, "framework");
		assert.equal(byCoord["symfony/console"].version, "7.0.8");
		assert.equal(byCoord["acme/private-package"].version, "2.1.0");
		const advisories = result.coverage.find(c => c.capability === "advisories");
		assert.equal(advisories.execution, "completed", "covered by the dependency lanes, not a gap");
		assert.equal(advisories.sourceId, "dependency-lanes");
		fs.rmSync(path.join(root, "artisan"));
		const withoutMarker = await runApplicationPlugins(root, { plugins: [laravel], selection: "laravel",
			resolvedDeps: deps, activeCodecIds: ["composer"] });
		assert.deepEqual(withoutMarker.applications, []);
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});
