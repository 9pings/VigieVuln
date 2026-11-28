const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { isManifestName, copyEcosystemManifests } = require("../lib/inventory/manifest-copy");

test("isManifestName matches non-Maven lockfiles/manifests, not pom.xml or random files", () => {
	for (const n of ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "symfony.lock", "poetry.lock",
		"Pipfile.lock", "go.mod", "go.sum", "Gemfile.lock", "packages.lock.json", "app.csproj",
		"Directory.Packages.props", "requirements.txt"]) {
		assert.equal(isManifestName(n), true, `${n} should match`);
	}
	assert.equal(isManifestName("pom.xml"), false, "Maven POMs are written cleaned, not copied raw");
	assert.equal(isManifestName("README.md"), false);
	assert.equal(isManifestName("App.java"), false);
});

test("copyEcosystemManifests mirrors manifests to target, skips node_modules/vendor", async () => {
	const src = fs.mkdtempSync(path.join(os.tmpdir(), "fad-mc-src-"));
	const tgt = fs.mkdtempSync(path.join(os.tmpdir(), "fad-mc-tgt-"));
	try {
		fs.mkdirSync(path.join(src, "web"), { recursive: true });
		fs.mkdirSync(path.join(src, "svc"), { recursive: true });
		fs.mkdirSync(path.join(src, "web", "node_modules", "lodash"), { recursive: true });
		fs.mkdirSync(path.join(src, "php", "vendor", "x"), { recursive: true });
		fs.writeFileSync(path.join(src, "web", "package.json"), "{}");
		fs.writeFileSync(path.join(src, "web", "package-lock.json"), "{}");
		fs.writeFileSync(path.join(src, "svc", "go.mod"), "module x");
		fs.writeFileSync(path.join(src, "php", "composer.lock"), "{}");
		fs.writeFileSync(path.join(src, "php", "symfony.lock"), "{}");
		fs.writeFileSync(path.join(src, "pom.xml"), "<project/>");                       // not copied
		fs.writeFileSync(path.join(src, "web", "node_modules", "lodash", "package.json"), "{}"); // pruned
		fs.writeFileSync(path.join(src, "php", "vendor", "x", "composer.json"), "{}");          // pruned

		const r = await copyEcosystemManifests(src, tgt);
		const got = r.files.map(f => f.split(path.sep).join("/")).sort();
		assert.deepEqual(got, ["php/composer.lock", "php/symfony.lock", "svc/go.mod", "web/package-lock.json", "web/package.json"]);
		assert.ok(fs.existsSync(path.join(tgt, "web", "package-lock.json")), "manifest mirrored at relative path");
		assert.ok(!fs.existsSync(path.join(tgt, "pom.xml")), "pom.xml not copied");
		assert.ok(!fs.existsSync(path.join(tgt, "web", "node_modules")), "node_modules pruned");
	} finally {
		fs.rmSync(src, { recursive: true, force: true });
		fs.rmSync(tgt, { recursive: true, force: true });
	}
});
