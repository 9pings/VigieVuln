const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const CLI = path.join(__dirname, "..", "vigievuln.js");

test("CLI lists bundled application plugins without a scan root", () => {
	const run = spawnSync(process.execPath, [CLI, "--list-app-plugins"], { encoding: "utf8" });
	assert.equal(run.status, 0, run.stderr);
	for (const name of ["symfony", "wordpress", "drupal", "laravel"]) assert.match(run.stdout, new RegExp(name));
});

test("Wordfence live scanning requires a key and explains how to provide it", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wordfence-key-"));
	try {
		const out = path.join(temp, "findings.json");
		const { WORDFENCE_PRODUCTION_URL } = require("../lib/application-providers/live-snapshot");
		const env = { ...process.env, FORCE_COLOR: "0" };
		delete env.WORDFENCE_API_KEY;
		const run = spawnSync(process.execPath, [CLI, "-s", path.join(__dirname, "fixtures", "wordpress-custom"),
			"--ecosystem", "composer", "--app-plugins", "wordpress", "--wordfence-feed-url", WORDFENCE_PRODUCTION_URL,
			"--report-json", out, "--no-checksums"], { encoding: "utf8", timeout: 30000, env });
		assert.equal(run.status, 2, `${run.stdout}\n${run.stderr}`);
		assert.match(run.stdout + run.stderr, /--wordfence-api-key.*WORDFENCE_API_KEY/);
		assert.equal(fs.existsSync(out), false);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("CLI exports a private custom WordPress plugin and incomplete advisory coverage", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-app-cli-"));
	try {
		const src = path.join(__dirname, "fixtures", "wordpress-custom");
		const out = path.join(temp, "findings.json");
		const args = [CLI, "-s", src, "--ecosystem", "composer", "--app-plugins", "wordpress",
			"--private-component", "site/wp-content/plugins/acme", "--offline", "-d", "eol,nvd,epss,kev,retire,transitive",
			"--report-json", out, "--no-checksums"];
		const run = spawnSync(process.execPath, args, { encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
		assert.match(run.stdout + run.stderr, /WordPress advisory scan did not run.*Wordfence API key/);
		const doc = JSON.parse(fs.readFileSync(out, "utf8"));
		assert.equal(doc.applications[0].id, "wordpress:site");
		const plugin = doc.applicationInventory.find(c => c.kind === "plugin");
		assert.equal(plugin.visibility, "private");
		assert.equal(doc.coverage.find(c => c.capability === "advisories").execution, "not-run");
		assert.equal(JSON.stringify(doc).includes("intranet.example.invalid"), false);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("--fail-on-incomplete returns 2 after writing the partial findings JSON", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-app-gate-"));
	try {
		const out = path.join(temp, "findings.json");
		const src = path.join(__dirname, "fixtures", "wordpress-custom");
		const run = spawnSync(process.execPath, [CLI, "-s", src, "--ecosystem", "composer", "--app-plugins", "wordpress",
			"--offline", "-d", "eol,nvd,epss,kev,retire,transitive", "--report-json", out, "--no-checksums",
			"--fail-on-incomplete", "advisories"], { encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(run.status, 2, `${run.stdout}\n${run.stderr}`);
		assert.ok(fs.existsSync(out));
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("CLI emits a local Wordfence finding for a user-declared public plugin", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wordfence-cli-"));
	try {
		const feed = path.join(temp, "feed.json");
		const out = path.join(temp, "findings.json");
		const uuid = "123e4567-e89b-12d3-a456-426614174000";
		fs.writeFileSync(feed, JSON.stringify({ [uuid]: { id: uuid, title: "Fixture advisory", cve: null,
			software: [{ type: "plugin", slug: "acme", affected_versions: { "1-3": {
				from_version: "1", from_inclusive: true, to_version: "3", to_inclusive: true,
			} }, patched_versions: ["3.1"] }], copyrights: { defiant: { notice: "Fixture copyright" } },
		} }));
		const src = path.join(temp, "scan");
		fs.cpSync(path.join(__dirname, "fixtures", "wordpress-custom"), src, { recursive: true });
		const pluginFile = path.join(src, "site/wp-content/plugins/acme/acme.php");
		fs.writeFileSync(pluginFile, fs.readFileSync(pluginFile, "utf8").replace(/^Update URI:.*\r?\n/m, ""));
		const args = [CLI, "-s", src, "--ecosystem", "composer", "--app-plugins", "wordpress",
			"--wordfence-feed", feed, "--public-component", "site/wp-content/plugins/acme=acme",
			"--offline", "-d", "eol,nvd,epss,kev,retire,transitive", "--report-json", out, "--no-checksums"];
		const run = spawnSync(process.execPath, args, { encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
		const doc = JSON.parse(fs.readFileSync(out, "utf8"));
		assert.ok(doc.cve.find(f => f.id === `WF-${uuid}`));
		assert.equal(doc.cve.find(f => f.id === `WF-${uuid}`).ownerComponentIds.length, 1);
		assert.equal(doc.coverage.find(c => c.occurrenceId?.includes(":plugin:")).result, "affected");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("CLI exports a Drupal advisory while marking custom module advisory coverage incomplete", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal-cli-"));
	try {
		const feed = path.join(temp, "feed.json");
		const out = path.join(temp, "findings.json");
		fs.writeFileSync(feed, JSON.stringify({ queriedPackages: ["drupal/core"], advisories: { "drupal/core": [
			{ advisoryId: "SA-CORE-2099-001", packageName: "drupal/core", title: "Drupal core - Critical - Fixture",
				link: "https://www.drupal.org/sa-core-2099-001", cve: null, affectedVersions: ">=10.3.0 <10.3.2" },
		] } }));
		const src = path.join(__dirname, "fixtures", "drupal-custom");
		const args = [CLI, "-s", src, "--ecosystem", "composer", "--app-plugins", "drupal",
			"--drupal-advisories", feed, "--offline", "-d", "eol,nvd,epss,kev,retire,transitive",
			"--report-json", out, "--no-checksums", "--fail-on-incomplete", "advisories"];
		const run = spawnSync(process.execPath, args, { encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(run.status, 2, `${run.stdout}\n${run.stderr}`);
		const doc = JSON.parse(fs.readFileSync(out, "utf8"));
		assert.ok(doc.cve.some(f => f.id === "SA-CORE-2099-001"));
		assert.ok(doc.coverage.some(c => c.diagnostic === "CMS_PRIVATE_COMPONENT"));
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("an invalid explicitly configured advisory snapshot exits 2 without writing a report", () => {
	for (const [plugin, flag, fixture] of [
		["wordpress", "--wordfence-feed", "wordpress-custom"],
		["drupal", "--drupal-advisories", "drupal-custom"],
	]) {
		const temp = fs.mkdtempSync(path.join(os.tmpdir(), `fad-${plugin}-invalid-`));
		try {
			const feed = path.join(temp, "broken.json");
			const out = path.join(temp, "findings.json");
			fs.writeFileSync(feed, "<html>not JSON</html>");
			const src = path.join(__dirname, "fixtures", fixture);
			const run = spawnSync(process.execPath, [CLI, "-s", src, "--ecosystem", "composer",
				"--app-plugins", plugin, flag, feed, "--offline", "-d", "eol,nvd,epss,kev,retire,transitive",
				"--report-json", out, "--no-checksums"],
			{ encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
			assert.equal(run.status, 2, `${run.stdout}\n${run.stderr}`);
			assert.equal(fs.existsSync(out), false);
		} finally { fs.rmSync(temp, { recursive: true, force: true }); }
	}
});

test("a configured advisory source cannot be silently ignored by auto plugin selection", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-source-unselected-"));
	try {
		const out = path.join(temp, "findings.json");
		const src = path.join(__dirname, "fixtures", "wordpress-custom");
		const run = spawnSync(process.execPath, [CLI, "-s", src, "--ecosystem", "composer",
			"--wordfence-feed", path.join(temp, "feed.json"), "--offline", "-d", "eol,nvd,epss,kev,retire,transitive",
			"--report-json", out, "--no-checksums"],
		{ encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(run.status, 2, `${run.stdout}\n${run.stderr}`);
		assert.equal(fs.existsSync(out), false);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("an explicitly configured local advisory source is validated before discovery, even with no matching instance", () => {
	const uuid = "123e4567-e89b-12d3-a456-426614174000";
	const validWordfence = JSON.stringify({ _fadSnapshot: { collectedAt: new Date().toISOString() }, [uuid]: { id: uuid, title: "Fixture advisory", cve: null,
		software: [{ type: "plugin", slug: "acme", affected_versions: { "1-3": { from_version: "1",
			from_inclusive: true, to_version: "3", to_inclusive: true } }, patched_versions: ["3.1"] }] } });
	const validDrupal = JSON.stringify({ collectedAt: new Date().toISOString(),
		queriedPackages: ["drupal/core"], advisories: { "drupal/core": [{ advisoryId: "SA-CORE-2099-001",
			packageName: "drupal/core", title: "Fixture", link: "https://www.drupal.org/sa-core-2099-001",
			cve: null, affectedVersions: ">=10.3.0 <10.3.2" }] } });
	// wordpress-custom holds no Drupal instance and drupal-custom holds no WordPress instance,
	// so no plugin assess() can ever reach the file: only a pre-discovery validation can fail.
	const noMatchTree = [
		["wordpress", "--wordfence-feed", "wordpress-custom", "<html>not JSON</html>"],
		["wordpress", "--wordfence-feed", "wordpress-custom", "{\"notAFeed\": true}"],
		["drupal", "--drupal-advisories", "drupal-custom", "<html>not JSON</html>"],
		["drupal", "--drupal-advisories", "drupal-custom", "{\"queriedPackages\": \"nope\", \"advisories\": {}}"],
	];
	for (const [plugin, flag, fixture, content] of noMatchTree) {
		for (const withAge of [false, true]) {
			const temp = fs.mkdtempSync(path.join(os.tmpdir(), `fad-nomatch-${plugin}-`));
			try {
				const out = path.join(temp, "findings.json");
				const args = [CLI, "-s", path.join(__dirname, "fixtures", fixture), "--ecosystem", "composer",
					"--app-plugins", plugin, flag, path.join(temp, "feed.json"), "--offline",
					"-d", "eol,nvd,epss,kev,retire,transitive", "--report-json", out, "--no-checksums"];
				if (withAge) args.push("--max-advisory-age", "72h");
				fs.writeFileSync(path.join(temp, "feed.json"), content);
				const run = spawnSync(process.execPath, args, { encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
				assert.equal(run.status, 2, `${plugin} must fail before any report (${withAge ? "with" : "without"} --max-advisory-age)\n${run.stdout}\n${run.stderr}`);
				assert.equal(fs.existsSync(out), false, "no report may be written for an unusable configured source");
			} finally { fs.rmSync(temp, { recursive: true, force: true }); }
		}
	}
	// A valid configured source stays accepted even when no instance matches it.
	for (const [plugin, flag, fixture, content] of [
		["wordpress", "--wordfence-feed", "wordpress-custom", validWordfence],
		["drupal", "--drupal-advisories", "drupal-custom", validDrupal],
	]) {
		const temp = fs.mkdtempSync(path.join(os.tmpdir(), `fad-valid-nomatch-${plugin}-`));
		try {
			const out = path.join(temp, "findings.json");
			fs.writeFileSync(path.join(temp, "feed.json"), content);
			const run = spawnSync(process.execPath, [CLI, "-s", path.join(__dirname, "fixtures", fixture),
				"--ecosystem", "composer", "--app-plugins", plugin, flag, path.join(temp, "feed.json"),
				"--offline", "-d", "eol,nvd,epss,kev,retire,transitive", "--report-json", out, "--no-checksums",
				"--max-advisory-age", "72h"], { encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
			assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
			assert.ok(fs.existsSync(out));
		} finally { fs.rmSync(temp, { recursive: true, force: true }); }
	}
	// A configured path that does not exist fails the same way, before discovery.
	for (const [plugin, flag, fixture] of [
		["wordpress", "--wordfence-feed", "wordpress-custom"],
		["drupal", "--drupal-advisories", "drupal-custom"],
	]) {
		const temp = fs.mkdtempSync(path.join(os.tmpdir(), `fad-absent-${plugin}-`));
		try {
			const out = path.join(temp, "findings.json");
			const run = spawnSync(process.execPath, [CLI, "-s", path.join(__dirname, "fixtures", fixture),
				"--ecosystem", "composer", "--app-plugins", plugin, flag, path.join(temp, "missing.json"),
				"--offline", "-d", "eol,nvd,epss,kev,retire,transitive", "--report-json", out, "--no-checksums"],
				{ encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
			assert.equal(run.status, 2, `${run.stdout}\n${run.stderr}`);
			assert.equal(fs.existsSync(out), false);
		} finally { fs.rmSync(temp, { recursive: true, force: true }); }
	}
});

test("CLI component context inventories a standalone private plugin without a WordPress core", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wp-component-cli-"));
	try {
		const src = path.join(temp, "plugin");
		fs.mkdirSync(src);
		fs.writeFileSync(path.join(src, "plugin.php"), "<?php /* Plugin Name: Custom Plugin\nVersion: 1.2.3\nUpdate URI: https://private.invalid/update\n */");
		fs.writeFileSync(path.join(src, "composer.json"), '{"name":"acme/plugin"}');
		const out = path.join(temp, "findings.json");
		const run = spawnSync(process.execPath, [CLI, "-s", src, "--ecosystem", "composer", "--app-plugins", "wordpress",
			"--scan-context", "component", "--offline", "-d", "eol,nvd,epss,kev,retire,transitive",
			"--report-json", out, "--no-checksums"],
		{ encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
		const doc = JSON.parse(fs.readFileSync(out, "utf8"));
		assert.deepEqual(doc.applications.map(a => a.layout), ["component"]);
		assert.deepEqual(doc.applicationInventory.map(c => c.kind), ["plugin"]);
		assert.equal(doc.applicationInventory[0].visibility, "private");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("--max-advisory-age rejects a stale or undeclared snapshot with exit 2 and no report", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-max-age-cli-"));
	try {
		const out = path.join(temp, "findings.json");
		const src = path.join(__dirname, "fixtures", "drupal-custom");
		const common = [CLI, "-s", src, "--ecosystem", "composer", "--app-plugins", "drupal",
			"--drupal-advisories", path.join(temp, "feed.json"), "--offline",
			"-d", "eol,nvd,epss,kev,retire,transitive", "--report-json", out, "--no-checksums"];
		fs.writeFileSync(path.join(temp, "feed.json"), JSON.stringify({ collectedAt: "2026-09-01T00:00:00Z",
			queriedPackages: [], advisories: {} }));
		const stale = spawnSync(process.execPath, [...common, "--max-advisory-age", "72h"],
			{ encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(stale.status, 2, `${stale.stdout}\n${stale.stderr}`);
		assert.match(stale.stderr, /stale/);
		assert.equal(fs.existsSync(out), false);
		fs.writeFileSync(path.join(temp, "feed.json"), JSON.stringify({ collectedAt: new Date().toISOString(),
			queriedPackages: [], advisories: {} }));
		const fresh = spawnSync(process.execPath, [...common, "--max-advisory-age", "72h"],
			{ encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(fresh.status, 0, `${fresh.stdout}\n${fresh.stderr}`);
		fs.writeFileSync(path.join(temp, "feed.json"), JSON.stringify({ queriedPackages: [], advisories: {} }));
		const undeclared = spawnSync(process.execPath, [...common, "--max-advisory-age", "72h"],
			{ encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(undeclared.status, 2, `${undeclared.stdout}\n${undeclared.stderr}`);
		assert.match(undeclared.stderr, /collection date/);
		const badDuration = spawnSync(process.execPath, [...common, "--max-advisory-age", "3 weeks"],
			{ encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(badDuration.status, 2, `${badDuration.stdout}\n${badDuration.stderr}`);
		assert.match(badDuration.stderr, /duration/);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});
