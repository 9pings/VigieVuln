const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const crypto = require("node:crypto");
const composer = require("../lib/codecs/composer.codec");
const drupal = require("../lib/application-plugins/drupal");
const wordpress = require("../lib/application-plugins/wordpress");
const { runApplicationPlugins } = require("../lib/application-plugins/runner");

const md5 = value => crypto.createHash("md5").update(value).digest("hex");
const STAMP = { collectedAt: "2026-09-24T08:00:00.000Z", completeness: "tool-fetched",
	sourceUrl: "https://packages.drupal.org/8/security-advisories" };
const drupalSnapshot = () => ({ queriedPackages: ["drupal/core"],
	advisories: { "drupal/core": [{ advisoryId: "SA-CORE-2099-001", packageName: "drupal/core",
		title: "Drupal core - Critical - Fixture", link: "https://www.drupal.org/sa-core-2099-001",
		cve: null, affectedVersions: ">=10.3.0 <10.3.2" }] },
	_fadSnapshot: { ...STAMP } });

function tempDir() { return fs.mkdtempSync(path.join(os.tmpdir(), "fad-offline-reuse-")); }
const writeCached = (cacheDir, file, snapshot) => {
	fs.mkdirSync(cacheDir, { recursive: true });
	const file_ = path.join(cacheDir, file);
	fs.writeFileSync(file_, JSON.stringify(snapshot));
	return file_;
};

test("offline: a cached Drupal advisory snapshot is consumed without --drupal-advisories", async () => {
	const temp = tempDir();
	try {
		const cacheDir = path.join(temp, "advisory-snapshots");
		writeCached(cacheDir, "drupal-security-advisories.json", drupalSnapshot());
		const root = path.join(__dirname, "fixtures", "drupal-custom");
		const { deps } = await composer.collect(root);
		const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal",
			resolvedDeps: deps, activeCodecIds: ["composer"], offline: true, advisoryCacheDir: cacheDir });
		assert.equal(result.findings.length, 1, "the cached snapshot assesses core like an explicit flag would");
		assert.equal(result.findings[0].cve.id, "SA-CORE-2099-001");
		const core = result.coverage.find(c => c.occurrenceId?.endsWith(":core"));
		assert.equal(core.execution, "completed");
		assert.equal(core.result, "affected");
		assert.equal(core.sourceSnapshot.completeness, "tool-fetched",
			"provenance reports the tool-fetched stamp, not a declaration the operator never made");
		assert.equal(core.sourceSnapshot.sourceUrl, STAMP.sourceUrl, "the stamp's source URL travels with the coverage");
		assert.equal(core.sourceSnapshot.collectedAt, STAMP.collectedAt);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("online: the cached Drupal snapshot is consumed too — the lanes follow the cache, not the mode", async () => {
	const temp = tempDir();
	try {
		const cacheDir = path.join(temp, "advisory-snapshots");
		writeCached(cacheDir, "drupal-security-advisories.json", drupalSnapshot());
		const root = path.join(__dirname, "fixtures", "drupal-custom");
		const { deps } = await composer.collect(root);
		// Same command, same options as the offline scan: an air-gapped phase 3 and its
		// online reference must produce identical results.
		const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal",
			resolvedDeps: deps, activeCodecIds: ["composer"], advisoryCacheDir: cacheDir });
		assert.equal(result.findings.length, 1, "the cached snapshot is assessed online as well");
		const core = result.coverage.find(c => c.occurrenceId?.endsWith(":core"));
		assert.equal(core.execution, "completed");
		assert.equal(core.sourceSnapshot.completeness, "tool-fetched");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("offline: an explicit --drupal-advisories flag wins over the cached snapshot", async () => {
	const temp = tempDir();
	try {
		const cacheDir = path.join(temp, "advisory-snapshots");
		const cachedFile = writeCached(cacheDir, "drupal-security-advisories.json", drupalSnapshot());
		const explicit = path.join(temp, "operator.json");
		fs.writeFileSync(explicit, JSON.stringify({ queriedPackages: ["drupal/core"],
			advisories: { "drupal/core": [{ advisoryId: "SA-CORE-2099-042", packageName: "drupal/core",
				title: "Operator-supplied", link: "", cve: null, affectedVersions: ">=10.3.0 <10.3.2" }] } }));
		const root = path.join(__dirname, "fixtures", "drupal-custom");
		const { deps } = await composer.collect(root);
		const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal",
			resolvedDeps: deps, activeCodecIds: ["composer"], offline: true, advisoryCacheDir: cacheDir,
			drupalAdvisoriesPath: explicit });
		assert.equal(result.findings[0].cve.id, "SA-CORE-2099-042", "the explicit file is assessed");
		const core = result.coverage.find(c => c.occurrenceId?.endsWith(":core"));
		assert.equal(core.sourceSnapshot.sha256, crypto.createHash("sha256").update(fs.readFileSync(explicit)).digest("hex"));
		assert.equal(core.sourceSnapshot.completeness, "operator-declared");
		assert.ok(cachedFile.length > 0);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("offline: a corrupt cached Drupal snapshot fails the scan like an invalid explicit one would", async () => {
	const temp = tempDir();
	try {
		const cacheDir = path.join(temp, "advisory-snapshots");
		writeCached(cacheDir, "drupal-security-advisories.json", { queriedPackages: ["drupal/core"] });
		const root = path.join(__dirname, "fixtures", "drupal-custom");
		const { deps } = await composer.collect(root);
		await assert.rejects(() => runApplicationPlugins(root, { plugins: [drupal], selection: "drupal",
			resolvedDeps: deps, activeCodecIds: ["composer"], offline: true, advisoryCacheDir: cacheDir }),
		/Drupal advisory snapshot needs an advisories object/);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("offline: a cached snapshot past --max-advisory-age is rejected (the fallback honors freshness)", async () => {
	const temp = tempDir();
	try {
		const cacheDir = path.join(temp, "advisory-snapshots");
		writeCached(cacheDir, "drupal-security-advisories.json", drupalSnapshot());
		const root = path.join(__dirname, "fixtures", "drupal-custom");
		const { deps } = await composer.collect(root);
		await assert.rejects(() => runApplicationPlugins(root, { plugins: [drupal], selection: "drupal",
			resolvedDeps: deps, activeCodecIds: ["composer"], offline: true, advisoryCacheDir: cacheDir,
			maxAdvisoryAgeMs: 3600 * 1000, now: Date.parse("2026-09-24T12:00:00.000Z") }),
		/is stale/);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("offline: a cached Drupal snapshot is not consumed when its plugin is not selected", async () => {
	const temp = tempDir();
	try {
		const cacheDir = path.join(temp, "advisory-snapshots");
		writeCached(cacheDir, "drupal-security-advisories.json", { queriedPackages: ["drupal/core"] });
		const root = path.join(__dirname, "fixtures", "wordpress-custom");
		const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
			offline: true, advisoryCacheDir: cacheDir });
		assert.equal(result.applications.length, 1, "the WordPress instance is scanned");
		assert.ok(!result.coverage.some(c => c.sourceId === "drupal-security-advisories"),
			"the Drupal source stays silent instead of failing the run");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("offline: a cached WordPress checksums reference for the instance's version is reused per instance", async () => {
	const temp = tempDir();
	try {
		const cacheDir = path.join(temp, "advisory-snapshots");
		const root = path.join(__dirname, "fixtures", "wordpress-custom");
		const load = rel => fs.readFileSync(path.join(root, "site", rel), "utf8");
		writeCached(cacheDir, "wordpress-checksums-6.6.2-en_US.json", {
			checksums: { "wp-load.php": md5(load("wp-load.php")), "wp-admin/index.php": "0123456789abcdef0123456789abcdef" },
			version: "6.6.2", locale: "en_US",
			_fadSnapshot: { collectedAt: STAMP.collectedAt, completeness: "tool-fetched",
				sourceUrl: "https://api.wordpress.org/core/checksums/1.0/?version=6.6.2&locale=en_US" } });
		const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
			offline: true, advisoryCacheDir: cacheDir });
		const integrity = result.coverage.find(c => c.capability === "integrity");
		assert.ok(integrity, "the integrity lane ran");
		assert.notEqual(integrity.execution, "not-run");
		assert.equal(integrity.sourceSnapshot.completeness, "tool-fetched");
		assert.match(integrity.sourceSnapshot.sourceUrl, /^https:\/\/api\.wordpress\.org/);
		// The wrong md5 for wp-admin/index.php is a divergence the reference must surface.
		assert.equal(integrity.result, "affected");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("offline: a cached WordPress checksums reference for ANOTHER version is not reused", async () => {
	const temp = tempDir();
	try {
		const cacheDir = path.join(temp, "advisory-snapshots");
		writeCached(cacheDir, "wordpress-checksums-6.5.0-en_US.json", {
			checksums: { "wp-load.php": "0123456789abcdef0123456789abcdef" },
			version: "6.5.0", locale: "en_US", _fadSnapshot: { ...STAMP } });
		const root = path.join(__dirname, "fixtures", "wordpress-custom");
		const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
			offline: true, advisoryCacheDir: cacheDir });
		const integrity = result.coverage.find(c => c.capability === "integrity");
		assert.equal(integrity.execution, "not-run", "no reference for 6.6.2 → the lane stays honest");
		assert.equal(integrity.diagnostic, "CMS_PROVIDER_UNCONFIGURED");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("a cached Wordfence catalogue is consumed without a flag and without an API key", async () => {
	const temp = tempDir();
	try {
		// A public plugin identity (no third-party Update URI) is what the feed matches;
		// the cached catalogue is the air-gap phase-2 warming product of a keyed fetch.
		const root = path.join(temp, "scan");
		fs.cpSync(path.join(__dirname, "fixtures", "wordpress-custom"), root, { recursive: true });
		const pluginFile = path.join(root, "site/wp-content/plugins/acme/acme.php");
		fs.writeFileSync(pluginFile, fs.readFileSync(pluginFile, "utf8").replace(/^Update URI:.*\r?\n/m, ""));
		const cacheDir = path.join(temp, "advisory-snapshots");
		writeCached(cacheDir, "wordfence-v3.json", {
			"123e4567-e89b-12d3-a456-426614174000": {
				id: "123e4567-e89b-12d3-a456-426614174000", title: "Acme public issue", cve: "CVE-2099-12345",
				software: [{ type: "plugin", slug: "acme", affected_versions: { "1-3": {
					from_version: "1", from_inclusive: true, to_version: "3", to_inclusive: true } },
					patched_versions: ["3.1"] }] },
			_fadSnapshot: { collectedAt: STAMP.collectedAt, completeness: "tool-fetched",
				sourceUrl: "https://www.wordfence.com/intelligence/v2/..." },
		});
		const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
			offline: true, advisoryCacheDir: cacheDir, publicComponents: ["site/wp-content/plugins/acme=acme"] });
		assert.equal(result.findings.length, 1, "the cached catalogue assesses the public plugin");
		assert.equal(result.findings[0].cve.id, "CVE-2099-12345");
		const advisory = result.coverage.find(c => c.sourceId === "wordfence-v3");
		assert.equal(advisory.execution, "partial", "aged automatic cache retains findings but cannot establish complete coverage");
		assert.equal(advisory.result, "indeterminate");
		assert.equal(advisory.sourceSnapshot.stale, true);
		assert.equal(advisory.sourceSnapshot.completeness, "tool-fetched",
			"the warmed catalogue reports its fetch stamp — the air-gapped side never saw the key");
		assert.match(advisory.sourceSnapshot.sourceUrl, /wordfence\.com/);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});
