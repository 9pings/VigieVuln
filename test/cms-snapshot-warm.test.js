const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { serializeDeps, deserializeDeps } = require("../lib/deps-descriptor");
const { warmCmsAdvisorySnapshots } = require("../lib/cms-snapshot-warm");

const NOW = Date.parse("2026-09-24T12:00:00Z");
const jsonResponse = body => ({ ok: true, status: 200, text: async () => JSON.stringify(body), json: async () => body });

const dep = (namespace, name) => ({ ecosystem: "composer", namespace, name, version: "1.0.0", scope: "prod", isDev: false });
const depsOf = (...coords) => new Map(coords.map(c => {
	const [namespace, name] = c.split("/");
	return [`composer:${c}`, dep(namespace, name)];
}));

const DRUPAL_ENTRY = { advisoryId: "SA-CORE-2099-001", packageName: "drupal/core", title: "Fixture",
	link: "", cve: null, affectedVersions: ">=10.3.0 <10.3.2" };
const GH_ADVISORY = { ghsa_id: "GHSA-xrwj-pq6w-f8m4", cve_id: "CVE-2026-44212", summary: "Fixture",
	severity: "high", cvss: { vector_string: null, score: null },
	vulnerabilities: [{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
		vulnerable_version_range: ">= 8.0.0 < 8.2.6", patched_versions: "8.2.6", vulnerable_functions: [] }],
	published_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" };
const WORDFENCE_FEED = { "123e4567-e89b-12d3-a456-426614174000": {
	id: "123e4567-e89b-12d3-a456-426614174000", title: "Acme public issue", cve: "CVE-2099-12345",
	software: [{ type: "plugin", slug: "acme", affected_versions: { "1-3": {
		from_version: "1", from_inclusive: true, to_version: "3", to_inclusive: true } },
		patched_versions: ["3.1"] }] } };

function tempCache() { return fs.mkdtempSync(path.join(os.tmpdir(), "fad-cms-warm-")); }
const read = (dir, file) => JSON.parse(require('../lib/application-providers/snapshot-cache').read(path.join(dir, file),{preferCache:true}).bytes);

test("descriptor: application identities round-trip (public product coordinates, no paths)", () => {
	const resolved = depsOf("guzzlehttp/guzzle");
	const descriptor = serializeDeps(resolved, { applications: [
		{ type: "wordpress", version: "6.4.2" }, { type: "drupal", version: null }, { type: "", version: "1" }, null,
	] });
	assert.equal(descriptor.summary.applications, 2, "invalid entries are dropped, version-less kept (type is the feed signal)");
	assert.deepEqual(descriptor.applications, [{ type: "wordpress", version: "6.4.2" }, { type: "drupal", version: null }]);
	assert.ok(!JSON.stringify(descriptor).includes("root") && !JSON.stringify(descriptor).includes("/home/"), "no path leaks");
	const imported = deserializeDeps(JSON.parse(JSON.stringify(descriptor)));
	assert.deepEqual(imported.applications, descriptor.applications);
	// legacy descriptor without the section → empty, not a crash
	assert.deepEqual(deserializeDeps({ schema: "fad-deps/1", deps: [] }).applications, []);
});

test("warming: drupal/* coordinates fetch and cache the per-package Drupal feed", async () => {
	const cacheDir = tempCache();
	const calls = [];
	const warmed = await warmCmsAdvisorySnapshots(depsOf("drupal/core", "drupal/webform", "guzzlehttp/guzzle"), {
		fetchImpl: async url => { calls.push(String(url)); return jsonResponse({ advisories: { "drupal/core": [DRUPAL_ENTRY] } }); },
		advisoryCacheDir: cacheDir, now: NOW });
	try {
		assert.equal(warmed.drupal, 2);
		const snapshot = read(cacheDir, "drupal-security-advisories.json");
		assert.deepEqual(snapshot.queriedPackages.sort(), ["drupal/core", "drupal/webform"]);
		assert.equal(snapshot._fadSnapshot.completeness, "tool-fetched");
		assert.ok(snapshot._fadSnapshot.collectedAt);
		assert.equal(calls.length, 1, "one query for the union of the descriptor's drupal/* identities");
	} finally { require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); }
});

test("warming: an inventoried drupal module absent from the lock is queried too (the live query set, not the lock set)", async () => {
	const cacheDir = tempCache();
	const warmed = await warmCmsAdvisorySnapshots(depsOf("drupal/core"), {
		fetchImpl: async () => jsonResponse({ advisories: { "drupal/core": [DRUPAL_ENTRY] } }),
		advisoryCacheDir: cacheDir, applications: [{ type: "drupal", version: "10.1.0",
			components: ["drupal/core", "drupal/webform", "acme/internal"] }], now: NOW });
	try {
		assert.equal(warmed.drupal, 2, "core (lock) + webform (.info.yml inventory) — one union query");
		const snapshot = read(cacheDir, "drupal-security-advisories.json");
		assert.deepEqual(snapshot.queriedPackages.sort(), ["drupal/core", "drupal/webform"]);
	} finally { require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); }
});

test("warming: a declared prestashop application fetches the publisher feed even with no prestashop/* coordinate", async () => {
	const cacheDir = tempCache();
	const warmed = await warmCmsAdvisorySnapshots(depsOf("ext-lib/lib"), {
		fetchImpl: async () => jsonResponse([GH_ADVISORY]),
		advisoryCacheDir: cacheDir, applications: [{ type: "prestashop", version: "8.2.1" }], now: NOW });
	try {
		assert.equal(warmed.prestashop, true, "the app identity is the signal when the lock holds none of the publisher's packages");
		const snapshot = read(cacheDir, "github-prestashop-advisories.json");
		assert.ok(Array.isArray(snapshot.advisories) && snapshot.advisories.length === 1);
		assert.equal(snapshot._fadSnapshot.completeness, "tool-fetched");
	} finally { require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); }
});

test("warming: a declared wordpress application warms its checksums reference per (version, locale)", async () => {
	const cacheDir = tempCache();
	const warmed = await warmCmsAdvisorySnapshots(depsOf("ext-lib/lib"), {
		fetchImpl: async () => jsonResponse({ checksums: { "wp-load.php": "0123456789abcdef0123456789abcdef" }, version: "6.4.2", locale: "en_US" }),
		advisoryCacheDir: cacheDir, applications: [{ type: "wordpress", version: "6.4.2" }, { type: "wordpress", version: "6.4.2" }], now: NOW });
	try {
		assert.deepEqual(warmed.wpChecksums, ["6.4.2"], "duplicate core versions warm ONE reference");
		const snapshot = read(cacheDir, "wordpress-checksums-6.4.2-en_US.json");
		assert.equal(snapshot.version, "6.4.2");
		assert.equal(snapshot.locale, "en_US");
		assert.equal(snapshot._fadSnapshot.completeness, "tool-fetched");
	} finally { require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); }
});

test("warming: the Wordfence catalogue is fetched only when an API key is present", async () => {
	const cacheDir = tempCache();
	const noKey = await warmCmsAdvisorySnapshots(depsOf("ext-lib/lib"), {
		fetchImpl: async () => { throw new Error("must not fetch"); },
		advisoryCacheDir: cacheDir, applications: [{ type: "wordpress", version: null }], now: NOW });
	assert.equal(noKey.wordfence, false, "no key → no Wordfence fetch, no crash; a version-less core also warms no checksums");
	const withKey = await warmCmsAdvisorySnapshots(depsOf("ext-lib/lib"), {
		fetchImpl: async url => jsonResponse(/api\.wordpress\.org/.test(String(url))
			? { checksums: { "wp-load.php": "0123456789abcdef0123456789abcdef" }, version: "6.4.2", locale: "en_US" }
			: WORDFENCE_FEED),
		advisoryCacheDir: cacheDir, applications: [{ type: "wordpress", version: "6.4.2" }],
		wordfenceApiKey: "test-key", now: NOW });
	try {
		assert.equal(withKey.wordfence, true);
		const snapshot = read(cacheDir, "wordfence-v3.json");
		assert.equal(snapshot._fadSnapshot.completeness, "tool-fetched");
	} finally { require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); }
});

test("warming: nothing relevant in the descriptor → no fetch, no files", async () => {
	const cacheDir = tempCache();
	const warmed = await warmCmsAdvisorySnapshots(depsOf("guzzlehttp/guzzle"), {
		fetchImpl: async () => { throw new Error("must not fetch"); }, advisoryCacheDir: cacheDir, now: NOW });
	assert.deepEqual(warmed, { drupal: 0, prestashop: false, typo3: false, spip: false, wpChecksums: [], wordfence: false });
	assert.equal(fs.readdirSync(cacheDir).length, 0);
	fs.rmSync(cacheDir, { recursive: true, force: true });
});

test("warming: a failed or shape-invalid fetch fails loudly instead of caching garbage", async () => {
	const cacheDir = tempCache();
	await assert.rejects(warmCmsAdvisorySnapshots(depsOf("drupal/core"), {
		fetchImpl: async () => jsonResponse({ status: "error", message: "Missing array of package names" }),
		advisoryCacheDir: cacheDir, now: NOW }), /Missing array of package names/);
	assert.equal(fs.readdirSync(cacheDir).length, 0, "nothing is written on failure");
	fs.rmSync(cacheDir, { recursive: true, force: true });
});
