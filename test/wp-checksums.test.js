const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { validateChecksums, evaluateChecksums, WP_CHECKSUMS_API } = require("../lib/application-providers/wp-checksums");
const { fetchWordpressChecksums } = require("../lib/application-providers/live-snapshot");
const wordpress = require("../lib/application-plugins/wordpress");
const { runApplicationPlugins } = require("../lib/application-plugins/runner");

const md5 = content => crypto.createHash("md5").update(content).digest("hex");
const NOW = Date.parse("2026-09-23T12:00:00Z");
const CONFORM = "<?php // core file\n";

test("validateChecksums accepts the official API shape and rejects forged references", () => {
	const snapshot = { version: "6.4.2", locale: "en_US",
		checksums: { "wp-load.php": md5(CONFORM), "wp-admin/index.php": md5(CONFORM) },
		_fadSnapshot: { collectedAt: "2026-09-23T10:00:00Z" } };
	const parsed = validateChecksums(snapshot);
	assert.equal(parsed.checksums.size, 2);
	assert.equal(parsed.version, "6.4.2");
	assert.equal(parsed.locale, "en_US");
	assert.throws(() => validateChecksums(null), /checksums/i);
	assert.throws(() => validateChecksums({ checksums: [] }), /object/i);
	assert.throws(() => validateChecksums({ checksums: { "a.php": "not-md5" } }), /md5/i);
	assert.throws(() => validateChecksums({ checksums: { "/abs.php": md5(CONFORM) } }), /relative/i);
	assert.throws(() => validateChecksums({ checksums: { "../escape.php": md5(CONFORM) } }), /escape/i);
});

test("evaluateChecksums separates conforming, modified, missing and extra files", () => {
	const reference = validateChecksums({ version: "6.4.2", locale: "en_US", checksums: {
		"wp-load.php": md5(CONFORM),
		"wp-admin/index.php": md5(CONFORM),
		"index.php": md5(CONFORM),
		"wp-content/plugins/akismet/akismet.php": md5(CONFORM),
	} });
	const files = new Map([
		["wp-load.php", CONFORM],                       // conforming
		["wp-admin/index.php", "<?php // tampered\n"],   // modified
		// index.php: absent on disk → missing
		["wp-content/plugins/akismet/akismet.php", CONFORM],
		["wp-admin/extra.php", "<?php\n"],              // extra inside the controlled perimeter
		["wp-includes/version.php", "<?php\n"],         // extra inside the controlled perimeter
		["wp-content/uploads/img.png", "\0\0"],         // wp-content: user land, never "extra"
	]);
	const verdict = evaluateChecksums(reference, {
		has: rel => files.has(rel),
		read: rel => Buffer.from(files.get(rel), "utf8"),
		filesIn: dir => [...files.keys()].filter(k => path.posix.dirname(k) === dir).map(k => path.posix.basename(k)),
		directories: ["wp-admin", "wp-includes", "wp-content/plugins/akismet", "wp-content/uploads"],
	});
	assert.deepEqual(verdict.modified, ["wp-admin/index.php"]);
	assert.deepEqual(verdict.missing, ["index.php"]);
	assert.equal(verdict.extra.includes("wp-admin/extra.php"), true);
	assert.equal(verdict.extra.includes("wp-includes/version.php"), true);
	assert.equal(verdict.extra.some(file => file.startsWith("wp-content/")), false, "wp-content is user land, not the controlled perimeter");
	assert.equal(verdict.uncertain.length, 0);
	assert.equal(verdict.checked, 4);
});

test("unreadable or oversized reference files stay uncertain, never guessed", () => {
	const reference = validateChecksums({ checksums: { "wp-load.php": md5(CONFORM), "wp-admin/index.php": md5(CONFORM) } });
	const verdict = evaluateChecksums(reference, {
		has: () => true,
		read: rel => rel === "wp-load.php" ? null : Buffer.from("x"),   // null = too large / unreadable
		filesIn: () => [], directories: [],
	});
	assert.deepEqual(verdict.uncertain, ["wp-load.php"]);
	assert.equal(verdict.checked, 1, "only the comparable file counts as executed");
});

test("per-code diagnostics are capped with an honest truncation notice", () => {
	const checksums = {};
	for (let i = 0; i < 150; i++) checksums[`wp-includes/mod-${i}.php`] = md5(CONFORM);
	const reference = validateChecksums({ checksums });
	const files = new Map(Object.keys(checksums).map(k => [k, "tampered"]));
	const verdict = evaluateChecksums(reference, {
		has: rel => files.has(rel), read: rel => Buffer.from(files.get(rel), "utf8"),
		filesIn: () => [], directories: [], maxDiagnosticsPerCode: 100,
	});
	assert.equal(verdict.diagnostics.filter(d => d.code === "CMS_FILE_MODIFIED").length, 100);
	assert.equal(verdict.diagnostics.some(d => d.code === "CMS_INTEGRITY_LIST_TRUNCATED"), true);
	assert.match(verdict.diagnostics.find(d => d.code === "CMS_INTEGRITY_LIST_TRUNCATED").message, /150/);
	assert.equal(verdict.modified.length, 150, "the counts stay exact, only the messages are capped");
});

test("the live checksums client pins version and locale and stamps collection", async () => {
	assert.equal(WP_CHECKSUMS_API, "https://api.wordpress.org/core/checksums/1.0/");
	const calls = [];
	const fetched = await fetchWordpressChecksums("6.4.2", "fr_FR", {
		fetchImpl: async url => { calls.push(url); return { ok: true, status: 200, text: async () => JSON.stringify({ checksums: { "wp-load.php": md5(CONFORM) } }) }; },
		now: NOW });
	assert.match(calls[0], /\?version=6\.4\.2&locale=fr_FR$/);
	assert.equal(fetched.snapshot.version, "6.4.2");
	assert.equal(fetched.snapshot.locale, "fr_FR");
	assert.equal(fetched.snapshot._fadSnapshot.collectedAt, "2026-09-23T12:00:00.000Z");
	assert.equal(fetched.snapshot._fadSnapshot.completeness, "tool-fetched");
	assert.match(fetched.sourceSnapshot.sha256, /^[a-f0-9]{64}$/);
	await assert.rejects(fetchWordpressChecksums("6.4.2", "en_US",
		{ fetchImpl: async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ checksums: [] }) }) }), /checksums/i);
	await assert.rejects(fetchWordpressChecksums("6.4.2", "en_US",
		{ fetchImpl: async () => ({ ok: false, status: 500, text: async () => "boom" }) }), /500/);
});

function fixture(fn) {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wp-checksums-"));
	return Promise.resolve().then(() => fn(root)).finally(() => fs.rmSync(root, { recursive: true, force: true }));
}
function put(root, relative, content) {
	const file = path.join(root, relative);
	fs.mkdirSync(path.dirname(file), { recursive: true });
	fs.writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content));
}
const wpSite = (root, { coreVersion = "6.4.2" } = {}) => {
	put(root, "wp-includes/version.php", `<?php\n$wp_version = '${coreVersion}';\n`);
	put(root, "wp-load.php", CONFORM);
	put(root, "wp-admin/index.php", CONFORM);
	put(root, "index.php", CONFORM);
};

test("the WordPress plugin runs the integrity check with a local reference snapshot", () => fixture(async root => {
	wpSite(root);
	put(root, "wp-admin/extra.php", "<?php\n");
	const snapshotFile = path.join(root, "wp-checksums.json");
	put(root, "wp-checksums.json", { version: "6.4.2", locale: "en_US", checksums: {
		"wp-load.php": md5(CONFORM),
		"wp-admin/index.php": md5(CONFORM),
		"index.php": md5(CONFORM),
	}, _fadSnapshot: { collectedAt: "2026-09-23T10:00:00Z" } });
	const { deps } = await require("../lib/codecs/composer.codec").collect(root);
	const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
		resolvedDeps: deps, activeCodecIds: [], wpChecksumsPath: snapshotFile, offline: true,
		requiredProviderIds: ["wordpress-checksums"] });
	const integrity = result.coverage.find(c => c.capability === "integrity");
	assert.ok(integrity, "the integrity capability is reported");
	assert.equal(integrity.sourceId, "wordpress-checksums");
	assert.equal(integrity.execution, "completed");
	assert.equal(integrity.result, "affected");
	assert.deepEqual(result.findings, [], "integrity divergences are diagnostics, not CVE findings");
	const codes = result.diagnostics.filter(d => d.applicationId === "wordpress:.").map(d => d.code);
	assert.ok(codes.includes("CMS_FILE_EXTRA"));
	assert.ok(!codes.some(c => c === "CMS_FILE_MODIFIED" || c === "CMS_FILE_MISSING"), "the untampered tree reports no divergence");
}));

test("the integrity check surfaces tampered and missing files and refuses a mismatched reference", () => fixture(async root => {
	wpSite(root);
	put(root, "wp-admin/index.php", "<?php // tampered\n");
	fs.rmSync(path.join(root, "index.php"));
	const snapshotFile = path.join(root, "wp-checksums.json");
	put(root, "wp-checksums.json", { version: "6.4.2", locale: "en_US", checksums: {
		"wp-load.php": md5(CONFORM),
		"wp-admin/index.php": md5(CONFORM),
		"index.php": md5(CONFORM),
	} });
	const { deps } = await require("../lib/codecs/composer.codec").collect(root);
	const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
		resolvedDeps: deps, activeCodecIds: [], wpChecksumsPath: snapshotFile });
	const codes = result.diagnostics.filter(d => d.applicationId === "wordpress:.").map(d => d.code);
	assert.ok(codes.includes("CMS_FILE_MODIFIED"));
	assert.ok(codes.includes("CMS_FILE_MISSING"));
	const mismatch = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
		resolvedDeps: deps, activeCodecIds: [], wpChecksumsPath: snapshotFile, now: NOW });
	const mismatchSnapshot = { version: "6.5", locale: "en_US", checksums: { "wp-load.php": md5(CONFORM) } };
	put(root, "other.json", mismatchSnapshot);
	const mismatched = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
		resolvedDeps: deps, activeCodecIds: [], wpChecksumsPath: path.join(root, "other.json") });
	const integrity = mismatched.coverage.find(c => c.capability === "integrity");
	assert.equal(integrity.execution, "not-run");
	assert.equal(integrity.diagnostic, "CMS_CHECKSUMS_REFERENCE_MISMATCH");
	assert.deepEqual(mismatched.diagnostics.filter(d => d.code === "CMS_FILE_MODIFIED"), [],
		"a reference for another version never produces fake modified files");
}));

test("without a checksums source the integrity capability stays honestly not-run", () => fixture(async root => {
	wpSite(root);
	const { deps } = await require("../lib/codecs/composer.codec").collect(root);
	const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
		resolvedDeps: deps, activeCodecIds: [] });
	const integrity = result.coverage.find(c => c.capability === "integrity");
	assert.equal(integrity.execution, "not-run");
	assert.equal(integrity.diagnostic, "CMS_PROVIDER_UNCONFIGURED");
}));
