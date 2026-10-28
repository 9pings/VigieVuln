/**
 * When the local OSV database turns itself on.
 *
 * A Java project is the one case where the per-dep OSV cache is not enough: offline
 * recall then depends on which deps happened to be queried online before, which is not
 * a property an air-gapped audit can rely on. So Maven/Gradle scans pull the full OSV
 * Maven export on their first run and reuse the cached index afterwards.
 */
const test = require("node:test");
const assert = require("node:assert");
const { autoEnableOsvDb } = require("../lib/osv-db");

test("a Java scan never pulls the 9 MB import on its own", () => {
	// It buys offline completeness, not speed — the per-dep OSV queries still run, and they
	// are not the bottleneck on a large reactor anyway. Nobody should pay for it unasked.
	assert.strictEqual(autoEnableOsvDb({}, { runMaven: true, hasIndex: false }), false);
	assert.strictEqual(autoEnableOsvDb({}, { runGradle: true, hasIndex: false }), false);
});

test("but an index already on disk is used, online or off — it is free recall", () => {
	assert.strictEqual(autoEnableOsvDb({}, { runMaven: true, hasIndex: true }), true);
	assert.strictEqual(autoEnableOsvDb({ vigievulnProxy: true }, { runMaven: true, hasIndex: true }), false);
	assert.strictEqual(autoEnableOsvDb({ vigievulnProxy: true, offline: true }, { runMaven: true, hasIndex: true }), true);
	assert.strictEqual(autoEnableOsvDb({ offline: true }, { runMaven: true, hasIndex: true }), true);
});

test("--no-osv-db still wins", () => {
	assert.strictEqual(autoEnableOsvDb({ osvDb: false }, { runMaven: true, hasIndex: true }), false);
});

test("--osv-db forces it on even where it would not auto-enable", () => {
	assert.strictEqual(autoEnableOsvDb({ osvDb: true }, { runMaven: false, runGradle: false }), true);
});

test("a non-Java scan does not pull a Maven-only database", () => {
	assert.strictEqual(autoEnableOsvDb({}, { runMaven: false, runGradle: false }), false);
});

test("--no-osv means no OSV data at all, local database included", () => {
	assert.strictEqual(autoEnableOsvDb({ osv: false }, { runMaven: true, hasIndex: true }), false);
	// unless the user asked for the database by name, which is unambiguous
	assert.strictEqual(autoEnableOsvDb({ osv: false, osvDb: true }, { runMaven: true, hasIndex: false }), true);
});

test("an offline scan never triggers the download", () => {
	// --offline is a zero-network guarantee; a 9 MB fetch would break it outright.
	assert.strictEqual(autoEnableOsvDb({ offline: true }, { runMaven: true, hasIndex: false }), false);
});

test("an offline scan DOES use an index it already has — that is the air-gapped case", () => {
	// Imported via --import-cache, say. Skipping it here would lose recall exactly where
	// the local database matters most, and costs no network.
	assert.strictEqual(autoEnableOsvDb({ offline: true }, { runMaven: true, hasIndex: true }), true);
});

test("--osv-db offline with no index is still honoured, and reports the miss itself", () => {
	assert.strictEqual(autoEnableOsvDb({ offline: true, osvDb: true }, { runMaven: true, hasIndex: false }), true);
});
