/**
 * Air-gap / "zero data sent" guarantee (air-gap relevant).
 *
 * Locks the contract that the network-heavy Maven paths make ZERO network calls in
 * offline mode, even on a COLD cache (fresh dir = guaranteed cache miss → would fetch
 * if not for the offline guard). The injected fetcher THROWS if touched, so any
 * regression that sneaks a network call into the offline path fails the suite.
 *
 * Empirical end-to-end proof (auditor-reproducible) is documented in README/USAGE:
 *   unshare -rn node vigievuln.js -s <tree> --offline …   # no network namespace
 *   → identical findings to a normal --offline run.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const core = require("../lib/core");
const { fetchPom, effectivePom, resolveTransitiveDeps } = require("../lib/transitive");
const { collectResolvedDeps } = require("../lib/cve-match");
const { resolveReactor } = require("../lib/maven-reactor");

const freshCache = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-airgap-"));
function tripwireFetcher() {
	let calls = 0;
	const fetcher = async (url) => { calls++; throw new Error(`NETWORK CALL in --offline mode: ${url}`); };
	fetcher.calls = () => calls;
	return fetcher;
}

test("offline: fetchPom returns null on a cache miss WITHOUT touching the network", async () => {
	const f = tripwireFetcher();
	const r = await fetchPom("com.none", "missing-artifact", "9.9.9", { offline: true, fetcher: f, cacheDir: freshCache() });
	assert.equal(r, null);
	assert.equal(f.calls(), 0, "fetcher must not be called in offline mode");
});

test("offline: effectivePom resolves to null on cold cache with zero network", async () => {
	const f = tripwireFetcher();
	const r = await effectivePom("com.none", "x", "1.0", { offline: true, fetcher: f, cacheDir: freshCache() });
	assert.equal(r, null);
	assert.equal(f.calls(), 0);
});

test("offline: resolveTransitiveDeps makes zero network calls on a cold cache", async () => {
	const f = tripwireFetcher();
	const out = await resolveTransitiveDeps(
		[{ groupId: "com.none", artifactId: "x", version: "1.0", scope: "compile" }],
		{ offline: true, fetcher: f, cacheDir: freshCache() },
	);
	assert.equal(f.calls(), 0, "no network in offline transitive resolution");
	assert.equal(out.size, 0);
});

test("offline: the per-module Maven resolution makes zero network calls", async () => {
	// Parse the masking fixture, then run the overlay offline with a tripwire fetcher.
	const FIXTURE = path.join(__dirname, "fixtures", "maven-version-masking");
	const store = core.newMetadataStore();
	for (const pom of core.findPomFiles(FIXTURE)) await core.parsePom(pom, store);
	const propsByPom = {};
	for (const pom of Object.keys(store.byPath)) await core.getAllInheritedProps(pom, store, propsByPom);
	const resolved = collectResolvedDeps(store, propsByPom, {});

	const f = tripwireFetcher();
	await resolveReactor(resolved, store, propsByPom, { offline: true, fetcher: f, cacheDir: freshCache() });
	assert.equal(f.calls(), 0, "the per-module resolution must respect --offline (cache-first, never network)");
});
