/**
 * checkOutdatedDeps must not query Maven Central for TRANSITIVE deps: the
 * Outdated chapter only reports deps you declare (vigievuln.js drops
 * transitive rows), so fetching their latest version is pure waste — on a
 * real reactor transitives outnumber directs 5-10× and this was where most
 * of the pass's wall-clock went.
 *
 * HOME is redirected to a temp dir BEFORE requiring lib/outdated so the
 * version-cache reads/writes land in an isolated ~/.vigie-vuln, never the
 * developer's real one.
 */
const os = require("os");
const fs = require("fs");
const path = require("path");

const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), "fad-outdated-test-"));
process.env.HOME = fakeHome;
process.env.USERPROFILE = fakeHome; // windows

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { checkOutdatedDeps, CACHE_DIR } = require("../lib/outdated");

test("cache dir is the isolated temp HOME (test-harness sanity)", () => {
	assert.ok(CACHE_DIR.startsWith(fakeHome), `CACHE_DIR ${CACHE_DIR} must live under ${fakeHome}`);
});

test("checkOutdatedDeps never fetches transitive deps, still fetches direct ones", async () => {
	const fetched = [];
	const realFetch = globalThis.fetch;
	globalThis.fetch = async (url) => {
		fetched.push(String(url));
		// Solr answer: latest 9.9.9 for whatever was asked.
		return {
			ok: true,
			json: async () => ({ response: { docs: [{ v: "9.9.9", timestamp: 1700000000000 }] } }),
		};
	};
	try {
		const deps = new Map([
			["com.example:direct-lib", { ecosystem: "maven", groupId: "com.example", artifactId: "direct-lib", version: "1.0.0", scope: "compile" }],
			["com.example:transitive-lib", { ecosystem: "maven", groupId: "com.example", artifactId: "transitive-lib", version: "1.0.0", scope: "transitive" }],
		]);
		const out = await checkOutdatedDeps(deps, { concurrency: 2 });
		assert.ok(fetched.some(u => u.includes("direct-lib")), "direct dep must be queried");
		assert.ok(!fetched.some(u => u.includes("transitive-lib")), "transitive dep must NOT be queried");
		assert.equal(out.length, 1);
		assert.equal(out[0].dep.artifactId, "direct-lib");
		assert.equal(out[0].latest, "9.9.9");
	} finally {
		globalThis.fetch = realFetch;
	}
});
