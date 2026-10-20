const test = require("node:test");
const assert = require("node:assert/strict");
const { checkMavenLibExist, discardUnverifiedEntries, MAX_AGE_MS } = require("../lib/maven-presence");
const { createRepoHealth } = require("../lib/maven-repo");

const repos = [{ url: "https://first.invalid/" }, { url: "https://second.invalid/" }];
const coord = ["org.slf4j", "slf4j-api"];
const key = coord.join(":");
const fresh = () => ({ meta: {}, entries: {} });
const neverFetch = async () => { assert.fail("offline must not fetch"); };
function fetcherFor(outcomes) {
	return async url => {
		const i = repos.findIndex(repo => url.startsWith(repo.url));
		const result = outcomes[i];
		if (result instanceof Error) throw result;
		return { ok: result >= 200 && result < 300, status: result };
	};
}

test("Maven: any successful repository wins, including after an error", async () => {
	const cache = fresh();
	assert.equal(await checkMavenLibExist(...coord, repos, cache, {
		fetcher: fetcherFor([503, 200]),
	}), true);
	assert.equal(cache.entries[key], true);
});

for (const status of [401, 403, 405, 429, 500, 503, new Error("ECONNRESET")]) {
	test(`Maven: 404 plus ${status} is unknown and never cached as absent`, async () => {
		const cache = fresh();
		assert.equal(await checkMavenLibExist(...coord, repos, cache, {
			fetcher: fetcherFor([404, status]),
		}), null);
		assert.deepEqual(cache.entries, {});
	});
}

test("Maven: every repository must answer 404/410; proven absence survives offline", async () => {
	const cache = fresh();
	assert.equal(await checkMavenLibExist(...coord, repos, cache, { fetcher: fetcherFor([404, 410]) }), false);
	assert.equal(cache.entries[key].found, false);
	assert.ok(cache.entries[key].evidence);
	assert.equal(await checkMavenLibExist(...coord, repos, cache, { offline: true, fetcher: neverFetch }), false);
});

test("Maven: legacy false, malformed values and a cold cache stay unknown offline", async () => {
	for (const value of [false, null, "false", {}, { found: false }]) {
		const cache = { entries: { [key]: value, "other:public": true } };
		assert.equal(discardUnverifiedEntries(cache), true);
		assert.deepEqual(cache.entries, { "other:public": true });
		assert.equal(await checkMavenLibExist(...coord, repos, cache, { offline: true, fetcher: neverFetch }), null);
	}
	assert.equal(await checkMavenLibExist(...coord, repos, fresh(), { offline: true, fetcher: neverFetch }), null);
});

test("Maven: legacy positives remain usable offline", async () => {
	const cache = { entries: { [key]: true } };
	assert.equal(discardUnverifiedEntries(cache), false);
	assert.equal(await checkMavenLibExist(...coord, repos, cache, { offline: true, fetcher: neverFetch }), true);
});

test("Maven: no repositories, a preflight omission or a disabled mirror cannot prove absence", async () => {
	assert.equal(await checkMavenLibExist(...coord, [], fresh(), { fetcher: neverFetch }), null);
	assert.equal(await checkMavenLibExist(...coord, repos.slice(0, 1), fresh(), {
		configuredRepos: repos, fetcher: fetcherFor([404, 404]),
	}), null);
	const mirrored = [repos[0], { ...repos[1], mirror: true }];
	const health = createRepoHealth();
	health.markDown(mirrored[1], "timeout");
	assert.equal(await checkMavenLibExist(...coord, mirrored, fresh(), {
		health, fetcher: fetcherFor([404, 404]),
	}), null);
});

test("Maven: an actual request deadline is unknown, not a cached absence", async () => {
	const cache = fresh();
	assert.equal(await checkMavenLibExist(...coord, repos, cache, {
		timeoutMs: 10,
		fetcher: (_url, { signal }) => new Promise((_resolve, reject) =>
			signal.addEventListener("abort", () => reject(new Error("timeout")), { once: true })),
	}), null);
	assert.deepEqual(cache.entries, {});
});

test("Maven: negative evidence is scoped to repositories and expires independently of file metadata", async () => {
	const cache = fresh(), now = Date.now();
	await checkMavenLibExist(...coord, repos, cache, { fetcher: fetcherFor([404, 404]), now });
	assert.equal(await checkMavenLibExist(...coord, [...repos].reverse(), cache, {
		offline: true, fetcher: neverFetch,
	}), false, "repository order does not change scope");
	const original = structuredClone(cache);
	assert.equal(await checkMavenLibExist(...coord, [...repos, { url: "https://new.invalid/" }], cache, {
		offline: true, fetcher: neverFetch,
	}), null);
	const changedAuth = structuredClone(original);
	assert.equal(await checkMavenLibExist(...coord, [{ ...repos[0], auth: "user:secret" }, repos[1]], changedAuth, {
		offline: true, fetcher: neverFetch,
	}), null);
	const stale = structuredClone(original);
	stale.meta.fetchedAt = now + MAX_AGE_MS * 2;
	assert.equal(await checkMavenLibExist(...coord, repos, stale, {
		now: now + MAX_AGE_MS * 2, fetcher: fetcherFor([200, 200]),
	}), true, "a refreshed file timestamp must not renew old negative evidence");
	assert.equal(await checkMavenLibExist(...coord, repos, original, {
		now: now + MAX_AGE_MS * 2, offline: true, fetcher: neverFetch,
	}), false, "offline keeps the last proven snapshot");
});

test("Maven: cache merges cannot upgrade legacy negatives to verified evidence", async () => {
	const verified = fresh();
	await checkMavenLibExist("internal", "lib", repos, verified, { fetcher: fetcherFor([404, 404]) });
	const merged = { ...verified, entries: { ...verified.entries, [key]: false } };
	discardUnverifiedEntries(merged);
	assert.equal(await checkMavenLibExist(...coord, repos, merged, { offline: true, fetcher: neverFetch }), null);
	assert.equal(await checkMavenLibExist("internal", "lib", repos, merged, { offline: true, fetcher: neverFetch }), false);
	assert.ok(!JSON.stringify(verified).includes("https://"), "cache evidence must not expose repository URLs");
});
