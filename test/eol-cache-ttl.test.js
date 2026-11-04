const { test } = require("node:test");
const assert = require("node:assert/strict");
const { fetchEndoflife, normalizeEolCache, EOL_CACHE_MAX_AGE_MS } = require("../lib/outdated");

// Pure, in-memory: an injected `fetcher` (never the network) and a fixed clock.
const DAY = 24 * 3600 * 1000;
const NOW = Date.parse("2026-09-02T00:00:00Z");
const OLD = [{ cycle: "5.4", eol: "2029-02-28", support: "2024-11-30" }];
const NEW = [{ cycle: "8.1", eol: "2027-01-31", support: "2027-01-31" }, ...OLD];

function fetcherReturning(body, ok = true) {
	const f = async () => { f.calls++; return { ok, status: ok ? 200 : 503, json: async () => body }; };
	f.calls = 0;
	return f;
}
function throwingFetcher() {
	const f = async () => { f.calls++; throw new Error("ENETUNREACH"); };
	f.calls = 0;
	return f;
}
const cacheWith = (entry, ageMs) => ({ meta: { fetchedAt: NOW - ageMs }, entries: { symfony: entry }, fetchedAt: { symfony: NOW - ageMs } });

test("online: a STALE entry (older than 4 h) is refetched and restamped", async () => {
	const cache = cacheWith(OLD, 8 * DAY);
	const f = fetcherReturning(NEW);
	const r = await fetchEndoflife("symfony", cache, { now: NOW, fetcher: f });
	assert.equal(f.calls, 1);
	assert.deepEqual(r, NEW);
	assert.deepEqual(cache.entries.symfony, NEW);
	assert.equal(cache.fetchedAt.symfony, NOW);
	assert.equal(cache.meta.fetchedAt, NOW, "meta = last successful online fetch (provenance)");
});

test("online: a FRESH entry is served from cache, no network, no restamp", async () => {
	const cache = cacheWith(OLD, 3 * 3600000);
	const f = fetcherReturning(NEW);
	const r = await fetchEndoflife("symfony", cache, { now: NOW, fetcher: f });
	assert.equal(f.calls, 0);
	assert.deepEqual(r, OLD);
	assert.equal(cache.fetchedAt.symfony, NOW - 3 * 3600000);
});

test("TTL boundary: exactly 4 h is stale, 4 h minus 1 ms is fresh", async () => {
	const stale = cacheWith(OLD, EOL_CACHE_MAX_AGE_MS), fs = fetcherReturning(NEW);
	await fetchEndoflife("symfony", stale, { now: NOW, fetcher: fs });
	assert.equal(fs.calls, 1);
	const fresh = cacheWith(OLD, EOL_CACHE_MAX_AGE_MS - 1), ff = fetcherReturning(NEW);
	await fetchEndoflife("symfony", fresh, { now: NOW, fetcher: ff });
	assert.equal(ff.calls, 0);
});

test("offline: a stale entry is served as-is (the warmed cache is the only source) and nothing is restamped", async () => {
	const cache = cacheWith(OLD, 30 * DAY);
	const f = fetcherReturning(NEW);
	const r = await fetchEndoflife("symfony", cache, { now: NOW, offline: true, fetcher: f });
	assert.equal(f.calls, 0);
	assert.deepEqual(r, OLD);
	assert.equal(cache.fetchedAt.symfony, NOW - 30 * DAY);
	assert.equal(cache.meta.fetchedAt, NOW - 30 * DAY);
});

test("offline: a missing product → null, no network", async () => {
	const cache = { meta: { fetchedAt: NOW }, entries: {}, fetchedAt: {} };
	const f = fetcherReturning(NEW);
	assert.equal(await fetchEndoflife("php", cache, { now: NOW, offline: true, fetcher: f }), null);
	assert.equal(f.calls, 0);
});

test("online: a failed refetch keeps serving the stale list (stale beats nothing) and does not restamp", async () => {
	const cache = cacheWith(OLD, 8 * DAY);
	const f = throwingFetcher();
	const r = await fetchEndoflife("symfony", cache, { now: NOW, fetcher: f });
	assert.equal(f.calls, 1);
	assert.deepEqual(r, OLD);
	assert.deepEqual(cache.entries.symfony, OLD, "the stale list is NOT replaced by an {error} entry");
	assert.equal(cache.fetchedAt.symfony, NOW - 8 * DAY);
});

test("online: an HTTP error on refetch keeps the stale list", async () => {
	const cache = cacheWith(OLD, 8 * DAY);
	const f = fetcherReturning(null, false);
	assert.deepEqual(await fetchEndoflife("symfony", cache, { now: NOW, fetcher: f }), OLD);
	assert.deepEqual(cache.entries.symfony, OLD);
});

test("online: an {error} entry is never fresh — retried on the next online run", async () => {
	const cache = { meta: { fetchedAt: NOW - 3600e3 }, entries: { symfony: { error: "HTTP 503" } }, fetchedAt: { symfony: NOW - 3600e3 } };
	const f = fetcherReturning(NEW);
	const r = await fetchEndoflife("symfony", cache, { now: NOW, fetcher: f });
	assert.equal(f.calls, 1);
	assert.deepEqual(r, NEW);
});

test("online: an unknown product (404) is cached as an error entry, and offline it yields null", async () => {
	const cache = { meta: { fetchedAt: NOW }, entries: {}, fetchedAt: {} };
	const f = async () => ({ ok: false, status: 404, json: async () => null });
	assert.deepEqual(await fetchEndoflife("nope", cache, { now: NOW, fetcher: f }), { error: "HTTP 404" });
	assert.deepEqual(cache.entries.nope, { error: "HTTP 404" });
	assert.equal(await fetchEndoflife("nope", cache, { now: NOW, offline: true, fetcher: f }), null);
});

test("legacy cache (global stamp only): normalizeEolCache stamps every entry ONCE; a later fetch cannot make untouched entries look fresh", async () => {
	const cache = normalizeEolCache({ meta: { fetchedAt: NOW - 8 * DAY }, entries: { symfony: OLD, react: OLD } });
	assert.equal(cache.fetchedAt.symfony, NOW - 8 * DAY);
	assert.equal(cache.fetchedAt.react, NOW - 8 * DAY);
	await fetchEndoflife("symfony", cache, { now: NOW, fetcher: fetcherReturning(NEW) });
	assert.equal(cache.meta.fetchedAt, NOW, "meta moved forward");
	const f2 = fetcherReturning(NEW);
	await fetchEndoflife("react", cache, { now: NOW, fetcher: f2 });
	assert.equal(f2.calls, 1, "react was still stale despite the meta bump");
});

test("normalizeEolCache tolerates an empty / malformed file", () => {
	const c = normalizeEolCache({});
	assert.deepEqual(c.entries, {});
	assert.deepEqual(c.fetchedAt, {});
	assert.equal(normalizeEolCache({ entries: null, meta: null }).fetchedAt.constructor, Object);
});
