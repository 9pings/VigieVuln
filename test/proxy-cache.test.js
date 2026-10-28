/**
 * test/proxy-cache.test.js — shared persistent proxy-cache: store, client rewrite,
 * server cache/single-flight/TTL/stale behaviour, persistence across restarts,
 * API-key injection, and the --proxy / --upstream-proxy re-exec plumbing.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");
const { createSourceHealth, guardedFetch } = require("../lib/source-health");

const {
	ttlForUrl, upstreamHeadersFor, createCacheStore, startProxyCacheServer,
	parseProxyFlag, DEFAULT_CACHE_DIR, CLIENT_CACHE_DIR,
} = require("../lib/proxy-cache");

const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-proxy-"));

test("client and server caches live in separate roots (never bundled/swapped together)", () => {
	const server = path.resolve(DEFAULT_CACHE_DIR());
	const client = path.resolve(CLIENT_CACHE_DIR());
	assert.ok(!server.startsWith(client + path.sep), "the shared store must NOT live inside the client cache root");
	assert.notEqual(server, client);
});
const URL_NPM = "https://registry.npmjs.org/express";          // known source (host match)
const URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-31210";
const URL_PRIVATE = "https://npm.acme.internal/express";       // unknown host → direct

/** Fake upstream: counts hits, records the headers it received, can fail / return huge bodies. */
function fakeUpstream() {
	const state = { hits: 0, mode: "ok", body: null, lastHeaders: {} };
	const server = http.createServer((req, res) => {
		state.hits++;
		state.lastHeaders = req.headers;
		if (state.mode === "500") { res.writeHead(500, { "content-type": "text/plain" }); res.end("boom"); return; }
		const body = state.body || Buffer.from(JSON.stringify({ url: req.url, n: state.hits }));
		res.writeHead(200, { "content-type": "application/json" });
		res.end(body);
	});
	return {
		state,
		start: () => new Promise(ok => server.listen(0, "127.0.0.1", ok)),
		url: () => `http://127.0.0.1:${server.address().port}`,
		close: () => new Promise(ok => server.close(ok)),
	};
}

/**
 * Harness: a proxy-cache server wired at a fake upstream. `rewrite` maps the target
 * URL's host onto the fake (default: npm registry); everything closes in `close()`.
 */
async function startProxy(opts = {}) {
	const up = fakeUpstream();
	await up.start();
	const { rewrite = t => t.replace(/^https:\/\/registry\.npmjs\.org/, up.url()) } = opts;
	const { server, url } = await startProxyCacheServer({
		port: 0, host: "127.0.0.1",
		store: createCacheStore(opts.dir || tmpDir()),
		fetcher: opts.fetcher ? (t, init) => opts.fetcher(t, init, up) : (t, init) => fetch(rewrite(t), init),
		overrideTtlMs: opts.overrideTtlMs ?? null,
		maxBodyBytes: opts.maxBodyBytes,
		swr: opts.swr,
		token: opts.token,
		keys: opts.keys,
	});
	return {
		up, server, url,
		close: async () => { await new Promise(ok => server.close(ok)); await up.close(); },
	};
}

const callResource = (base, provider, type, params, headers = {}) => fetch(base + "/v1/resource", {
	method: "POST", headers: { "content-type": "application/json", ...headers },
	body: JSON.stringify({ provider, type, params }),
});
const get = url => {
	const mark = url.indexOf("/https://");
	let result;
	if (mark > 0) {
		const source = new URL(url.slice(mark + 1));
		const base = url.slice(0, mark);
		result = source.hostname === "registry.npmjs.org"
			? callResource(base, "npm", "package", { name: source.pathname.slice(1) })
			: source.hostname === "services.nvd.nist.gov"
				? callResource(base, "nvd", "cve", { id: source.searchParams.get("cveId") })
				: fetch(url);
	} else result = fetch(url);
	return result.then(async r => ({ status: r.status, tag: r.headers.get("x-fad-proxy"), body: await r.text() }));
};

// ------------------------------------------------------------------ store ----

test("store: set/get roundtrip, TTL freshness, persistence across instances", () => {
	const dir = tmpDir();
	const s1 = createCacheStore(dir);
	const tmpBody = path.join(dir, "seed");
	fs.writeFileSync(tmpBody, "hello");
	s1.commit(URL_NPM, tmpBody, { fetchedAt: Date.now(), ttlMs: 60_000, contentType: "text/plain", bytes: 5 });
	const e = s1.get(URL_NPM);
	assert.equal(fs.readFileSync(e.bodyPath, "utf8"), "hello");
	assert.equal(e.contentType, "text/plain");
	assert.ok((Date.now() - e.fetchedAt) < e.ttlMs);

	// a second store over the same dir sees the entry (the multi-instance contract)
	const s2 = createCacheStore(dir);
	assert.equal(fs.readFileSync(s2.get(URL_NPM).bodyPath, "utf8"), "hello");

	assert.equal(s2.size(), 1);
	s2.clear();
	assert.equal(s2.size(), 0);
	assert.equal(s2.get(URL_NPM), null);
});

test("store: refresh publishes a new body atomically and keeps active readers alive", () => {
	const dir = tmpDir(), store = createCacheStore(dir);
	const seed = path.join(dir, "seed"), update = path.join(dir, "update");
	fs.writeFileSync(seed, "old");
	store.commit(URL_NPM, seed, { fetchedAt: 1, ttlMs: 1, contentType: "text/plain", bytes: 3 });
	const old = store.get(URL_NPM);
	const release = store.acquire(old);
	fs.writeFileSync(update, "new value");
	store.commit(URL_NPM, update, { fetchedAt: 2, ttlMs: 1, contentType: "text/plain", bytes: 9 });
	const current = store.get(URL_NPM);
	assert.notEqual(current.bodyPath, old.bodyPath);
	assert.equal(fs.readFileSync(old.bodyPath, "utf8"), "old", "an in-flight response can finish");
	assert.equal(fs.readFileSync(current.bodyPath, "utf8"), "new value");
	assert.equal(fs.readFileSync(createCacheStore(dir).get(URL_NPM).bodyPath, "utf8"), "new value");
	release();
	assert.equal(fs.existsSync(old.bodyPath), false, "the retired body is removed after its last reader");
});

test("store: failed metadata publication preserves the previous cached body", () => {
	const dir = tmpDir(), store = createCacheStore(dir);
	const first = path.join(dir, "first"), second = path.join(dir, "second");
	fs.writeFileSync(first, "old");
	store.commit(URL_NPM, first, { fetchedAt: 1, ttlMs: 1, contentType: "text/plain", bytes: 3 });
	fs.writeFileSync(second, "new");
	const originalRename = fs.renameSync;
	try {
		fs.renameSync = (from, to) => {
			if (to === store.metaPath(store.hash(URL_NPM))) throw new Error("disk publication failed");
			return originalRename(from, to);
		};
		assert.throws(() => store.commit(URL_NPM, second,
			{ fetchedAt: 2, ttlMs: 1, contentType: "text/plain", bytes: 3 }), /disk publication failed/);
	} finally { fs.renameSync = originalRename; }
	assert.equal(fs.readFileSync(createCacheStore(dir).get(URL_NPM).bodyPath, "utf8"), "old");
});

test("ttlForUrl: per-source table + override + default", () => {
	assert.equal(ttlForUrl("https://api.osv.dev/v1/querybatch"), 12 * 3600 * 1000);
	assert.equal(ttlForUrl("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=X"), 7 * 24 * 3600 * 1000);
	assert.equal(ttlForUrl("https://registry.npmjs.org/express"), 24 * 3600 * 1000); // default
	assert.equal(ttlForUrl("https://registry.npmjs.org/express", { overrideTtlMs: 1000 }), 1000);
});

// ----------------------------------------------------------------- client ----

// ----------------------------------------------------------------- server ----

test("server: miss → hit (one upstream call), x-fad-proxy tags, __stats", async () => {
	const p = await startProxy();
	try {
		const target = p.url + "/" + URL_NPM;
		const r1 = await get(target);
		assert.equal(r1.status, 200);
		assert.equal(r1.tag, "miss");
		assert.equal(p.up.state.hits, 1);
		const r2 = await get(target);
		assert.equal(r2.tag, "hit");
		assert.equal(r2.body, r1.body);
		assert.equal(p.up.state.hits, 1); // served from the store, zero extra upstream
		const stats = await get(p.url + "/__stats").then(r => JSON.parse(r.body));
		assert.equal(stats.hits, 1);
		assert.equal(stats.misses, 1);
		assert.equal(stats.upstream, 1);
		assert.equal(stats.entries, 1);
	} finally { await p.close(); }
});

test("server: single-flight — 10 concurrent identical lookups → one upstream call", async () => {
	const p = await startProxy();
	try {
		const target = p.url + "/" + URL_NPM;
		const rs = await Promise.all(Array.from({ length: 10 }, () => get(target)));
		assert.ok(rs.every(r => r.status === 200));
		assert.equal(p.up.state.hits, 1);
	} finally { await p.close(); }
});

// A stale-while-revalidate response returns BEFORE its background refetch lands —
// under CI load the upstream may not have been called yet when the next line runs,
// so a background revalidation is awaited, never raced.
async function waitFor(condition, { timeoutMs = 5000, stepMs = 10 } = {}) {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (condition()) return;
		await new Promise(r => setTimeout(r, stepMs));
	}
	if (!condition()) throw new Error("waitFor: condition not met within " + timeoutMs + "ms");
}

test("server: TTL expiry refetches; swr serves stale then refreshes in the background", async () => {
	// The TTL must stay comfortably larger than CI scheduling jitter: after the
	// background revalidate lands, the refreshed entry needs to still be FRESH
	// when the next request reads it — a 50ms TTL expired again mid-assert on a
	// loaded runner and the third read got "stale" instead of "hit".
	const p = await startProxy({ overrideTtlMs: 500 });
	try {
		const target = p.url + "/" + URL_NPM;
		await get(target);
		assert.equal(p.up.state.hits, 1);
		await new Promise(r => setTimeout(r, 700)); // expired
		const r2 = await get(target);
		assert.equal(r2.tag, "stale"); // served the old copy immediately
		// …and refreshed upstream in the background. The refreshed entry is
		// served once the revalidate LANDS — poll for that observable instead of
		// guessing when the store write lands: a loaded runner may interleave
		// further "stale" reads (each one re-arming the coalesced revalidate),
		// and the loop converges on the first read inside the fresh TTL.
		let r3 = r2;
		const deadline = Date.now() + 10000;
		while (r3.tag !== "hit" && Date.now() < deadline) {
			await new Promise(r => setTimeout(r, 25));
			r3 = await get(target);
		}
		assert.equal(r3.tag, "hit"); // the refreshed entry is now served
	} finally { await p.close(); }
});

test("server: --no-swr makes expiry a blocking refetch", async () => {
	const p = await startProxy({ overrideTtlMs: 50, swr: false });
	try {
		const target = p.url + "/" + URL_NPM;
		await get(target);
		await new Promise(r => setTimeout(r, 80));
		const r2 = await get(target);
		assert.equal(r2.tag, "miss"); // blocking: no stale was served
		assert.equal(p.up.state.hits, 2);
	} finally { await p.close(); }
});

test("server: stale-if-error — a dead upstream serves the stale copy instead of 502", async () => {
	const p = await startProxy({ overrideTtlMs: 50, swr: false });
	try {
		const target = p.url + "/" + URL_NPM;
		const first = await get(target);
		await new Promise(r => setTimeout(r, 80)); // expired
		p.up.state.mode = "500";
		const r2 = await get(target);
		assert.equal(r2.status, 200);
		assert.equal(r2.tag, "stale");
		assert.equal(r2.body, first.body);
	} finally { await p.close(); }
});

test("server: a refresh body that breaks midstream serves the old entry intact", async () => {
	let failBody = false;
	const p = await startProxy({ overrideTtlMs: 30, swr: false,
		fetcher: (target, init, up) => failBody
			? new Response(new ReadableStream({ start(controller) {
				controller.enqueue(new TextEncoder().encode("partial"));
				controller.error(new Error("upstream stream broke"));
			} }), { status: 200, headers: { "content-type": "application/json" } })
			: fetch(target.replace(/^https:\/\/registry\.npmjs\.org/, up.url()), init) });
	try {
		const target = p.url + "/" + URL_NPM;
		const old = await get(target);
		failBody = true;
		await new Promise(r => setTimeout(r, 45));
		const after = await get(target);
		assert.equal(after.status, 200);
		assert.equal(after.tag, "stale");
		assert.equal(after.body, old.body);
		assert.equal(p.server.fadStore.size(), 1);
	} finally { await p.close(); }
});

test("server: default stale-while-revalidate survives offline upstream", async () => {
	let online = true, attempts = 0;
	const p = await startProxy({ overrideTtlMs: 30, fetcher: (target, init, up) => {
		attempts++;
		if (!online) throw new Error("upstream offline");
		return fetch(target.replace(/^https:\/\/registry\.npmjs\.org/, up.url()), init);
	} });
	try {
		const target = p.url + "/" + URL_NPM;
		const first = await get(target);
		online = false;
		await new Promise(r => setTimeout(r, 45));
		const answers = await Promise.all(Array.from({ length: 20 }, () => get(target)));
		assert.ok(answers.every(r => r.status === 200 && r.tag === "stale" && r.body === first.body));
		assert.ok(attempts <= 3, `offline refreshes should coalesce (${attempts} attempts)`);
		assert.equal(p.server.fadStore.size(), 1);
	} finally { await p.close(); }
});

test("server: 40 concurrent readers survive an offline upstream; a cold miss fails at the client", async () => {
	const dir = tmpDir();
	let online = true, attempts = 0;
	const fetcher = (target, init, up) => {
		attempts++;
		if (!online) throw new Error("upstream offline");
		return fetch(target.replace(/^https:\/\/registry\.npmjs\.org/, up.url()), init);
	};
	const p = await startProxy({ dir, overrideTtlMs: 40, swr: false, fetcher });
	try {
		const target = p.url + "/" + URL_NPM;
		const seed = await get(target);
		assert.equal(seed.status, 200);
		const entry = p.server.fadStore.get(require("../lib/providers").providerKey("npm", "package", { name: "express" }));
		const saved = fs.readFileSync(entry.bodyPath);
		online = false;
		await new Promise(r => setTimeout(r, 60));
		const results = await Promise.all(Array.from({ length: 40 }, () => get(target)));
		assert.ok(results.every(r => r.status === 200 && r.body === seed.body));
		assert.ok(results.every(r => r.tag === "stale"));
		assert.ok(attempts <= 3, `offline stale reads should not hammer upstream (${attempts} attempts)`);
		assert.deepEqual(fs.readFileSync(p.server.fadStore.get(require("../lib/providers").providerKey("npm", "package", { name: "express" })).bodyPath), saved);
		assert.equal(p.server.fadStore.size(), 1, "no outage may delete the cached entry");

		const cold = URL_NPM + "-uncached";
		assert.equal((await get(p.url + "/" + cold)).status, 502);
		const health = createSourceHealth();
		const client = guardedFetch({ health, fetch: () => callResource(p.url, "npm", "package", { name: "express-uncached" }), sleep: async () => {} });
		const res = await client(cold);
		assert.equal(res.status, 502);
		assert.equal(health.degraded().length, 1, "the client records a required source outage");
		assert.ok(attempts >= 2);
	} finally { await p.close(); }

	const restarted = await startProxy({ dir, overrideTtlMs: 40, swr: false,
		fetcher: () => { throw new Error("still offline"); } });
	try {
		const r = await get(restarted.url + "/" + URL_NPM);
		assert.equal(r.status, 200);
		assert.equal(r.tag, "stale");
	} finally { await restarted.close(); }
});

test("server: a 500 upstream with NO cached copy is mirrored, never cached", async () => {
	const p = await startProxy();
	try {
		p.up.state.mode = "500";
		const r = await get(p.url + "/" + URL_NPM);
		assert.equal(r.status, 500);
		assert.equal(r.tag, "pass");
		const stats = await get(p.url + "/__stats").then(x => JSON.parse(x.body));
		assert.equal(stats.entries, 0);
	} finally { await p.close(); }
});

test("server: rejects URL-level forwarding", async () => {
	const p = await startProxy();
	try {
		assert.equal((await fetch(p.url + "/" + URL_NPM)).status, 404);
		assert.equal((await fetch(p.url + "/" + URL_PRIVATE)).status, 404);
	} finally { await p.close(); }
});

test("server: bodies over maxBodyBytes stream through uncached", async () => {
	const p = await startProxy({ maxBodyBytes: 512 });
	try {
		p.up.state.body = Buffer.from(JSON.stringify({ data: "x".repeat(1013) })); // valid JSON above the cap
		const r = await get(p.url + "/" + URL_NPM);
		assert.equal(r.status, 200);
		assert.equal(r.body.length, 1024); // streamed to the client in full
		assert.equal(r.tag, "miss");
		const stats = await get(p.url + "/__stats").then(x => JSON.parse(x.body));
		assert.equal(stats.entries, 0); // …but never stored
	} finally { await p.close(); }
});

test("server: oversized concurrent responses share one upstream stream", async () => {
	let calls = 0;
	const p = await startProxy({ maxBodyBytes: 512, fetcher: async () => {
		calls++;
		await new Promise(ok => setTimeout(ok, 40));
		return new Response(JSON.stringify("x".repeat(2046)), { headers: { "content-type": "text/plain" } });
	} });
	try {
		const responses = await Promise.all(Array.from({ length: 20 }, () => get(p.url + "/" + URL_NPM)));
		assert.ok(responses.every(r => r.status === 200 && r.body === JSON.stringify("x".repeat(2046))));
		assert.equal(calls, 1);
		assert.equal(p.server.fadStore.size(), 0, "oversized body is not persisted");
	} finally { await p.close(); }
});

test("server: --token requires Bearer auth on everything but __health", async () => {
	const p = await startProxy({ token: "s3cret" });
	try {
		assert.equal((await get(p.url + "/__health")).status, 200);
		let r = await get(p.url + "/" + URL_NPM);
		assert.equal(r.status, 401);
		r = await callResource(p.url, "npm", "package", { name: "express" }, { "x-fad-proxy-token": "s3cret" });
		assert.equal(r.status, 200);
		r = await callResource(p.url, "npm", "package", { name: "express" }, { "x-fad-proxy-token": "s3cret" });
		assert.equal(r.status, 200);
	} finally { await p.close(); }
});

test("server: persistence — a restarted server serves the store with zero upstream calls", async () => {
	const dir = tmpDir();
	const up = fakeUpstream();
	await up.start();
	const swap = t => t.replace(/^https:\/\/registry\.npmjs\.org/, up.url());
	const s1 = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(dir), fetcher: (t, init) => fetch(swap(t), init) });
	const r1 = await get(s1.url + "/" + URL_NPM);
	await new Promise(ok => s1.server.close(ok));
	// "restart": brand-new server + store over the SAME dir
	const s2 = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(dir), fetcher: (t, init) => fetch(swap(t), init) });
	try {
		const r2 = await get(s2.url + "/" + URL_NPM);
		assert.equal(r2.tag, "hit");
		assert.equal(r2.body, r1.body);
		assert.equal(up.state.hits, 1); // the base survived the restart
	} finally {
		await new Promise(ok => s2.server.close(ok));
		await up.close();
	}
});

test("server: __clear wipes the shared base", async () => {
	const p = await startProxy();
	try {
		await get(p.url + "/" + URL_NPM);
		const r = await fetch(p.url + "/__clear", { method: "POST" });
		const { cleared } = await r.json();
		assert.equal(cleared, 1);
		const stats = await get(p.url + "/__stats").then(x => JSON.parse(x.body));
		assert.equal(stats.entries, 0);
	} finally { await p.close(); }
});

// ------------------------------------------------------------- api keys ----

test("upstreamHeadersFor: injects the right credential per host, client headers forwarded as baseline", () => {
	const keys = { nvd: "NVD-KEY", wordfence: "WF-KEY", github: "GH-TOK" };
	let h = upstreamHeadersFor("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=X", {}, keys);
	assert.equal(h.apiKey, "NVD-KEY");
	h = upstreamHeadersFor("https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production", {}, keys);
	assert.equal(h.authorization, "Bearer WF-KEY");
	h = upstreamHeadersFor("https://api.github.com/repos/TYPO3/typo3/security-advisories?per_page=100", {}, keys);
	assert.equal(h.authorization, "Bearer GH-TOK");
	// no server key → the client's own credential travels (either spelling)
	h = upstreamHeadersFor(URL_NVD, { apikey: "CLIENT-KEY" }, {});
	assert.equal(h.apiKey, "CLIENT-KEY");
	h = upstreamHeadersFor(URL_NVD, { apiKey: "CLIENT-KEY" }, {});
	assert.equal(h.apiKey, "CLIENT-KEY");
	// a server key overrides the client's — one header, not two spellings
	h = upstreamHeadersFor(URL_NVD, { apikey: "CLIENT-KEY" }, keys);
	assert.equal(h.apiKey, "NVD-KEY");
	assert.equal(Object.keys(h).filter(k => k.toLowerCase() === "apikey").length, 1);
	// keys never leak onto unrelated hosts
	h = upstreamHeadersFor(URL_NPM, { authorization: "Bearer private-registry" }, keys);
	assert.equal(h.authorization, "Bearer private-registry"); // forwarded, not overridden
});

test("server: a keyless instance is served by the server's NVD key (shared quota)", async () => {
	const p = await startProxy({ keys: { nvd: "NVD-KEY" }, rewrite: t => t.replace(/^https:\/\/services\.nvd\.nist\.gov/, p.up.url()) });
	try {
		p.up.state.body = Buffer.from(JSON.stringify({ totalResults: 0, vulnerabilities: [] }));
		// the client sends NO apiKey header at all
		const r = await get(p.url + "/" + URL_NVD);
		assert.equal(r.status, 200);
		assert.equal(p.up.state.lastHeaders.apikey, "NVD-KEY"); // the server injected its own
		// second instance, same keyless request → served from the shared entry
		await get(p.url + "/" + URL_NVD);
		assert.equal(p.up.state.hits, 1);
	} finally { await p.close(); }
});

// -------------------------------------------------- --proxy re-exec plumbing ----

test("parseProxyFlag: --proxy and serve-cache --upstream-proxy, never --proxy-cache", () => {
	// exact-token match: --proxy-cache must NOT be read as --proxy
	assert.equal(parseProxyFlag(["node", "vigievuln.js", "-s", ".", "--proxy-cache", "http://127.0.0.1:8321"]), null);
	assert.equal(parseProxyFlag(["node", "vigievuln.js", "-s", ".", "--proxy", "http://corp:3128"]), "http://corp:3128");
	assert.equal(parseProxyFlag(["node", "vigievuln.js", "serve-cache", "--upstream-proxy", "http://corp:3128", "--port", "9000"]), "http://corp:3128");
	assert.equal(parseProxyFlag(["node", "vigievuln.js", "serve-cache", "--proxy", "http://x:1"]), null); // serve-cache uses --upstream-proxy
	// a missing/bad value is ignored, not fatal
	assert.equal(parseProxyFlag(["node", "vigievuln.js", "--proxy"]), null);
	assert.equal(parseProxyFlag(["node", "vigievuln.js", "--proxy", "--verbose"]), null);
});

test("--proxy re-exec: the child runs with the proxy env applied and exit code is preserved", { timeout: 30_000 }, async () => {
	// `vigievuln.js --proxy <url> --version` re-execs itself; the child prints the
	// version and exits 0. A sentinel env var prevents infinite recursion, and the
	// proxy host is exempted from NO_PROXY handling — asserted by __FAD_PROXY_URL.
	const root = path.join(__dirname, "..");
	const res = await new Promise(resolve => {
		const child = spawn(process.execPath, [path.join(root, "vigievuln.js"), "--proxy", "http://127.0.0.1:3128", "--version"], { cwd: root });
		let out = "", err = "";
		child.stdout.on("data", d => out += d);
		child.stderr.on("data", d => err += d);
		child.on("exit", (code, sig) => resolve({ code, sig, out, err }));
	});
	assert.equal(res.code, 0);
	assert.match(res.out, /\d+\.\d+\.\d+/);
	// Node only honours HTTP(S)_PROXY for fetch from 24 -- on older runtimes the
	// CLI prints its documented "continuing anyway" warning. Strip that one line
	// (it is the only sanctioned stderr) and anything left fails the test.
	const expected = `Node ${process.versions.node} ignores HTTP(S)_PROXY for fetch (needs Node >= 24, or bun) — continuing anyway`;
	const rest = res.err.replace(expected, "");
	// The only sanctioned stderr is the CLI's own old-Node warning (its glyph plus
	// that sentence) — anything alphanumeric beyond it fails the test.
	assert.ok(res.err === "" || (res.err.includes(expected) && /^[^A-Za-z0-9]*$/.test(rest)),
		`unexpected stderr: ${JSON.stringify(res.err)}`);
});
