// The resource engine (lib/resource-cache/engine.js) runs over ANY store implementing the
// interface documented in lib/resource-cache/fs-store.js — including an asynchronous one,
// which is what a PostgreSQL store will be. This suite drives the engine over an in-memory
// store whose every lookup is async, so single-flight and batch coalescing are proven not
// to depend on the directory store being synchronous. Zero network.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { Readable, Writable } = require("node:stream");
const { createResourceEngine } = require("../lib/resource-cache/engine");
const { configureResourceRoute, providerKey } = require("../lib/providers");

const tick = () => new Promise(ok => setImmediate(ok));

/** A store with the engine interface; every read/write yields to the event loop first. */
function memoryStore() {
	const rows = new Map();
	return {
		rows,
		async get(key) { await tick(); return rows.get(key) || null; },
		acquire() { return () => {}; },
		openBody(entry) { return Readable.from([entry.body]); },
		async readBody(entry) { await tick(); return entry.body; },
		createWriter() {
			const chunks = [];
			let body = null;
			return {
				account() {},
				sink() { return new Writable({ write(c, e, done) { chunks.push(c); done(); } }); },
				bytes() { body = Buffer.concat(chunks); return body.length; },
				async commit(key, meta) { await tick(); rows.set(key, { ...meta, body }); },
				detach(meta) { return { ...meta, body }; },
				abort() {},
			};
		},
		async put(key, buffer, meta) { await tick(); rows.set(key, { ...meta, body: buffer }); },
		purge(key) { return rows.delete(key); },
		size() { return rows.size; },
		clear() { rows.clear(); },
	};
}

async function serve(engine) {
	const server = http.createServer((req, res) => {
		const chunks = [];
		req.on("data", c => chunks.push(c)).on("end", () => {
			engine.handleResource(JSON.parse(Buffer.concat(chunks).toString("utf8")), res).catch(err => {
				if (!res.headersSent) { res.writeHead(502); res.end(String(err.message)); } else res.destroy();
			});
		});
	});
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const url = `http://127.0.0.1:${server.address().port}`;
	const ask = payload => fetch(url, { method: "POST", body: JSON.stringify(payload) });
	return { server, ask, close: () => new Promise(ok => server.close(ok)) };
}

test("engine over an async store: miss → upstream once → hit, concurrent misses share one fetch", async () => {
	configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
	let hits = 0;
	const store = memoryStore();
	const engine = createResourceEngine({ store, fetcher: async url => {
		hits++;
		assert.match(url, /services\.nvd\.nist\.gov/);
		await new Promise(ok => setTimeout(ok, 20));
		return new Response(JSON.stringify({ id: "CVE-2024-31210" }), { status: 200, headers: { "content-type": "application/json" } });
	} });
	const s = await serve(engine);
	try {
		const payload = { provider: "nvd", type: "cve", params: { id: "CVE-2024-31210" } };
		const all = await Promise.all(Array.from({ length: 8 }, () => s.ask(payload)));
		for (const r of all) assert.equal((await r.json()).id, "CVE-2024-31210");
		assert.equal(hits, 1, "eight concurrent misses, one upstream request");
		const again = await s.ask(payload);
		assert.equal(again.headers.get("x-fad-proxy"), "hit");
		assert.equal(hits, 1);
		assert.equal(store.size(), 1);
	} finally { await s.close(); }
});

test("engine over an async store: stale-if-error keeps serving the last good answer", async () => {
	const store = memoryStore();
	const key = providerKey("nvd", "cve", { id: "CVE-2024-31210" }, {});
	const old = Buffer.from(JSON.stringify({ id: "old" }));
	await store.put(key, old, { fetchedAt: 0, ttlMs: 1, contentType: "application/json", bytes: old.length });
	const engine = createResourceEngine({ store, swr: false, fetcher: async () => new Response("", { status: 503 }) });
	const s = await serve(engine);
	try {
		const r = await s.ask({ provider: "nvd", type: "cve", params: { id: "CVE-2024-31210" } });
		assert.equal(r.headers.get("x-fad-proxy"), "stale");
		assert.equal((await r.json()).id, "old");
	} finally { await s.close(); }
});

test("engine over an async store: overlapping EPSS batches fetch each CVE once", async () => {
	const store = memoryStore();
	const asked = [];
	const engine = createResourceEngine({ store, fetcher: async url => {
		const ids = decodeURIComponent(new URL(url).searchParams.get("cve")).split(",");
		asked.push(...ids);
		await new Promise(ok => setTimeout(ok, 20));
		return new Response(JSON.stringify({ data: ids.map(cve => ({ cve, epss: "0.5", percentile: "0.9" })) }), { status: 200 });
	} });
	const s = await serve(engine);
	try {
		const a = s.ask({ provider: "epss", type: "scores", params: { ids: ["CVE-2021-0001", "CVE-2021-0002"] } });
		const b = s.ask({ provider: "epss", type: "scores", params: { ids: ["CVE-2021-0002", "CVE-2021-0003"] } });
		const [ra, rb] = await Promise.all([a, b]);
		assert.deepEqual((await ra.json()).data.map(d => d.cve).sort(), ["CVE-2021-0001", "CVE-2021-0002"]);
		assert.deepEqual((await rb.json()).data.map(d => d.cve).sort(), ["CVE-2021-0002", "CVE-2021-0003"]);
		assert.deepEqual(asked.sort(), ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"], "the shared CVE is fetched once");
		assert.equal(store.size(), 3, "cached per CVE, not per batch");
	} finally { await s.close(); }
});

test("engine: an invalid request is a 400, and a store is mandatory", async () => {
	assert.throws(() => createResourceEngine({}), /needs a store/);
	const engine = createResourceEngine({ store: memoryStore(), fetcher: () => { throw new Error("must not fetch"); } });
	const s = await serve(engine);
	try {
		assert.equal((await s.ask({ provider: "nope", type: "x", params: {} })).status, 400);
		assert.equal((await s.ask({ provider: "nvd", type: "cve", params: { id: "../etc/passwd" } })).status, 400);
	} finally { await s.close(); }
});
