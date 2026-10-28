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
const nvdRecord = (id = 'CVE-2024-31210') => ({ id, published: '2024-01-01T00:00:00.000',
	lastModified: '2024-01-02T00:00:00.000', descriptions: [{ lang: 'en', value: 'Test CVE' }], references: [] });
const nvdEnvelope = (...records) => ({ totalResults: records.length, startIndex: 0,
	resultsPerPage: records.length, vulnerabilities: records.map(cve => ({ cve })) });

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
				read() { return Buffer.concat(chunks); },
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
		return Response.json(nvdEnvelope(nvdRecord()));
	} });
	const s = await serve(engine);
	try {
		const payload = { provider: "nvd", type: "cve", params: { id: "CVE-2024-31210" } };
		const all = await Promise.all(Array.from({ length: 8 }, () => s.ask(payload)));
		for (const r of all) assert.equal((await r.json()).vulnerabilities[0].cve.id, "CVE-2024-31210");
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

const nvdPayload = { provider: 'nvd', type: 'cve', params: { id: 'CVE-2024-31210' } };
const nvdKey = () => providerKey(nvdPayload.provider, nvdPayload.type, nvdPayload.params, {});
async function seedNvd(store) {
	const body = Buffer.from(JSON.stringify(nvdEnvelope(nvdRecord())));
	await store.put(nvdKey(), body, { fetchedAt: 123, ttlMs: 1, contentType: 'application/json', bytes: body.length });
	return store.get(nvdKey());
}

test('engine: invalid JSON HTTP 200 preserves stale bytes and metadata, regardless of Content-Type', async t => {
	for (const [body, type] of [
		['<html>private-upstream-detail</html>', 'text/html'],
		['<html>private-upstream-detail</html>', 'application/json'],
		['{"private-upstream-detail":', 'application/json'],
		['', 'application/json'],
		[Buffer.from([0x22, 0xff, 0x22]), 'application/json'],
	]) await t.test(type + ':' + String(body).slice(0, 12), async () => {
		const store = memoryStore(), old = await seedNvd(store);
		let calls = 0, transforms = 0;
		const engine = createResourceEngine({ store, swr: false,
			transform() { transforms++; return Buffer.from('{}'); },
			fetcher: async () => { calls++; await new Promise(ok => setTimeout(ok, 20)); return new Response(body, { headers: { 'content-type': type } }); },
		});
		const s = await serve(engine);
		try {
			const replies = await Promise.all([s.ask(nvdPayload), s.ask(nvdPayload)]);
			for (const r of replies) {
				assert.equal(r.status, 200);
				assert.equal(r.headers.get('x-fad-proxy'), 'stale');
				assert.equal(r.headers.get('x-fad-proxy-fetched-at'), new Date(old.fetchedAt).toISOString());
				assert.equal(await r.text(), old.body.toString());
			}
			assert.equal(await store.get(nvdKey()), old, 'no new generation or timestamp');
			assert.equal(transforms, 0, 'invalid data must not reach a transform');
			assert.equal(calls, 1, 'one shared failed refresh');
			assert.equal((await s.ask(nvdPayload)).headers.get('x-fad-proxy'), 'stale');
			assert.equal(calls, 1, 'invalid content triggers retry backoff');
		} finally { await s.close(); }
	});
});

test('engine: invalid JSON on a cold miss or strict refresh returns a sanitized 502 and publishes nothing', async () => {
	for (const seeded of [false, true]) {
		const store = memoryStore(), old = seeded ? await seedNvd(store) : null;
		let calls = 0;
		const engine = createResourceEngine({ store, swr: false, allowStale: false, maxBodyBytes: 8,
			fetcher: async () => { calls++; return new Response('<html>private-upstream-detail</html>'); } });
		const s = await serve(engine);
		try {
			const r = await s.ask(nvdPayload);
			assert.equal(r.status, 502);
			assert.equal(r.headers.get('x-fad-proxy'), 'error');
			assert.deepEqual(await r.json(), { error: 'invalid upstream JSON response' });
			assert.equal(await store.get(nvdKey()), old, 'even oversized uncached data must be validated');
			assert.equal((await s.ask(nvdPayload)).status, 502);
			assert.equal(calls, 1);
		} finally { await s.close(); }
	}
});

test('engine: an invalid background refresh never replaces the good stale entry', async () => {
	const store = memoryStore(), old = await seedNvd(store);
	let announce, finish;
	const started = new Promise(ok => { announce = ok; }), ready = new Promise(ok => { finish = ok; });
	const engine = createResourceEngine({ store, fetcher: async () => { announce(); await ready; return new Response('<html>bad</html>'); } });
	const s = await serve(engine);
	try {
		const first = await s.ask(nvdPayload);
		assert.equal(await first.text(), old.body.toString());
		assert.equal(first.headers.get('x-fad-proxy'), 'stale');
		await started; finish();
		while (engine.activeUpstream()) await tick();
		await tick();
		assert.equal(await store.get(nvdKey()), old);
		const second = await s.ask(nvdPayload);
		assert.equal(await second.text(), old.body.toString());
		assert.equal(engine.stats.upstream, 1);
	} finally { finish(); await s.close(); }
});

test('engine: JSON validation cleans disk spools and also validates transformed output', async t => {
	const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
	const { createCacheStore } = require('../lib/resource-cache/fs-store');
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-engine-format-'));
	t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
	const store = createCacheStore(dir), old = await seedNvd(store);
	const files = fs.readdirSync(store.entriesDir).sort();
	for (const transformed of [false, true]) {
		const engine = createResourceEngine({ store, swr: false,
			fetcher: async () => new Response(transformed ? JSON.stringify(nvdEnvelope(nvdRecord())) : '<html>bad</html>'),
			transform: transformed ? () => Buffer.from('<html>bad projection</html>') : null });
		const s = await serve(engine);
		try {
			const r = await s.ask(nvdPayload);
			assert.equal(r.headers.get('x-fad-proxy'), 'stale');
			assert.equal(await r.text(), fs.readFileSync(old.bodyPath, 'utf8'));
			assert.deepEqual(await store.get(nvdKey()), old);
			assert.deepEqual(fs.readdirSync(store.entriesDir).sort(), files);
		} finally { await s.close(); }
	}
});

test('engine: valid raw JSON is accepted; XML, CSV and archives retain their non-JSON formats', async () => {
	const samples = [
		[nvdPayload, Buffer.from('{"totalResults":0,"vulnerabilities":[]}'), 'text/plain'],
		[{ provider: 'github', type: 'publisher-advisories', params: { repo: 'owner/repo' } }, Buffer.from('[]'), 'application/vnd.github+json'],
		[{ provider: 'maven', type: 'artifact', params: { path: 'org/x/a/1/a-1.pom' } }, Buffer.from('<project/>'), 'application/xml'],
		[{ provider: 'euvd', type: 'cve-mapping', params: {} }, Buffer.from('cve,euvd\nCVE-2024-31210,EUVD-1\n'), 'text/csv'],
		[{ provider: 'epss', type: 'current-csv', params: {} }, require('node:zlib').gzipSync('cve,epss\nCVE-2024-31210,0.5\n'), 'application/gzip'],
		[{ provider: 'github', type: 'cve-archive', params: { tag: 'v1', name: 'cves.zip' } }, Buffer.from('PK\x05\x06' + '\0'.repeat(18)), 'application/zip'],
		[{ provider: 'osvdb', type: 'ecosystem-archive', params: { ecosystem: 'npm' } }, Buffer.from('PK\x05\x06' + '\0'.repeat(18)), 'application/zip'],
	];
	for (const [payload, body, contentType] of samples) {
		const store = memoryStore();
		let calls = 0;
		const engine = createResourceEngine({ store, fetcher: async () => { calls++; return new Response(body, { headers: { 'content-type': contentType } }); } });
		const s = await serve(engine);
		try {
			for (const tag of ['miss', 'hit']) {
				const r = await s.ask(payload);
				assert.equal(r.status, 200);
				assert.equal(r.headers.get('x-fad-proxy'), tag);
				assert.deepEqual(Buffer.from(await r.arrayBuffer()), body);
			}
			assert.equal(calls, 1);
		} finally { await s.close(); }
	}
});

test('engine: invalid NVD schemas cannot replace a good API, mirror or SPIP entry', async () => {
	const record = nvdRecord();
	const malformedRecords = [
		{}, { id: record.id }, { ...record, id: 'not-a-cve' }, { ...record, published: 'yesterday' },
		{ ...record, lastModified: null }, { ...record, descriptions: {} }, { ...record, descriptions: [] },
		{ ...record, descriptions: [{ lang: 'en', value: 42 }] }, { ...record, references: [null] },
		{ ...record, references: [{ url: 'https://example.test', tags: 'Patch' }] },
		{ ...record, weaknesses: [{ description: 'CWE-79' }] }, { ...record, metrics: [] },
		{ ...record, metrics: { cvssMetricV31: [{}] } },
		{ ...record, metrics: { cvssMetricV31: [{ cvssData: { baseScore: 20, vectorString: 'bad' } }] } },
		{ ...record, configurations: [{ nodes: null }] },
		{ ...record, configurations: [{ nodes: [{ cpeMatch: [{}] }] }] },
	];
	for (const type of ['cve', 'cve-mirror', 'spip-advisories']) {
		const payload = { ...nvdPayload, type };
		const goodRecord = { ...record, configurations: [] };
		const good = type === 'cve-mirror' ? goodRecord : nvdEnvelope(goodRecord);
		const invalid = [{}, null, [], true, { message: 'private-upstream-detail' }, { error: 'private-upstream-detail' },
			{ vulnerabilities: null }, { vulnerabilities: [{}] }, { vulnerabilities: [] },
			{ totalResults: 1, vulnerabilities: [] }, { ...nvdEnvelope(goodRecord), totalResults: 2 },
			{ ...nvdEnvelope(goodRecord), totalResults: '1' }, { ...nvdEnvelope(goodRecord), resultsPerPage: 0 },
			{ ...nvdEnvelope(goodRecord), startIndex: 1 }, nvdEnvelope(goodRecord, goodRecord),
			...malformedRecords.map(cve => type === 'cve-mirror' ? cve : nvdEnvelope(cve))];
		if (type !== 'spip-advisories') invalid.push(nvdEnvelope({ ...record, id: 'CVE-2024-99999' }));
		if (type === 'cve') invalid.push(goodRecord); // raw records belong to the mirror only
		if (type === 'cve-mirror') invalid.push(nvdEnvelope(), { ...goodRecord, id: 'CVE-2024-99999' });
		if (type === 'spip-advisories') invalid.push(nvdEnvelope(record)); // missing CPE configurations
		for (const bad of invalid) {
			const store = memoryStore(), key = providerKey('nvd', type, payload.params);
			const bytes = Buffer.from(JSON.stringify(good));
			await store.put(key, bytes, { fetchedAt: 123, ttlMs: 1, bytes: bytes.length, contentType: 'application/json' });
			const previous = await store.get(key);
			let transformed = false;
			const engine = createResourceEngine({ store, swr: false, fetcher: async () => Response.json(bad),
				transform() { transformed = true; return Buffer.from(JSON.stringify(good)); } });
			const s = await serve(engine);
			try {
				const response = await s.ask(payload);
				assert.equal(response.status, 200);
				assert.equal(response.headers.get('x-fad-proxy'), 'stale', `${type}: ${JSON.stringify(bad)}`);
				assert.equal(response.headers.get('x-fad-proxy-fetched-at'), new Date(123).toISOString());
				assert.deepEqual(await response.json(), good);
				assert.equal(await store.get(key), previous);
				assert.equal(transformed, false, 'reject before transformation');
			} finally { await s.close(); }
		}
	}
});

test('engine: NVD schemas preserve supported API/mirror shapes, empty results and optional enrichment', async () => {
	const record = nvdRecord();
	const enriched = { ...record, newField: { allowed: true }, vulnStatus: 'Awaiting Analysis',
		metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5, vectorString: 'CVSS:3.1/AV:N', baseSeverity: 'HIGH' } }], futureMetric: {} },
		weaknesses: [{ description: [{ lang: 'en', value: 'CWE-79' }] }],
		configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:spip:spip:*', versionEndExcluding: '4.0' }] }] }] };
	const cases = [
		['cve', nvdEnvelope(record)], ['cve', nvdEnvelope(enriched)], ['cve', nvdEnvelope()],
		['cve', nvdEnvelope({ ...record, vulnStatus: 'Rejected' })],
		['cve-mirror', record], ['cve-mirror', nvdEnvelope(record)],
		['spip-advisories', nvdEnvelope(enriched, { ...record, id: 'CVE-2024-99999', configurations: [] })],
		['spip-advisories', nvdEnvelope()],
	];
	for (const [type, body] of cases) {
		const payload = { ...nvdPayload, type, params: { id: nvdPayload.params.id.toLowerCase() } };
		const store = memoryStore();
		let calls = 0;
		const engine = createResourceEngine({ store, fetcher: async () => { calls++; return Response.json(body); } });
		const s = await serve(engine);
		try {
			for (const tag of ['miss', 'hit']) {
				const response = await s.ask(payload);
				assert.equal(response.status, 200, type);
				assert.equal(response.headers.get('x-fad-proxy'), tag);
				assert.deepEqual(await response.json(), body);
			}
			assert.equal(calls, 1);
		} finally { await s.close(); }
	}
});

test('engine: bad NVD schema returns a safe 502 without stale permission and is checked after transforms', async () => {
	for (const mode of ['cold', 'strict', 'transformed']) {
		const store = memoryStore(), previous = mode === 'cold' ? null : await seedNvd(store);
		let calls = 0, transforms = 0;
		const engine = createResourceEngine({ store, swr: false, allowStale: mode === 'transformed',
			fetcher: async () => { calls++; return Response.json(mode === 'transformed' ? nvdEnvelope(nvdRecord()) : {}); },
			transform() { transforms++; return Buffer.from('{}'); } });
		const s = await serve(engine);
		try {
			for (let i = 0; i < 2; i++) {
				const response = await s.ask(nvdPayload);
				if (mode === 'transformed') {
					assert.equal(response.headers.get('x-fad-proxy'), 'stale');
					assert.equal(await response.text(), previous.body.toString());
				} else {
					assert.equal(response.status, 502);
					assert.deepEqual(await response.json(), { error: i ? 'upstream unavailable and no cached response' : 'invalid upstream NVD response' });
				}
			}
			assert.equal(calls, 1);
			assert.equal(transforms, mode === 'transformed' ? 1 : 0);
			assert.equal(await store.get(nvdKey()), previous);
		} finally { await s.close(); }
	}
});

test('engine: schema errors preserve stale on a background refresh and coalesced readers', async () => {
	for (const swr of [true, false]) {
		const store = memoryStore(), previous = await seedNvd(store);
		let calls = 0;
		const engine = createResourceEngine({ store, swr, fetcher: async () => {
			calls++; await new Promise(ok => setTimeout(ok, 20)); return Response.json({});
		} });
		const s = await serve(engine);
		try {
			const responses = await Promise.all([s.ask(nvdPayload), s.ask(nvdPayload)]);
			for (const response of responses) {
				assert.equal(response.headers.get('x-fad-proxy'), 'stale');
				assert.equal(await response.text(), previous.body.toString());
			}
			while (engine.activeUpstream()) await tick();
			await tick();
			assert.equal(await store.get(nvdKey()), previous);
			assert.equal(calls, 1);
		} finally { await s.close(); }
	}
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

test("engine: a 404 is remembered (in memory, hashed) — not asked again until it expires", async () => {
	let calls = 0;
	const store = memoryStore();
	const engine = createResourceEngine({ store, negativeTtlMs: 200, fetcher: async () => { calls++; return new Response('{"error":"Not found"}', { status: 404 }); } });
	const s = await serve(engine);
	try {
		const ask = () => s.ask({ provider: "npm", type: "package", params: { name: "@acme/private-thing" } });
		const first = await ask();
		assert.equal(first.status, 404);
		const again = await ask();
		assert.equal(again.status, 404);
		assert.equal(again.headers.get("x-fad-proxy"), "negative");
		assert.equal(calls, 1, "asked upstream once");
		assert.equal(store.size(), 0, "nothing written to the store");
		assert.equal(engine.negativeEntries(), 1);
		await new Promise(ok => setTimeout(ok, 250));
		await (await ask()).text();
		assert.equal(calls, 2, "asked again once the 6 h (here 200 ms) are over");
	} finally { await s.close(); }
});

test("engine: transforms run at most transformConcurrency at a time; the projection is served from its buffer", async () => {
	configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
	const store = memoryStore();
	let gets = 0;
	const get = store.get;
	store.get = key => { gets++; return get(key); };
	let running = 0, peak = 0, reads = 0;
	const engine = createResourceEngine({ store, transformConcurrency: 2,
		fetcher: async url => new Response(JSON.stringify({ name: url.split("/").pop(), big: "x".repeat(1000) }), { headers: { "content-type": "application/json" } }),
		transform: async (resource, buffer) => {
			reads++;
			running++; peak = Math.max(peak, running);
			await new Promise(ok => setTimeout(ok, 30));
			running--;
			return Buffer.from(JSON.stringify({ name: JSON.parse(buffer).name, projected: true }));
		} });
	const s = await serve(engine);
	try {
		const names = Array.from({ length: 8 }, (_, i) => `pkg-${i}`);
		const bodies = await Promise.all(names.map(name => s.ask({ provider: "npm", type: "package", params: { name } }).then(r => r.json())));
		assert.deepEqual(bodies.map(b => b.name), names);
		assert.ok(bodies.every(b => b.projected === true));
		assert.equal(reads, 8);
		assert.equal(peak, 2, "never more than two whole answers parsed at once");
		// Two lookups per miss (the request's, the single-flight's stale check) — and no third:
		// the projection is served from its buffer, not read back from the store.
		assert.equal(gets, 16);
	} finally { await s.close(); }
});
