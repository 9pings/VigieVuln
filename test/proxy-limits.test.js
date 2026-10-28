const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createCacheStore, startProxyCacheServer } = require("../lib/proxy-cache");
const { providerKey } = require("../lib/providers");
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-proxy-limits-"));
async function harness(opts = {}) {
	const dir = temp(), store = createCacheStore(dir);
	const running = await startProxyCacheServer({ port: 0, store, ...opts });
	return { ...running, dir, store, close: async () => {
		running.server.closeAllConnections();
		await new Promise(ok => running.server.close(ok)); fs.rmSync(dir, { recursive: true, force: true });
	} };
}
const call = (h, name, signal) => fetch(h.url + "/v1/resource", { method: "POST", signal,
	headers: { "content-type": "application/json" }, body: JSON.stringify({ provider: "npm", type: "package", params: { name } }) });
const key = name => providerKey("npm", "package", { name });
const stalled = (url, { signal }) => new Promise((resolve, reject) => {
	signal.addEventListener("abort", () => reject(signal.reason), { once: true });
});

test("proxy deadline cancels cold and stalled-body fetches and releases upstream slots", async () => {
	let mode = "headers";
	const h = await harness({ upstreamTimeoutMs: 50, maxConcurrent: 1, fetcher: (url, init) => mode === "headers"
		? stalled(url, init) : mode === "body" ? Promise.resolve(new Response(new ReadableStream({ pull() {} }))) : Promise.resolve(Response.json("ok")) });
	try {
		for (mode of ["headers", "body"]) {
			const response = await call(h, mode);
			assert.equal(response.status, 502); await response.text();
			assert.equal(h.store.bodyBytes(), 0);
		}
		mode = "ok";
		assert.equal(await (await call(h, "healthy")).json(), "ok");
		assert.equal(fs.readdirSync(h.store.entriesDir).some(f => f.startsWith(".tmp-")), false);
	} finally { await h.close(); }
});

test("deadline on a stale refresh retains the previous body", async () => {
	let slow = false;
	const h = await harness({ upstreamTimeoutMs: 50, overrideTtlMs: 1, swr: false,
		fetcher: (url, init) => slow ? stalled(url, init) : Promise.resolve(Response.json("old")) });
	try {
		await (await call(h, "a")).text(); slow = true;
		await new Promise(ok => setTimeout(ok, 5));
		const response = await call(h, "a");
		assert.equal(response.headers.get("x-fad-proxy"), "stale");
		assert.equal(await response.json(), "old");
		assert.equal(JSON.parse(fs.readFileSync(h.store.get(key("a")).bodyPath, "utf8")), "old");
	} finally { await h.close(); }
});

test("batch stale fallback identifies the old data and its date", async () => {
	let broken = false;
	const h = await harness({ overrideTtlMs: 1, swr: false, fetcher: async () => broken
		? new Response('unavailable', {status:503}) : Response.json({results:[{vulns:[]}]}) });
	const request = () => fetch(h.url + '/v1/resource', {method:'POST',headers:{'content-type':'application/json'},
		body:JSON.stringify({provider:'osv',type:'packages',params:{queries:[{ecosystem:'npm',name:'example',version:'1'}]}})});
	try {
		assert.equal((await request()).status,200); broken=true;
		await new Promise(ok=>setTimeout(ok,5));
		const result=await request();
		assert.equal(result.status,200); assert.equal(result.headers.get('x-fad-proxy'),'stale');
		assert.ok(Number.isFinite(Date.parse(result.headers.get('x-fad-proxy-fetched-at'))));
		assert.deepEqual(await result.json(),{results:[{vulns:[]}]});
	} finally {await h.close()}
});

test("concurrent readers both see stale when the shared refresh fails", async () => {
	let broken=false;
	const h=await harness({overrideTtlMs:1,swr:false,fetcher:async()=>{
		if (broken) { await new Promise(ok=>setTimeout(ok,25)); return new Response('',{status:503}); }
		return Response.json('previous');
	}});
	try {
		await (await call(h,'shared')).text(); broken=true;
		await new Promise(ok=>setTimeout(ok,5));
		const responses=await Promise.all([call(h,'shared'),call(h,'shared')]);
		for(const r of responses) {assert.equal(r.headers.get('x-fad-proxy'),'stale'); assert.equal(await r.json(),'previous');}
	} finally {await h.close()}
});

test("chunked transfers exceeding the hard cap leave no temporary or cache entry", async () => {
	const h = await harness({ maxTransferBytes: 8, fetcher: async () => new Response(new ReadableStream({
		start(c) { c.enqueue(Buffer.from("123456")); c.enqueue(Buffer.from("789")); c.close(); },
	})) });
	try {
		const response = await call(h, "large");
		assert.equal(response.status, 502); assert.match(await response.text(), /transfer limit/);
		assert.equal(h.store.bodyBytes(), 0); assert.equal(h.store.size(), 0);
		assert.deepEqual(fs.readdirSync(h.store.entriesDir), []);
	} finally { await h.close(); }
});

test("quota evicts old unpinned entries and refuses to evict active readers", async () => {
	const h = await harness({ maxStoreBytes: 1024, maxEntries: 1, fetcher: async () => new Response("123456") });
	try {
		await (await call(h, "a")).text();
		const release = h.store.acquire(h.store.get(key("a")));
		const blocked = await call(h, "b");
		assert.equal(blocked.status, 502); assert.match(await blocked.text(), /quota/);
		assert.ok(h.store.get(key("a"))); assert.equal(h.store.bodyBytes(), 6);
		release();
		assert.equal(await (await call(h, "c")).text(), "123456");
		assert.equal(h.store.get(key("a")), null); assert.equal(h.store.size(), 1);
		assert.equal(h.store.bodyBytes(), 6);
	} finally { await h.close(); }
});

test("server startup removes orphaned spools and generations, with exclusive store ownership", async () => {
	const dir = temp(), store = createCacheStore(dir);
	fs.writeFileSync(path.join(store.entriesDir, ".tmp-crash"), "orphan");
	fs.writeFileSync(path.join(store.entriesDir, "a".repeat(64) + ".body-abc"), "orphan");
	const h = await startProxyCacheServer({ port: 0, store });
	try {
		assert.deepEqual(fs.readdirSync(store.entriesDir), []);
		assert.throws(() => startProxyCacheServer({ port: 0, store: createCacheStore(dir) }), /already owned/);
	} finally { await new Promise(ok => h.server.close(ok)); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("batch responses obey deadlines and size limits", async () => {
	let slow = true;
	const h = await harness({ upstreamTimeoutMs: 50, maxTransferBytes: 64,
		fetcher: (url, init) => slow ? stalled(url, init) : Promise.resolve(new Response(" ".repeat(65))) });
	const batch = name => fetch(h.url + "/v1/resource", { method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ provider: "osv", type: "packages", params: { queries: [{ package: { ecosystem: "npm", name }, version: "1" }] } }) });
	try {
		assert.equal((await batch("slow")).status, 502); slow = false;
		const response = await batch("huge"); assert.equal(response.status, 502);
		assert.match(await response.text(), /transfer limit/); assert.equal(h.store.size(), 0);
	} finally { await h.close(); }
});

test("disk publication failure retains the old body and removes the staged file", async () => {
	let body = "old";
	const h = await harness({ overrideTtlMs: 1, swr: false, fetcher: async () => Response.json(body) });
	try {
		await (await call(h, "a")).text(); body = "new";
		await new Promise(ok => setTimeout(ok, 5));
		const commit = h.store.commit;
		h.store.commit = () => { throw Object.assign(new Error("disk full"), { code: "ENOSPC" }); };
		try { assert.equal(await (await call(h, "a")).json(), "old"); }
		finally { h.store.commit = commit; }
		assert.equal(h.store.bodyBytes(), 5);
		assert.equal(fs.readdirSync(h.store.entriesDir).some(f => f.startsWith(".tmp-")), false);
	} finally { await h.close(); }
});

test("a slow disk applies backpressure to upstream production", async () => {
	let produced = 0, written = 0, ahead = 0;
	const h = await harness({ fetcher: async () => new Response(new ReadableStream({ pull(controller) {
		if (produced === 32) { controller.close(); return; }
		produced++; ahead = Math.max(ahead, produced - written);
		const chunk = Buffer.alloc(65536, 32); // one large JSON object, same chunk sizes/backpressure
		if (produced === 1) chunk[0] = 123;
		if (produced === 32) chunk[chunk.length - 1] = 125;
		controller.enqueue(chunk);
	} })) });
	const create = fs.createWriteStream;
	fs.createWriteStream = (...args) => {
		const stream = create(...args), write = stream._write;
		stream._write = function(chunk, encoding, callback) {
			setTimeout(() => write.call(this, chunk, encoding, error => { written++; callback(error); }), 2);
		};
		return stream;
	};
	try {
		const response = await call(h, "slow-disk");
		assert.equal((await response.arrayBuffer()).byteLength, 32 * 65536);
		assert.ok(ahead < 10, `upstream queued ${ahead} chunks while disk was slow`);
	} finally { fs.createWriteStream = create; await h.close(); }
});

test("a disconnected initiator does not cancel another reader's shared fetch", async () => {
	let announce;
	const started = new Promise(ok => { announce = ok; });
	let finish;
	const ready = new Promise(ok => { finish = ok; });
	const h = await harness({ fetcher: async () => { announce(); await ready; return Response.json("shared"); } });
	try {
		const controller = new AbortController();
		const first = call(h, "same", controller.signal).catch(() => null);
		await started;
		const second = call(h, "same"); controller.abort(); finish();
		await first; assert.equal(await (await second).json(), "shared");
		assert.equal(h.server.fadStats.upstream, 1);
	} finally { finish(); await h.close(); }
});

test("concurrent distinct upstream fetches are capped without blocking a cached reader", async () => {
	let begin, finish;
	const started = new Promise(ok => { begin = ok; }), ready = new Promise(ok => { finish = ok; });
	const h = await harness({ maxConcurrent: 1, fetcher: async url => {
		if (url.endsWith("/slow")) { begin(); await ready; }
		return Response.json("ok");
	} });
	try {
		await (await call(h, "cached")).text();
		const slow = call(h, "slow"); await started;
		const overloaded = await call(h, "other"); assert.equal(overloaded.status, 502);
		assert.match(await overloaded.text(), /concurrency limit/);
		assert.equal(await (await call(h, "cached")).json(), "ok");
		finish(); assert.equal(await (await slow).json(), "ok");
	} finally { finish(); await h.close(); }
});

test('strict freshness refuses an expired response when its source fails', async () => {
 let fail=false;
 const h=await harness({overrideTtlMs:40,allowStale:false,swr:false,fetcher:async()=>{
  if(fail)throw Error('source unavailable');
  return new Response(JSON.stringify({name:'freshness-test'}),{status:200,headers:{'content-type':'application/json'}});
 }});
 try {
  assert.equal((await call(h,'freshness-test')).status,200);
  await new Promise(r=>setTimeout(r,60)); fail=true;
  const r=await call(h,'freshness-test');assert.equal(r.status,502);assert.notEqual(r.headers.get('x-fad-proxy'),'stale');
 } finally {await h.close()}
});
