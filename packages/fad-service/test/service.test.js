// fad-service: SQLite store, tokens, server (auth, roles, logs, headers) and the CLI with
// --workers. Zero network: upstreams are mock fetchers. Skipped where node:sqlite is
// missing (Node < 22.13 — the service requires it, the CLI does not).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");

let sqlite = true;
try { require("node:sqlite"); } catch { sqlite = false; }
const opts = { skip: !sqlite && "node:sqlite unavailable" };

const BIN = path.join(__dirname, "..", "bin", "fad-service.js");
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-service-"));
const NVD = { provider: "nvd", type: "cve", params: { id: "CVE-2024-31210" } };

function nvdFetcher(counter) {
	return async url => {
		counter.n++;
		assert.match(url, /services\.nvd\.nist\.gov/);
		await new Promise(ok => setTimeout(ok, 15));
		return new Response(JSON.stringify({ id: "CVE-2024-31210" }), { status: 200, headers: { "content-type": "application/json" } });
	};
}

async function startService(extra = {}) {
	const { openDatabase, createSqliteStore } = require("../lib/sqlite-store");
	const { createTokenStore } = require("../lib/tokens");
	const { createServiceServer } = require("../lib/server");
	const db = openDatabase(extra.file || ":memory:");
	const store = createSqliteStore({ db }), tokens = createTokenStore(db);
	const client = tokens.add({ role: "client", label: "ci" }).token;
	const admin = tokens.add({ role: "admin" }).token;
	const lines = [];
	const server = createServiceServer({ store, tokens, region: "fr", version: "9.9.9", log: l => lines.push(l), ...extra });
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const base = `http://127.0.0.1:${server.address().port}`;
	const call = (p, { token, body, method } = {}) => fetch(base + p, {
		method: method || (body ? "POST" : "GET"),
		headers: token ? { authorization: `Bearer ${token}` } : {},
		...(body ? { body: JSON.stringify(body) } : {}),
	});
	return { server, store, tokens, client, admin, lines, call, db,
		close: () => new Promise(ok => server.close(() => { db.close(); ok(); })) };
}

test("tokens: shown once, stored hashed, verifiable, revocable", opts, () => {
	const { openDatabase } = require("../lib/sqlite-store");
	const { createTokenStore } = require("../lib/tokens");
	const db = openDatabase(":memory:");
	const tokens = createTokenStore(db);
	const { id, token } = tokens.add({ role: "admin", label: "ops" });
	assert.match(token, /^fad_[A-Za-z0-9_-]{43}$/);
	const dump = JSON.stringify(db.prepare("SELECT * FROM tokens").all());
	assert.ok(!dump.includes(token.slice(4)), "the plaintext token is never stored");
	assert.equal(tokens.verify(token).role, "admin");
	assert.equal(tokens.verify("fad_wrong"), null);
	assert.equal(tokens.verify(token + "x"), null);
	assert.throws(() => tokens.add({ role: "root" }), /role/);
	assert.ok(tokens.revoke(id));
	assert.equal(tokens.verify(token), null);
	db.close();
});

test("sqlite store: the resource engine works on it — miss, one upstream fetch, hit, survives reopen", opts, async () => {
	const dir = tmp(), file = path.join(dir, "svc.db"), counter = { n: 0 };
	const s = await startService({ file, fetcher: nvdFetcher(counter) });
	try {
		const all = await Promise.all(Array.from({ length: 6 }, () => s.call("/v1/resource", { token: s.client, body: NVD })));
		for (const r of all) { assert.equal(r.status, 200); assert.equal((await r.json()).id, "CVE-2024-31210"); }
		assert.equal(counter.n, 1, "six concurrent misses, one upstream request");
		assert.equal((await s.call("/v1/resource", { token: s.client, body: NVD })).headers.get("x-fad-proxy"), "hit");
	} finally { await s.close(); }
	const again = await startService({ file, fetcher: () => { throw new Error("must not fetch"); } });
	try {
		const r = await again.call("/v1/resource", { token: again.client, body: NVD });
		assert.equal(r.headers.get("x-fad-proxy"), "hit", "the store outlives the process");
	} finally { await again.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("server: /health is public; /v1/resource needs a token; /admin needs the admin role", opts, async () => {
	const s = await startService({ fetcher: nvdFetcher({ n: 0 }) });
	try {
		const health = await s.call("/health");
		assert.equal(health.status, 200);
		assert.deepEqual(Object.fromEntries(Object.entries(await health.json()).filter(([k]) => ["ok", "region", "store", "version"].includes(k))),
			{ ok: true, region: "fr", store: "sqlite", version: "9.9.9" });
		assert.equal((await s.call("/v1/resource", { body: NVD })).status, 401);
		assert.equal((await s.call("/v1/resource", { token: "fad_forged", body: NVD })).status, 401);
		assert.equal((await s.call("/admin/stats", { token: s.client })).status, 403);
		assert.equal((await s.call("/admin/stats", { token: s.admin })).status, 200);
		assert.equal((await s.call("/nope", { token: s.admin })).status, 404);
		// The fad CLI's existing header keeps working.
		const legacy = await fetch(`http://127.0.0.1:${s.server.address().port}/v1/resource`,
			{ method: "POST", headers: { "x-fad-proxy-token": s.client }, body: JSON.stringify(NVD) });
		assert.equal(legacy.status, 200);
	} finally { await s.close(); }
});

test("server: admin purge drops exactly one resource", opts, async () => {
	const counter = { n: 0 };
	const s = await startService({ fetcher: nvdFetcher(counter) });
	try {
		await (await s.call("/v1/resource", { token: s.client, body: NVD })).text();
		assert.equal(s.store.size(), 1);
		assert.equal((await s.call("/admin/purge", { token: s.client, body: NVD })).status, 403);
		assert.deepEqual(await (await s.call("/admin/purge", { token: s.admin, body: NVD })).json(), { purged: true });
		assert.equal(s.store.size(), 0);
		assert.equal((await s.call("/admin/purge", { token: s.admin, body: { provider: "nvd", type: "cve", params: { id: "x" } } })).status, 400);
	} finally { await s.close(); }
});

test("server: logs never carry the requested coordinates; security headers on every answer", opts, async () => {
	const s = await startService({ fetcher: nvdFetcher({ n: 0 }) });
	try {
		const r = await s.call("/v1/resource", { token: s.client, body: NVD });
		await r.text();
		for (const h of ["x-content-type-options", "content-security-policy", "referrer-policy", "strict-transport-security"])
			assert.ok(r.headers.get(h), h);
		await (await s.call("/health")).text();
		await new Promise(ok => setTimeout(ok, 10));
		assert.ok(s.lines.some(l => / POST \/v1\/resource 200 /.test(l)));
		const all = s.lines.join("\n");
		assert.ok(!all.includes("CVE-2024-31210"), "no coordinate in logs");
		assert.ok(!all.includes(s.client) && !all.includes(s.client.slice(4, 20)), "no token in logs");
		assert.match(all, /client=[0-9a-f]{12}/);
	} finally { await s.close(); }
});

test("server: per-token rate limit", opts, async () => {
	const s = await startService({ fetcher: nvdFetcher({ n: 0 }), ratePerMinute: 2 });
	try {
		const codes = [];
		for (let i = 0; i < 3; i++) { const r = await s.call("/admin/stats", { token: s.admin }); await r.text(); codes.push(r.status); }
		assert.deepEqual(codes, [200, 200, 429]);
	} finally { await s.close(); }
});

test("cli: token add/list/revoke, and serve --workers 2 answers /health from several processes", opts, async () => {
	const dir = tmp(), db = path.join(dir, "svc.db");
	try {
		const out = execFileSync(process.execPath, [BIN, "token", "add", "--role", "client", "--label", "ci", "--db", db], { encoding: "utf8" });
		assert.match(out, /token #1 \(client\)/);
		assert.match(execFileSync(process.execPath, [BIN, "token", "list", "--db", db], { encoding: "utf8" }), /#1\tclient\tactive/);
		assert.match(execFileSync(process.execPath, [BIN, "token", "revoke", "1", "--db", db], { encoding: "utf8" }), /revoked/);

		const child = spawn(process.execPath, [BIN, "serve", "--db", db, "--port", "0", "--workers", "2", "--region", "fr"], { stdio: ["ignore", "pipe", "pipe"] });
		try {
			const pids = new Set();
			let port = null, buf = "";
			await new Promise((ok, fail) => {
				const timer = setTimeout(() => fail(new Error(`workers did not start: ${buf}`)), 15000);
				child.stdout.on("data", d => {
					buf += d;
					for (const m of buf.matchAll(/listening on http:\/\/127\.0\.0\.1:(\d+) \(pid (\d+)/g)) { port = m[1]; pids.add(m[2]); }
					if (pids.size >= 2) { clearTimeout(timer); ok(); }
				});
			});
			const r = await fetch(`http://127.0.0.1:${port}/health`);
			assert.equal((await r.json()).region, "fr");
		} finally { child.kill("SIGTERM"); }
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
