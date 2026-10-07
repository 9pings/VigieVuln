// The verification audit of 2026-10-07 (N1–N14): memory bounds of the SQL store, what the
// public pages and the access log may reveal, the cost of the hottest paths, bounded
// registry projections, deployment and operations defaults. Zero network.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { Readable } = require("node:stream");
const { execFileSync } = require("node:child_process");

let sqlite = true;
try { require("node:sqlite"); } catch { sqlite = false; }
const opts = { skip: !sqlite && "node:sqlite unavailable" };
const { open } = require("./helpers/db");
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-audit-"));
const meta = (bytes, at = 1) => ({ fetchedAt: at, ttlMs: 60000, contentType: "application/json", bytes });

test("N1 sql-store: get() is metadata only; a body is loaded for one generation and never paired with another", opts, async () => {
	const { store } = await open(":memory:");
	await store.put("k", Buffer.from("first"), meta(5, 1));
	const entry = await store.get("k");
	assert.equal(entry.body, undefined, "no body in the lookup");
	assert.equal((await store.readBody(entry)).toString(), "first");
	await store.put("k", Buffer.from("second!"), meta(7, 2));
	await assert.rejects(store.readBody(entry), /replaced/);
	const stream = store.openBody(entry);
	await assert.rejects(new Promise((ok, ko) => { stream.on("error", ko).on("end", ok).resume(); }), /replaced/);
	assert.equal(store.budget.used, 0, "the budget is given back on error");
	const fresh = store.openBody(await store.get("k"));
	const chunks = [];
	for await (const c of fresh) chunks.push(c);
	assert.equal(Buffer.concat(chunks).toString(), "second!");
	assert.equal(store.budget.used, 0, "and at the end of a stream");
});

test("N1 sql-store: concurrent bodies share a byte budget; one larger than it passes alone", async () => {
	const { byteSemaphore } = require("../lib/sql-store");
	const b = byteSemaphore(10);
	const order = [];
	await b.acquire(6); order.push("a");
	const second = b.acquire(6).then(() => order.push("b"));
	await new Promise(ok => setImmediate(ok));
	assert.deepEqual(order, ["a"], "6 + 6 > 10: the second waits");
	b.release(6); await second;
	assert.deepEqual(order, ["a", "b"]);
	b.release(6);
	await b.acquire(50);                     // larger than the budget, nobody else: not starved
	assert.equal(b.used, 50);
	b.release(50);
});

test("N1 sql-store: spool files share a quota — past it a fetch is refused, an aborted spool gives its share back", opts, async () => {
	const { createSqlStore } = require("../lib/sql-store");
	const { openDb } = require("../lib/db");
	const store = await createSqlStore({ driver: openDb(":memory:"), spoolDir: tmp(), maxSpoolBytes: 10 });
	const a = store.createWriter(), b = store.createWriter();
	a.account(8);
	assert.throws(() => b.account(5), /spool quota/);
	a.abort();
	assert.equal(store.spoolBytes(), 0);
	b.account(5);
	b.abort();
});

test("N2 /sources shows a status, never a job's internal error detail", () => {
	const { sourcesPage } = require("../lib/web/render");
	const html = sourcesPage({ t: s => s, jobs: [{ label: "NVD", status: "failed", lastFinished: Date.now(), detail: "ECONNREFUSED 10.0.3.7:5432 /srv/fad/data" }] });
	assert.match(html, /failed/);
	assert.ok(!html.includes("ECONNREFUSED") && !html.includes("/srv/fad"));
});

test("N3 a read error on a streamed file ends that response, not the process", async () => {
	const { streamTo } = require("../lib/server");
	const server = http.createServer((req, res) => {
		res.writeHead(200, { "content-length": 100 });
		const failing = new Readable({ read() { this.push("partial"); this.destroy(new Error("EIO")); } });
		streamTo(failing, res);
	});
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const url = `http://127.0.0.1:${server.address().port}/`;
	try {
		await assert.rejects(fetch(url).then(r => r.text()));
		await assert.rejects(fetch(url).then(r => r.text()), "the server still answers the next one");
	} finally { await new Promise(ok => server.close(ok)); }
});

test("N4 counts(): memoised and single-flight for the hot paths, exact when asked without maxAgeMs", opts, async () => {
	const { assets, driver } = await open(":memory:");
	const cve = key => ({ type: "cve", key, title: key, data: {}, sources: [] });
	await assets.upsert(cve("CVE-2024-0001"));
	let scans = 0;
	const all = driver.all.bind(driver);
	driver.all = (sql, p) => { if (/GROUP BY type/.test(sql)) scans++; return all(sql, p); };
	const [x, y] = await Promise.all([assets.counts({ maxAgeMs: 60000 }), assets.counts({ maxAgeMs: 60000 })]);
	assert.deepEqual(x, { cve: 1 }); assert.equal(x, y);
	assert.equal(scans, 1, "two concurrent scrapes, one GROUP BY");
	await assets.upsert(cve("CVE-2024-0002"));
	assert.deepEqual(await assets.counts({ maxAgeMs: 60000 }), { cve: 1 }, "memoised");
	assert.equal(scans, 1);
	assert.deepEqual(await assets.counts(), { cve: 2 }, "exact without maxAgeMs");
	assert.deepEqual(await assets.counts({ maxAgeMs: 60000 }), { cve: 2 }, "and the memo is refreshed by it");
});

test("N5 static files: a stable precomputed ETag, 304 on a match", opts, async () => {
	const { createServiceServer } = require("../lib/server");
	const s = await open(":memory:");
	const server = createServiceServer({ store: s.store, tokens: s.tokens, assets: s.assets });
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const base = `http://127.0.0.1:${server.address().port}`;
	try {
		const a = await fetch(base + "/static/site.css"), b = await fetch(base + "/static/site.css");
		assert.equal(a.status, 200);
		assert.ok(a.headers.get("etag"));
		assert.equal(a.headers.get("etag"), b.headers.get("etag"));
		assert.equal(await a.text(), await b.text());
		const c = await fetch(base + "/static/site.css", { headers: { "if-none-match": a.headers.get("etag") } });
		assert.equal(c.status, 304);
	} finally { await new Promise(ok => server.close(ok)); }
});

test("N7 the Caddy access log masks detail paths, search text and the Referer", () => {
	const caddy = fs.readFileSync(path.join(__dirname, "..", "deploy", "docker", "Caddyfile"), "utf8");
	assert.match(caddy, /regexp "\^\/\(cve\|api\/cve\|pkg\|advisory\/osv\|advisory\/certfr\)\/\[\^\?\]\*" "\/\$\{1\}\/:id"/);
	assert.match(caddy, /regexp "\(\[\?&\]\)q=\[\^&\]\*" "\$\{1\}q=-"/);
	assert.match(caddy, /request>headers>Referer delete/);
	// The rewrite itself, as Caddy's RE2 applies it to a few real request lines.
	const rewrite = uri => uri.replace(/^\/(cve|api\/cve|pkg|advisory\/osv|advisory\/certfr)\/[^?]*/, "/$1/:id").replace(/([?&])q=[^&]*/g, "$1q=-");
	assert.equal(rewrite("/cve/CVE-2024-31210?lang=fr"), "/cve/:id?lang=fr");
	assert.equal(rewrite("/advisory/osv/GHSA-xxxx-yyyy-zzzz"), "/advisory/osv/:id");
	assert.equal(rewrite("/api/search?type=cve&q=secret+words&limit=5"), "/api/search?type=cve&q=-&limit=5");
});

test("N8 demand: a repeat by the same client, or any request for a published package, costs no SQL", opts, async () => {
	const { assets } = await open(":memory:");
	const { createRegistryLayer, packageAsset } = require("../lib/registry");
	await assets.upsert(packageAsset({ key: "pkg:npm/left-pad", type: "npm", name: "left-pad" }, false));
	let sql = 0;
	const counted = new Proxy(assets, { get: (t, k) => typeof t[k] === "function" && ["get", "isPublished", "demand", "publish"].includes(k)
		? (...a) => { sql++; return t[k](...a); } : t[k] });
	const registry = createRegistryLayer({ assets: counted, threshold: 2, salt: "s" });
	const LP = { provider: "npm", type: "package", params: { name: "left-pad" } };
	const alice = { hash: "a".repeat(64) }, bob = { hash: "b".repeat(64) };
	await registry.recordDemand(LP, alice);
	const first = sql;
	assert.ok(first >= 3);
	await registry.recordDemand(LP, alice);
	assert.equal(sql, first, "the same client again: nothing to write");
	await registry.recordDemand(LP, bob);                  // second distinct client → published
	assert.ok(await assets.isPublished("package", "pkg:npm/left-pad"));
	const after = sql;
	await registry.recordDemand(LP, { hash: "c".repeat(64) });
	assert.equal(sql, after, "a published package needs no demand bookkeeping");
	const memo = registry.memo();
	assert.equal(await registry.recordDemand({ provider: "npm", type: "package", params: { name: "@acme/private" } }, alice), null);
	assert.deepEqual(registry.memo(), memo, "an unknown (private) name is never remembered");
});

test("N9 registry projections bound every string, list and map they keep", () => {
	const { project } = require("../lib/registry/project");
	const huge = "x".repeat(1_000_000);
	const longName = "n".repeat(1000), longVersion = "1.0.0-" + "a".repeat(1000);
	const packument = { name: "evil", "dist-tags": { latest: "1.0.0", [huge]: "2.0.0" }, license: huge, repository: { type: "git", url: huge, deep: { a: { b: { c: { d: huge } } } } },
		homepage: huge, time: { "1.0.0": huge },
		versions: { "1.0.0": { license: { type: huge }, dependencies: { [longName]: "1", ok: huge } }, [longVersion]: { license: "MIT" } } };
	const out = project({ provider: "npm", type: "package", params: { name: "evil" } }, Buffer.from(JSON.stringify(packument)));
	assert.ok(out.body.length < 20000, `projection ${out.body.length} bytes`);
	const body = JSON.parse(out.body);
	assert.deepEqual(Object.keys(body.versions), ["1.0.0"], "a version key longer than any real one is dropped");
	assert.deepEqual(body.versions["1.0.0"].dependencies, { ok: "x".repeat(256) });
	assert.equal(body["dist-tags"].latest, "1.0.0");
	assert.ok(JSON.stringify(out.pkg).length < 5000, "the asset row too");
	assert.equal(out.pkg.license.length, 300);

	const pypi = project({ provider: "pypi", type: "package", params: { name: "evil" } }, Buffer.from(JSON.stringify({
		info: { name: "evil", version: "1.0", license: huge, classifiers: [huge], project_urls: Object.fromEntries(Array.from({ length: 500 }, (_, i) => [`k${i}`, i ? "https://x.example/" : huge])),
			requires_dist: [huge] }, releases: { "1.0": [{ upload_time_iso_8601: huge, yanked_reason: huge }], [longVersion]: [] } })));
	assert.ok(pypi.body.length < 40000, `pypi projection ${pypi.body.length} bytes`);
	assert.deepEqual(Object.keys(JSON.parse(pypi.body).releases), ["1.0"]);
	for (const [provider, j] of [["ruby", { name: "g", version: "1", licenses: [huge], dependencies: { runtime: [{ name: huge, requirements: huge }] } }],
		["nuget", { items: [{ items: [{ catalogEntry: { id: "N", version: "1.0.0", licenseExpression: huge, dependencyGroups: [{ targetFramework: huge, dependencies: [{ id: huge, range: huge }] }] } }] }] }],
		["packagist", { packages: { "a/b": [{ version: "1.0.0", license: [huge], require: { [huge]: huge, "c/d": huge } }] } }]]) {
		const name = provider === "packagist" ? "a/b" : provider === "nuget" ? "N" : "g";
		const r = project({ provider, type: { nuget: "registration", ruby: "gem" }[provider] || "package", params: { name } }, Buffer.from(JSON.stringify(j)));
		assert.ok(r.pkg, provider);
		assert.ok(JSON.stringify(r.pkg).length < 5000, `${provider}: ${JSON.stringify(r.pkg).length}`);
	}
});

test("N11 metrics off loopback without a token: refused at startup", async () => {
	const { startMetricsServer, isLoopback } = require("../lib/metrics");
	for (const h of ["127.0.0.1", "127.9.9.9", "::1", "[::1]", "localhost"]) assert.ok(isLoopback(h), h);
	for (const h of ["0.0.0.0", "::", "10.0.0.5", "fad.example"]) assert.ok(!isLoopback(h), h);
	assert.throws(() => startMetricsServer({ host: "0.0.0.0", port: 0, collect: async () => "" }), /not loopback/);
	const s = await startMetricsServer({ host: "0.0.0.0", port: 0, token: "t", collect: async () => "x 1\n" });
	await new Promise(ok => s.close(ok));
	const compose = fs.readFileSync(path.join(__dirname, "..", "deploy", "docker", "docker-compose.yml"), "utf8");
	assert.match(compose, /FAD_SERVICE_METRICS_TOKEN: \$\{FAD_SERVICE_METRICS_TOKEN:\?/);
	assert.equal((compose.match(/mem_limit:/g) || []).length, 4, "web, worker, caddy, backup");
});

test("N12 backups are created 0600; the seed's admin token never touches the database", opts, async () => {
	const dir = tmp();
	const dbFile = path.join(dir, "svc.db");
	const s = await open(dbFile);
	await s.tokens.add({ role: "client" });
	s.driver.close?.();
	const out = path.join(dir, "backup.db");
	execFileSync(process.execPath, [path.join(__dirname, "..", "bin", "fad-service.js"), "backup", "--db", dbFile, "--out", out], { stdio: "pipe" });
	assert.equal(fs.statSync(out).mode & 0o777, 0o600);
	assert.ok(fs.statSync(out).size > 0);

	const { withEphemeralToken } = require("../lib/tokens");
	const t = await open(":memory:");
	const client = (await t.tokens.add({ role: "client" })).token;
	const before = (await t.tokens.list()).length;
	const temp = withEphemeralToken(t.tokens, { role: "admin", label: "seed" });
	assert.equal((await temp.tokens.verify(temp.token)).role, "admin");
	assert.equal((await temp.tokens.verify(client)).role, "client", "real tokens still work");
	assert.equal(await t.tokens.verify(temp.token), null, "unknown to the database");
	const altered = temp.token.slice(0, -1) + (temp.token.endsWith("A") ? "B" : "A");
	assert.equal(await temp.tokens.verify(altered), null);
	assert.equal((await t.tokens.list()).length, before);
});

test("N14 analytics: pending counters are bounded; a burst past the cap loses only its per-page split", opts, async () => {
	const { createServerAnalytics } = require("../lib/analytics");
	const { driver } = await open(":memory:");
	const a = await createServerAnalytics(driver, { maxPending: 5 });
	try {
		for (let i = 0; i < 200; i++) {
			a.record({ family: "/cve/:id", status: 200, asset: `cve:CVE-2024-${String(i).padStart(4, "0")}` });
			assert.ok(a.pendingSize() <= 5 + 2, `pending ${a.pendingSize()}`);
		}
		const r = await a.report(1);
		const day = Object.values(r.days)[0];
		assert.equal(day.view["/cve/:id"], 200, "every view counted");
		const pages = (await driver.all("SELECT SUM(count) AS n FROM analytics_daily WHERE metric = 'asset'"))[0].n;
		assert.equal(Number(pages), 200, "every page read counted, some under (overflow)");
	} finally { await a.close(); }
});
