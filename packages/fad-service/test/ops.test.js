// fad-service operations: configuration, log rotation, metrics, analytics, branding,
// graceful drain, reverse-proxy client address, backup, maintenance. Zero network.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

let sqlite = true;
try { require("node:sqlite"); } catch { sqlite = false; }
const opts = { skip: !sqlite && "node:sqlite unavailable" };
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-ops-"));
const BIN = path.join(__dirname, "..", "bin", "fad-service.js");

test("config: file ← flags, relative paths from the file, secrets refused, bad values refused", () => {
	const { loadConfig } = require("../lib/config");
	const dir = tmp();
	try {
		const file = path.join(dir, "svc.json");
		fs.writeFileSync(file, JSON.stringify({ db: "data/svc.db", region: "fr", log: { file: "logs/svc.log", format: "json", maxSize: "1M" },
			brand: { name: "Vulns FR", accent: "#123456", baseUrl: "https://vuln.example.fr" } }));
		const cfg = loadConfig({ config: file, region: "eu", port: "9000" }, {});
		assert.equal(cfg.db, path.join(dir, "data", "svc.db"));
		assert.equal(cfg.log.file, path.join(dir, "logs", "svc.log"));
		assert.equal(cfg.log.maxBytes, 1024 * 1024);
		assert.equal(cfg.region, "eu", "a flag wins over the file");
		assert.equal(cfg.listen.port, 9000);
		assert.equal(cfg.listen.host, "127.0.0.1", "defaults kept");
		assert.equal(cfg.brand.name, "Vulns FR");
		fs.writeFileSync(file, JSON.stringify({ keys: { nvd: "secret" } }));
		assert.throws(() => loadConfig({ config: file }, {}), /must not be in the config file/);
		fs.writeFileSync(file, JSON.stringify({ analytics: { provider: "plausible", scriptSrc: "http://x" } }));
		assert.throws(() => loadConfig({ config: file }, {}), /https URL/);
		fs.writeFileSync(file, JSON.stringify({ brand: { accent: "red; } body { display:none" } }));
		assert.throws(() => loadConfig({ config: file }, {}), /CSS colour/);
		assert.equal(loadConfig({}, { FAD_SERVICE_METRICS_TOKEN: "m" }).metrics.token, "m");
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("logger: size-based rotation keeps N files, reopen after an external rotation, JSON lines", () => {
	const { createLogger } = require("../lib/logger");
	const dir = tmp(), file = path.join(dir, "svc.log");
	try {
		const log = createLogger({ file, format: "json", maxBytes: 400, keep: 2 });
		for (let i = 0; i < 40; i++) log.info("http", { route: "/cve", status: 200, i });
		const files = fs.readdirSync(dir).sort();
		assert.deepEqual(files, ["svc.log", "svc.log.1", "svc.log.2"], "current + 2 rotated, the oldest dropped");
		for (const f of files) for (const line of fs.readFileSync(path.join(dir, f), "utf8").trim().split("\n")) {
			const j = JSON.parse(line);
			assert.equal(j.msg, "http");
			assert.ok(fs.statSync(path.join(dir, f)).size <= 400 + 100);
		}
		fs.renameSync(file, file + ".ext");
		log.reopen();
		log.warn("after reopen");
		assert.match(fs.readFileSync(file, "utf8"), /after reopen/);
		log.close();
		const text = createLogger({ file: path.join(dir, "t.log"), format: "text" });
		text.info("listening", { url: "http://h:1", note: "a b" });
		assert.match(fs.readFileSync(path.join(dir, "t.log"), "utf8"), /INFO  listening url=http:\/\/h:1 note="a b"/);
		text.close();
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("metrics: counters aggregate across processes; Prometheus text; token on its own listener", async () => {
	const { createCounters, createAggregate, render, startMetricsServer } = require("../lib/metrics");
	const a = createCounters(), b = createCounters(), agg = createAggregate();
	a.observe({ route: "/cve", status: 200, ms: 10 }); a.observe({ route: "/cve", status: 200, ms: 30 });
	b.observe({ route: "/cve", status: 200, ms: 5 }); b.observe({ route: "/v1/resource", status: 401, ms: 1 });
	agg.add(a.drain({ hits: 3, misses: 1 })); agg.add(b.drain({ hits: 2 }));
	agg.add(a.drain({ hits: 4, misses: 1 }));            // deltas, not totals
	const text = render(agg, { jobs: [{ job: "kev", status: "ok", lastFinished: 2000 }, { job: "nvd", status: "error" }], assets: { cve: 7 } });
	assert.match(text, /fad_http_requests_total\{route="\/cve",status="200"\} 3/);
	assert.match(text, /fad_http_requests_total\{route="\/v1\/resource",status="401"\} 1/);
	assert.match(text, /fad_resource_cache_total\{result="hits"\} 6/);
	assert.match(text, /fad_job_last_success_timestamp_seconds\{job="kev"\} 2/);
	assert.match(text, /fad_job_last_failed\{job="nvd"\} 1/);
	assert.match(text, /fad_assets\{type="cve"\} 7/);
	const server = await startMetricsServer({ port: 0, token: "m", collect: () => text });
	try {
		const url = `http://127.0.0.1:${server.address().port}/metrics`;
		assert.equal((await fetch(url)).status, 401);
		const ok = await fetch(url, { headers: { authorization: "Bearer m" } });
		assert.equal(ok.status, 200);
		assert.match(ok.headers.get("content-type"), /text\/plain; version=0\.0\.4/);
	} finally { await new Promise(ok => server.close(ok)); }
});

async function site(extra = {}) {
	const { openDatabase, createSqliteStore } = require("../lib/sqlite-store");
	const { createTokenStore } = require("../lib/tokens");
	const { createAssetStore } = require("../lib/assets");
	const { createServiceServer } = require("../lib/server");
	const { createServerAnalytics } = require("../lib/analytics");
	const db = openDatabase(":memory:");
	const assets = createAssetStore(db);
	assets.upsert({ type: "cve", key: "CVE-2021-44228", title: "Log4Shell", summary: "log4j", data: { id: "CVE-2021-44228", description: "x" },
		sources: [{ name: "CVE List", licence: "ToU", url: "https://www.cve.org/" }] });
	const serverAnalytics = extra.analytics?.provider === "plausible" ? null : createServerAnalytics(db);
	const server = createServiceServer({ store: createSqliteStore({ db }), tokens: createTokenStore(db), assets, serverAnalytics, ...extra });
	const admin = server.fadStore && createTokenStore(db).add({ role: "admin" }).token;
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const base = `http://127.0.0.1:${server.address().port}`;
	return { server, db, serverAnalytics, admin, get: (p, h = {}) => fetch(base + p, { headers: h }), close: () => new Promise(ok => server.close(ok)) };
}

test("analytics (server): daily aggregates only — no IP, no search text, readable by an admin", opts, async () => {
	const s = await site();
	try {
		await (await s.get("/cve/CVE-2021-44228")).text();
		await (await s.get("/cve/CVE-2021-44228")).text();
		await (await s.get("/search?q=secret%20internal%20project")).text();
		await (await s.get("/health")).text();
		s.serverAnalytics.flush();
		const rows = s.db.prepare("SELECT * FROM analytics_daily").all();
		const dump = JSON.stringify(rows);
		assert.ok(!dump.includes("secret") && !dump.includes("127.0.0.1"), "no query text, no address");
		const report = await (await s.get("/admin/analytics", { authorization: `Bearer ${s.admin}` })).json();
		const day = Object.values(report.days)[0];
		assert.equal(day.view["/cve"], 2);
		assert.equal(day.search, 1);
		assert.deepEqual(report.topAssets[0], ["cve:CVE-2021-44228", 2]);
		assert.equal(day.view["/health"], undefined, "probes are not audience");
	} finally { await s.close(); }
});

test("analytics (plausible): one script tag, CSP opened to that origin only", opts, async () => {
	const s = await site({ analytics: { provider: "plausible", scriptSrc: "https://stats.example.eu/js/script.js", domain: "vuln.example.fr" } });
	try {
		const r = await s.get("/");
		const html = await r.text();
		assert.match(html, /<script defer data-domain="vuln\.example\.fr" src="https:\/\/stats\.example\.eu\/js\/script\.js"><\/script>/);
		assert.match(r.headers.get("content-security-policy"), /script-src https:\/\/stats\.example\.eu; .*connect-src https:\/\/stats\.example\.eu/);
	} finally { await s.close(); }
	const { clientAnalytics } = require("../lib/analytics");
	const m = clientAnalytics({ provider: "matomo", scriptSrc: "https://matomo.example.eu/", siteId: 3 });
	assert.match(m.initScript, /disableCookies/);
	assert.deepEqual(m.csp["script-src"], ["'self'", "https://matomo.example.eu"]);
});

test("branding: name, logo (sandboxed SVG), accent, footer, canonical, publisher and host in the legal notice", opts, async () => {
	const dir = tmp(), logo = path.join(dir, "logo.svg");
	fs.writeFileSync(logo, "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>");
	const s = await site({ brand: { name: "Vulns <FR>", logo, accent: "#ff0000", footer: "Service public", baseUrl: "https://vuln.example.fr",
		publisher: { name: "ACME SAS", address: "1 rue X, Paris", director: "J. Doe", contact: "mailto:dpo@acme.fr" }, host: { name: "Hébergeur SAS", address: "Roubaix" } } });
	try {
		const home = await (await s.get("/?lang=fr")).text();
		assert.match(home, /<title>[^<]*Vulns &lt;FR&gt;<\/title>/);
		assert.match(home, /<img src="\/static\/logo"/);
		assert.match(home, /<link rel="stylesheet" href="\/static\/brand\.css">/);
		assert.match(home, /<link rel="canonical" href="https:\/\/vuln\.example\.fr\/">/);
		assert.match(home, /Service public/);
		assert.equal(await (await s.get("/static/brand.css")).text(), ":root { --accent: #ff0000; }\n");
		const l = await s.get("/static/logo");
		assert.equal(l.headers.get("content-type"), "image/svg+xml");
		assert.match(l.headers.get("content-security-policy"), /sandbox/);
		const legal = await (await s.get("/legal?lang=fr")).text();
		assert.match(legal, /Éditeur[\s\S]*ACME SAS[\s\S]*Directeur de la publication[\s\S]*J\. Doe/);
		assert.match(legal, /Hébergeur[\s\S]*Hébergeur SAS/);
	} finally { await s.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("drain: /health turns 503 at once; request ids; trusted proxy picks the appended address", opts, async () => {
	const s = await site({ trustProxy: true, publicRatePerMinute: 2 });
	try {
		const r = await s.get("/health", { "x-request-id": "abc12345" });
		assert.equal(r.headers.get("x-request-id"), "abc12345");
		assert.match((await s.get("/health", { "x-request-id": "bad id!" })).headers.get("x-request-id"), /^[0-9a-f]{16}$/);
		// Rate limit buckets follow the LAST X-Forwarded-For entry (the one our proxy appended).
		for (let i = 0; i < 2; i++) await (await s.get("/", { "x-forwarded-for": "6.6.6.6, 10.0.0.1" })).text();
		assert.equal((await s.get("/", { "x-forwarded-for": "7.7.7.7, 10.0.0.1" })).status, 429, "same appended address");
		assert.equal((await s.get("/", { "x-forwarded-for": "6.6.6.6, 10.0.0.2" })).status, 200, "a spoofed first entry changes nothing");
		const draining = s.server.fadDrain(1000);
		const h = await s.get("/health").catch(() => null);
		if (h) assert.equal(h.status, 503);
		await draining;
	} finally { s.server.listening && await s.close(); }
});

test("backup (VACUUM INTO) with rotation; maintenance job; config command hides the metrics token", opts, async () => {
	const dir = tmp(), db = path.join(dir, "svc.db");
	try {
		execFileSync(process.execPath, [BIN, "token", "add", "--db", db], { encoding: "utf8" });
		for (let i = 0; i < 3; i++) {
			const out = execFileSync(process.execPath, [BIN, "backup", "--db", db, "--dir", path.join(dir, "bk"), "--keep", "2"], { encoding: "utf8" });
			assert.match(out, /backup .*fad-service-.*\.db/);
			await new Promise(ok => setTimeout(ok, 5));
		}
		const kept = fs.readdirSync(path.join(dir, "bk"));
		assert.equal(kept.length, 2);
		const { openDatabase } = require("../lib/sqlite-store");
		const copy = openDatabase(path.join(dir, "bk", kept[0]));
		assert.equal(copy.prepare("SELECT COUNT(*) AS n FROM tokens").get().n, 1, "the copy is a working database");
		copy.close();
		const { createAssetStore } = require("../lib/assets");
		const live = openDatabase(db);
		assert.match(await require("../lib/jobs/maintenance").run({ assets: createAssetStore(live) }), /fts optimized/);
		live.close();
		const printed = execFileSync(process.execPath, [BIN, "config", "--db", db], { encoding: "utf8", env: { ...process.env, FAD_SERVICE_METRICS_TOKEN: "very-secret" } });
		assert.ok(!printed.includes("very-secret"));
		assert.match(printed, /"token": "\(set\)"/);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
