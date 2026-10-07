// fad-service on PostgreSQL (milestone 6): the same stores, search, leases, publication and
// dumps as on SQLite, and two web instances sharing one database. A throwaway
// postgres:16-alpine container is started when Docker is available (or FAD_SERVICE_TEST_PG
// is used); without either the suite is skipped.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { open, pgUrl, freshPg } = require("./helpers/db");

const available = pgUrl();
const opts = { skip: !available && "no PostgreSQL (Docker or FAD_SERVICE_TEST_PG)", timeout: 120000 };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

test("pg: stores, search (tsvector), links, signals, demand, tokens, resource cache", opts, async () => {
	const s = await open(await freshPg());
	try {
		assert.equal(s.driver.dialect, "pg");
		await s.assets.upsert({ type: "cve", key: "CVE-2021-44228", title: "Apache Log4j2 JNDI features", summary: "remote code execution via LDAP lookups",
			aliases: ["GCVE-0-2021-44228"], data: { id: "CVE-2021-44228" }, sources: [] });
		await s.assets.upsert({ type: "package", key: "pkg:npm/internal", title: "internal", data: {}, sources: [], published: false });
		assert.equal((await s.assets.search("log4j jndi"))[0].key, "CVE-2021-44228");
		assert.equal((await s.assets.search("ldap look"))[0].key, "CVE-2021-44228", "prefix on the last word");
		assert.equal((await s.assets.search("GCVE-0-2021-44228"))[0].key, "CVE-2021-44228");
		assert.deepEqual(await s.assets.search("internal"), [], "unpublished = invisible");
		assert.deepEqual(await s.assets.search("'); DROP TABLE assets; --"), []);
		assert.ok(await s.assets.get("cve", "CVE-2021-44228"), "still there");
		await s.assets.transaction(async t => { await t.linkAdvisory("osv:GHSA-x", ["CVE-2021-44228"]); });
		await s.assets.upsert({ type: "advisory", key: "osv:GHSA-x", title: "x", data: {}, sources: [] });
		assert.deepEqual((await s.assets.advisoriesForCve("CVE-2021-44228")).map(a => a.key), ["osv:GHSA-x"]);
		await s.assets.setSignal("kev", [["CVE-2021-44228", { dateAdded: "2021-12-10" }]]);
		await s.assets.setEpss([["CVE-2021-44228", 0.97, 0.999]], "2026-10-06");
		const sig = await s.assets.signals("CVE-2021-44228");
		assert.equal(sig.kev.dateAdded, "2021-12-10");
		assert.equal(sig.epss_score, 0.97);
		assert.deepEqual(await s.assets.demand("pkg:npm/internal", "a1"), { distinct: 1, seeded: false });
		assert.deepEqual(await s.assets.demand("pkg:npm/internal", "seed"), { distinct: 2, seeded: true });
		assert.ok(await s.assets.publish("package", "pkg:npm/internal"));
		assert.equal((await s.driver.get("SELECT COUNT(*) AS n FROM package_demand")).n, 0);
		const t = await s.tokens.add({ role: "client" });
		assert.equal((await s.tokens.verify(t.token)).role, "client");
		await s.store.put("k", Buffer.from("body"), { fetchedAt: 1, ttlMs: 2, contentType: "text/plain", bytes: 4 });
		assert.equal((await s.store.readBody(await s.store.get("k"))).toString(), "body");
		assert.equal(await s.store.size(), 1);
		assert.deepEqual(await s.assets.counts(), { cve: 1, advisory: 1, package: 1 });
	} finally { await s.driver.close(); }
});

test("pg: a job lease is shared by every worker on the database", opts, async () => {
	const url = await freshPg();
	const a = await open(url), b = await open(url);
	const { createJobRunner } = require("../lib/jobs");
	let release;
	const gate = new Promise(ok => { release = ok; });
	const fetcher = async () => { await gate; return json({ vulnerabilities: [{ cveID: "CVE-2021-44228", dateAdded: "2021-12-10" }] }); };
	try {
		const r1 = createJobRunner({ assets: a.assets, fetcher, owner: "host-a" }), r2 = createJobRunner({ assets: b.assets, fetcher, owner: "host-b" });
		const running = r1.runJob("kev");
		await new Promise(ok => setTimeout(ok, 100));
		assert.deepEqual(await r2.runJob("kev"), { ran: false, status: "leased" }, "another host sees the lease");
		release();
		assert.equal((await running).status, "ok");
		assert.equal((await b.assets.signals("CVE-2021-44228")).kev.dateAdded, "2021-12-10", "written once, seen by all");
	} finally { await a.driver.close(); await b.driver.close(); }
});

test("pg: two web instances on one database — shared cache, shared publication rule, same pages", opts, async () => {
	const url = await freshPg();
	const { createServiceServer } = require("../lib/server");
	const { createRegistryLayer } = require("../lib/registry");
	let upstreamCalls = 0;
	const fetcher = async u => { upstreamCalls++; return u === "https://registry.npmjs.org/left-pad"
		? json({ name: "left-pad", "dist-tags": { latest: "1.3.0" }, time: {}, versions: { "1.3.0": { version: "1.3.0" } }, description: "pad" })
		: json({}, 404); };
	const start = async () => {
		const s = await open(url);
		const server = createServiceServer({ store: s.store, tokens: s.tokens, assets: s.assets,
			registry: createRegistryLayer({ assets: s.assets, threshold: 2, salt: "same-salt-everywhere" }), fetcher });
		await new Promise(ok => server.listen(0, "127.0.0.1", ok));
		return { ...s, server, base: `http://127.0.0.1:${server.address().port}` };
	};
	const one = await start(), two = await start();
	try {
		const ta = (await one.tokens.add({ role: "client" })).token, tb = (await one.tokens.add({ role: "client" })).token;
		const ask = (inst, token) => fetch(`${inst.base}/v1/resource`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
			body: JSON.stringify({ provider: "npm", type: "package", params: { name: "left-pad" } }) });
		assert.equal((await (await ask(one, ta)).json()).name, "left-pad");
		const hit = await ask(two, tb);
		assert.equal(hit.headers.get("x-fad-proxy"), "hit", "instance two serves what instance one cached");
		await hit.text();
		assert.equal(upstreamCalls, 1);
		// Demand is recorded right after the answer is sent: give it a moment.
		let status = 0;
		for (let i = 0; i < 20 && status !== 200; i++) { status = (await fetch(`${one.base}/pkg/npm/left-pad`)).status; if (status !== 200) await new Promise(ok => setTimeout(ok, 50)); }
		assert.equal(status, 200, "two distinct clients across two instances: published");
		assert.equal((await fetch(`${two.base}/pkg/npm/left-pad`)).status, 200);
	} finally {
		for (const i of [one, two]) { await new Promise(ok => i.server.close(ok)); await i.driver.close(); }
	}
});

test("pg: a dump built on SQLite restores into PostgreSQL (and back), search included", opts, async () => {
	const { buildDump } = require("../lib/dumps/build");
	const { restoreDump } = require("../lib/dumps/restore");
	const src = await open(":memory:");
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pgdump-"));
	try {
		await src.assets.upsert({ type: "cve", key: "CVE-2021-44228", title: "Log4Shell", summary: "log4j jndi", aliases: ["GCVE-0-2021-44228"], data: { id: "CVE-2021-44228" }, sources: [] });
		await src.assets.setNvd([{ id: "CVE-2021-44228", vulnStatus: "Analyzed", metrics: [] }]);
		await src.store.put("r", Buffer.from("x"), { fetchedAt: 5, ttlMs: 9, contentType: "text/plain", bytes: 1 });
		const m = await buildDump({ driver: src.driver, dir, kind: "full" });
		const pg = await open(await freshPg());
		const { counts } = await restoreDump({ assets: pg.assets, store: pg.store, manifestPath: path.join(dir, `${m.id}.manifest.json`) });
		assert.equal(counts.asset, 1); assert.equal(counts.nvd, 1); assert.equal(counts.resource, 1);
		assert.equal((await pg.assets.search("GCVE-0-2021-44228"))[0].key, "CVE-2021-44228");
		assert.equal((await pg.assets.nvd("CVE-2021-44228")).vulnStatus, "Analyzed");
		const back = await buildDump({ driver: pg.driver, dir, kind: "full" });
		const lite = await open(":memory:");
		await restoreDump({ assets: lite.assets, store: lite.store, manifestPath: path.join(dir, `${back.id}.manifest.json`) });
		assert.equal((await lite.assets.search("log4shell"))[0].key, "CVE-2021-44228");
		await pg.driver.close();
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
