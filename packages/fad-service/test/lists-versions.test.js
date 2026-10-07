// CVE lists (home page, /cves) and per-version package pages, on SQLite and — when Docker
// or FAD_SERVICE_TEST_PG gives one — PostgreSQL. Zero network.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { open, pgUrl, freshPg } = require("./helpers/db");

let sqlite = true;
try { require("node:sqlite"); } catch { sqlite = false; }
const opts = { skip: !sqlite && "node:sqlite unavailable" };
const pgOpts = { skip: !pgUrl() && "no PostgreSQL (Docker or FAD_SERVICE_TEST_PG)", timeout: 120000 };

const cve = (id, { score = null, published = "2026-01-01T00:00:00Z", state = "PUBLISHED", pub = true, title = `title ${id}` } = {}) =>
	({ type: "cve", key: id, title, data: { id, state, published, score }, sources: [], published: pub });

async function seedLists(assets) {
	await assets.upsertMany([
		cve("CVE-2026-0001", { score: 9.8, published: "2026-03-01T10:00:00Z" }),          // critical (CNA)
		cve("CVE-2026-0002", { score: 7.5, published: "2026-03-05T10:00:00Z" }),          // high, but NVD says 9.1 below
		cve("CVE-2026-0003", { score: 10, published: "2026-03-09T10:00:00Z", state: "REJECTED" }),
		cve("CVE-2026-0004", { score: 9.9, published: "2026-03-10T10:00:00Z", pub: false }),
		cve("CVE-2026-0005", { score: 9.0, published: "2099-01-01T00:00:00Z" }),          // future date: ignored
		cve("CVE-2026-0006", { score: 5.0, published: "2026-03-07T10:00:00Z" }),
		cve("CVE-2026-0007", { score: null, published: "2026-02-01T10:00:00Z" }),         // scored by NVD only
	]);
	await assets.setNvd([
		{ id: "CVE-2026-0002", published: "2026-03-05T10:00:00", metrics: [{ version: "3.1", score: 9.1, type: "Primary" }, { version: "2.0", score: 10, type: "Primary" }] },
		{ id: "CVE-2026-0006", published: "2026-03-07T10:00:00", metrics: [{ version: "3.1", score: 5.0, type: "Primary" }, { version: "3.1", score: 9.8, type: "Secondary" }] },
		{ id: "CVE-2026-0007", published: "2026-02-01T10:00:00", metrics: [{ version: "4.0", score: 9.3, type: "Secondary" }, { version: "3.1", score: 4.0, type: "Primary" }] },
	]);
	await assets.setEpss([["CVE-2026-0001", 0.5, 0.9], ["CVE-2026-0006", 0.97, 0.999], ["CVE-2026-0002", 0.01, 0.3]], "2026-10-01");
	await assets.setSignal("kev", [["CVE-2026-0006", { dateAdded: "2026-04-01" }], ["CVE-2026-0001", { dateAdded: "2026-05-02" }], ["CVE-2026-0004", { dateAdded: "2026-06-01" }]]);
}

async function checkLists(assets) {
	const critical = await assets.listCves("critical", 10);
	assert.deepEqual(critical.map(r => r.cve), ["CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0007"],
		"CNA or NVD >= 9 (newest CVSS version, NVD Primary first), newest first; rejected, unpublished, future and NVD-Secondary-only-high excluded");
	assert.equal(critical[0].score, 9.1);
	assert.equal(critical[2].score, 9.3, "a v4.0 score outranks an older version's, even Secondary");
	assert.equal(critical[1].title, "title CVE-2026-0001");
	assert.deepEqual((await assets.listCves("exploited", 2)).map(r => r.cve), ["CVE-2026-0006", "CVE-2026-0001"]);
	const kev = await assets.listCves("kev", 10);
	assert.deepEqual(kev.map(r => r.cve), ["CVE-2026-0001", "CVE-2026-0006"], "latest addition first; an unpublished CVE is not listed");
	assert.equal(kev[0].kev.dateAdded, "2026-05-02");
	await assert.rejects(assets.listCves("nope"), /unknown list/);
	// A CVE that becomes rejected leaves the lists.
	await assets.upsert(cve("CVE-2026-0001", { score: 9.8, state: "REJECTED" }));
	assert.ok(!(await assets.listCves("critical", 10)).some(r => r.cve === "CVE-2026-0001"));
}

test("lists: latest critical / most exploited / KEV on SQLite", opts, async () => {
	const { assets } = await open(":memory:");
	await seedLists(assets);
	await checkLists(assets);
});

test("lists: the same on PostgreSQL", pgOpts, async () => {
	const { assets, driver } = await open(await freshPg());
	try { await seedLists(assets); await checkLists(assets); } finally { await driver.close(); }
});

test("lists: an existing database is backfilled once at open (CVE records + NVD rows)", opts, async () => {
	const { assets, driver } = await open(":memory:");
	await seedLists(assets);
	await driver.run("DELETE FROM cve_rank");
	await driver.run("DELETE FROM settings WHERE name = 'cve_rank_v1'");
	const { createAssetStore } = require("../lib/assets");
	const logs = [];
	const again = await createAssetStore(driver, { log: m => logs.push(m) });
	assert.match(logs[0], /backfilled from 7 CVE records/);
	await checkLists(again);
	await createAssetStore(driver, { log: m => logs.push(m) });
	assert.equal(logs.length, 1, "done once");
});

// ------------------------------------------------------------------ pages ----

const PKG = { key: "pkg:npm/demo", type: "npm", name: "demo", latest: "2.1.0",
	versions: ["2.1.0", "2.0.0", "1.2.0", "1.1.0", "1.0.0"].map(version => ({ version, date: "2025-01-01T00:00:00Z" })) };
const advisory = (id, events, { withdrawn = null, cves = [] } = {}) => ({
	type: "advisory", key: `osv:${id}`, title: `adv ${id}`, sources: [],
	data: { id, withdrawn, affected: [{ ecosystem: "npm", name: "demo", ranges: [{ type: "SEMVER", events }] }] }, cves });

async function site() {
	const { createServiceServer } = require("../lib/server");
	const { packageAsset } = require("../lib/registry");
	const s = await open(":memory:");
	await s.assets.upsert(packageAsset(PKG, true));
	await seedLists(s.assets);
	const advs = [
		advisory("GHSA-aaaa", [{ introduced: "0" }, { fixed: "1.2.0" }], { cves: ["CVE-2026-0001"] }),
		advisory("GHSA-bbbb", [{ introduced: "1.1.0" }, { fixed: "2.0.0" }], { cves: ["CVE-2026-0006"] }),
		advisory("GHSA-gone", [{ introduced: "0" }, { fixed: "2.1.0" }], { withdrawn: "2026-01-01T00:00:00Z" }),
	];
	await s.assets.upsertMany(advs.map(({ cves, ...a }) => a));
	await s.assets.linkMany(advs.map(a => ({ advisory: a.key, cves: a.cves, packages: ["pkg:npm/demo"] })));
	const server = createServiceServer({ store: s.store, tokens: s.tokens, assets: s.assets });
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const base = `http://127.0.0.1:${server.address().port}`;
	const get = async p => { const r = await fetch(base + p); return { status: r.status, body: await r.text() }; };
	return { get, close: () => new Promise(ok => server.close(ok)) };
}

test("pages: home lists, /cves?list=…, strict list parameter", opts, async () => {
	const s = await site();
	try {
		const home = await s.get("/?lang=en");
		assert.equal(home.status, 200);
		for (const h of ["Latest critical vulnerabilities", "Most likely to be exploited", "Recently added to CISA KEV"]) assert.ok(home.body.includes(h), h);
		assert.ok(home.body.includes('href="/cve/CVE-2026-0002?lang=en"'));
		const crit = await s.get("/cves?list=critical&lang=fr");
		assert.equal(crit.status, 200);
		assert.ok(crit.body.includes("Dernières vulnérabilités critiques"));
		assert.ok(crit.body.indexOf("CVE-2026-0002") < crit.body.indexOf("CVE-2026-0007"));
		assert.ok(crit.body.includes('href="/cves?list=critical&amp;lang=en"'), "the language switch keeps the list");
		assert.equal((await s.get("/cves?list=kev")).status, 200);
		assert.equal((await s.get("/cves?list=all")).status, 400);
		assert.equal((await s.get("/cves?list=critical&limit=1000")).status, 400);
	} finally { await s.close(); }
});

test("pages: a version page lists what affects it, the closest safe upgrade, never a withdrawn advisory", opts, async () => {
	const s = await site();
	try {
		const pkg = await s.get("/pkg/npm/demo?lang=en");
		assert.equal(pkg.status, 200);
		assert.ok(pkg.body.includes('href="/pkg/npm/demo?version=1.1.0&amp;lang=en"'), "versions link to their page");
		assert.ok(pkg.body.includes("Withdrawn advisories (1)"));

		const v = await s.get("/pkg/npm/demo?version=1.1.0&lang=en");
		assert.equal(v.status, 200);
		assert.ok(v.body.includes("Advisories affecting this version (2)"), "aaaa (<1.2.0) and bbbb (>=1.1.0 <2.0.0); not the withdrawn one");
		assert.ok(v.body.includes('href="/cve/CVE-2026-0006?lang=en"'));
		assert.match(v.body, /Closest safe upgrade<\/dt><dd><a href="\/pkg\/npm\/demo\?version=2\.0\.0&amp;lang=en">2\.0\.0</, "2.0.0, not 2.1.0 (that bound is the withdrawn advisory's)");
		// Worst first, by the same headline score as the lists: CVE-2026-0001 is 9.8; CVE-2026-0006 is 5.0
		// (NVD's Primary 5.0 wins over a Secondary 9.8).
		assert.ok(v.body.indexOf("GHSA-aaaa") < v.body.indexOf("GHSA-bbbb"));
		assert.ok(v.body.includes("Withdrawn advisories (1)"));

		const clean = await s.get("/pkg/npm/demo?version=2.0.0&lang=en");
		assert.ok(clean.body.includes("No known advisory affects it"));
		assert.ok(!clean.body.includes("Closest safe upgrade"));

		assert.equal((await s.get("/pkg/npm/demo?version=9.9.9")).status, 404, "only versions the registry listed");
		assert.equal((await s.get("/pkg/npm/demo?version=%3Cscript%3E")).status, 400);
		assert.equal((await s.get("/pkg/npm/demo?version=1.1.0&x=1")).status, 400);
	} finally { await s.close(); }
});

test("lists: latest critical vulnerabilities in libraries — CVE → advisory → package, withdrawn excluded", opts, async () => {
	const { assets } = await open(":memory:");
	await seedLists(assets);
	const adv = (id, cves, pkgs, extra = {}) => ({ type: "advisory", key: `osv:${id}`, title: id, sources: [],
		data: { id, affected: pkgs.map(n => ({ ecosystem: "npm", name: n, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }] })), ...extra }, cves, pkgs });
	const advs = [
		adv("GHSA-1", ["CVE-2026-0002"], ["lib-a", "lib-b"]),
		adv("GHSA-2", ["CVE-2026-0007"], ["lib-c"], { withdrawn: "2026-01-01" }),   // withdrawn: CVE-0007 has no library
		adv("GHSA-3", ["CVE-2026-0006"], ["lib-d"]),                                 // CVE-0006 is not critical (5.0)
	];
	await assets.upsertMany(advs.map(({ cves, pkgs, ...a }) => a));
	await assets.linkMany(advs.map(a => ({ advisory: a.key, cves: a.cves, packages: a.pkgs.map(n => `pkg:npm/${n}`) })));
	const rows = await assets.listLibraries(10);
	assert.deepEqual(rows.map(r => r.cve), ["CVE-2026-0002"]);
	assert.deepEqual(rows[0].packages.map(p => p.key), ["pkg:npm/lib-a", "pkg:npm/lib-b"]);
	assert.equal(rows[0].packages[0].advisory, "osv:GHSA-1");
	assert.equal(rows[0].score, 9.1);
	const one = await assets.listLibraries(10, { packagesPerCve: 1 });
	assert.equal(one[0].packages.length, 1);
	assert.equal(one[0].packagesTotal, 2);
});

test("pages: /cves?list=libraries, the versions panel on package and version pages, a branch without a fix is said so", opts, async () => {
	const { createServiceServer } = require("../lib/server");
	const { packageAsset } = require("../lib/registry");
	const s = await open(":memory:");
	await seedLists(s.assets);
	await s.assets.upsert(packageAsset(PKG, true));
	const a = { type: "advisory", key: "osv:GHSA-two", title: "two branches", sources: [], data: { id: "GHSA-two", affected: [
		{ ecosystem: "npm", name: "demo", ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.2.0" }] }] },
		{ ecosystem: "npm", name: "demo", ranges: [{ type: "SEMVER", events: [{ introduced: "2.0.0" }, { last_affected: "2.1.0" }] }] }] } };
	await s.assets.upsertMany([a]);
	await s.assets.linkMany([{ advisory: a.key, cves: ["CVE-2026-0002"], packages: ["pkg:npm/demo"] }]);
	const server = createServiceServer({ store: s.store, tokens: s.tokens, assets: s.assets });
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const base = `http://127.0.0.1:${server.address().port}`;
	const get = async p => (await fetch(base + p)).text();
	try {
		const libs = await get("/cves?list=libraries&lang=en");
		assert.ok(libs.includes("Latest critical vulnerabilities in libraries"));
		assert.ok(libs.includes('href="/pkg/npm/demo?lang=en"'), "a library with a public page links to it");
		assert.ok(libs.includes("1.2.0") && libs.includes("≤ 2.1.0, no fix"), "each branch: its fix, or no fix");
		const home = await get("/?lang=en");
		assert.ok(home.includes("Latest critical vulnerabilities in libraries"));

		const pkg = await get("/pkg/npm/demo?lang=en");
		assert.match(pkg, /<div class="pkg-layout"><div class="pkg-main"><h1>demo<\/h1>/);
		assert.match(pkg, /<aside class="versions-panel"[^>]*><h2>Versions <span class="muted">\(5\)<\/span><\/h2>/);
		assert.match(pkg, /version=2\.1\.0&amp;lang=en">2\.1\.0<\/a><span class="v-meta"><time[^>]*>2025-01-01<\/time> <span class="flag"[^>]*>1<\/span>/, "the 2.x branch without a fix");
		assert.match(pkg, /version=1\.2\.0&amp;lang=en">1\.2\.0<\/a><span class="v-meta"><time[^>]*>2025-01-01<\/time> <span class="ok"/);

		const v = await get("/pkg/npm/demo?version=2.1.0&lang=en");
		assert.match(v, /<li class="current"><a href="\/pkg\/npm\/demo\?version=2\.1\.0&amp;lang=en" aria-current="page">2\.1\.0<\/a>/);
		assert.ok(v.includes("≤ 2.1.0, no fix"));
		assert.ok(v.includes("No newer version is free of known advisories"));
	} finally { await new Promise(ok => server.close(ok)); }
});
