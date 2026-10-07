// fad-service milestone 3: vulnerability mirrors (cvelistV5, KEV, EPSS, EUVD, CERT-FR),
// search and public pages. Zero network: every upstream is a mock answering from
// in-memory fixtures; the CVE record is CVEProject's own published Log4Shell record.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const zlib = require("node:zlib");
const fs = require("node:fs");

let sqlite = true;
try { require("node:sqlite"); } catch { sqlite = false; }
const opts = { skip: !sqlite && "node:sqlite unavailable" };

const LOG4SHELL = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "..", "test", "fixtures", "cve-samples", "cve-2021-44228-real.json"), "utf8"));
const record = (id, description, extra = {}) => ({
	dataType: "CVE_RECORD", dataVersion: "5.1",
	cveMetadata: { cveId: id, state: "PUBLISHED", assignerShortName: "acme", datePublished: "2024-01-02T00:00:00Z", dateUpdated: "2024-02-03T00:00:00Z" },
	containers: { cna: { descriptions: [{ lang: "en", value: description }], metrics: [{ cvssV3_1: { baseScore: 7.5, baseSeverity: "HIGH", vectorString: "CVSS:3.1/AV:N" } }],
		problemTypes: [{ descriptions: [{ cweId: "CWE-79" }] }], references: [{ url: "https://example.org/a" }, { url: "javascript:alert(1)" }], ...extra } },
});

function zipOf(files, nested = false) {
	const { zipSync, strToU8 } = require("fflate");
	const inner = zipSync(Object.fromEntries(Object.entries(files).map(([n, v]) => [n, strToU8(JSON.stringify(v))])));
	return nested ? zipSync({ "inner.zip": [inner, { level: 0 }] }) : inner;
}

function open() {
	const { openDatabase } = require("../lib/sqlite-store");
	const { createAssetStore } = require("../lib/assets");
	const db = openDatabase(":memory:");
	return { db, assets: createAssetStore(db) };
}

const bin = (buf, type = "application/zip") => new Response(buf, { status: 200, headers: { "content-type": type } });
const json = body => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

function cvelistUpstream({ tag, day, baseline, delta }) {
	const calls = [];
	const fetcher = async url => {
		calls.push(url);
		if (url.endsWith("/releases/latest")) return json({ tag_name: tag, assets: [
			{ name: `${day}_all_CVEs_at_midnight.zip.zip`, browser_download_url: "https://dl/baseline" },
			{ name: `${day}_delta_CVEs_at_0800Z.zip`, browser_download_url: "https://dl/delta" }] });
		if (url === "https://dl/baseline") return bin(baseline);
		if (url === "https://dl/delta") return bin(delta);
		throw new Error(`unexpected ${url}`);
	};
	return { fetcher, calls };
}

test("cve record: Log4Shell parsed as published — CVSS with its scorer, CWE, references, affected", opts, () => {
	const { parseCveRecord, headlineCvss } = require("../lib/cve-record");
	const r = parseCveRecord(LOG4SHELL);
	assert.equal(r.id, "CVE-2021-44228");
	assert.match(r.description, /JNDI/);
	assert.ok(r.cvss.length >= 1 && r.cvss.every(c => c.source));
	assert.equal(headlineCvss(r.cvss).score, 10);
	assert.ok(r.cwes.includes("CWE-502") || r.cwes.length >= 1);
	assert.ok(r.references.every(x => /^https?:/.test(x.url)));
	assert.equal(parseCveRecord({ cveMetadata: { cveId: "nope" } }), null);
});

test("cvelist job: baseline (nested zip) then delta; same release = no-op; new release = delta only", opts, async () => {
	const { createJobRunner } = require("../lib/jobs");
	const { assets } = open();
	const baseline = zipOf({ "cves/2021/44xxx/CVE-2021-44228.json": LOG4SHELL, "cves/2024/1xxx/CVE-2024-1000.json": record("CVE-2024-1000", "old text") }, true);
	const delta = zipOf({ "deltaCves/CVE-2024-1000.json": record("CVE-2024-1000", "Cross-site scripting in Widget Pro") });
	let up = cvelistUpstream({ tag: "cve_2026-10-07_0800Z", day: "2026-10-07", baseline, delta });
	let runner = createJobRunner({ assets, fetcher: up.fetcher });
	const first = await runner.runJob("cvelist");
	assert.equal(first.status, "ok", first.detail);
	assert.match(first.detail, /baseline 2026-10-07: 2 CVEs · delta cve_2026-10-07_0800Z: 1 CVEs/);
	assert.equal(assets.get("cve", "CVE-2024-1000").data.description, "Cross-site scripting in Widget Pro", "the delta wins over the baseline");
	assert.equal(assets.get("cve", "CVE-2021-44228").data.score, 10);

	assert.match((await runner.runJob("cvelist")).detail, /up to date/);
	assert.equal(up.calls.length, 4, "one release lookup, nothing downloaded");

	up = cvelistUpstream({ tag: "cve_2026-10-07_0900Z", day: "2026-10-07", baseline, delta });
	runner = createJobRunner({ assets, fetcher: up.fetcher });
	const third = await runner.runJob("cvelist");
	assert.match(third.detail, /^delta/);
	assert.ok(!up.calls.includes("https://dl/baseline"), "same day: the baseline is not downloaded again");
});

test("jobs are leased: a job already running elsewhere is not started twice", opts, async () => {
	const { createJobRunner } = require("../lib/jobs");
	const { assets } = open();
	let release;
	const slow = new Promise(ok => { release = ok; });
	const fetcher = async () => { await slow; return json({ vulnerabilities: [{ cveID: "CVE-2021-44228", dateAdded: "2021-12-10" }] }); };
	const a = createJobRunner({ assets, fetcher, owner: "a" }), b = createJobRunner({ assets, fetcher, owner: "b" });
	const running = a.runJob("kev");
	await new Promise(ok => setImmediate(ok));
	assert.deepEqual(await b.runJob("kev"), { ran: false, status: "leased" });
	release();
	assert.equal((await running).status, "ok");
	assert.equal((await b.runJob("kev")).ran, true, "the lease is released at the end");
});

test("signal jobs: KEV, EPSS (gzip CSV), EUVD write their own columns", opts, async () => {
	const { createJobRunner } = require("../lib/jobs");
	const { assets } = open();
	const csv = "#model_version:v2025.03.14,score_date:2026-10-06T00:00:00+0000\ncve,epss,percentile\nCVE-2021-44228,0.94358,0.99962\nnot-a-cve,1,1\n";
	const fetcher = async url => {
		if (url.includes("known_exploited")) return json({ vulnerabilities: [{ cveID: "CVE-2021-44228", dateAdded: "2021-12-10", dueDate: "2021-12-24", knownRansomwareCampaignUse: "Known" }] });
		if (url.includes("epss_scores-current")) return bin(zlib.gzipSync(csv), "application/gzip");
		if (url.endsWith("/dump/cve-euvd-mapping")) return bin("euvd_id,cve_id\nEUVD-2021-34768,CVE-2021-44228\n", "text/csv");
		if (url.includes("exploited=true")) return json({ total: 1, items: [{ aliases: "CVE-2021-44228", exploitedSince: "Dec 10, 2021, 12:00:00 AM" }] });
		throw new Error(`unexpected ${url}`);
	};
	const runner = createJobRunner({ assets, fetcher });
	for (const job of ["kev", "epss", "euvd"]) assert.equal((await runner.runJob(job)).status, "ok", job);
	const s = assets.signals("CVE-2021-44228");
	assert.equal(s.kev.dateAdded, "2021-12-10");
	assert.equal(s.epss_score, 0.94358);
	assert.equal(s.epss_date, "2026-10-06");
	assert.equal(s.euvd_id, "EUVD-2021-34768");
	assert.equal(s.euvd_exploited_since, "2021-12-10");
	assert.equal(assets.cveForEuvd("EUVD-2021-34768"), "CVE-2021-44228");
	// An empty feed never wipes what is there.
	const empty = createJobRunner({ assets, fetcher: async () => json({ vulnerabilities: [] }) });
	assert.equal((await empty.runJob("kev")).status, "error");
	assert.equal(assets.signals("CVE-2021-44228").kev.dateAdded, "2021-12-10");
});

test("certfr job: advisories become pages, CVEs get their citations, a revision drops a CVE", opts, async () => {
	const { createJobRunner } = require("../lib/jobs");
	const { assets } = open();
	let rev = "2021-12-14T00:00:00", cves = [{ name: "CVE-2021-44228" }, { name: "CVE-2021-45046" }];
	const fetcher = async url => {
		if (/\/avis\/json\/$/.test(url)) return json([{ reference: "CERTFR-2021-AVI-951", last_revision_date: rev, title: "Vulnérabilité dans Apache Log4j" }]);
		if (/\/alerte\/json\/$/.test(url)) return json([]);
		if (url.includes("CERTFR-2021-AVI-951")) return json({ cves });
		throw new Error(`unexpected ${url}`);
	};
	const runner = createJobRunner({ assets, fetcher });
	assert.match((await runner.runJob("certfr")).detail, /1 advisories updated · 2 CVEs cited/);
	const adv = assets.get("advisory", "certfr:CERTFR-2021-AVI-951");
	assert.deepEqual(adv.data.cves, ["CVE-2021-44228", "CVE-2021-45046"]);
	assert.equal(assets.signals("CVE-2021-45046").certfr[0].ref, "CERTFR-2021-AVI-951");
	rev = "2022-01-01T00:00:00"; cves = [{ name: "CVE-2021-44228" }];
	await runner.runJob("certfr");
	assert.equal(assets.signals("CVE-2021-45046").certfr, null, "a CVE the revision dropped loses the citation");
	assert.match((await runner.runJob("certfr")).detail, /no change/);
});

test("search: keywords, id prefix, aliases; unpublished assets never surface", opts, () => {
	const { assets } = open();
	const { cveAsset } = require("../lib/jobs/cvelist");
	const { parseCveRecord } = require("../lib/cve-record");
	assets.upsert(cveAsset(parseCveRecord(LOG4SHELL)));
	assets.upsert(cveAsset(parseCveRecord(record("CVE-2024-1000", "Cross-site scripting in Widget Pro"))));
	assets.upsert({ type: "package", key: "pkg:npm/internal-thing", title: "internal-thing", published: false });
	assert.equal(assets.search("log4j")[0].key, "CVE-2021-44228");
	assert.equal(assets.search("widget scrip")[0].key, "CVE-2024-1000", "prefix on the last word");
	assert.equal(assets.search("GCVE-0-2021-44228")[0].key, "CVE-2021-44228", "GCVE alias is indexed");
	assert.deepEqual(assets.search("internal-thing"), [], "unpublished = invisible");
	// Hostile input is only ever quoted FTS tokens: no SQL, no FTS operator survives.
	assert.deepEqual(assets.search('"); DROP TABLE assets; --'), []);
	assert.deepEqual(assets.search("NEAR(log4j) OR *"), assets.search("NEAR log4j OR"));
	assert.equal(assets.get("cve", "CVE-2021-44228").key, "CVE-2021-44228", "the table is still there");
	assert.deepEqual(assets.search(""), []);
});

async function site() {
	const { createSqliteStore } = require("../lib/sqlite-store");
	const { createTokenStore } = require("../lib/tokens");
	const { createServiceServer } = require("../lib/server");
	const { cveAsset } = require("../lib/jobs/cvelist");
	const { advisoryAsset } = require("../lib/jobs/certfr");
	const { parseCveRecord } = require("../lib/cve-record");
	const { db, assets } = open();
	assets.upsert(cveAsset(parseCveRecord(LOG4SHELL)));
	assets.upsert(cveAsset(parseCveRecord(record("CVE-2024-6666", "Bad <script>alert(1)</script> in Widget"))));
	assets.upsert(advisoryAsset("CERTFR-2021-AVI-951", { kind: "avis", rev: "2021-12-14", title: "Vulnérabilité dans Apache Log4j", cves: ["CVE-2021-44228"] }));
	assets.setSignal("kev", [["CVE-2021-44228", { dateAdded: "2021-12-10" }]]);
	assets.setEuvd([["CVE-2021-44228", "EUVD-2021-34768", "2021-12-10"]]);
	assets.setSignal("certfr", [["CVE-2021-44228", [{ ref: "CERTFR-2021-AVI-951", kind: "avis", title: "Vulnérabilité dans Apache Log4j" }]]]);
	const server = createServiceServer({ store: createSqliteStore({ db }), tokens: createTokenStore(db), assets, region: "fr" });
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const base = `http://127.0.0.1:${server.address().port}`;
	return { get: (p, h = {}) => fetch(base + p, { headers: h, redirect: "manual" }), close: () => new Promise(ok => server.close(ok)) };
}

test("pages: CVE page with exploitation, European refs and sources; evidence escaped; strict CSP", opts, async () => {
	const s = await site();
	try {
		const r = await s.get("/cve/CVE-2021-44228?lang=en");
		assert.equal(r.status, 200);
		assert.match(r.headers.get("content-security-policy"), /default-src 'none'; style-src 'self'/);
		const html = await r.text();
		assert.match(html, /Known exploited \(CISA KEV\) · added 2021-12-10/);
		assert.match(html, /Exploited per ENISA since 2021-12-10/);
		assert.match(html, /href="https:\/\/euvd\.enisa\.europa\.eu\/vulnerability\/EUVD-2021-34768"/);
		assert.match(html, /href="https:\/\/db\.gcve\.eu\/vuln\/GCVE-0-2021-44228"/);
		assert.match(html, /href="\/advisory\/certfr\/CERTFR-2021-AVI-951\?lang=en"/);
		assert.match(html, /CVE Program Terms of Use/);
		assert.doesNotMatch(html, /<script/i, "no script anywhere");
		const xss = await (await s.get("/cve/CVE-2024-6666")).text();
		assert.match(xss, /Bad &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
		assert.doesNotMatch(xss, /href="javascript:/, "a non-http reference is never a link");
		const fr = await (await s.get("/cve/CVE-2021-44228", { "accept-language": "fr-FR,fr;q=0.9" })).text();
		assert.match(fr, /Exploitée selon l'ENISA depuis le 2021-12-10|Exploitée selon l&#39;ENISA/);
		assert.match(fr, /<html lang="fr">/);
		assert.equal((await s.get("/cve/CVE-2099-0001")).status, 404);
	} finally { await s.close(); }
});

test("pages: ETag/304, search redirects on an exact id (CVE, GCVE, EUVD, CERT-FR), JSON API", opts, async () => {
	const s = await site();
	try {
		const first = await s.get("/cve/CVE-2021-44228");
		await first.text();
		assert.match(first.headers.get("cache-control"), /public, max-age=300/);
		assert.equal((await s.get("/cve/CVE-2021-44228", { "if-none-match": first.headers.get("etag") })).status, 304);
		for (const [q, to] of [["cve-2021-44228", "/cve/CVE-2021-44228"], ["GCVE-0-2021-44228", "/cve/CVE-2021-44228"],
			["EUVD-2021-34768", "/cve/CVE-2021-44228"], ["CERTFR-2021-AVI-951", "/advisory/certfr/CERTFR-2021-AVI-951"]]) {
			const r = await s.get(`/search?q=${encodeURIComponent(q)}&lang=en`);
			assert.equal(r.status, 302, q);
			assert.equal(r.headers.get("location"), `${to}?lang=en`, q);
		}
		const page = await (await s.get("/search?q=widget&lang=en")).text();
		assert.match(page, /CVE-2024-6666/);
		const api = await (await s.get("/api/search?q=log4j")).json();
		assert.ok(api.results.some(r => r.key === "CVE-2021-44228"));
		assert.ok(api.results.some(r => r.key === "certfr:CERTFR-2021-AVI-951"));
		const cve = await (await s.get("/api/cve/CVE-2021-44228")).json();
		assert.equal(cve.signals.euvd_id, "EUVD-2021-34768");
		const adv = await (await s.get("/advisory/certfr/CERTFR-2021-AVI-951?lang=fr")).text();
		assert.match(adv, /Vulnérabilité dans Apache Log4j/);
		assert.match(adv, /Licence Ouverte/);
		assert.equal((await s.get("/legal")).status, 200);
		assert.equal((await s.get("/static/site.css")).headers.get("content-type"), "text/css; charset=utf-8");
	} finally { await s.close(); }
});
