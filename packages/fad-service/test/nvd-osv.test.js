// fad-service: NVD (fkie mirror, xz + streamed JSON) and OSV (all.zip + incremental)
// jobs, and the pages they feed. Zero network: mock upstreams. The NVD test needs the
// `xz` binary (as the job does) and is skipped without it.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

let sqlite = true;
try { require("node:sqlite"); } catch { sqlite = false; }
let xz = true;
try { execFileSync("xz", ["--version"], { stdio: "ignore" }); } catch { xz = false; }
const opts = { skip: !sqlite && "node:sqlite unavailable" };
const optsXz = { skip: (!sqlite && "node:sqlite unavailable") || (!xz && "xz not installed") };

const NVD_LOG4SHELL = (() => {
	const j = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "..", "test", "fixtures", "cve-samples", "nvd-log4shell.json"), "utf8"));
	return j.vulnerabilities?.[0]?.cve || j;
})();
const json = body => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
const bin = buf => new Response(buf, { status: 200 });

function open() {
	const { openDatabase } = require("../lib/sqlite-store");
	const { createAssetStore } = require("../lib/assets");
	const db = openDatabase(":memory:");
	return { db, assets: createAssetStore(db) };
}

test("json-stream: items of a huge array, chunked anywhere, strings with braces and escapes", opts, async () => {
	const { forEachArrayItem } = require("../lib/json-stream");
	const doc = JSON.stringify({ note: "\"cve_items\" [ decoy", cve_items: [{ id: "a", s: "}{][" }, { id: "b", n: { d: [1, { e: "\\\"}" }] } }, { id: "é€" }], after: [1] }, null, 2);
	for (const size of [1, 2, 7, 4096]) {
		const got = [];
		async function* chunks() { const b = Buffer.from(doc); for (let i = 0; i < b.length; i += size) yield b.subarray(i, i + size); }
		assert.equal(await forEachArrayItem(chunks(), "cve_items", v => got.push(v.id)), 3, `chunk ${size}`);
		assert.deepEqual(got, ["a", "b", "é€"], `chunk ${size} (a multi-byte char split across chunks survives)`);
	}
	await assert.rejects(forEachArrayItem((async function* () { yield Buffer.from("{}"); })(), "cve_items", () => {}), /no "cve_items"/);
});

test("nvd job: a year is re-imported only when its sha256 changes; every CVSS metric kept with its source", optsXz, async () => {
	const { createJobRunner } = require("../lib/jobs");
	const { assets } = open();
	const doc = JSON.stringify({ timestamp: "x", cve_count: 1, feed_name: "CVE-2021", cve_items: [{ ...NVD_LOG4SHELL, vulnStatus: "Analyzed" }] });
	const feed = execFileSync("xz", ["-c"], { input: doc });
	let sha = "aaa";
	const calls = [];
	const fetcher = async url => {
		calls.push(url);
		if (url.endsWith("/releases/latest")) return json({ tag_name: "v1", assets: [
			{ name: "CVE-2021.json.xz", browser_download_url: "https://dl/2021.xz" }, { name: "CVE-2021.meta", browser_download_url: "https://dl/2021.meta" },
			{ name: "CVE-all.json.xz", browser_download_url: "https://dl/all.xz" }] });
		if (url === "https://dl/2021.meta") return bin(`lastModifiedDate:2026-10-06T22:10:00+00:00\nsize:1\nsha256:${sha}\n`);
		if (url === "https://dl/2021.xz") return bin(feed);
		throw new Error(`unexpected ${url}`);
	};
	const runner = createJobRunner({ assets, fetcher });
	const first = await runner.runJob("nvd");
	assert.equal(first.status, "ok", first.detail);
	assert.match(first.detail, /1 year file\(s\) re-imported, 1 records/);
	const n = assets.nvd("CVE-2021-44228");
	assert.equal(n.vulnStatus, "Analyzed");
	assert.ok(n.metrics.some(m => m.score === 10));
	assert.ok(n.configurations.length >= 1);
	assert.ok(!calls.includes("https://dl/all.xz"), "the all-in-one file is never downloaded");
	assert.match((await runner.runJob("nvd")).detail, /up to date/);
	sha = "bbb";
	assert.match((await runner.runJob("nvd")).detail, /1 year file/);
});

const GHSA = { id: "GHSA-jfh8-c2jp-5v3q", summary: "Remote code injection in Log4j", details: "Log4j <script>x</script> JNDI.", aliases: ["CVE-2021-44228"],
	published: "2021-12-10T00:40:56Z", modified: "2025-10-22T19:37:02Z",
	affected: [{ package: { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core", purl: "pkg:maven/org.apache.logging.log4j/log4j-core" },
		ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.0-beta9" }, { fixed: "2.15.0" }] }] }],
	references: [{ type: "ADVISORY", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" }, { type: "WEB", url: "javascript:alert(1)" }] };

test("osv job: all.zip first, then only modified records; advisories link their CVEs", opts, async () => {
	const { createJobRunner } = require("../lib/jobs");
	const { osvAsset, modifiedSince } = require("../lib/jobs/osv");
	const { zipSync, strToU8 } = require("fflate");
	const { assets } = open();
	const all = zipSync({ "GHSA-jfh8-c2jp-5v3q.json": strToU8(JSON.stringify(GHSA)), "MAL-2024-1.json": strToU8(JSON.stringify({ id: "MAL-2024-1", summary: "Malicious code in evil-pkg", affected: [{ package: { ecosystem: "Maven", name: "evil:pkg" } }] })) });
	let csv = "";
	const calls = [];
	const fetcher = async url => {
		calls.push(url);
		if (url.endsWith("/Maven/all.zip")) return bin(all);
		if (url.endsWith("/Maven/modified_id.csv")) return bin(csv);
		if (url.endsWith("/Maven/GHSA-jfh8-c2jp-5v3q.json")) return json({ ...GHSA, summary: "Remote code injection in Log4j (updated)" });
		throw new Error(`unexpected ${url}`);
	};
	const runOsv = st => require("../lib/jobs/osv").run({ assets, fetcher, state: st.state, setState: v => { st.state = v; }, ecosystems: ["Maven"] });
	const st = { state: {} };
	assert.match(await runOsv(st), /Maven 2 all/);
	assert.equal(assets.get("advisory", "osv:GHSA-jfh8-c2jp-5v3q").sources[0].licence, "CC-BY 4.0 — GitHub Advisory Database");
	assert.equal(assets.get("advisory", "osv:MAL-2024-1").sources[0].licence, "Apache-2.0 — OpenSSF Malicious Packages");
	assert.deepEqual(assets.advisoriesForCve("CVE-2021-44228").map(a => a.key), ["osv:GHSA-jfh8-c2jp-5v3q"]);
	assert.equal(assets.search("evil")[0].key, "osv:MAL-2024-1", "package names are searchable");

	csv = `2999-01-01T00:00:00Z,GHSA-jfh8-c2jp-5v3q\n2000-01-01T00:00:00Z,OLD-1\n`;
	assert.match(await runOsv(st), /Maven 1 changed/);
	assert.equal(assets.get("advisory", "osv:GHSA-jfh8-c2jp-5v3q").title, "Remote code injection in Log4j (updated)");
	assert.equal(calls.filter(u => u.endsWith("all.zip")).length, 1, "the zip is not downloaded again");

	assert.equal(modifiedSince("b,2\na,1", "0", 1), null, "too many changes → full re-import");
	assert.deepEqual(osvAsset(GHSA).cves, ["CVE-2021-44228"]);
});

test("pages: OSV advisory page, CVE page with NVD scores + CPE + linked advisories, id redirects", opts, async () => {
	const { createSqliteStore } = require("../lib/sqlite-store");
	const { createTokenStore } = require("../lib/tokens");
	const { createServiceServer } = require("../lib/server");
	const { cveAsset } = require("../lib/jobs/cvelist");
	const { parseCveRecord } = require("../lib/cve-record");
	const { osvAsset } = require("../lib/jobs/osv");
	const { nvdRow } = require("../lib/jobs/nvd");
	const { db, assets } = open();
	const rec = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "..", "test", "fixtures", "cve-samples", "cve-2021-44228-real.json"), "utf8"));
	assets.upsert(cveAsset(parseCveRecord(rec)));
	const o = osvAsset(GHSA);
	assets.transaction(() => { assets.upsert(o.asset); assets.linkAdvisory(o.asset.key, o.cves); });
	assets.setNvd([nvdRow({ ...NVD_LOG4SHELL, vulnStatus: "Analyzed" })]);
	const server = createServiceServer({ store: createSqliteStore({ db }), tokens: createTokenStore(db), assets });
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const base = `http://127.0.0.1:${server.address().port}`;
	try {
		const cve = await (await fetch(`${base}/cve/CVE-2021-44228?lang=en`)).text();
		assert.match(cve, /NVD status<\/dt><dd>Analyzed/);
		assert.match(cve, /href="\/advisory\/osv\/GHSA-jfh8-c2jp-5v3q\?lang=en"/);
		assert.match(cve, /cpe:2\.3:a:apache:log4j/);
		assert.match(cve, /not endorsed or certified by the NVD/);
		const adv = await (await fetch(`${base}/advisory/osv/GHSA-jfh8-c2jp-5v3q?lang=fr`)).text();
		assert.match(adv, /Paquets affectés/);
		assert.match(adv, /introduced 2\.0-beta9, fixed 2\.15\.0/);
		assert.match(adv, /Log4j &lt;script&gt;/);
		assert.doesNotMatch(adv, /href="javascript:/);
		assert.match(adv, /CC-BY 4\.0 — GitHub Advisory Database/);
		const r = await fetch(`${base}/search?q=ghsa-JFH8-c2jp-5v3q&lang=en`, { redirect: "manual" });
		assert.equal(r.headers.get("location"), "/advisory/osv/GHSA-jfh8-c2jp-5v3q?lang=en");
	} finally { await new Promise(ok => server.close(ok)); }
});
