/**
 * NVD → fkie-cad/nvd-json-data-feeds fallback (lib/nvd.js#fetchOne). Fake fetcher, fake
 * CVE ids in the year 2099 so the real ~/.vigie-vuln/nvd-cache is never shadowed; every
 * test removes what it wrote.
 */
const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const N = require("../lib/nvd");
const { createSourceHealth, setActiveLedger } = require("../lib/source-health");
const { getProvider } = require("../lib/providers");

const written = [];
const id = n => { const c = `CVE-2099-${n}`; written.push(c); return c; };
afterEach(() => { for (const c of written.splice(0)) fs.rmSync(path.join(N.NVD_CACHE_DIR, `${c}.json`), { force: true }); setActiveLedger(null); });

const record = cve => ({ id: cve, descriptions: [{ lang: "en", value: "EVIDENCE mirror description" }],
	metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }] },
	weaknesses: [{ description: [{ lang: "en", value: "CWE-502" }] }], references: [], configurations: [] });
const res = (status, body) => ({ ok: status >= 200 && status < 300, status, headers: new Headers(), json: async () => body, text: async () => JSON.stringify(body), clone() { return this; }, arrayBuffer: async () => Buffer.from(JSON.stringify(body)) });

function fakeFetcher(nvd, mirror) {
	const calls = [];
	const f = async (url, init) => {
		const u = String(url);
		calls.push({ u, signal: !!init?.signal });
		if (u.includes("services.nvd.nist.gov")) return typeof nvd === "function" ? nvd(u) : nvd;
		if (u.includes("fkie-cad/nvd-json-data-feeds")) return typeof mirror === "function" ? mirror(u) : mirror;
		throw new Error("unexpected " + u);
	};
	f.calls = calls;
	return f;
}

test("mirror URL: bucket = the id minus its last two digits, for 4-, 5- and 6-digit ids", () => {
	const p = getProvider("nvd");
	assert.equal(p.build("cve-mirror", { id: "CVE-2014-0160" }).url, "https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/CVE-2014/CVE-2014-01xx/CVE-2014-0160.json");
	assert.equal(p.build("cve-mirror", { id: "CVE-2021-44228" }).url, "https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/CVE-2021/CVE-2021-442xx/CVE-2021-44228.json");
	assert.equal(p.build("cve-mirror", { id: "CVE-2026-100660" }).url, "https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/CVE-2026/CVE-2026-1006xx/CVE-2026-100660.json");
});

test("NVD throttled → the record comes from the mirror, tagged, and no outage is recorded", async () => {
	const health = createSourceHealth(); setActiveLedger(health);
	const c = id("0000101");
	const f = fakeFetcher(res(429, {}), u => res(200, record(c)));
	const r = await N.fetchOne(c, { fetcher: f });
	assert.equal(r.score, 9.8);
	assert.equal(r.severity, "CRITICAL");
	assert.equal(r.via, "fkie-cad/nvd-json-data-feeds");
	assert.deepEqual(r.cwes, ["CWE-502"]);
	assert.deepEqual(health.degraded(), []);
	assert.ok(f.calls[0].signal, "the NVD request owns its deadline, so the guard does not burn its retry schedule");
});

test("a definitive NVD 404 is an answer: the mirror is never asked", async () => {
	const c = id("0000102");
	const f = fakeFetcher(res(404, {}), () => { throw new Error("mirror must not be called"); });
	assert.equal(await N.fetchOne(c, { fetcher: f }), null);
	assert.equal(f.calls.length, 1);
});

test("NVD down AND mirror without the record → the hole is reported under NVD (the run will stop)", async () => {
	const health = createSourceHealth(); setActiveLedger(health);
	const c = id("0000103");
	const f = fakeFetcher(res(503, {}), res(404, {}));
	assert.equal(await N.fetchOne(c, { fetcher: f }), null);
	assert.deepEqual(health.degraded().map(d => d.id), ["nvd"]);
});

test("NVD down, mirror down, but a cached record past its TTL exists → served stale, not dropped", async () => {
	const health = createSourceHealth(); setActiveLedger(health);
	const c = id("0000104");
	fs.mkdirSync(N.NVD_CACHE_DIR, { recursive: true });
	fs.writeFileSync(path.join(N.NVD_CACHE_DIR, `${c}.json`), JSON.stringify({ _fetchedAt: 0, _schema: N.NVD_CACHE_SCHEMA, body: { score: 5.0, cwes: ["CWE-79"] } }));
	const r = await N.fetchOne(c, { fetcher: fakeFetcher(res(503, {}), res(503, {})) });
	assert.deepEqual(r.cwes, ["CWE-79"]);
	assert.deepEqual(health.degraded(), []);
});

test("--no-nvd-mirror: NVD only, request left to the guard's retry schedule (no own deadline)", async () => {
	const c = id("0000105");
	const f = fakeFetcher(res(503, {}), () => { throw new Error("mirror must not be called"); });
	await N.fetchOne(c, { fetcher: f, mirror: false });
	assert.equal(f.calls.length, 1);
	assert.equal(f.calls[0].signal, false);
});

test("no NVD key: the mirror goes FIRST; only what it does not hold is asked of NVD, which must answer (guarded, retried)", async () => {
	const a = id("0000201"), b = id("0000202");
	const f = fakeFetcher(u => res(200, { vulnerabilities: [{ cve: record(b) }] }), u => (u.includes(a) ? res(200, record(a)) : res(404, {})));
	const matches = [{ cve: { id: a } }, { cve: { id: b } }];
	await N.enrichMatches(matches, { fetcher: f, hasKey: false, onProgress: () => {} });
	const nvdCalls = f.calls.filter(c => c.u.includes("services.nvd.nist.gov"));
	assert.equal(nvdCalls.length, 1, "NVD is asked only for the CVE the mirror lacks");
	assert.ok(nvdCalls[0].u.includes(b));
	assert.equal(nvdCalls[0].signal, false, "NVD is the last source here: left to the guard's full retry schedule");
	assert.equal(matches[0].cve.severity, "CRITICAL");
	assert.equal(matches[1].cve.severity, "CRITICAL");
});

test("with an NVD key: NVD first, the mirror is never asked when NVD answers", async () => {
	const a = id("0000203");
	const f = fakeFetcher(res(200, { vulnerabilities: [{ cve: record(a) }] }), () => { throw new Error("mirror must not be called"); });
	await N.enrichMatches([{ cve: { id: a } }], { fetcher: f, hasKey: true, onProgress: () => {} });
	assert.equal(f.calls.length, 1);
});

test('hosted mode checks the NVD primary before its secondary mirror',async()=>{
	const c=id('0000225'), calls=[];
	const {configureResourceRoute}=require('../lib/providers');
	const fetcher=async (_url,init)=>{const body=JSON.parse(init.body);calls.push(body.type);return Response.json({vulnerabilities:[{cve:record(c)}]});};
	configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null,health:null,token:'test',fetcher});
	try {await N.enrichMatches([{cve:{id:c}}],{fetcher,hasKey:false,onProgress:()=>{}});assert.deepEqual(calls,['cve']);}
	finally {configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null});}
});
