/**
 * NVD → fkie-cad/nvd-json-data-feeds fallback (lib/providers/nvd/enrich.js#fetchOne). Fake fetcher, fake
 * CVE ids in the year 2099 so the real ~/.vigie-vuln/nvd-cache is never shadowed; every
 * test removes what it wrote.
 */
require('./helpers/isolated-cache')('nvd-mirror');
const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const N = require("../lib/providers/nvd/enrich");
const { createSourceHealth, setActiveLedger } = require("../lib/scan/source-health");
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

test('per-CVE evidence distinguishes cache, offline miss, and a cached confirmed absence', async () => {
	const available = id('0001101'), missing = id('0001102'), absent = id('0001103');
	N.writeCache(available, N.extractFromNvdRecord(record(available)));
	N.writeCache(absent, null);
	const matches = [available, missing, absent].map(id => ({cve:{id}}));
	await N.enrichMatches(matches, {offline:true,onProgress:()=>{},fetcher:()=>{throw Error('offline network')}});
	assert.deepEqual(matches.map(m => m.cve.nvdRecordEvidence), [
		{status:'available',stale:false}, {status:'unavailable',reason:'offline',stale:false}, {status:'no-match',stale:false},
	]);
});

test('per-CVE evidence identifies stale cache after failed refresh and definitive empty responses', async () => {
	const staleId = id('0001111'), absentId = id('0001112');
	N.writeCache(staleId, N.extractFromNvdRecord(record(staleId)), Date.now() - 86400000);
	const matches = [{cve:{id:staleId}},{cve:{id:absentId}}];
	const fetcher = fakeFetcher(url => url.includes(staleId) ? res(429,{}) : res(200,{totalResults:0,vulnerabilities:[]}), res(503,{}));
	await N.enrichMatches(matches, {fetcher,hasKey:true,onProgress:()=>{}});
	assert.deepEqual(matches[0].cve.nvdRecordEvidence,{status:'available',stale:true,refreshFailed:true,reason:'HTTP 429'});
	assert.deepEqual(matches[1].cve.nvdRecordEvidence,{status:'no-match',stale:false});
});

test('successful fallback reports available evidence even after a primary error', async () => {
	const c = id('0001121'), matches = [{cve:{id:c}},{cve:{id:c}}];
	await N.enrichMatches(matches, {fetcher:fakeFetcher(res(429,{}),res(200,record(c))),hasKey:true,onProgress:()=>{}});
	for (const m of matches) assert.deepEqual(m.cve.nvdRecordEvidence,{status:'available',stale:false});
});

test('an unanswered CVE keeps its own HTTP reason while a different CVE succeeds', async () => {
	const failed = id('0001122'), success = id('0001123');
	const matches = [{cve:{id:failed}},{cve:{id:success}}], observed = [];
	const fetcher = fakeFetcher(url => url.includes(failed) ? res(429,{}) : res(200,{vulnerabilities:[{cve:record(success)}]}),res(503,{}));
	await N.enrichMatches(matches,{fetcher,hasKey:true,onProgress:()=>{},onRecordEvidence:(id,e)=>observed.push([id,e])});
	assert.deepEqual(matches[0].cve.nvdRecordEvidence,{status:'unavailable',reason:'HTTP 429',stale:false});
	assert.deepEqual(matches[1].cve.nvdRecordEvidence,{status:'available',stale:false});
	assert.equal(observed.length,2);
});

test('offline expired records are marked stale without claiming an attempted refresh', async () => {
	const c = id('0001124');
	N.writeCache(c,N.extractFromNvdRecord(record(c)),Date.now()-86400000);
	const m = {cve:{id:c}};
	await N.enrichMatches([m],{offline:true,onProgress:()=>{}});
	assert.deepEqual(m.cve.nvdRecordEvidence,{status:'available',stale:true,reason:'offline'});
});

test('a stale hosted response without a failure indication does not invent one', async () => {
	const c = id('0001131'), matches = [{cve:{id:c}}], providers = require('../lib/providers');
	const fetcher = async () => Response.json({vulnerabilities:[{cve:record(c)}]}, {headers:{'x-fad-proxy':'stale'}});
	providers.configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null,health:null,token:'test',fetcher,proxyRateLimitMaxWaitMs:0});
	try {
		await N.enrichMatches(matches,{fetcher,hasKey:true,onProgress:()=>{}});
		assert.deepEqual(matches[0].cve.nvdRecordEvidence,{status:'available',stale:true,reason:'stale proxy response'});
	} finally { providers.configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null,proxyRateLimitMaxWaitMs:null}); }
});

test('a hosted stale refresh failure retains its HTTP status when cached and replayed', async () => {
	const c = id('0001132'), matches = [{cve:{id:c}}], providers = require('../lib/providers');
	const fetcher = async () => Response.json({vulnerabilities:[{cve:record(c)}]}, {headers:{'x-fad-proxy':'stale','x-fad-proxy-reason':'refresh-failed','x-fad-proxy-refresh-status':'429'}});
	providers.configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null,health:null,token:'test',fetcher,proxyRateLimitMaxWaitMs:0});
	try {
		await N.enrichMatches(matches,{fetcher,hasKey:true,onProgress:()=>{}});
		assert.deepEqual(matches[0].cve.nvdRecordEvidence,{status:'available',stale:true,reason:'HTTP 429',refreshFailed:true});
		const offline = [{cve:{id:c}}];
		await N.enrichMatches(offline,{offline:true,onProgress:()=>{}});
		assert.deepEqual(offline[0].cve.nvdRecordEvidence,{status:'available',stale:true,reason:'HTTP 429',refreshFailed:true});
	} finally { providers.configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null,proxyRateLimitMaxWaitMs:null}); }
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
	const body=Buffer.from(JSON.stringify({score:5.0,cwes:['CWE-79']}));
	require('../lib/cache/db').getCacheDb(path.dirname(N.NVD_CACHE_DIR)).prepare(`INSERT INTO nvd_records
	 (cve,kind,fetched_at,revision_ms,body_deflate,body_bytes,metadata_json) VALUES (?,?,?,?,?,?,?)`).run(
	 c,'live',1,null,require('../lib/cache/advisory-compression').compress(body),body.length,JSON.stringify({schema:N.NVD_CACHE_SCHEMA}));
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

test('hosted NVD enrichment does not apply the direct NVD thirty-second window', {timeout: 8000}, async()=>{
	const ids=Array.from({length:12},(_,i)=>id(String(300+i).padStart(7,'0'))), calls=[];
	const {configureResourceRoute}=require('../lib/providers');
	const fetcher=async (_url,init)=>{const body=JSON.parse(init.body);calls.push(body.params.id);return Response.json({vulnerabilities:[{cve:record(body.params.id)}]});};
	configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null,health:null,token:'test',fetcher});
	try {await N.enrichMatches(ids.map(c=>({cve:{id:c}})),{fetcher,hasKey:false,onProgress:()=>{}});assert.equal(calls.length,12);}
	finally {configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null});}
});

test('a hosted NVD budget refusal proceeds to the targeted mirror once the scan wait budget is exhausted', {timeout:3000}, async()=>{
	const c=id('0000320'), calls=[];
	const {configureResourceRoute}=require('../lib/providers');
	const fetcher=async (_url,init)=>{const body=JSON.parse(init.body);calls.push(body.type);return body.type==='cve' ? new Response('',{status:503,headers:{'x-fad-proxy':'denied','retry-after':'30'}}) : Response.json(record(c));};
	configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null,health:null,token:'test',fetcher,resetRateLimit:true,proxyRateLimitMaxWaitMs:0});
	try {const result=await N.fetchOne(c,{fetcher});assert.equal(result.score,9.8);assert.deepEqual(calls,['cve','cve-mirror']);}
	finally {configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null,resetRateLimit:true,proxyRateLimitMaxWaitMs:null});}
});

test('hosted NVD primary retries stale admission with mirror enabled and returns fresh without mirror',async()=>{
 const http=require('node:http'),{configureResourceRoute}=require('../lib/providers'),{createProxyThrottle}=require('../lib/providers/proxy-throttle');const c=id('0000999'),health=createSourceHealth(),calls=[];let clock=0;
 const server=http.createServer((req,res)=>{let body='';req.on('data',x=>body+=x);req.on('end',()=>{const q=JSON.parse(body);calls.push(q.type);const stale=calls.length===1;res.writeHead(200,{'content-type':'application/json','x-fad-proxy':stale?'stale':'miss','x-fad-proxy-fetched-at':new Date().toISOString(),...(stale?{'x-fad-proxy-reason':'refresh-failed','x-fad-proxy-refresh-status':'503','x-fad-proxy-refresh-cause':'admission','retry-after':'1'}:{})});res.end(JSON.stringify({totalResults:1,vulnerabilities:[{cve:record(c)}]}));});});
 await new Promise(ok=>server.listen(0,'127.0.0.1',ok));const url=`http://127.0.0.1:${server.address().port}`;
 configureResourceRoute({proxyUrl:url,hosted:true,store:null,hostedStore:null,health,token:'test',fetcher:globalThis.fetch,proxyThrottle:createProxyThrottle({now:()=>clock,sleep:async ms=>{clock+=ms},warn:()=>{}})});
 try{const result=await N.fetchOne(c,{fetcher:globalThis.fetch,mirror:true});assert.equal(result.score,9.8);assert.deepEqual(calls,['cve','cve']);assert(clock>=1000);assert.deepEqual(health.stale(),[]);assert.deepEqual(health.degraded(),[]);}
 finally{configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null,proxyThrottle:null,resetRateLimit:true});await new Promise(ok=>server.close(ok));}
});
