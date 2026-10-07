// Exposed surface: strict typing of every input, the real fad client still accepted,
// upstream budgets (never get banned by NVD & co.), answers from the mirrors, search input.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

let sqlite = true;
try { require("node:sqlite"); } catch { sqlite = false; }
const opts = { skip: !sqlite && "node:sqlite unavailable" };
const FAD = path.join(__dirname, "..", "..", "..", "lib");
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

async function site(extra = {}) {
	const { open } = require("./helpers/db");
	const { createServiceServer } = require("../lib/server");
	const s = await open(":memory:");
	const server = createServiceServer({ store: s.store, tokens: s.tokens, assets: s.assets, ...extra });
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const base = `http://127.0.0.1:${server.address().port}`;
	const client = (await s.tokens.add({ role: "client" })).token;
	const admin = (await s.tokens.add({ role: "admin" })).token;
	const post = (body, { token = client, type = "application/json", route = "/v1/resource" } = {}) => fetch(base + route, { method: "POST",
		headers: { authorization: `Bearer ${token}`, ...(type ? { "content-type": type } : {}) }, body: typeof body === "string" ? body : JSON.stringify(body) });
	return { ...s, server, base, client, admin, post, get: (p, h = {}) => fetch(base + p, { headers: h }), close: () => new Promise(ok => server.close(ok)) };
}

test("validate: every (provider, type) fad sends passes; anything else is refused", () => {
	const { validateResource } = require("../lib/validate");
	const ok = [
		{ provider: "nvd", type: "cve", params: { id: "CVE-2021-44228" } },
		{ provider: "osv", type: "packages", params: { queries: [{ ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core", version: "2.14.1" }] } },
		{ provider: "epss", type: "scores", params: { ids: ["CVE-2021-44228", "CVE-2022-22965"] } },
		{ provider: "npm", type: "package", params: { name: "@types/node" } },
		{ provider: "pypi", type: "package", params: { name: "zope.interface" } },
		{ provider: "maven", type: "artifact", params: { path: "org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.pom" } },
		{ provider: "maven", type: "artifact", params: { path: "org/slf4j/slf4j-api/maven-metadata.xml", method: "HEAD" } },
		{ provider: "go", type: "module-latest", params: { module: "github.com/!burnt!sushi/toml" } },
		{ provider: "packagist", type: "advisories", params: { packages: ["symfony/http-kernel", "twig/twig"] } },
		{ provider: "hashid", type: "depsdev-sha1", params: { base64: "2jmj7l5rSw0yVb/vlWAYkK/YBwk=" } },
		{ provider: "certfr", type: "advisory", params: { kind: "avis", ref: "CERTFR-2021-AVI-951", rev: "" } },
		{ provider: "kev", type: "catalog" },
		{ provider: "nvd", type: "cve", params: { id: "CVE-2021-44228" }, headers: { "User-Agent": "fad-checker-nvd", apiKey: "abc-123" } },
	];
	for (const p of ok) assert.doesNotThrow(() => validateResource(p), JSON.stringify(p));
	const bad = [
		[{ provider: "nvd", type: "cve", params: { id: "CVE-2021-44228", extra: 1 } }, /unexpected field/],
		[{ provider: "nvd", type: "cve", params: { id: 202144228 } }, /invalid value/],
		[{ provider: "nvd", type: "cve", params: {} }, /required/],
		[{ provider: "nvd", type: "cves", params: { id: "CVE-2021-44228" } }, /unknown resource/],
		[{ provider: "epss", type: "current-csv" }, /unknown resource/],
		[{ provider: "maven", type: "artifact", params: { path: "../../etc/passwd" } }, /invalid value/],
		[{ provider: "maven", type: "artifact", params: { path: "org/x/a/1.0/a-1.0.pom", method: "DELETE" } }, /one of/],
		[{ provider: "npm", type: "package", params: { name: "x?y=1" } }, /invalid value/],
		[{ provider: "npm", type: "package", params: { name: ["lodash"] } }, /invalid value/],
		[{ provider: "epss", type: "scores", params: { ids: Array(101).fill("CVE-2021-44228") } }, /items expected/],
		[{ provider: "osv", type: "packages", params: { queries: [{ ecosystem: "Nope", name: "x", version: "1" }] } }, /one of/],
		[{ provider: "nvd", type: "cve", params: { id: "CVE-2021-44228" }, headers: { cookie: "a=b" } }, /not allowed/],
		[{ provider: "nvd", type: "cve", params: { id: "CVE-2021-44228" }, headers: { "user-agent": "a\nb" } }, /invalid value/],
		[{ provider: "nvd", type: "cve", params: { id: "CVE-2021-44228" }, url: "http://evil" }, /unexpected field/],
		[[], /JSON object/],
		[{ provider: "nvd", type: "cve", params: Object.create({ id: "CVE-2021-44228" }) }, /object expected/],
	];
	for (const [p, re] of bad) assert.throws(() => validateResource(p), re, JSON.stringify(p));
});

test("routes: strict query strings and bodies — 400/415 before any lookup", opts, async () => {
	let upstream = 0;
	const s = await site({ fetcher: async () => { upstream++; return json({}); } });
	try {
		for (const [p, code] of [["/search?q=log4j&lang=xx", 400], ["/search?q=log4j&q=x", 400], ["/search?q=log4j&utm=1", 400],
			["/api/search?q=log4j&limit=abc", 400], ["/api/search?q=log4j&limit=1000", 400], ["/search?q=a%00b", 400],
			["/static/site.css?v=../../x", 400], ["/admin/analytics?days=-1", 401], ["/cve/CVE-2021-44228?debug=1", 400],
			["/search?q=log4j&lang=fr&type=cve", 200], ["/api/search?q=log4j&limit=5", 200]])
			assert.equal((await s.get(p)).status, code, p);
		assert.equal((await s.get("/admin/analytics?days=-1", { authorization: `Bearer ${s.admin}` })).status, 400);
		assert.equal((await s.post({ provider: "nvd", type: "cve", params: { id: "CVE-2021-44228" } }, { type: "text/plain" })).status, 415);
		assert.equal((await s.post("{not json")).status, 400);
		const r = await s.post({ provider: "nvd", type: "cve", params: { id: "CVE-2021-44228" }, headers: { cookie: "x" } });
		assert.equal(r.status, 400);
		assert.match((await r.json()).field, /headers/);
		assert.equal((await s.post({ provider: "nvd", type: "cve", params: { id: "nope" } }, { token: s.admin, route: "/admin/purge" })).status, 400);
		assert.equal(upstream, 0, "nothing invalid ever reached an upstream");
	} finally { await s.close(); }
});

test("the real fad client (providers.getResource via --proxy-cache) passes the strict validation", opts, async () => {
	const seen = [];
	const s = await site({ fetcher: async url => {
		seen.push(url);
		if (url.startsWith("https://registry.npmjs.org/")) return json({ name: "left-pad", "dist-tags": { latest: "1.3.0" }, versions: {} });
		if (url.startsWith("https://api.osv.dev/v1/querybatch")) return json({ results: [{ vulns: [] }] });
		if (url.startsWith("https://api.first.org/")) return json({ data: [{ cve: "CVE-2021-44228", epss: "0.9", percentile: "0.99" }] });
		return json({ vulnerabilities: [] });
	} });
	const providers = require(path.join(FAD, "providers"));
	try {
		providers.configureResourceRoute({ proxyUrl: s.base, token: s.client, store: null, health: null, fetcher: globalThis.fetch });
		const npm = await providers.getResource("npm", "package", { name: "left-pad" }, { headers: { "User-Agent": "fad-checker-npm" } });
		assert.equal(npm.status, 200);
		const osv = await providers.getResource("osv", "packages", { queries: [{ ecosystem: "npm", name: "left-pad", version: "1.3.0" }] }, { headers: { "User-Agent": "fad-checker-osv" } });
		assert.equal(osv.status, 200, await osv.clone().text());
		const nvd = await providers.getResource("nvd", "cve", { id: "CVE-2021-44228" }, { headers: { apiKey: "client-key-123" } });
		assert.equal(nvd.status, 200);
		const epss = await providers.getResource("epss", "scores", { ids: ["CVE-2021-44228"] }, { headers: { "User-Agent": "fad-checker-epss" } });
		assert.equal(epss.status, 200);
		assert.equal(seen.length, 4);
	} finally {
		providers.configureResourceRoute({ proxyUrl: null, token: null, store: null, health: null, fetcher: null });
		await s.close();
	}
});

test("anti-ban: NVD answered from the mirror, no upstream; past the budget a 503, the stale copy when there is one", opts, async () => {
	const { createUpstreamPolicy } = require("../lib/upstream-policy");
	const { extractFromNvdRecord } = require(path.join(FAD, "nvd.js"));
	let upstream = 0;
	const policy = createUpstreamPolicy({ budgets: { nvd: "2/1h" }, clientPerHour: 1000 });
	const s = await site({ admit: policy.admit, fetcher: async () => { upstream++; return json({ vulnerabilities: [] }); } });
	try {
		await s.assets.upsert({ type: "cve", key: "CVE-2021-44228", title: "Log4Shell", data: { id: "CVE-2021-44228", description: "JNDI lookup RCE" }, sources: [] });
		await s.assets.setNvd([{ id: "CVE-2021-44228", vulnStatus: "Analyzed", lastModified: "2025-10-21",
			metrics: [{ version: "3.1", score: 10, severity: "CRITICAL", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", source: "nvd@nist.gov", type: "Primary" }],
			cwes: ["CWE-502"], references: [{ url: "https://logging.apache.org/log4j/2.x/security.html", tags: ["Vendor Advisory"] }], configurations: [] }]);
		const r = await s.post({ provider: "nvd", type: "cve", params: { id: "CVE-2021-44228" } });
		assert.equal(r.headers.get("x-fad-proxy"), "mirror");
		const parsed = extractFromNvdRecord((await r.json()).vulnerabilities[0].cve);
		assert.equal(parsed.score, 10);
		assert.equal(parsed.cvssVersion, "CVSS:3.1");
		assert.deepEqual(parsed.cwes, ["CWE-502"]);
		assert.match(parsed.description, /JNDI/);
		assert.equal(upstream, 0, "a mirrored CVE never reaches NVD");

		// Unknown CVEs go upstream — within the budget only.
		const ask = id => s.post({ provider: "nvd", type: "cve", params: { id } });
		assert.equal((await ask("CVE-2099-0001")).status, 200);
		assert.equal((await ask("CVE-2099-0002")).status, 200);
		const denied = await ask("CVE-2099-0003");
		assert.equal(denied.status, 503);
		assert.ok(Number(denied.headers.get("retry-after")) > 0);
		assert.equal(upstream, 2, "the budget is never exceeded");
		assert.equal(policy.stats.deniedSource, 1);
	} finally { await s.close(); }
});

test("anti-ban: one client cannot spend everyone's budget", opts, async () => {
	const { createUpstreamPolicy } = require("../lib/upstream-policy");
	let upstream = 0;
	const policy = createUpstreamPolicy({ budgets: { npm: "100/1s" }, clientPerHour: 2 });
	const s = await site({ admit: policy.admit, fetcher: async () => { upstream++; return json({ name: "x", "dist-tags": {}, versions: {} }); } });
	try {
		const other = (await s.tokens.add({ role: "client" })).token;
		const ask = (name, token) => s.post({ provider: "npm", type: "package", params: { name } }, { token });
		assert.equal((await ask("a1", s.client)).status, 200);
		assert.equal((await ask("a2", s.client)).status, 200);
		assert.equal((await ask("a3", s.client)).status, 503, "this client's hourly upstream allowance is spent");
		assert.equal((await ask("a1", s.client)).status, 200, "cache hits stay free");
		assert.equal((await ask("b1", other)).status, 200, "other clients are unaffected");
		assert.equal(upstream, 3);
	} finally { await s.close(); }
});

test("search input: whitelist characters, minimum lengths, no prefix on short words", () => {
	const { searchTerms, ftsQuery, tsQuery } = require("../lib/assets");
	assert.deepEqual(searchTerms("a"), []);
	assert.deepEqual(searchTerms("%*\"()"), []);
	assert.deepEqual(searchTerms("x\u0000log4j"), [], "control characters reject the whole query");
	assert.deepEqual(searchTerms("ab log4j"), [{ word: "ab", prefix: false }, { word: "log4j", prefix: true }]);
	assert.equal(searchTerms("w".repeat(65)).length, 0, "a 65-character word is dropped");
	assert.equal(searchTerms(Array(20).fill("word").join(" ")).length, 8);
	assert.equal(ftsQuery("NEAR(log4j) OR *"), '"NEAR"* "log4j"* "OR"');
	assert.equal(tsQuery("'); DROP TABLE x; --"), "drop:* & table:*");
	assert.equal(ftsQuery("%%%"), null);
});
