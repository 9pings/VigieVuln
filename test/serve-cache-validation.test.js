// serve-cache exposed on a network: the /v1/resource document is typed strictly BEFORE any
// lookup (lib/resource-cache/validate.js — the same whitelist fad-service applies), and the
// providers that put a client value in an upstream PATH encode every segment, so no query,
// fragment or dot-segment can be smuggled to the upstream host. Zero network.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { startProxyCacheServer, createCacheStore } = require("../lib/proxy-cache");
const { validateResource } = require("../lib/resource-cache/validate");

test("providers: Maven / NuGet / Go paths are encoded segment by segment, dot-segments refused", () => {
	const maven = require("../lib/providers/maven"), nuget = require("../lib/providers/nuget"), go = require("../lib/providers/go");
	assert.equal(maven.build("artifact", { path: "org/x/a/1.0/a-1.0.pom" }).url, "https://repo1.maven.org/maven2/org/x/a/1.0/a-1.0.pom");
	const tricky = maven.build("artifact", { path: "org/%2e%2e/a?b#c/x.pom" }).url;
	assert.equal(tricky, "https://repo1.maven.org/maven2/org/%252e%252e/a%3Fb%23c/x.pom");
	assert.equal(new URL(tricky).search, "");
	assert.equal(new URL(tricky).hash, "");
	assert.throws(() => maven.build("artifact", { path: "org/../../etc/passwd" }), /invalid Maven/);
	assert.throws(() => maven.build("artifact", { path: "org/./a" }), /invalid Maven/);
	assert.equal(nuget.build("registration-page", { path: "/v3/registration5-gz-semver2/x/page/1.0/2.0.json" }).url,
		"https://api.nuget.org/v3/registration5-gz-semver2/x/page/1.0/2.0.json");
	assert.throws(() => nuget.build("registration-page", { path: "/v3/../admin.json" }), /invalid NuGet/);
	assert.throws(() => nuget.build("registration-page", { path: "/v3/x.json?y=1.json" }), /invalid NuGet/);
	assert.equal(go.build("module-latest", { module: "github.com/!burnt!sushi/toml" }).url, "https://proxy.golang.org/github.com/!burnt!sushi/toml/@latest");
	for (const module of ["github.com/x/../y", "github.com/x?y", "github.com/%2e%2e/y", "github.com/x#y", "/github.com/x"])
		assert.throws(() => go.build("module-latest", { module }), /invalid Go/, module);
});

test("validate: OSV queries in fad's flat form or OSV's nested form, both normalised; nothing else", () => {
	const flat = validateResource({ provider: "osv", type: "packages", params: { queries: [{ ecosystem: "npm", name: "a", version: "1.0.0" }] } });
	const nested = validateResource({ provider: "osv", type: "packages", params: { queries: [{ package: { ecosystem: "npm", name: "a" }, version: "1.0.0" }] } });
	assert.deepEqual(nested.params, flat.params);
	for (const q of [
		{ package: { ecosystem: "npm", name: "a", purl: "pkg:npm/a" }, version: "1" },     // unknown nested field
		{ package: { ecosystem: "npm", name: "a" }, ecosystem: "npm", version: "1" },      // both forms at once
		{ package: { ecosystem: "Nope", name: "a" }, version: "1" },
		{ ecosystem: "npm", name: "a b", version: "1" },
		{ ecosystem: "npm", name: "a" },
	]) assert.throws(() => validateResource({ provider: "osv", type: "packages", params: { queries: [q] } }), /invalid|unexpected|required|one of/, JSON.stringify(q));
});

test("serve-cache: an invalid /v1/resource document is a 400 before any lookup or upstream request", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-sc-validate-"));
	let upstream = 0;
	const h = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(dir),
		fetcher: async () => { upstream++; return new Response("{}", { headers: { "content-type": "application/json" } }); } });
	const post = body => fetch(h.url + "/v1/resource", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
	try {
		for (const body of [
			{ provider: "maven", type: "artifact", params: { path: "org/../../x" } },
			{ provider: "go", type: "module-latest", params: { module: "x?y" } },
			{ provider: "npm", type: "package", params: { name: "express/../x" } },
			{ provider: "npm", type: "package", params: { name: "express", extra: 1 } },
			{ provider: "nope", type: "x", params: {} },
			{ provider: "nvd", type: "cve", params: { id: "CVE-2024-1" } },
		]) {
			const r = await post(body);
			assert.equal(r.status, 400, JSON.stringify(body));
			assert.ok((await r.json()).error);
		}
		assert.equal(upstream, 0, "no refused request reached an upstream");
		assert.equal((await post({ provider: "npm", type: "package", params: { name: "express" } })).status, 200);
		assert.equal(upstream, 1);
	} finally { await new Promise(ok => h.server.close(ok)); fs.rmSync(dir, { recursive: true, force: true }); }
});
