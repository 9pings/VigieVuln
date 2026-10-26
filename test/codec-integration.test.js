/**
 * Cross-ecosystem integration tests — exercise all codecs together the way the
 * orchestrator does: detect → collect → merge into one Map → shared services.
 */
const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { allCodecs, getCodec, detectCodecs } = require("../lib/codecs");
const { assertCodecShape } = require("../lib/codecs/codec.interface");
const { osvEcosystemFor, osvPkgName } = require("../lib/osv");
const { findEolProduct } = require("../lib/outdated");
const { generateHtmlReport } = require("../lib/cve-report");

const POLY = path.join(__dirname, "fixtures", "polyglot");

// Collect every active codec into one Map, exactly like vigievuln.js main().
async function collectAll(dir) {
	const resolved = new Map();
	const warnings = [];
	for (const id of (await detectCodecs(dir)).map(c => c.id)) {
		if (id === "yarn") continue;
		const { deps, warnings: w } = await getCodec(id).collect(dir, {});
		for (const [k, v] of deps) resolved.set(k, v);
		if (w) warnings.push(...w);
	}
	return { resolved, warnings };
}

test("every registered codec satisfies the interface contract", () => {
	for (const c of allCodecs()) assertCodecShape(c);
});

test("detectCodecs finds all five ecosystems in the polyglot tree", async () => {
	const ids = (await detectCodecs(POLY)).map(c => c.id).sort();
	assert.deepStrictEqual(ids, ["composer", "maven", "npm", "nuget", "pypi"]);
});

test("collecting all codecs merges into one Map with NO coordKey collisions", async () => {
	const { resolved } = await collectAll(POLY);
	// Every key unique (Map guarantees) AND every record's coordKey === its key.
	for (const [k, d] of resolved) {
		assert.strictEqual(d.coordKey, k, `coordKey mismatch for ${k}`);
		assert.ok(d.ecosystem, `missing ecosystem for ${k}`);
		assert.ok(d.name, `missing name for ${k}`);
	}
	// All five ecosystems represented.
	const ecos = new Set([...resolved.values()].map(d => d.ecosystem));
	for (const e of ["maven", "npm", "composer", "pypi", "nuget"]) assert.ok(ecos.has(e), `missing ${e} deps`);
	// Spot-check one coord per ecosystem.
	assert.ok(resolved.has("org.apache.logging.log4j:log4j-core"));
	assert.ok(resolved.has("npm:lodash"));
	assert.ok(resolved.has("composer:guzzlehttp/guzzle"));
	assert.ok(resolved.has("pypi:requests"));
	assert.ok(resolved.has("nuget:newtonsoft.json"));
});

test("coordKeys from different ecosystems never collide even for same bare name", () => {
	const { coordKeyFor } = require("../lib/dep-record");
	const keys = [
		coordKeyFor("maven", "org.x", "thing"),
		coordKeyFor("npm", "", "thing"),
		coordKeyFor("composer", "vendor", "thing"),
		coordKeyFor("pypi", "", "thing"),
		coordKeyFor("nuget", "", "thing"),
	];
	assert.strictEqual(new Set(keys).size, keys.length, `collision among ${keys.join(", ")}`);
});

test("osv ecosystem + package name are correct for every codec", () => {
	const cases = [
		{ dep: { ecosystem: "maven", namespace: "org.apache", name: "log4j-core", groupId: "org.apache", artifactId: "log4j-core" }, eco: "Maven", pkg: "org.apache:log4j-core" },
		{ dep: { ecosystem: "npm", namespace: "", name: "lodash", artifactId: "lodash" }, eco: "npm", pkg: "lodash" },
		{ dep: { ecosystem: "composer", namespace: "guzzlehttp", name: "guzzle" }, eco: "Packagist", pkg: "guzzlehttp/guzzle" },
		{ dep: { ecosystem: "pypi", namespace: "", name: "requests" }, eco: "PyPI", pkg: "requests" },
		{ dep: { ecosystem: "nuget", namespace: "", name: "Newtonsoft.Json" }, eco: "NuGet", pkg: "Newtonsoft.Json" },
	];
	for (const c of cases) {
		assert.strictEqual(osvEcosystemFor(c.dep), c.eco, `osv eco for ${c.dep.ecosystem}`);
		assert.strictEqual(osvPkgName(c.dep), c.pkg, `osv pkg for ${c.dep.ecosystem}`);
	}
});

test("findEolProduct dispatches per ecosystem to the right product", () => {
	assert.strictEqual(findEolProduct({ ecosystem: "maven", groupId: "org.apache.logging.log4j", artifactId: "log4j-core", namespace: "org.apache.logging.log4j", name: "log4j-core" })?.product, "log4j");
	assert.strictEqual(findEolProduct({ ecosystem: "npm", artifactId: "angular", name: "angular" })?.product, "angularjs");
	assert.strictEqual(findEolProduct({ ecosystem: "composer", namespace: "symfony", name: "console" })?.product, "symfony");
	assert.strictEqual(findEolProduct({ ecosystem: "pypi", name: "django" })?.product, "django");
	assert.strictEqual(findEolProduct({ ecosystem: "nuget", name: "Microsoft.EntityFrameworkCore" })?.product, "dotnet");
	// unknown → null
	assert.strictEqual(findEolProduct({ ecosystem: "pypi", name: "totally-unknown-pkg" }), null);
});

test("generateHtmlReport renders findings from every ecosystem without throwing", async () => {
	const { resolved } = await collectAll(POLY);
	const deps = [...resolved.values()];
	const mk = d => ({ dep: d, cve: { id: `CVE-TEST-${d.ecosystem}`, severity: "HIGH", score: 7.5, description: `vuln in ${d.name}` }, source: "osv", confidence: "exact" });
	const html = generateHtmlReport({
		cveMatches: deps.map(mk),
		eolResults: [], obsoleteResults: [], outdatedResults: [],
		resolvedDeps: resolved,
		projectInfo: { name: "polyglot", generatedAt: "2026-05-29", toolVersion: "test" },
	});
	assert.ok(html.startsWith("<!doctype html>"));
	// Each ecosystem's section label should appear.
	for (const label of ["Maven", "npm", "Composer", "PyPI", "NuGet"]) {
		assert.ok(html.includes(label), `report should mention ${label}`);
	}
	// Ecosystem-tagged coordinates render (non-maven get a prefix).
	assert.ok(html.includes("composer:") || html.includes("guzzlehttp/guzzle"));
});

test("every codec recipe renders a non-empty snippet from a sample finding", () => {
	const sample = [{ groupId: "g", artifactId: "pkg", fixVersion: "1.2.3" }];
	for (const c of allCodecs()) {
		const out = c.recipe.snippet(sample);
		assert.strictEqual(typeof out, "string");
		assert.ok(out.length > 0, `${c.id} recipe snippet empty`);
	}
});
