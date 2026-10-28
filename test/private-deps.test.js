/**
 * "Absent from every registry" — the private-dependency signal, outside Maven.
 *
 * The danger here is the inverse of a missed finding: telling a client they ship internal
 * packages because their proxy timed out. Only a definitive answer from EVERY base counts.
 */
const test = require("node:test");
const assert = require("node:assert");
const { isAbsentStatus, classifyLookup, foldAbsent, buildPrivateItems } = require("../lib/private-deps");

test("404 and Go's 410 are definitive; nothing else is", () => {
	assert.strictEqual(isAbsentStatus(404), true);
	assert.strictEqual(isAbsentStatus(410), true);
	for (const s of [200, 401, 403, 429, 500, 502, 503]) assert.strictEqual(isAbsentStatus(s), false, String(s));
});

test("a successful lookup is 'found'", () => {
	assert.strictEqual(classifyLookup({ name: "lodash" }), "found");
});

test("absent only when the codec folded it as such", () => {
	assert.strictEqual(classifyLookup({ error: "HTTP 404", absent: true }), "absent");
	assert.strictEqual(classifyLookup({ error: "HTTP 404" }), "unknown");
});

test("a failure that is not a definitive answer is 'unknown', never 'absent'", () => {
	for (const e of ["timeout after 15000ms", "HTTP 500", "HTTP 403", "ECONNREFUSED", "no data"]) {
		assert.strictEqual(classifyLookup({ error: e, absent: false }), "unknown", e);
	}
});

test("offline / never attempted is 'unknown'", () => {
	assert.strictEqual(classifyLookup(null), "unknown");
});

test("every base must answer 404 — one inconclusive base poisons the verdict", () => {
	assert.strictEqual(foldAbsent([404]), true);
	assert.strictEqual(foldAbsent([404, 404]), true);
	assert.strictEqual(foldAbsent([404, 410]), true);
	// the private registry timed out and the public one 404'd: the package may well live in
	// the one that did not answer, so this must NOT be reported as private
	assert.strictEqual(foldAbsent([null, 404]), false);
	assert.strictEqual(foldAbsent([503, 404]), false);
	assert.strictEqual(foldAbsent([404, 500]), false);
});

test("asking nobody proves nothing", () => {
	assert.strictEqual(foldAbsent([]), false);
	assert.strictEqual(foldAbsent(null), false);
});

test("items carry the ecosystem and the declaring manifests, in a stable order", () => {
	const items = buildPrivateItems([
		{ ecosystem: "npm", dep: { ecosystem: "npm", namespace: "@acme", name: "ui", manifestPaths: ["/p/package.json"] } },
		{ ecosystem: "pypi", dep: { ecosystem: "pypi", name: "acme-core", manifestPaths: [] } },
		{ ecosystem: "npm", dep: { ecosystem: "npm", namespace: "@acme", name: "api", manifestPaths: [] } },
	], { relativise: p => p.replace("/p/", "") });
	assert.deepStrictEqual(items.map(i => `${i.ecosystem}:${i.id}`),
		["npm:@acme/api", "npm:@acme/ui", "pypi:acme-core"]);
	assert.deepStrictEqual(items[1].manifestPaths, ["package.json"]);
});

test("a Maven coordinate keeps its colon separator", () => {
	const [i] = buildPrivateItems([{ ecosystem: "maven", dep: { ecosystem: "maven", groupId: "com.acme", artifactId: "core" } }]);
	assert.strictEqual(i.id, "com.acme:core");
});

// ---- the signal actually reaches the codec result ----
const { checkComposerRegistryDeps } = require("../lib/codecs/composer/registry");
const os = require("node:os"), path = require("node:path"), fs = require("node:fs");

// Seeds a REAL cache file for the duration of fn, then restores the user's. fn MUST be
// awaited before restoring: the codec saves its cache at the END, and restoring early lets
// that save clobber the user's file — a bug this repo has already been bitten by.
async function withSeededCache(file, data, fn) {
	const had = fs.existsSync(file);
	const backup = had ? fs.readFileSync(file) : null;
	try {
		fs.mkdirSync(path.dirname(file), { recursive: true });
		fs.writeFileSync(file, JSON.stringify(data));
		return await fn();
	} finally {
		if (had) fs.writeFileSync(file, backup); else { try { fs.unlinkSync(file); } catch { /* ignore */ } }
	}
}
const PACKAGIST_CACHE = path.join(os.homedir(), ".vigie-vuln", "packagist-cache.json");

const dep = (name, version) => ({
	ecosystem: "composer", namespace: name.split("/")[0], name: name.split("/")[1],
	version, coordKey: `composer:${name}@${version}`, manifestPaths: ["composer.lock"],
});
const deps = list => new Map(list.map(d => [d.coordKey, d]));

test("Adobe Commerce packages are not looked up in the public Packagist registry", async () => {
	const product = dep("magento/product-enterprise-edition", "2.4.7-p3");
	const marketplace = { ...dep("acme/module-pay", "1.2.3"), occurrences: [{ distHost: "repo.magento.com" }] };
	const fetcher = async () => { throw new Error("wrong registry queried"); };
	const result = await checkComposerRegistryDeps(deps([product, marketplace]), { fetcher });
	assert.deepStrictEqual(result, { deprecated: [], outdated: [], licensed: [], private: [] });
});

test("a package every registry 404s lands in result.private", async () => {
	const fetcher = async () => ({ ok: false, status: 404 });
	const r = await withSeededCache(PACKAGIST_CACHE, { meta: {}, entries: {} }, () =>
		checkComposerRegistryDeps(deps([dep("acme-internal/core", "1.0.0")]), { fetcher, allLibs: true }));
	assert.strictEqual(r.private.length, 1);
	assert.strictEqual(r.private[0].ecosystem, "composer");
	assert.strictEqual(r.private[0].dep.name, "core");
});

test("a registry that TIMES OUT never makes a package look private", async () => {
	// The failure that matters: telling a client they ship internal packages because their
	// proxy was down. An inconclusive answer must leave the package unreported.
	const fetcher = async () => { const e = new Error("timeout"); e.name = "TimeoutError"; throw e; };
	const r = await withSeededCache(PACKAGIST_CACHE, { meta: {}, entries: {} }, () =>
		checkComposerRegistryDeps(deps([dep("acme-internal/core", "1.0.0")]), { fetcher, allLibs: true }));
	assert.strictEqual(r.private.length, 0);
});

test("a 500 from the registry is not a verdict either", async () => {
	const fetcher = async () => ({ ok: false, status: 503 });
	const r = await withSeededCache(PACKAGIST_CACHE, { meta: {}, entries: {} }, () =>
		checkComposerRegistryDeps(deps([dep("acme-internal/core", "1.0.0")]), { fetcher, allLibs: true }));
	assert.strictEqual(r.private.length, 0);
});
