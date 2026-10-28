/**
 * Detailed capability tests for EVERY codec: EOL detection, registry findings
 * (deprecated / abandoned / yanked / inactive / deprecation) + outdated, fix
 * recipes, and report rendering of each finding type.
 *
 * Network is avoided by seeding the on-disk caches with synthetic data (the live
 * fetch is bypassed on a cache hit). Real cache files are backed up + restored.
 */
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { makeDepRecord } = require("../lib/dep-record");
const outdated = require("../lib/outdated");
const { findEolProduct, findCycleForVersion, isEol, checkEolDeps, EOL_MAPPING, EOL_CACHE_PATH } = outdated;

const CACHE_DIR = path.join(os.homedir(), ".vigie-vuln");
// Seeds a REAL cache file under ~/.vigie-vuln for the duration of `fn`, then restores the
// user's file. `fn` is async (checkEolDeps saves the cache at its END), so it MUST be awaited
// here — restoring before it finishes lets its final save overwrite the user's real cache.
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
const mapOf = (...recs) => { const m = new Map(); for (const r of recs) m.set(r.coordKey, r); return m; };
const dep = (ecosystem, namespace, name, version) => makeDepRecord({ ecosystem, namespace, name, version, manifestPath: "x" });

/* ===================== EOL detection (end-to-end, seeded cycles) ===================== */

const EOL_FIXTURE = {
	meta: { fetchedAt: Date.now() },
	entries: {
		django: [{ cycle: "2.2", eol: "2020-01-01" }, { cycle: "4.2", eol: "2099-01-01" }],
		numpy: [{ cycle: "1.20", eol: "2020-01-01" }],
		symfony: [{ cycle: "4.4", eol: "2020-01-01" }],
		laravel: [{ cycle: "8", eol: "2020-01-01" }],
		dotnet: [{ cycle: "2.1", eol: "2020-01-01" }, { cycle: "3.1", eol: "2020-01-01" }],
		"spring-boot": [{ cycle: "2.5", eol: "2020-01-01" }],
		angularjs: [{ cycle: "1.8", eol: "2020-01-01" }],
	},
};

test("EOL: detected end-to-end for maven/npm/composer/pypi/nuget (seeded cycles)", async () => {
	const deps = mapOf(
		dep("maven", "org.springframework.boot", "spring-boot-starter-parent", "2.5.0"),
		dep("npm", "", "angular", "1.8.3"),
		dep("composer", "symfony", "console", "4.4.0"),
		dep("composer", "laravel", "framework", "8.0.0"),
		dep("pypi", "", "django", "2.2.0"),
		dep("pypi", "", "numpy", "1.20.0"),
		dep("nuget", "", "Microsoft.AspNetCore.App", "2.1.0"),
		dep("nuget", "", "Microsoft.EntityFrameworkCore", "3.1.0"),
	);
	const results = await withSeededCache(EOL_CACHE_PATH, EOL_FIXTURE, () => checkEolDeps(deps, { offline: true }));
	const byCoord = new Map(results.map(r => [`${r.dep.ecosystem}:${r.dep.name || r.dep.artifactId}@${r.dep.version}`, r]));
	for (const k of [
		"maven:spring-boot-starter-parent@2.5.0", "npm:angular@1.8.3",
		"composer:console@4.4.0", "composer:framework@8.0.0",
		"pypi:django@2.2.0", "pypi:numpy@1.20.0",
		"nuget:Microsoft.AspNetCore.App@2.1.0", "nuget:Microsoft.EntityFrameworkCore@3.1.0",
	]) assert.ok(byCoord.has(k), `expected EOL finding for ${k}`);
	// Result shape carries product label + cycle + eol date.
	const dj = byCoord.get("pypi:django@2.2.0");
	assert.strictEqual(dj.product, "Django");
	assert.strictEqual(dj.cycle, "2.2");

	// A non-EOL version (Django 4.2, eol in the future) must NOT be flagged.
	const fresh = mapOf(dep("pypi", "", "django", "4.2.0"));
	const none = await withSeededCache(EOL_CACHE_PATH, EOL_FIXTURE, () => checkEolDeps(fresh, { offline: true }));
	assert.strictEqual(none.length, 0, "non-EOL django 4.2 must NOT be flagged");
});

test("EOL: every product slug in eol-mapping.json is a known-valid endoflife.date slug", () => {
	// Guards against dead slugs. Verified against endoflife.date/api/all.json on 2026-09-18:
	// these are CANONICAL ids that resolve 200 directly. The previous list accepted seven that
	// do not exist — "hibernate", "jetty" and "maven" only answer through a 301, and "netty",
	// "jackson", "junit" and "logback" are plain 404s, so any rule pointing at them could never
	// produce a verdict while still implying the product was covered.
	const VALID = new Set([
		"spring-boot", "spring-framework", "spring-security", "spring-cloud",
		"hibernate-orm", "tomcat", "eclipse-jetty", "apache-maven", "log4j",
		"angular", "angularjs", "react", "vue", "jquery", "bootstrap",
		"django", "numpy", "symfony", "laravel", "drupal", "php", "dotnet",
	]);
	const collect = obj => Object.values(obj || {}).map(v => v.product);
	const products = [
		...collect(EOL_MAPPING.by_group_artifact), ...collect(EOL_MAPPING.by_group_prefix),
		...collect(EOL_MAPPING.by_npm_name), ...collect(EOL_MAPPING.by_npm_scope),
		...collect(EOL_MAPPING.by_composer_name), ...collect(EOL_MAPPING.by_pypi_name),
		...collect(EOL_MAPPING.by_nuget_name),
	];
	const bad = [...new Set(products)].filter(p => !VALID.has(p));
	assert.deepStrictEqual(bad, [], `eol-mapping references unknown endoflife.date slugs: ${bad.join(", ")}`);
});

test("EOL: findCycleForVersion matches by cycle prefix; isEol respects dates", () => {
	const cycles = [{ cycle: "4.4", eol: "2020-01-01" }, { cycle: "5.4", eol: "2099-01-01" }, { cycle: "6.0", eol: true }];
	assert.strictEqual(findCycleForVersion(cycles, "4.4.7").cycle, "4.4");
	assert.strictEqual(findCycleForVersion(cycles, "5.4.0").cycle, "5.4");
	assert.strictEqual(findCycleForVersion(cycles, "9.9.9"), null);
	assert.strictEqual(isEol({ eol: "2020-01-01" }), true);
	assert.strictEqual(isEol({ eol: "2099-01-01" }), false);
	assert.strictEqual(isEol({ eol: true }), true);
	assert.strictEqual(isEol({ eol: false }), false);
});

/* ===================== Registry findings (seeded per-registry caches) ===================== */

test("composer registry: abandoned → deprecated entry + outdated entry", async () => {
	const { checkComposerRegistryDeps } = require("../lib/codecs/composer/registry");
	const deps = mapOf(dep("composer", "guzzlehttp", "guzzle", "6.0.0"));
	const seeded = { meta: { fetchedAt: Date.now() }, entries: { "guzzlehttp/guzzle@6.0.0": { abandoned: { replacement: "psr/http-client" }, latest: "7.5.0" } } };
	const r = await withSeededCache(path.join(CACHE_DIR, "packagist-cache.json"), seeded, () => checkComposerRegistryDeps(deps, { allLibs: true }));
	assert.strictEqual(r.deprecated.length, 1);
	assert.deepStrictEqual({ sev: r.deprecated[0].severity, repl: r.deprecated[0].replacement, src: r.deprecated[0].source }, { sev: "MEDIUM", repl: "psr/http-client", src: "packagist" });
	assert.match(r.deprecated[0].reason, /abandoned/i);
	assert.deepStrictEqual({ name: r.outdated[0].dep.name, latest: r.outdated[0].latest }, { name: "guzzle", latest: "7.5.0" });
});

test("pypi registry: yanked → HIGH; inactive → LOW; + outdated", async () => {
	const { checkPypiRegistryDeps } = require("../lib/codecs/pypi/registry");
	const deps = mapOf(dep("pypi", "", "django", "2.2.0"), dep("pypi", "", "oldlib", "1.0.0"));
	const seeded = { meta: { fetchedAt: Date.now() }, entries: {
		"django@2.2.0": { yanked: { reason: "security" }, inactive: false, latest: "4.2.0" },
		"oldlib@1.0.0": { yanked: null, inactive: true, latest: null },
	} };
	const r = await withSeededCache(path.join(CACHE_DIR, "pypi-cache.json"), seeded, () => checkPypiRegistryDeps(deps, { allLibs: true }));
	const byName = Object.fromEntries(r.deprecated.map(d => [d.dep.name, d]));
	assert.strictEqual(byName.django.severity, "HIGH");
	assert.match(byName.django.reason, /yank/i);
	assert.strictEqual(byName.django.source, "pypi");
	assert.strictEqual(byName.oldlib.severity, "LOW");
	assert.match(byName.oldlib.reason, /inactive/i);
	assert.ok(r.outdated.find(o => o.dep.name === "django" && o.latest === "4.2.0"));
});

test("nuget registry: deprecation → deprecated entry with replacement + outdated", async () => {
	const { checkNugetRegistryDeps } = require("../lib/codecs/nuget/registry");
	const deps = mapOf(dep("nuget", "", "Newtonsoft.Json", "9.0.1"));
	const seeded = { meta: { fetchedAt: Date.now() }, entries: { "newtonsoft.json@9.0.1": { deprecated: { reason: "Legacy", replacement: "System.Text.Json" }, latest: "13.0.3" } } };
	const r = await withSeededCache(path.join(CACHE_DIR, "nuget-cache.json"), seeded, () => checkNugetRegistryDeps(deps, { allLibs: true }));
	assert.strictEqual(r.deprecated.length, 1);
	assert.deepStrictEqual({ sev: r.deprecated[0].severity, repl: r.deprecated[0].replacement, src: r.deprecated[0].source }, { sev: "MEDIUM", repl: "System.Text.Json", src: "nuget" });
	assert.strictEqual(r.outdated[0].latest, "13.0.3");
});

test("registry: --no-all-libs suppresses outdated but keeps deprecation", async () => {
	const { checkComposerRegistryDeps } = require("../lib/codecs/composer/registry");
	const deps = mapOf(dep("composer", "guzzlehttp", "guzzle", "6.0.0"));
	const seeded = { meta: { fetchedAt: Date.now() }, entries: { "guzzlehttp/guzzle@6.0.0": { abandoned: { replacement: null }, latest: "7.5.0" } } };
	const r = await withSeededCache(path.join(CACHE_DIR, "packagist-cache.json"), seeded, () => checkComposerRegistryDeps(deps, { allLibs: false }));
	assert.strictEqual(r.deprecated.length, 1, "deprecation still reported without allLibs");
	assert.strictEqual(r.outdated.length, 0, "outdated gated by allLibs");
});

/* ===================== Fix recipes ===================== */

test("recipes: each ecosystem emits the right install/pin command", () => {
	const recipes = require("../lib/codecs/recipes");
	assert.match(recipes.maven.snippet([{ groupId: "g", artifactId: "a", fixVersion: "1.2.3" }]), /<dependencyManagement>[\s\S]*<artifactId>a<\/artifactId>[\s\S]*1\.2\.3/);
	assert.match(recipes.npm.snippet([{ artifactId: "lodash", fixVersion: "4.17.21" }]), /"overrides"[\s\S]*"lodash": "4\.17\.21"/);
	assert.match(recipes.yarn.snippet([{ artifactId: "lodash", fixVersion: "4.17.21" }]), /"resolutions"[\s\S]*"lodash": "4\.17\.21"/);
	assert.match(recipes.composer.snippet([{ groupId: "guzzlehttp", artifactId: "guzzle", fixVersion: "7.5.0" }]), /composer require guzzlehttp\/guzzle:\^7\.5\.0/);
	assert.match(recipes.pypi.snippet([{ artifactId: "django", fixVersion: "4.2.0" }]), /pip install 'django>=4\.2\.0'/);
	assert.match(recipes.nuget.snippet([{ artifactId: "Newtonsoft.Json", fixVersion: "13.0.3" }]), /dotnet add package Newtonsoft\.Json --version 13\.0\.3/);
});

/* ===================== Report rendering of EOL / Obsolete / Outdated per ecosystem ===================== */

test("report: renders EOL + Obsolete + Outdated findings for all ecosystems", () => {
	const { generateHtmlReport } = require("../lib/cve-report");
	const d = (eco, ns, name, ver) => ({ ...dep(eco, ns, name, ver) });
	const html = generateHtmlReport({
		cveMatches: [],
		eolResults: [
			{ dep: d("composer", "symfony", "console", "4.4.0"), product: "Symfony", cycle: "4.4", eol: "2023-11-21" },
			{ dep: d("pypi", "", "django", "2.2.0"), product: "Django", cycle: "2.2", eol: "2022-04-11" },
			{ dep: d("nuget", "", "Microsoft.AspNetCore.App", "2.1.0"), product: "ASP.NET Core (.NET)", cycle: "2.1", eol: "2021-08-21" },
		],
		obsoleteResults: [
			{ dep: d("composer", "guzzlehttp", "guzzle", "6.0.0"), severity: "MEDIUM", replacement: "psr/http-client", reason: "abandoned" },
			{ dep: d("pypi", "", "oldlib", "1.0.0"), severity: "LOW", replacement: null, reason: "Inactive" },
			{ dep: d("nuget", "", "Newtonsoft.Json", "9.0.1"), severity: "MEDIUM", replacement: "System.Text.Json", reason: "Legacy" },
		],
		outdatedResults: [
			{ dep: d("composer", "symfony", "console", "4.4.0"), latest: "6.4.0" },
			{ dep: d("pypi", "", "numpy", "1.20.0"), latest: "2.0.0" },
			{ dep: d("nuget", "", "Newtonsoft.Json", "9.0.1"), latest: "13.0.3" },
		],
		projectInfo: { name: "caps", generatedAt: "2026-05-30", toolVersion: "test" },
	});
	assert.ok(html.startsWith("<!doctype html>"));
	// EOL products
	for (const s of ["Symfony", "Django", "ASP.NET Core"]) assert.ok(html.includes(s), `EOL: ${s}`);
	// Obsolete replacements + reasons
	for (const s of ["psr/http-client", "System.Text.Json", "Inactive"]) assert.ok(html.includes(s), `Obsolete: ${s}`);
	// Outdated latest versions
	for (const s of ["6.4.0", "2.0.0", "13.0.3"]) assert.ok(html.includes(s), `Outdated: ${s}`);
	// Each ecosystem's coordinate is shown
	for (const s of ["symfony/console", "django", "Newtonsoft.Json"]) assert.ok(html.includes(s), `coord: ${s}`);
});
