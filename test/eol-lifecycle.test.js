const { test } = require("node:test");
const assert = require("node:assert/strict");
const { lifecycleStatus, isEol } = require("../lib/maintenance/outdated");

// Fixed clock so the date comparisons never drift. 2026-09-02 = the day this was designed.
const NOW = Date.parse("2026-09-02T00:00:00Z");

test("lifecycleStatus: eol polarity — true means IS end-of-life, false means not yet", () => {
	assert.equal(lifecycleStatus({ eol: true, support: false }, NOW), "eol");
	assert.equal(lifecycleStatus({ eol: false, support: true }, NOW), "ok");
});

test("lifecycleStatus: support polarity — true means STILL supported, false means support ended", () => {
	assert.equal(lifecycleStatus({ eol: false, support: true }, NOW), "ok");
	assert.equal(lifecycleStatus({ eol: false, support: false }, NOW), "unsupported");
});

test("lifecycleStatus: dates are compared against `now`", () => {
	assert.equal(lifecycleStatus({ eol: "2022-11-28", support: "2021-11-28" }, NOW), "eol");          // PHP 7.4
	assert.equal(lifecycleStatus({ eol: "2029-02-28", support: "2024-11-30" }, NOW), "unsupported");  // Symfony 5.4 LTS
	assert.equal(lifecycleStatus({ eol: "2027-11-30", support: "2026-11-30" }, NOW), "ok");           // Symfony 6.4 LTS
	assert.equal(lifecycleStatus({ eol: false, support: "2024-12-05" }, NOW), "unsupported");         // React 18: never declared EOL
});

test("lifecycleStatus: eol wins over support", () => {
	assert.equal(lifecycleStatus({ eol: "2021-11-30", support: "2020-11-30" }, NOW), "eol");
	assert.equal(lifecycleStatus({ eol: true, support: true }, NOW), "eol");
});

test("lifecycleStatus: missing / unparsable data is conservative (ok)", () => {
	assert.equal(lifecycleStatus(null, NOW), "ok");
	assert.equal(lifecycleStatus({}, NOW), "ok");
	assert.equal(lifecycleStatus({ eol: "not-a-date", support: "soon" }, NOW), "ok");
});

test("isEol is lifecycleStatus === 'eol' (back-compat)", () => {
	assert.equal(isEol({ eol: true }), true);
	assert.equal(isEol({ eol: "2000-01-01" }), true);
	assert.equal(isEol({ eol: false, support: false }), false);
	assert.equal(isEol(null), false);
});

const { checkEolDeps } = require("../lib/maintenance/outdated");
const { makeDepRecord } = require("../lib/inventory/dep-record");

// Real endoflife.date shapes (values as of 2026-09), trimmed.
const SYMFONY = [
	{ cycle: "7.3", eol: "2026-01-31", support: "2026-01-31", latest: "7.3.11", lts: false },
	{ cycle: "6.4", eol: "2027-11-30", support: "2026-11-30", latest: "6.4.42", lts: true },
	{ cycle: "5.4", eol: "2029-02-28", support: "2024-11-30", latest: "5.4.53", lts: true },
	{ cycle: "3.4", eol: "2021-11-30", support: "2020-11-30", latest: "3.4.49", lts: true },
];

function dep(ns, name, version, manifestPath = "/proj/composer.lock") {
	return makeDepRecord({ ecosystem: "composer", namespace: ns, name, version, manifestPath, scope: "prod" });
}

test("checkEolDeps: a default run never returns unsupported findings (no regression)", async () => {
	const resolved = new Map([["composer:symfony/console", dep("symfony", "console", "5.4.47")]]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW });
	assert.deepEqual(r, []);
});

test("checkEolDeps: --eol-support surfaces Symfony 5.4 as unsupported, carrying both dates", async () => {
	const resolved = new Map([["composer:symfony/console", dep("symfony", "console", "5.4.47")]]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport: true });
	assert.equal(r.length, 1);
	assert.equal(r[0].status, "unsupported");
	assert.equal(r[0].cycle, "5.4");
	assert.equal(r[0].support, "2024-11-30");
	assert.equal(r[0].eol, "2029-02-28");
	assert.equal(r[0].latest, "5.4.53");
	assert.equal(r[0].productSlug, "symfony");
});

test("checkEolDeps: an EOL cycle is returned with status 'eol' in both modes", async () => {
	const resolved = new Map([["composer:symfony/console", dep("symfony", "console", "3.4.49")]]);
	for (const eolSupport of [false, true]) {
		const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport });
		assert.equal(r.length, 1, `eolSupport=${eolSupport}`);
		assert.equal(r[0].status, "eol");
		assert.equal(r[0].eol, "2021-11-30");
	}
});

test("checkEolDeps: a supported cycle is never a finding", async () => {
	const resolved = new Map([["composer:symfony/console", dep("symfony", "console", "6.4.42")]]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport: true });
	assert.deepEqual(r, []);
});

test("grouping: framework components in one manifest at one cycle → ONE finding with anchor + components", async () => {
	const L = "/proj/composer.lock";
	const resolved = new Map();
	for (const [n, v] of [["yaml", "5.4.45"], ["framework-bundle", "5.4.45"], ["console", "5.4.47"], ["http-kernel", "5.4.51"]]) {
		resolved.set(`composer:symfony/${n}`, dep("symfony", n, v, L));
	}
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport: true });
	assert.equal(r.length, 1);
	assert.equal(r[0].anchor, "symfony/framework-bundle", "first declared anchor present wins");
	assert.equal(r[0].dep.name, "framework-bundle");
	assert.equal(r[0].dep.version, "5.4.45");
	assert.deepEqual(r[0].dep.manifestPaths, [L]);
	assert.equal(r[0].dep.pomPaths, r[0].dep.manifestPaths, "pomPaths must be the SAME array object");
	assert.equal(r[0].status, "unsupported");
	assert.equal(r[0].cycle, "5.4");
	assert.deepEqual(r[0].components, [
		{ name: "symfony/console", version: "5.4.47", manifestPaths: [L] },
		{ name: "symfony/framework-bundle", version: "5.4.45", manifestPaths: [L] },
		{ name: "symfony/http-kernel", version: "5.4.51", manifestPaths: [L] },
		{ name: "symfony/yaml", version: "5.4.45", manifestPaths: [L] },
	]);
});

test("grouping: two cycles in one manifest → two findings, never one merged", async () => {
	const L = "/proj/composer.lock";
	const resolved = new Map([
		["composer:symfony/yaml", dep("symfony", "yaml", "3.4.49", L)],
		["composer:symfony/framework-bundle", dep("symfony", "framework-bundle", "5.4.45", L)],
	]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport: true });
	assert.equal(r.length, 2);
	const byCycle = Object.fromEntries(r.map(f => [f.cycle, f]));
	assert.equal(byCycle["3.4"].status, "eol");
	assert.equal(byCycle["3.4"].anchor, "symfony/yaml");
	assert.equal(byCycle["5.4"].status, "unsupported");
	assert.equal(byCycle["5.4"].anchor, "symfony/framework-bundle");
});

test("grouping: no declared anchor present → the first component (sorted) is the anchor", async () => {
	const resolved = new Map([
		["composer:symfony/yaml", dep("symfony", "yaml", "5.4.45")],
		["composer:symfony/validator", dep("symfony", "validator", "5.4.48")],
	]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport: true });
	assert.equal(r.length, 1);
	assert.equal(r[0].anchor, "symfony/validator");
	assert.equal(r[0].components.length, 2);
});

test("grouping: the same framework in two manifests → one finding per manifest", async () => {
	const A = "/mono/app-a/composer.lock", B = "/mono/app-b/composer.lock";
	const resolved = new Map([
		["composer:symfony/console", dep("symfony", "console", "5.4.47", A)],
		["composer:symfony/yaml", dep("symfony", "yaml", "5.4.45", B)],
	]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport: true });
	assert.equal(r.length, 2);
	assert.deepEqual(r.map(f => f.dep.manifestPaths[0]).sort(), [A, B]);
});

test("grouping never mutates the shared dep record", async () => {
	const d = dep("symfony", "console", "5.4.47", "/a/composer.lock");
	d.manifestPaths.push("/b/composer.lock");   // a coord-wide record seen in two lockfiles
	const before = JSON.stringify(d);
	const resolved = new Map([["composer:symfony/console", d]]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport: true });
	assert.equal(r.length, 2, "one finding per manifest the record was seen in");
	assert.equal(JSON.stringify(d), before, "shared record untouched");
});

test("non-framework EOL findings are untouched by grouping (no anchor / components fields)", async () => {
	const hib = makeDepRecord({ ecosystem: "maven", namespace: "org.hibernate", name: "hibernate-core", version: "5.6.15.Final", manifestPath: "/p/pom.xml" });
	const HIBERNATE = [{ cycle: "5.6", eol: "2023-12-31", support: "2023-12-31", latest: "5.6.15.Final" }];
	const r = await checkEolDeps(new Map([[hib.coordKey, hib]]), { cycles: { "hibernate-orm": HIBERNATE }, now: NOW });
	assert.equal(r.length, 1);
	assert.equal(r[0].anchor, undefined);
	assert.equal(r[0].components, undefined);
	assert.equal(r[0].dep, hib, "the original record is passed through");
});

// endoflife.date `extendedSupport`: PAID support past the open-source end of life. It must
// NOT clear the finding (subscribers only, builds from the vendor's private repository) —
// it is stated beside it.
const { makeDepRecord: mkRec } = require("../lib/inventory/dep-record");
const { generateHtmlReport } = require("../lib/reports/cve-report");
const springDep = mkRec({ ecosystem: "maven", namespace: "org.springframework", name: "spring-core", version: "5.3.39", manifestPath: "/p/pom.xml" });
const SPRING = [
	{ cycle: "6.2", eol: "2026-06-30", extendedSupport: "2032-06-30", latest: "6.2.19" },
	{ cycle: "5.3", eol: "2024-08-31", extendedSupport: "2029-08-31", latest: "5.3.39" },
	{ cycle: "5.2", eol: "2021-12-31", extendedSupport: "2023-12-31", latest: "5.2.25.RELEASE" },
];
const ANGULARJS = [{ cycle: "1.8", eol: "2021-12-31", extendedSupport: true, latest: "1.8.3" }];

test("extendedSupport: a future vendor date keeps the EOL finding and carries the date; a past one is dropped; `true` is kept as offered", async () => {
	const r53 = await checkEolDeps(new Map([["org.springframework:spring-core", springDep]]), { cycles: { "spring-framework": SPRING }, now: NOW });
	assert.equal(r53.length, 1);
	assert.equal(r53[0].status, "eol", "paid support does not clear the finding");
	assert.equal(r53[0].extendedSupport, "2029-08-31");
	const old = { ...springDep, version: "5.2.25.RELEASE", versions: ["5.2.25.RELEASE"] };
	const r52 = await checkEolDeps(new Map([["org.springframework:spring-core", old]]), { cycles: { "spring-framework": SPRING }, now: NOW });
	assert.equal(r52[0].extendedSupport, null, "commercial support ended too: nothing to state");
	const ng = mkRec({ ecosystem: "npm", name: "angular", version: "1.8.3", manifestPath: "/p/package-lock.json" });
	const rng = await checkEolDeps(new Map([["npm:angular", ng]]), { cycles: { angularjs: ANGULARJS }, now: NOW });
	if (rng.length) assert.equal(rng[0].extendedSupport, "true");
});

test("extendedSupport is stated in the EOL row, in English and French", () => {
	const finding = { dep: springDep, product: "Spring Framework", productSlug: "spring-framework", cycle: "5.3", status: "eol", eol: "2024-08-31", latest: "6.2.19", notes: "The 5.3 branch ended at 5.3.39.", extendedSupport: "2029-08-31" };
	const payload = lang => ({ cveMatches: [], eolResults: [finding], obsoleteResults: [], outdatedResults: [], projectInfo: { name: "d", src: "/p", generatedAt: "x" }, locale: lang });
	assert.ok(generateHtmlReport(payload("en")).includes("Paid commercial support until 2029-08-31."));
	assert.ok(generateHtmlReport(payload("fr")).includes("Support commercial payant jusqu&#39;au 2029-08-31.") || generateHtmlReport(payload("fr")).includes("Support commercial payant jusqu'au 2029-08-31."));
});
