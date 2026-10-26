/**
 * The Packagist security-advisories lane (the data `composer audit` itself queries).
 *
 * Why it exists: three advisories measured missing from vigievuln's OSV lane on the
 * real-instance corpus (2026-09-23) — twig/twig CVE-2026-46636 + CVE-2026-46627
 * (drupal 8.5.0 @1.35.0 AND symfony-demo @3.10.3) and knplabs/knp-snappy CVE-2026-46643
 * (BookStack @1.4.2). In OSV these CVEs exist only as CVEProject entries with GIT/CPE
 * ranges — no Packagist package coordinates — so a package+version query to OSV can
 * never return them, while Packagist's own advisory database (the endpoint
 * `composer audit` queries, built from GitHub advisories + FriendsOfPHP) carries them
 * with proper composer constraints. Values below are the real published ones.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { makeDepRecord } = require("../lib/dep-record");
const {
	satisfiesComposerConstraint,
	fixVersionFromConstraint,
	collectPackagistMatches,
	queryPackagistAudit,
} = require("../lib/packagist-audit");

// Real published advisory records (Packagist security-advisories API, 2026-09-23).
const FIXTURE_ADVISORIES = {
	"twig/twig": [
		{ advisoryId: "PKSA-twig-46636", packageName: "twig/twig", remoteId: "GHSA-7fxw-r6jv-74c8-mirror",
			title: "Twig: Sandbox method allowlist bypass via `Markup` subclass",
			link: "https://symfony.com/cve-2026-46636", cve: "CVE-2026-46636",
			affectedVersions: ">=1.0.0,<2.0.0|>=2.0.0,<3.0.0|>=3.0.0,<3.27.0",
			severity: "medium", reportedAt: "2026-09-10 03:30:22", source: "GitHub" },
		{ advisoryId: "PKSA-twig-46627", packageName: "twig/twig", remoteId: null,
			title: "Twig: Sandbox resource exhaustion via unbounded `for` / `range()`",
			link: "https://symfony.com/cve-2026-46627", cve: "CVE-2026-46627",
			affectedVersions: ">=1.0.0,<2.0.0|>=2.0.0,<3.0.0|>=3.0.0,<3.26.0",
			severity: "medium", reportedAt: "2026-08-12 03:51:25", source: "Symfony" },
	],
	"knplabs/knp-snappy": [
		{ advisoryId: "PKSA-13wp-m816-mvdd", packageName: "knplabs/knp-snappy", remoteId: "GHSA-vpr4-p6fq-85jc",
			title: "Snappy: Binary path is never shell-escaped due to an inverted is_executable check",
			link: "https://github.com/advisories/GHSA-vpr4-p6fq-85jc", cve: "CVE-2026-46643",
			affectedVersions: "<=1.7.0", severity: "medium", reportedAt: "2026-08-12 03:51:34", source: "GitHub" },
	],
	"zendframework/zend-feed": [
		{ advisoryId: "PKSA-ff9b-2qcw-k86n", packageName: "zendframework/zend-feed", remoteId: "GHSA-jmmp-vh96-78rm",
			title: "Zend-Feed URL Rewrite vulnerability",
			link: "https://github.com/advisories/GHSA-jmmp-vh96-78rm", cve: null,
			affectedVersions: ">=1.0.0,<2.10.3", severity: "high",
			reportedAt: "2024-06-07 22:01:20", source: "GitHub" },
	],
};

const dep = (ns, name, version) => {
	const r = makeDepRecord({ ecosystem: "composer", namespace: ns, name, version, manifestPath: "composer.lock" });
	return r;
};

test("satisfiesComposerConstraint evaluates the Packagist constraint grammar", () => {
	const c = ">=1.0.0,<2.0.0|>=2.0.0,<3.0.0|>=3.0.0,<3.27.0";
	assert.equal(satisfiesComposerConstraint("1.35.0", c), true);   // drupal 8.5.0 lock
	assert.equal(satisfiesComposerConstraint("3.10.3", c), true);   // symfony-demo lock
	assert.equal(satisfiesComposerConstraint("3.27.0", c), false);  // the fix itself
	assert.equal(satisfiesComposerConstraint("0.9.0", c), false);
	assert.equal(satisfiesComposerConstraint("1.4.2", "<=1.7.0"), true);   // snappy, inverted-check CVE
	assert.equal(satisfiesComposerConstraint("1.7.1", "<=1.7.0"), false);
	assert.equal(satisfiesComposerConstraint("11.2.5", "11.2.*"), true);   // Drupal API wildcard branch
	assert.equal(satisfiesComposerConstraint("8.5.0", "11.2.*"), false);
	assert.equal(satisfiesComposerConstraint("7.4.33", "7.4"), true);       // partial = branch wildcard
	assert.equal(satisfiesComposerConstraint("7.5.0", "7.4"), false);
	assert.equal(satisfiesComposerConstraint("2.4.2", "*"), true);
	assert.equal(satisfiesComposerConstraint("2.4.2", "^2.0"), true);
	assert.equal(satisfiesComposerConstraint("3.0.0", "^2.0"), false);
	assert.equal(satisfiesComposerConstraint("0.0.9", "^0.0.3"), false);
	assert.equal(satisfiesComposerConstraint("0.0.3", "^0.0.3"), true);
	assert.equal(satisfiesComposerConstraint("2.0.5", "1.0 - 2.0"), true);
	assert.equal(satisfiesComposerConstraint("2.1.0", "1.0 - 2.0"), false);
	// Undecidable must stay null — never a verdict built on an unparsed token.
	// (A version that DOES match another branch is affected regardless — OR semantics.)
	// GitHub-feed grammar quirks (spaced operators, spaceless hyphen intervals, bare
	// 4-part exacts) are normalized in lib/application-providers/github-advisories.js —
	// this shared evaluator keeps the exact behavior the Packagist/Drupal lanes rely on.
	assert.equal(satisfiesComposerConstraint("1.0.0", ">=banana"), null);
	assert.equal(satisfiesComposerConstraint("3.0.0", "<2.0.0|>=banana"), null);
});

test("fixVersionFromConstraint derives the fix from the satisfied branch's strict bound", () => {
	assert.equal(fixVersionFromConstraint("3.10.3", ">=1.0.0,<2.0.0|>=2.0.0,<3.0.0|>=3.0.0,<3.27.0"), "3.27.0");
	assert.equal(fixVersionFromConstraint("1.35.0", ">=1.0.0,<2.0.0|>=2.0.0,<3.0.0|>=3.0.0,<3.27.0"), "2.0.0");
	// `<=` gives no next-version name: no fix version, not a fabricated one.
	assert.equal(fixVersionFromConstraint("1.4.2", "<=1.7.0"), null);
});

test("collectPackagistMatches reproduces the three recall misses with the real constraints", () => {
	const deps = new Map();
	for (const [ns, name, v] of [
		["twig", "twig", "1.35.0"],
		["twig", "twig", "3.10.3"],
		["knplabs", "knp-snappy", "1.4.2"],
	]) {
		const r = dep(ns, name, v);
		deps.set(`${r.coordKey}@${v}`, { ...r, version: v });
	}
	const matches = collectPackagistMatches(deps, FIXTURE_ADVISORIES);
	const ids = matches.map(m => `${m.dep.namespace}/${m.dep.name}@${m.dep.version}:${m.cve.id}`).sort();
	assert.deepEqual(ids, [
		"knplabs/knp-snappy@1.4.2:CVE-2026-46643",
		"twig/twig@1.35.0:CVE-2026-46627",
		"twig/twig@1.35.0:CVE-2026-46636",
		"twig/twig@3.10.3:CVE-2026-46627",
		"twig/twig@3.10.3:CVE-2026-46636",
	]);
	const twig = matches.find(m => m.cve.id === "CVE-2026-46636" && m.dep.version === "3.10.3");
	assert.equal(twig.source, "packagist");
	assert.equal(twig.confidence, "exact");
	assert.equal(twig.cve.severity, "MEDIUM");
	assert.equal(twig.cve.fixVersion, "3.27.0");
	assert.ok(twig.cve.aliases.includes("PKSA-twig-46636"));
	assert.ok(twig.cve.description.includes("Sandbox method allowlist bypass"));
});

test("collectPackagistMatches keys a CVE-less advisory by its remote GHSA id", () => {
	const deps = new Map();
	const r = dep("zendframework", "zend-feed", "2.8.1");
	deps.set(`${r.coordKey}@2.8.1`, { ...r, version: "2.8.1" });
	const matches = collectPackagistMatches(deps, FIXTURE_ADVISORIES);
	assert.equal(matches.length, 1);
	const m = matches[0];
	assert.equal(m.cve.id, "GHSA-jmmp-vh96-78rm", "the GHSA key merges with OSV's own GHSA-keyed finding");
	assert.equal(m.cve.severity, "HIGH");
	assert.ok(m.cve.aliases.includes("PKSA-ff9b-2qcw-k86n"));
	assert.equal(m.cve.fixVersion, "2.10.3");
});

test("Packagist source aliases merge with an OSV GHSA when deprecated remoteId is absent", () => {
	const { mergeBySource } = require("../lib/merge-sources");
	const r = dep("foo", "bar", "1.0.0");
	const advisory = { advisoryId: "PKSA-1111-2222-3333", packageName: "foo/bar", cve: null,
		affectedVersions: "<2.0.0", sources: [{ name: "GitHub", remoteId: "GHSA-aaaa-bbbb-cccc" }] };
	const [packagist] = collectPackagistMatches(new Map([[r.coordKey, r]]), { "foo/bar": [advisory] });
	assert.equal(packagist.cve.id, "GHSA-aaaa-bbbb-cccc");
	const osv = { dep: r, cve: { id: "GHSA-aaaa-bbbb-cccc", aliases: [] }, source: "osv" };
	assert.equal(mergeBySource([osv], [packagist]).length, 1);
});

test("collectPackagistMatches never emits a finding for an unaffected version", () => {
	const deps = new Map();
	const r = dep("twig", "twig", "3.27.0");
	deps.set(`${r.coordKey}@3.27.0`, { ...r, version: "3.27.0" });
	assert.equal(collectPackagistMatches(deps, FIXTURE_ADVISORIES).length, 0);
});

test("collectPackagistMatches ignores non-composer deps and non-concrete versions", () => {
	const deps = new Map();
	const maven = makeDepRecord({ ecosystem: "maven", namespace: "org.apache", name: "log4j-core", version: "2.14.1", manifestPath: "pom.xml" });
	deps.set(maven.coordKey, maven);
	const ranged = dep("doctrine", "annotations", "1.2.*");
	deps.set(`${ranged.coordKey}@1.2.*`, ranged);
	assert.equal(collectPackagistMatches(deps, FIXTURE_ADVISORIES).length, 0);
});

function fetcherWith(body) {
	const calls = [];
	const fetcher = async (url) => {
		calls.push(String(url));
		return { ok: true, json: async () => body };
	};
	fetcher.calls = () => calls;
	return fetcher;
}

test("queryPackagistAudit batches package names, caches per package, and serves warm cache offline", async () => {
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pksa-"));
	const deps = new Map();
	for (const [ns, name, v] of [
		["twig", "twig", "1.35.0"],
		["knplabs", "knp-snappy", "1.4.2"],
	]) {
		const r = dep(ns, name, v);
		deps.set(`${r.coordKey}@${v}`, { ...r, version: v });
	}
	const fetcher = fetcherWith({ advisories: {
		"twig/twig": FIXTURE_ADVISORIES["twig/twig"],
		"knplabs/knp-snappy": FIXTURE_ADVISORIES["knplabs/knp-snappy"],
	} });
	const first = await queryPackagistAudit(deps, { offline: false, cacheDir, fetcher });
	assert.equal(first.length, 3, "twig 1.35.0 × 2 advisories + snappy 1.4.2 × 1");
	assert.equal(fetcher.calls().length, 1, "one batched request for both packages");
	assert.ok(fetcher.calls()[0].includes("packages[]="), "the packages[] query convention");
	assert.ok(fs.existsSync(path.join(cacheDir, "twig__twig.json")), "per-package cache file");
	assert.ok(fs.existsSync(path.join(cacheDir, "knplabs__knp-snappy.json")));

	// Offline on the warm cache: zero network, same recall.
	const tripwire = async (url) => { throw new Error(`NETWORK CALL in offline mode: ${url}`); };
	const second = await queryPackagistAudit(deps, { offline: true, cacheDir, fetcher: tripwire });
	assert.equal(second.length, 3);
});

test("Packagist audit does not query Adobe's Composer repository packages", async () => {
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pksa-adobe-"));
	try {
		const magento = dep("magento", "product-community-edition", "2.4.7");
		const marketplace = dep("acme", "module-pay", "1.2.3");
		marketplace.occurrences = [{ distHost: "repo.magento.com" }];
		const twig = dep("twig", "twig", "1.35.0");
		const deps = new Map([["magento", magento], ["marketplace", marketplace], ["twig", twig]]);
		const fetcher = fetcherWith({ advisories: { "twig/twig": [] } });
		let skipped;
		await queryPackagistAudit(deps, { cacheDir, fetcher, onSkipped: names => { skipped = names; } });
		assert.deepEqual(skipped, ["acme/module-pay", "magento/product-community-edition"]);
		assert.equal(fetcher.calls().length, 1);
		assert.match(fetcher.calls()[0], /twig%2Ftwig|twig\/twig/);
		assert.doesNotMatch(fetcher.calls()[0], /magento|module-pay/);
	} finally { fs.rmSync(cacheDir, { recursive: true, force: true }); }
});

test("queryPackagistAudit makes zero network calls offline on a cold cache", async () => {
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pksa-"));
	const deps = new Map();
	const r = dep("twig", "twig", "1.35.0");
	deps.set(`${r.coordKey}@1.35.0`, { ...r, version: "1.35.0" });
	const tripwire = async (url) => { throw new Error(`NETWORK CALL in offline mode: ${url}`); };
	const out = await queryPackagistAudit(deps, { offline: true, cacheDir, fetcher: tripwire });
	assert.equal(out.length, 0);
});

test("queryPackagistAudit matches response package names case-insensitively", async () => {
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pksa-"));
	const deps = new Map();
	const r = dep("Twig", "Twig", "1.35.0");
	deps.set(`${r.coordKey}@1.35.0`, { ...r, version: "1.35.0" });
	const fetcher = fetcherWith({ advisories: { "twig/twig": FIXTURE_ADVISORIES["twig/twig"] } });
	const out = await queryPackagistAudit(deps, { offline: false, cacheDir, fetcher });
	assert.equal(out.length, 2);
});

test("Packagist keeps omitted packages unknown while retaining valid results", async () => {
	const missing = dep("disp", "log-bundle", "1.0.0");
	const known = dep("twig", "twig", "1.35.0");
	const deps = new Map([[missing.coordKey, missing], [known.coordKey, known]]);
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pksa-unknown-"));
	try {
		let unknown;
		const fetcher = fetcherWith({ advisories: { "twig/twig": FIXTURE_ADVISORIES["twig/twig"] } });
		const matches = await queryPackagistAudit(deps, { cacheDir, fetcher, onUnknown: names => { unknown = names; } });
		assert.equal(matches.length, 2, "the known package is still audited");
		assert.deepEqual(unknown, ["disp/log-bundle"]);
		assert.deepEqual(fs.readdirSync(cacheDir), ["twig__twig.json"], "unknown is never cached as clean");
		await queryPackagistAudit(deps, { cacheDir, fetcher, onUnknown: names => { unknown = names; } });
		assert.equal(fetcher.calls().length, 2, "the unknown package is retried next run");
		assert.deepEqual(unknown, ["disp/log-bundle"]);
	} finally { fs.rmSync(cacheDir, { recursive: true, force: true }); }
});

test("Packagist accepts an empty top-level advisory array as unknown, not clean", async () => {
	const missing = dep("disp", "log-bundle", "1.0.0");
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pksa-empty-"));
	try {
		let unknown;
		const matches = await queryPackagistAudit(new Map([[missing.coordKey, missing]]), {
			cacheDir, fetcher: fetcherWith({ advisories: [] }), onUnknown: names => { unknown = names; },
		});
		assert.deepEqual(matches, []);
		assert.deepEqual(unknown, ["disp/log-bundle"]);
		assert.deepEqual(fs.readdirSync(cacheDir), []);
	} finally { fs.rmSync(cacheDir, { recursive: true, force: true }); }
});

test("Packagist refuses malformed answers without caching them as clean", async () => {
	const r = dep("twig", "twig", "1.35.0");
	const deps = new Map([[r.coordKey, r]]);
	for (const [label, response] of [
		["missing object", { ok: true, json: async () => ({}) }],
		["malformed top-level list", { ok: true, json: async () => ({ advisories: ["wrong"] }) }],
		["malformed list", { ok: true, json: async () => ({ advisories: { "twig/twig": null } }) }],
		["HTTP error", { ok: false, status: 429 }],
	]) {
		const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pksa-incomplete-"));
		try {
			await assert.rejects(queryPackagistAudit(deps, { cacheDir, fetcher: async () => response }),
				/Packagist audit batch/, label);
			assert.deepEqual(fs.readdirSync(cacheDir), [], `${label} must not write a clean cache entry`);
		} finally { fs.rmSync(cacheDir, { recursive: true, force: true }); }
	}
});

test("a legacy empty Packagist cache entry is revalidated online", async () => {
	const r = dep("twig", "twig", "1.35.0");
	const deps = new Map([[r.coordKey, r]]);
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pksa-legacy-"));
	try {
		fs.writeFileSync(path.join(cacheDir, "twig__twig.json"), JSON.stringify({ _fetchedAt: Date.now(), body: [] }));
		let calls = 0;
		await queryPackagistAudit(deps, { cacheDir, fetcher: async () => {
			calls++;
			return { ok: true, json: async () => ({ advisories: { "twig/twig": [] } }) };
		} });
		assert.equal(calls, 1);
		assert.equal(JSON.parse(fs.readFileSync(path.join(cacheDir, "twig__twig.json")))._schema, 2);
	} finally { fs.rmSync(cacheDir, { recursive: true, force: true }); }
});
