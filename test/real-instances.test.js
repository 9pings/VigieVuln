/**
 * Real-instance integration tests: clone the representative GitHub repository of each
 * wave-1 CMS/framework at a tag whose shipped files pin a version known to be vulnerable,
 * scan the actual tree, and verify the end-to-end behavior. These tests need network and
 * git and are NOT part of the ordinary offline suite — run them explicitly:
 *
 *     FAD_REAL_INSTANCES=1 node --test test/real-instances.test.js
 *
 * Advisory identifiers and affected ranges below are the real published ones, verified
 * against the live sources (Wordfence/NVD for WordPress, the packages.drupal.org API for
 * Drupal, OSV for Symfony and Laravel):
 *
 *   WordPress/WordPress @ 6.4.2       CVE-2024-31210 — plugin-upload file type,
 *                                     fixed in 6.4.3. CVE-2024-31211 was fixed in 6.4.2.
 *   drupal/drupal @ 8.5.0             SA-CORE-2018-002 / CVE-2018-7600 — >=8.5.0 <8.5.1.
 *                                     A git clone ships no lock, so the observed version
 *                                     comes from the real core/lib/Drupal.php marker.
 *                                     The online test drives --drupal-advisories-live
 *                                     and asserts the FULL official record (15
 *                                     advisories affecting 8.5.0 as of 2026-09-23)
 *   symfony/symfony-demo @ v2.6.0     composer.lock pins symfony/http-foundation v7.1.1 —
 *                                     CVE-2024-50345, fixed 7.1.7
 *   BookStackApp/BookStack @ v24.10    composer.lock pins laravel/framework v10.48.22 —
 *                                     CVE-2024-52301. (The laravel/laravel skeleton ships
 *                                     no composer.lock, so a real application stands in.)
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const RUN = process.env.FAD_REAL_INSTANCES === "1";
const SKIP = !RUN && "set FAD_REAL_INSTANCES=1 (network + git required)";
const CLI = path.join(__dirname, "..", "vigievuln.js");
const CLONE_TIMEOUT_MS = 300000;
const SCAN_TIMEOUT_MS = 600000;

const REPOS = [
	{ dir: "wordpress-6.4.2", url: "https://github.com/WordPress/WordPress", tag: "6.4.2" },
	{ dir: "drupal-8.5.0", url: "https://github.com/drupal/drupal", tag: "8.5.0" },
	{ dir: "symfony-demo-v2.6.0", url: "https://github.com/symfony/symfony-demo", tag: "v2.6.0" },
	{ dir: "bookstack-v24.10", url: "https://github.com/BookStackApp/BookStack", tag: "v24.10" },
];

let WORK = null;

// Reduced Wordfence v3-shaped fixture for CVE-2024-31210 (affected <= 6.4.2,
// fixed in 6.4.3). It exercises matching; it is not the complete production feed.
// The vendor advisory scores the issue 7.6 HIGH. UUID and title are test data.
const WORDFENCE_UUID = "e0f1d2c3-b4a5-4968-8d7e-6f5a4b3c2d10";
const wordfenceFeed = path => JSON.stringify({
	[WORDFENCE_UUID]: {
		id: WORDFENCE_UUID, title: "WordPress Core 6.4.2 - Plugin Upload File Type", cve: "CVE-2024-31210",
		description: "WordPress is an open publishing platform for the Web. It's possible for a file of a "
			+ "type other than a zip file to be submitted as a new plugin on the Plugins -> Add New "
			+ "-> Upload Plugin screen.",
		cvss: { score: 7.6, rating: "HIGH", vector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H" },
		published: "2024-01-31 00:00:00", updated: "2024-01-31 00:00:00",
		software: [{ type: "core", slug: "wordpress", affected_versions: {
			"0 - 6.4.2": { from_version: "*", from_inclusive: true, to_version: "6.4.2", to_inclusive: true } },
			patched_versions: ["6.4.3"] }] },
});

// Real packages.drupal.org/8/security-advisories response record for drupal/core,
// captured from the official API: SA-CORE-2018-002 / CVE-2018-7600 (Drupalgeddon2).
const drupalAdvisories = () => JSON.stringify({ collectedAt: "2026-09-23T00:00:00Z",
	queriedPackages: ["drupal/core"],
	advisories: { "drupal/core": [{
		advisoryId: "SA-CORE-2018-002", packageName: "drupal/core",
		title: "Drupal core - Highly critical - Remote Code Execution  - SA-CORE-2018-002",
		link: "https://www.drupal.org/sa-core-2018-002", cve: "CVE-2018-7600",
		affectedVersions: ">=7.0 <7.58 || >= 8.0.0 <8.3.9 || >=8.4.0 <8.4.6 || >=8.5.0 <8.5.1",
		reportedAt: "2018-03-28 18:14:10" }] } });


test.before(async () => {
	if (!RUN) return;
	WORK = fs.mkdtempSync(path.join(os.tmpdir(), "fad-real-instances-"));
	for (const repo of REPOS) {
		const run = spawnSync("git", ["clone", "--depth", "1", "--branch", repo.tag, repo.url, path.join(WORK, repo.dir)],
			{ timeout: CLONE_TIMEOUT_MS, encoding: "utf8" });
		if (run.status !== 0) throw new Error(`git clone of ${repo.url}@${repo.tag} failed: ${run.stderr}`);
	}
	fs.writeFileSync(path.join(WORK, "wordfence.json"), wordfenceFeed());
	fs.writeFileSync(path.join(WORK, "drupal-advisories.json"), drupalAdvisories());
});

test.after(() => { if (WORK) fs.rmSync(WORK, { recursive: true, force: true }); });

function scan(root, extraArgs, outName) {
	const out = path.join(WORK, outName);
	const run = spawnSync(process.execPath, [CLI, "-s", root, "--offline", "--ecosystem", "composer",
		"-d", "eol,nvd,epss,kev,retire,transitive", "--report-json", out, "--no-checksums", ...extraArgs],
		{ timeout: SCAN_TIMEOUT_MS, encoding: "utf8", env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
	return JSON.parse(fs.readFileSync(out, "utf8"));
}

test("a corpus of four real repositories scans as four distinct applications", { skip: SKIP }, () => {
	const doc = scan(WORK, ["--app-plugins", "wordpress,drupal,symfony,laravel",
		"--wordfence-feed", path.join(WORK, "wordfence.json"),
		"--drupal-advisories", path.join(WORK, "drupal-advisories.json")], "corpus.json");

	assert.deepEqual(doc.applications.map(a => [a.type, a.root]).sort(), [
		["drupal", "drupal-8.5.0"], ["laravel", "bookstack-v24.10"],
		["symfony", "symfony-demo-v2.6.0"], ["wordpress", "wordpress-6.4.2"]]);

	const inventoryBy = (type, pred) => doc.applicationInventory
		.find(c => doc.applications.find(a => a.id === c.applicationId)?.type === type && pred(c));

	// WordPress 6.4.2: the version observed in the real wp-includes/version.php matches the
	// real advisory, directly, with the core as the owning component.
	const wpCore = inventoryBy("wordpress", c => c.kind === "core");
	assert.equal(wpCore.version, "6.4.2");
	for (const cveId of ["CVE-2024-31210"]) {
		const wpFinding = doc.cve.find(f => f.id === cveId);
		assert.ok(wpFinding, `${cveId} must match the real tree`);
		assert.equal(wpFinding.applicationRelation, "direct");
		assert.deepEqual(wpFinding.applicationIds, ["wordpress:wordpress-6.4.2"]);
		assert.equal(wpFinding.ownerComponentIds.length, 1);
	}
	assert.ok(!doc.cve.some(f => f.id === "CVE-2024-31211"), "6.4.2 already contains the WP_HTML_Token fix");
	const wpFinding = doc.cve.find(f => f.id === "CVE-2024-31210");
	assert.ok(wpFinding, "the real core advisory must match the real tree");
	assert.equal(wpFinding.applicationRelation, "direct");
	assert.deepEqual(wpFinding.applicationIds, ["wordpress:wordpress-6.4.2"]);
	assert.equal(wpFinding.ownerComponentIds.length, 1);
	const wpCoreCoverage = doc.coverage.find(c => c.occurrenceId === wpCore.id);
	assert.equal(wpCoreCoverage.execution, "completed");
	assert.equal(wpCoreCoverage.result, "affected");
	// The real repository ships its default themes; they stay inventoried with unverified
	// catalogue identity instead of being matched or dropped.
	assert.ok(doc.applicationInventory.some(c => c.kind === "theme" && c.slug === "twentytwentyfour"));
	const themeCoverage = doc.coverage.find(c => c.applicationId === "wordpress:wordpress-6.4.2" &&
		c.execution === "not-run" && c.result === "indeterminate");
	assert.ok(themeCoverage, "unverified real themes keep an honest indeterminate coverage");

	// Drupal 8.5.0: the tree is known-vulnerable (SA-CORE-2018-002 covers 8.5.0) and a
	// source clone ships no lock — the scan reads the observed version from the real
	// core/lib/Drupal.php marker and matches the real advisory, with exactly one
	// application (no phantom Drupal 7 under core/).
	const drupalApp = doc.applications.find(a => a.type === "drupal");
	assert.equal(drupalApp.layout, "composer");
	const drupalCore = inventoryBy("drupal", c => c.kind === "core");
	assert.equal(drupalCore.version, "8.5.0");
	assert.equal(drupalCore.versionStatus, "observed");
	const drupalFinding = doc.cve.find(f => f.id === "CVE-2018-7600");
	assert.ok(drupalFinding, "the observed 8.5.0 marker matches the real SA-CORE-2018-002 record");
	assert.deepEqual(drupalFinding.applicationIds, ["drupal:drupal-8.5.0"]);
	assert.equal(drupalFinding.applicationRelation, "direct");
	const drupalCoverage = doc.coverage.find(c => c.occurrenceId === drupalCore.id);
	assert.equal(drupalCoverage.execution, "completed");
	assert.equal(drupalCoverage.result, "affected");

	// Symfony demo v2.6.0: the real lock pins the lockstep v7.1.1 across the framework.
	const sfFramework = inventoryBy("symfony", c => c.kind === "framework");
	const sfHttpFoundation = inventoryBy("symfony", c => c.coord === "symfony/http-foundation");
	assert.equal(sfFramework.version, "7.1.1");
	assert.equal(sfHttpFoundation.version, "7.1.1");
	assert.ok(doc.coverage.some(c => c.applicationId === "symfony:symfony-demo-v2.6.0" &&
		c.diagnostic === "CMS_ADVISORY_NOT_QUALIFIED"), "unqualified advisory capability stays announced");

	// BookStack v24.10: the real lock pins laravel/framework 10.48.22.
	const bsFramework = inventoryBy("laravel", c => c.kind === "framework");
	assert.equal(bsFramework.version, "10.48.22");
	assert.ok(doc.coverage.some(c => c.applicationId === "laravel:bookstack-v24.10" &&
		c.diagnostic === "CMS_ADVISORY_NOT_QUALIFIED"));

	// The real drupal/drupal tree ships intentionally invalid test fixtures
	// (core/modules/system/tests/fixtures/HtaccessTest): they must stay visible as scoped
	// parse limits and never leak components or findings into the inventory.
	const fixtureTouched = doc.applicationInventory.filter(c =>
		/tests\/fixtures|HtaccessTest/i.test(`${c.path || ""} ${(c.evidence || []).map(e => e.path).join(" ")}`));
	assert.equal(fixtureTouched.length, 0, "no inventory component may come from a CMS test fixture");
	assert.ok(!doc.cve.some(f => /tests\/fixtures|HtaccessTest/i.test(JSON.stringify(f.dep?.provenance || {}) +
		(f.dep?.manifestPaths || []).join(" "))), "no finding may come from a CMS test fixture");
	const htaccess = doc.warnings.filter(w => w.type === "parse-error" &&
		/HtaccessTest\/composer\.(json|lock)/.test(w.manifestPath || ""));
	assert.equal(htaccess.length, 2, "the broken fixture stays listed as a scoped parse limit");
	assert.match(htaccess[0].message || "", /parse failed/);
});

test("the real symfony-demo lock attributes CVE-2024-50345 along the real require chain", { skip: SKIP }, async () => {
	const composer = require("../lib/codecs/composer.codec");
	const { runApplicationPlugins } = require("../lib/application-plugins/runner");
	const symfony = require("../lib/application-plugins/symfony");
	const { buildApplicationRelations, expandComposerFindings } = require("../lib/application-inventory");
	const root = path.join(WORK, "symfony-demo-v2.6.0");
	const { deps } = await composer.collect(root);
	const result = await runApplicationPlugins(root, { plugins: [symfony], selection: "symfony",
		resolvedDeps: deps, activeCodecIds: ["composer"] });
	const framework = result.inventory.find(c => c.kind === "framework");
	const httpFoundation = result.inventory.find(c => c.coord === "symfony/http-foundation");
	// CVE-2024-50345 (open redirect in symfony/http-foundation, fixed 7.1.7): the affected
	// package is an official framework component, so the relation is direct with the exact
	// package named, per the plan's direct/indirect rule.
	const relations = buildApplicationRelations(root, result.applications, result.inventory, deps);
	const finding = expandComposerFindings([{ dep: deps.get("composer:symfony/http-foundation"),
		cve: { id: "CVE-2024-50345", severity: "MEDIUM" } }], root, relations)[0];
	assert.ok(finding.ownerComponentIds.includes(framework.id));
	assert.ok(finding.ownerComponentIds.includes(httpFoundation.id));
	assert.equal(finding.applicationRelation, "direct");
	assert.ok(finding.dependencyPaths.some(p => p[0] === "symfony/framework-bundle" &&
		p[p.length - 1] === "symfony/http-foundation"), "the introduction path follows the real lock's require graph");
});

test("the real BookStack lock attributes CVE-2024-52301 directly to laravel/framework", { skip: SKIP }, async () => {
	const composer = require("../lib/codecs/composer.codec");
	const { runApplicationPlugins } = require("../lib/application-plugins/runner");
	const laravel = require("../lib/application-plugins/laravel");
	const { buildApplicationRelations, expandComposerFindings } = require("../lib/application-inventory");
	const root = path.join(WORK, "bookstack-v24.10");
	const { deps } = await composer.collect(root);
	const result = await runApplicationPlugins(root, { plugins: [laravel], selection: "laravel",
		resolvedDeps: deps, activeCodecIds: ["composer"] });
	const framework = result.inventory.find(c => c.kind === "framework");
	assert.equal(framework.version, "10.48.22");
	// CVE-2024-52301 (query-string environment manipulation, fixed 10.48.23): the advisory
	// targets the framework itself.
	const relations = buildApplicationRelations(root, result.applications, result.inventory, deps);
	const finding = expandComposerFindings([{ dep: deps.get("composer:laravel/framework"),
		cve: { id: "CVE-2024-52301", severity: "MEDIUM" } }], root, relations)[0];
	assert.deepEqual(finding.ownerComponentIds, [framework.id]);
	assert.equal(finding.applicationRelation, "direct");
});

test("online OSV + the live official Drupal API find the real CVEs on the real trees", { skip: SKIP }, () => {
	// Live OSV.dev (the standard Composer SCA lane) + `--drupal-advisories-live` (the
	// official packages.drupal.org API — the same record `composer audit`/drush consume).
	// The pinned versions are historical facts, so the advisories below are stable
	// assertions, not snapshots. 15 official advisories affect drupal/core 8.5.0 as of
	// 2026-09-23 (the live count may only GROW); the offline corpus above uses a
	// 1-advisory operator snapshot, so this is the test that catches an under-reporting
	// snapshot or matcher against the authoritative record.
	const out = path.join(WORK, "online.json");
	const run = spawnSync(process.execPath, [CLI, "-s", WORK, "--app-plugins", "wordpress,drupal,symfony,laravel",
		"--wordfence-feed", path.join(WORK, "wordfence.json"),
		"--drupal-advisories-live",
		"--wp-checksums-live",
		"--ecosystem", "composer", "-d", "eol,nvd,epss,kev,retire,transitive",
		"--report-json", out, "--no-checksums"],
		{ timeout: SCAN_TIMEOUT_MS, encoding: "utf8", env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
	const doc = JSON.parse(fs.readFileSync(out, "utf8"));
	const has = (id, appId) => doc.cve.some(f => f.id === id && f.applicationIds?.includes(appId));
	assert.ok(has("CVE-2024-50345", "symfony:symfony-demo-v2.6.0"), "symfony/http-foundation 7.1.1 is affected by CVE-2024-50345 (fixed 7.1.7)");
	assert.ok(has("CVE-2024-52301", "laravel:bookstack-v24.10"), "laravel/framework 10.48.22 is affected by CVE-2024-52301 (fixed 10.48.23)");
	assert.ok(has("CVE-2024-31210", "wordpress:wordpress-6.4.2"));
	assert.ok(!doc.cve.some(f => f.id === "CVE-2024-31211"), "6.4.2 already contains the WP_HTML_Token fix");
	assert.equal(doc.cve.filter(f => !f.applicationIds?.length).length, 0, "every finding is attributed to its application");

	// The official Drupal record for 8.5.0, end to end: the 2018 Drupalgeddon trio, the
	// CVE-less SA-CORE-2023-* wave (keyed by advisory id), and the 2026 advisories whose
	// `X.Y.*` wildcard branches must be DECIDED (fix: 8.5.0 is in none of them) — a
	// matcher that shrugs at a wildcard shows up here as a partial coverage record.
	const drupalCoreAdvisories = doc.cve.filter(f => f.applicationIds?.includes("drupal:drupal-8.5.0") &&
		String(f.source || "").includes("drupal-security-advisories"));
	assert.ok(drupalCoreAdvisories.length >= 15,
		`the official API holds 15 advisories affecting 8.5.0 (2026-09-23); got ${drupalCoreAdvisories.length}`);
	for (const id of ["CVE-2018-7600", "CVE-2018-7602", "CVE-2018-9861", "CVE-2024-11941", "SA-CORE-2023-001"]) {
		assert.ok(drupalCoreAdvisories.some(f => f.id === id), `${id} comes from the official Drupal record`);
	}
	const drupalCore = doc.applicationInventory.find(c => c.kind === "core" &&
		doc.applications.find(a => a.id === c.applicationId)?.type === "drupal");
	const drupalCoverage = doc.coverage.find(c => c.occurrenceId === drupalCore.id);
	assert.equal(drupalCoverage.execution, "completed",
		"every official constraint — incl. the `11.2.*`/`11.0.*` wildcard branches — must be decidable");
	assert.equal(drupalCoverage.result, "affected");
	assert.equal(drupalCoverage.sourceSnapshot?.completeness, "tool-fetched");
});

test("the live WordPress checksums reference finds a tampered core file on the real tree", { skip: SKIP }, () => {
	// The pristine 6.4.2 git tree matches every official checksum of the files it ships
	// (verified 2026-09-23: integrity coverage completed/no-match). A git checkout is
	// not the distribution archive — the four default akismet files ship only in the
	// tarball — so CMS_FILE_MISSING warnings are the honest observation of a source
	// tree; they do not flip the verdict. One appended comment in wp-load.php must flip
	// it to affected with a CMS_FILE_MODIFIED warning naming the file. The tree is
	// restored afterwards.
	const wpRoot = path.join(WORK, "wordpress-6.4.2");
	try {
		const pristine = path.join(WORK, "wp-integrity-pristine.json");
		const clean = spawnSync(process.execPath, [CLI, "-s", wpRoot, "--app-plugins", "wordpress",
			"--wp-checksums-live", "--ecosystem", "composer", "-d", "eol,nvd,epss,kev,retire,transitive",
			"--report-json", pristine, "--no-checksums"],
			{ timeout: SCAN_TIMEOUT_MS, encoding: "utf8", env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(clean.status, 0, `${clean.stdout}\n${clean.stderr}`);
		const cleanDoc = JSON.parse(fs.readFileSync(pristine, "utf8"));
		const cleanIntegrity = cleanDoc.coverage.find(c => c.capability === "integrity");
		assert.equal(cleanIntegrity.execution, "completed");
		assert.equal(cleanIntegrity.result, "no-match", "the pristine tree diverges from no reference file it ships");
		assert.equal(cleanIntegrity.expected, cleanIntegrity.executed);
		assert.equal(cleanIntegrity.sourceSnapshot?.completeness, "tool-fetched");
		assert.ok(!cleanDoc.warnings.some(d => d.code === "CMS_FILE_MODIFIED"),
			"a pristine checkout carries no modified core file");

		fs.appendFileSync(path.join(wpRoot, "wp-load.php"), "\n// tampered for the integrity test\n");
		const tampered = path.join(WORK, "wp-integrity-tampered.json");
		const dirty = spawnSync(process.execPath, [CLI, "-s", wpRoot, "--app-plugins", "wordpress",
			"--wp-checksums-live", "--ecosystem", "composer", "-d", "eol,nvd,epss,kev,retire,transitive",
			"--report-json", tampered, "--no-checksums"],
			{ timeout: SCAN_TIMEOUT_MS, encoding: "utf8", env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(dirty.status, 0, `${dirty.stdout}\n${dirty.stderr}`);
		const dirtyDoc = JSON.parse(fs.readFileSync(tampered, "utf8"));
		const dirtyIntegrity = dirtyDoc.coverage.find(c => c.capability === "integrity");
		assert.equal(dirtyIntegrity.execution, "completed");
		assert.equal(dirtyIntegrity.result, "affected", "a modified core file flips the verdict");
		assert.equal(dirtyDoc.cve.filter(f => String(f.source || "") === "wordpress-checksums").length, 0,
			"integrity divergences are diagnostics, never CVE findings");
		assert.ok(dirtyDoc.warnings.some(d => d.code === "CMS_FILE_MODIFIED" && String(d.message).includes("wp-load.php")),
			"the warning names the divergent file");
	} finally {
		spawnSync("git", ["-C", wpRoot, "checkout", "--", "wp-load.php"], { timeout: 60000, encoding: "utf8" });
	}
});
