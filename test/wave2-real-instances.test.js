/**
 * Wave-two real-instance integration tests: download the official publisher tarball of
 * PrestaShop and TYPO3 at a vulnerable tag, reduce it to the marker files the plugins
 * read (the same documented reduction as the offline wave-2 fixtures), scan the result
 * with the publishers' live GitHub advisory feeds, and verify the end-to-end behavior.
 * These tests need network and are NOT part of the ordinary offline suite:
 *
 *     FAD_REAL_INSTANCES=1 node --test test/wave2-real-instances.test.js
 *
 * Advisory identifiers and affected ranges below are the real published ones, verified
 * against the live publisher feeds (2026-09-23):
 *
 *   PrestaShop/PrestaShop @ 8.2.1   GHSA-xrwj-pq6w-f8m4 (SSRF, fixed 8.2.8),
 *                                   CVE-2026-44212 (SQLi, fixed 8.2.6) — and the
 *                                   2020-era records ("> 1.7.0.0", patched 1.7.6.x)
 *                                   must NOT fire on 8.2.1.
 *   TYPO3/typo3 @ v13.4.2           CVE-2026-19418 (typo3/cms-core, 13.0.0-13.4.33,
 *                                   fixed 13.4.34) among the 13.4.x advisories.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const RUN = process.env.FAD_REAL_INSTANCES === "1";
const SKIP = !RUN && "set FAD_REAL_INSTANCES=1 (network required)";
const CLI = path.join(__dirname, "..", "vigievuln.js");
const SCAN_TIMEOUT_MS = 600000;

let WORK = null;

const EXTRACTS = [
	{ dir: "prestashop", url: "https://github.com/PrestaShop/PrestaShop/archive/refs/tags/8.2.1.tar.gz",
		prefix: "PrestaShop-8.2.1/",
		files: ["composer.json", "config/config.inc.php", "install-dev/install_version.php"] },
	{ dir: "typo3", url: "https://github.com/TYPO3/typo3/archive/refs/tags/v13.4.2.tar.gz",
		prefix: "typo3-13.4.2/",
		files: ["composer.json", "typo3/sysext/core/ext_emconf.php",
			"typo3/sysext/seo/composer.json", "typo3/sysext/seo/ext_emconf.php"] },
];

test.before(() => {
	if (!RUN) return;
	WORK = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wave2-real-"));
	for (const extract of EXTRACTS) {
		// Documented reduction of the official distribution: only the marker files the
		// plugins actually read, straight from the publisher's own release archive.
		const dir = path.join(WORK, extract.dir);
		fs.mkdirSync(dir, { recursive: true });
		const download = spawnSync("bash", ["-c", `curl -sL --max-time 240 '${extract.url}' | tar -xzf - -C '${dir}' --strip-components=1 ${extract.files.map(file => `'${extract.prefix}${file}'`).join(" ")}`],
			{ timeout: 300000, encoding: "utf8" });
		assert.equal(download.status, 0, `download/reduction of ${extract.url} failed: ${download.stderr}`);
	}
});

test.after(() => { if (WORK) fs.rmSync(WORK, { recursive: true, force: true }); });

test("the live PrestaShop publisher feed finds the real 8.2.1 advisories and no 2020 false positive", { skip: SKIP }, () => {
	const out = path.join(WORK, "prestashop.json");
	const run = spawnSync(process.execPath, [CLI, "-s", path.join(WORK, "prestashop"),
		"--app-plugins", "prestashop", "--prestashop-advisories-live", "--ecosystem", "composer",
		"-d", "eol,nvd,epss,kev,retire,transitive", "--report-json", out, "--no-checksums"],
		{ timeout: SCAN_TIMEOUT_MS, encoding: "utf8", env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
	const doc = JSON.parse(fs.readFileSync(out, "utf8"));
	const app = doc.applications?.[0];
	assert.equal(app?.type, "prestashop", "the official extract is detected");
	const core = doc.applicationInventory.find(c => c.kind === "core" && c.applicationId === app.id);
	assert.equal(core.version, "8.2.1", "the installer marker carries the real version");
	assert.equal(core.versionStatus, "source-observed");
	const lane = doc.cve.filter(f => String(f.source || "").includes("github-prestashop-advisories"));
	assert.ok(lane.length >= 8, `the publisher feed holds several advisories affecting 8.2.1; got ${lane.length}`);
	const has = id => lane.some(f => f.id === id);
	assert.ok(has("GHSA-xrwj-pq6w-f8m4"), "8.2.1 is affected by the SSRF advisory fixed in 8.2.8");
	assert.equal(lane.find(f => f.id === "GHSA-xrwj-pq6w-f8m4").fixVersion, "8.2.8");
	assert.ok(has("CVE-2026-44212"), "8.2.1 sits in the < 8.2.6 branch of the SQLi advisory");
	assert.ok(!has("CVE-2020-5293") && !has("CVE-2020-15160") && !has("CVE-2021-21398"),
		"the lossy unbounded 2020 records are refined away by their patched bounds");
	const coverage = doc.coverage.find(c => c.occurrenceId === core.id);
	assert.equal(coverage.execution, "completed", "every published range is decidable");
	assert.equal(coverage.result, "affected");
	assert.equal(coverage.sourceSnapshot?.completeness, "tool-fetched");
});

test("the live TYPO3 publisher feed finds the real 13.4.2 cms-core advisories", { skip: SKIP }, () => {
	const out = path.join(WORK, "typo3.json");
	const run = spawnSync(process.execPath, [CLI, "-s", path.join(WORK, "typo3"),
		"--app-plugins", "typo3", "--typo3-advisories-live", "--ecosystem", "composer",
		"-d", "eol,nvd,epss,kev,retire,transitive", "--report-json", out, "--no-checksums"],
		{ timeout: SCAN_TIMEOUT_MS, encoding: "utf8", env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
	const doc = JSON.parse(fs.readFileSync(out, "utf8"));
	const app = doc.applications?.[0];
	assert.equal(app?.type, "typo3", "the official extract is detected");
	const core = doc.applicationInventory.find(c => c.kind === "core" && c.applicationId === app.id);
	assert.equal(core.version, "13.4.2");
	const lane = doc.cve.filter(f => String(f.source || "").includes("github-typo3-advisories"));
	assert.ok(lane.length >= 8, `the publisher feed holds several cms-core advisories affecting 13.4.2; got ${lane.length}`);
	const cve = lane.find(f => f.id === "CVE-2026-19418");
	assert.ok(cve, "13.4.2 is inside the 13.0.0-13.4.33 branch of CVE-2026-19418");
	assert.equal(cve.fixVersion, "13.4.34");
	const seo = doc.applicationInventory.find(c => c.coord === "typo3/cms-seo" && c.applicationId === app.id);
	const seoCoverage = doc.coverage.find(c => c.occurrenceId === seo.id);
	assert.equal(seoCoverage.execution, "completed");
	assert.equal(seoCoverage.result, "no-match", "no published advisory targets cms-seo: an honest no-match, never silence");
	const coverage = doc.coverage.find(c => c.occurrenceId === core.id);
	assert.equal(coverage.execution, "completed", "comma-joined hyphen intervals are decidable OR branches");
	assert.equal(coverage.result, "affected");
});
