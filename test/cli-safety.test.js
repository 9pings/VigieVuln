/**
 * test/cli-safety.test.js — guards on the two CLI behaviours whose failure is
 * destructive or silently disables CI gating. These spawn the real binary.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CLI = path.join(__dirname, "..", "fad-checker.js");

function run(args, opts = {}) {
	return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", ...opts });
}

// The catastrophic case: --target is a PARENT of --src. --target is rimraf'd
// before being rewritten, so this would delete the source tree + siblings.
test("--target that is a parent of --src is rejected (and deletes nothing)", () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-safety-"));
	const src = path.join(root, "src", "inner");
	fs.mkdirSync(src, { recursive: true });
	fs.writeFileSync(path.join(root, "IMPORTANT.txt"), "precious");
	fs.writeFileSync(path.join(src, "pom.xml"),
		"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>");

	const res = run(["-s", src, "-t", root, "--no-report", "--offline"]);
	assert.notEqual(res.status, 0, "must exit non-zero");
	assert.match(res.stderr, /must not overlap/i);
	assert.ok(fs.existsSync(path.join(root, "IMPORTANT.txt")), "source tree must be untouched");
	assert.ok(fs.existsSync(path.join(src, "pom.xml")));
	fs.rmSync(root, { recursive: true, force: true });
});

test("--target equal to --src is rejected", () => {
	const src = fs.mkdtempSync(path.join(os.tmpdir(), "fad-safety-"));
	fs.writeFileSync(path.join(src, "pom.xml"),
		"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>");
	const res = run(["-s", src, "-t", src, "--no-report", "--offline"]);
	assert.notEqual(res.status, 0);
	assert.match(res.stderr, /must not overlap/i);
	fs.rmSync(src, { recursive: true, force: true });
});

test("non-empty --target requires --force and preserves its contents on refusal", () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-safety-target-"));
	try {
		const src = path.join(root, "src");
		const target = path.join(root, "target");
		fs.mkdirSync(src);
		fs.mkdirSync(target);
		fs.writeFileSync(path.join(target, "IMPORTANT.txt"), "precious");
		const denied = run(["-s", src, "-t", target, "--offline"]);
		assert.notEqual(denied.status, 0);
		assert.match(denied.stderr, /--force/);
		assert.equal(fs.readFileSync(path.join(target, "IMPORTANT.txt"), "utf8"), "precious");
		const allowed = run(["-s", src, "-t", target, "--force", "--offline"]);
		assert.equal(allowed.status, 0, allowed.stderr);
		assert.ok(!fs.existsSync(path.join(target, "IMPORTANT.txt")));
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("empty --target works without --force", () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-safety-empty-"));
	try {
		const src = path.join(root, "src");
		const target = path.join(root, "target");
		fs.mkdirSync(src);
		fs.mkdirSync(target);
		const result = run(["-s", src, "-t", target, "--offline"]);
		assert.equal(result.status, 0, result.stderr);
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("--force still refuses a symlink target", () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-safety-link-"));
	try {
		const src = path.join(root, "src");
		const destination = path.join(root, "destination");
		const target = path.join(root, "target-link");
		fs.mkdirSync(src); fs.mkdirSync(destination);
		fs.writeFileSync(path.join(destination, "IMPORTANT.txt"), "precious");
		// Directory junctions exercise the same symlink guard on Windows
		// without requiring administrator rights or Developer Mode.
		fs.symlinkSync(destination, target, process.platform === "win32" ? "junction" : "dir");
		const result = run(["-s", src, "-t", target, "--force", "--offline"]);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /symlink/i);
		assert.equal(fs.readFileSync(path.join(destination, "IMPORTANT.txt"), "utf8"), "precious");
	} finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// An unrecognised --fail-on (CI typo) must hard-fail, never silently pass.
test("invalid --fail-on hard-fails instead of disabling the gate", () => {
	const src = path.join(__dirname, "fixtures", "simple");
	const res = run(["-s", src, "--offline", "--no-report", "--fail-on", "hgih"]);
	assert.equal(res.status, 2);
	assert.match(res.stderr, /invalid --fail-on/i);
});

test("a valid --fail-on level is accepted", () => {
	const src = path.join(__dirname, "fixtures", "simple");
	const res = run(["-s", src, "--offline", "--no-report", "--fail-on", "none"]);
	assert.equal(res.status, 0);
});

// --no-report writes NO files, but the scan + CI gate still run.
// HERMETIC: a temp HOME carries a one-CVE warmed index, so the gate outcome is
// deterministic — the old version read this machine's real ~/.fad-checker and
// failed on any box whose cache was cold or stale (it did catch the amputated
// 2026-06 index that way, but a fixture keeps the signal without the flake).
test("--no-report still runs the gate (and fails on a high finding)", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "fad-home-"));
	const cveDir = path.join(home, ".fad-checker", "cve-data");
	fs.mkdirSync(cveDir, { recursive: true });
	const entry = {
		id: "CVE-2099-0001", severity: "HIGH", score: 8.8, description: "gate sentinel",
		fixVersion: "2.15.0", vendor: "apache", product: "apache log4j2",
		ranges: [{ version: "2.0", status: "affected", lessThan: "2.15.0" }],
	};
	fs.writeFileSync(path.join(cveDir, "maven-cve-index.json"), JSON.stringify({
		meta: { builtAt: new Date().toISOString(), cveCount: 1 },
		byPackageName: { "org.apache.logging.log4j:log4j-core": [entry] },
		byProduct: {},
	}));
	const src = path.join(__dirname, "fixtures", "polyglot");
	const res = run(["-s", src, "--offline", "--no-report", "--fail-on", "high"],
		{ env: { ...process.env, HOME: home, USERPROFILE: home } });
	assert.equal(res.status, 1, `gate must fail on the HIGH sentinel\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
	fs.rmSync(home, { recursive: true, force: true });
});

test("--no-report writes no files at all", () => {
	const src = path.join(__dirname, "fixtures", "polyglot");
	const out = fs.mkdtempSync(path.join(os.tmpdir(), "fad-noreport-"));
	const res = run(["-s", src, "--offline", "--no-report", "--report-output", out], { env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(res.status, 0);
	assert.ok(!fs.existsSync(out) || fs.readdirSync(out).length === 0, "no output files written");
	fs.rmSync(out, { recursive: true, force: true });
});

// Selecting any --report-* flag overrides the default HTML+JSON set: only the
// chosen outputs are written (each to its given path or its default name).
test("--report-sbom alone writes only the SBOM (no HTML/doc)", () => {
	const src = path.join(__dirname, "fixtures", "polyglot");
	const out = fs.mkdtempSync(path.join(os.tmpdir(), "fad-report-"));
	const res = run(["-s", src, "--offline", "--report-output", out, "--report-sbom"], { env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(res.status, 0);
	assert.ok(fs.existsSync(path.join(out, "sbom.cdx.json")), "SBOM written to default name");
	assert.ok(!fs.existsSync(path.join(out, "cve-report.html")), "no HTML when a --report-* is selected");
	fs.rmSync(out, { recursive: true, force: true });
});

test("--report-html with an explicit path writes there", () => {
	const src = path.join(__dirname, "fixtures", "polyglot");
	const out = fs.mkdtempSync(path.join(os.tmpdir(), "fad-report-"));
	const target = path.join(out, "nested", "my.html");
	const res = run(["-s", src, "--offline", "--report-html", target], { env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(res.status, 0);
	assert.ok(fs.existsSync(target), "HTML written to the explicit (nested) path");
	fs.rmSync(out, { recursive: true, force: true });
});

test("--report-xlsx and -r xlsx select a standalone Excel workbook", () => {
	const src = path.join(__dirname, "fixtures", "polyglot");
	const out = fs.mkdtempSync(path.join(os.tmpdir(), "fad-xlsx-cli-"));
	try {
		const explicit = path.join(out, "nested", "audit.xlsx");
		const one = run(["-s", src, "--offline", "--report-xlsx", explicit], { env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(one.status, 0, one.stderr);
		assert.equal(fs.readFileSync(explicit).subarray(0, 2).toString(), "PK");
		assert.match(fs.readFileSync(path.join(out, "nested", "SHA256SUMS"), "utf8"), /audit\.xlsx/);
		assert.ok(!fs.existsSync(path.join(out, "nested", "cve-report.html")));
		const two = run(["-s", src, "--offline", "-r", "xlsx", "-o", out, "--no-checksums"],
			{ env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(two.status, 0, two.stderr);
		assert.equal(fs.readFileSync(path.join(out, "findings.xlsx")).subarray(0, 2).toString(), "PK");
		const bad = path.join(out, "mislabelled.xls");
		const invalid = run(["-s", src, "--offline", "--report-xlsx", bad, "--no-checksums"],
			{ env: { ...process.env, FORCE_COLOR: "0" } });
		assert.equal(invalid.status, 2, invalid.stderr);
		assert.match(invalid.stdout + invalid.stderr, /must end in \.xlsx/);
		assert.ok(!fs.existsSync(bad));
	} finally { fs.rmSync(out, { recursive: true, force: true }); }
});
