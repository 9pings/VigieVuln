/**
 * test/extract-mode.test.js — `-t <dir>` is an EXTRACTION step, not a scan.
 *
 * With -t, vigievuln walks the source tree, links the reactor modules, writes the
 * cleaned POM tree + mirrored manifests, reports the Maven POM analysis (missing
 * parents / private libs — the ONLY online action, and only when online) and STOPS.
 * The vulnerability scan + report only run when something explicitly asks for them
 * (--snyk, a --report-* flag, --fail-on / --fail-on-new / --baseline).
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CLI = path.join(__dirname, "..", "vigievuln.js");
const SIMPLE = path.join(__dirname, "fixtures", "simple");

function run(args, cwd) {
	return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", cwd });
}

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "fad-extract-")); }

test("-t alone writes the cleaned tree and stops before the vulnerability scan", () => {
	const root = tmp();
	const target = path.join(root, "clean");
	const res = run(["-s", SIMPLE, "-t", target, "--offline"], root);
	assert.equal(res.status, 0, res.stderr);
	assert.ok(fs.existsSync(path.join(target, "pom.xml")), "root cleaned POM written");
	assert.ok(fs.existsSync(path.join(target, "app", "pom.xml")), "module cleaned POM written");
	assert.doesNotMatch(res.stdout, /Vulnerability database update/, "no scan in extraction mode");
	assert.ok(!fs.existsSync(path.join(root, "vigievuln-report")), "no report dir in extraction mode");
	assert.match(res.stdout, /extraction/i, "the terminal says it was an extraction");
	fs.rmSync(root, { recursive: true, force: true });
});

test("-t with an explicit --report-* flag still runs the scan and writes that report", () => {
	const root = tmp();
	const target = path.join(root, "clean");
	const out = path.join(root, "findings.json");
	const res = run(["-s", SIMPLE, "-t", target, "--offline", "--report-json", out], root);
	assert.equal(res.status, 0, res.stderr);
	assert.ok(fs.existsSync(path.join(target, "pom.xml")));
	assert.match(res.stdout, /Vulnerability database update/, "scan requested explicitly");
	assert.ok(fs.existsSync(out), "requested findings JSON written");
	fs.rmSync(root, { recursive: true, force: true });
});

test("-t with --fail-on still runs the scan (CI gate needs findings)", () => {
	const root = tmp();
	const res = run(["-s", SIMPLE, "-t", path.join(root, "clean"), "--offline", "--no-report", "--fail-on", "critical"], root);
	assert.match(res.stdout, /Vulnerability database update/);
	fs.rmSync(root, { recursive: true, force: true });
});
