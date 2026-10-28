const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("child_process");
const path = require("path");
const CLI = path.join(__dirname, "..", "vigievuln.js");
const pkg = require("../package.json");

// FORCE_COLOR=0 so the assertions see plain text, not ANSI.
function run(args) {
	try {
		return { out: execFileSync("node", [CLI, ...args], { env: { ...process.env, FORCE_COLOR: "0" }, encoding: "utf8" }), code: 0 };
	} catch (e) {
		return { out: `${e.stdout || ""}${e.stderr || ""}`, code: e.status };
	}
}

test("no arguments prints a mini help carrying the current version, and exits non-zero", () => {
	const { out, code } = run([]);
	assert.match(out, new RegExp(`VigieVuln v${pkg.version.replace(/\./g, "\\.")}\\b`), "banner names the running version");
	assert.match(out, /vigievuln scan <dir>/, "leads users to the positional scan command");
	assert.match(out, /vigievuln watch <dir>/);
	assert.match(out, /vigievuln login/);
	assert.match(out, /-s <dir>/, "retains a legacy invocation example");
	assert.match(out, /--help/, "points at the full help");
	assert.ok(out.length < 2000, "mini help stays mini (full --help is far longer)");
	assert.notEqual(code, 0, "a bare invocation scanned nothing — it must not read as success");
});

test("short flags: -h is help, -v is version, -V still works, verbose is long-form only", () => {
	assert.match(run(["-h"]).out, new RegExp(`VigieVuln v${pkg.version.replace(/\./g, "\\.")}`), "-h prints the full help");
	assert.equal(run(["-h"]).out, run(["--help"]).out, "-h is --help");
	assert.ok(run(["-h"]).out.length > 1200, "-h still lists the scan options");
	assert.equal(run(["-h"]).code, 0);

	assert.equal(run(["-v"]).out.trim(), pkg.version, "-v is the version");
	assert.equal(run(["-V"]).out.trim(), pkg.version, "-V kept as an alias: it WAS the version flag");
	assert.equal(run(["--version"]).out.trim(), pkg.version);
	assert.equal(run(["-v"]).code, 0);

	const help = run(["--help"]).out;
	assert.match(help, /-v, --version/, "-v is bound to version");
	assert.doesNotMatch(help, /-v, --verbose/, "-v must no longer mean verbose");
	assert.match(help, /^\s+--verbose\b/m, "verbose is still there, long-form only");
});

test("a lone --verbose cannot be a verbose scan, so it lands on the mini help", () => {
	const { out, code } = run(["--verbose"]);
	assert.match(out, new RegExp(`VigieVuln v${pkg.version.replace(/\./g, "\\.")}\\b`));
	assert.ok(out.length < 2000, "mini help, not the full one");
	assert.notEqual(code, 0);
	assert.doesNotMatch(out, /required option/, "no bare commander error");
});

test("--help carries the current version too", () => {
	const { out, code } = run(["--help"]);
	assert.equal(code, 0);
	assert.match(out, new RegExp(`VigieVuln v${pkg.version.replace(/\./g, "\\.")}\\b`), "version header on the full help");
	assert.match(out, /-r, --report/, "the scan options are there");   // --report-json is folded into -r and shown by --help-all
	// --help is one screen now; --help-all is where everything lives.
	assert.ok(out.length > 1200, "--help lists the scan options");
	assert.ok(run(["--help-all"]).out.length > out.length, "--help-all is longer");
});

test("main and scan help put scan/watch/login before the legacy options", () => {
	for (const args of [["--help"], ["scan", "--help"], ["--help-all"]]) {
		const { out, code } = run(args);
		assert.equal(code, 0);
		const optionsStart = out.indexOf("Options:");
		assert.ok(optionsStart > 0);
		const introduction = out.slice(0, optionsStart);
		assert.match(introduction, /Usage: vigievuln scan <dir> \[options\]/);
		assert.match(introduction, /vigievuln watch <dir>/);
		assert.match(introduction, /vigievuln login \| logout \| whoami/);
		assert.ok(introduction.indexOf("scan <dir>") < introduction.indexOf("watch <dir>"));
		assert.ok(introduction.indexOf("watch <dir>") < introduction.indexOf("login | logout"));
		assert.doesNotMatch(introduction, /vigievuln -s/);
		assert.match(out.slice(optionsStart), /-s, --src <src>/);
		assert.match(out.slice(optionsStart), /-t, --target <target>/);
	}
	assert.equal(run(["scan", "--help"]).out, run(["--help"]).out);
});

test("the mini help and the full help agree on the version, and it is package.json's", () => {
	const v = run(["--version"]).out.trim();
	assert.equal(v, pkg.version);
	for (const args of [[], ["--help"]]) {
		assert.ok(run(args).out.includes(`v${v}`), `${args[0] || "(no args)"} shows v${v}`);
	}
});
