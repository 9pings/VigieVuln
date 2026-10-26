const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("child_process");
const path = require("path");
const { DISABLE, ACTIVATE, REPORTS, applyGroups, applyReports, foldedFlags, parseList } = require("../lib/cli-groups");
const CLI = path.join(__dirname, "..", "vigievuln.js");

function help(args) {
	try { return execFileSync("node", [CLI, ...args], { env: { ...process.env, FORCE_COLOR: "0" }, encoding: "utf8" }); }
	catch (e) { return `${e.stdout || ""}${e.stderr || ""}`; }
}

test("--help fits a screen; --help-all still lists everything", () => {
	// It was 176 lines across two screens, eighty options, thirty-six of them a --no-X or
	// an opt-in switch. Those are two lists, not thirty-six decisions.
	const short = help(["--help"]).split("\n");
	const all = help(["--help-all"]).split("\n");
	assert.ok(short.length <= 65, `--help is ${short.length} lines`);
	assert.ok(all.length > short.length + 20, `--help-all (${all.length}) must show much more than --help (${short.length})`);
	for (const f of ["-d, --disable", "-a, --activate", "-r, --report", "-o, --report-output"]) {
		assert.ok(short.join("\n").includes(f), `${f} must be visible`);
	}
	// the folded flags are hidden, not removed
	assert.ok(!short.join("\n").includes("--no-nvd"), "--no-nvd is hidden from --help");
	assert.ok(all.join("\n").includes("--no-nvd"), "--no-nvd is still listed by --help-all");
	assert.ok(all.join("\n").includes("--export-cache"), "admin commands listed by --help-all");
});

test("the folded flags still work — hiding them breaks no existing script", () => {
	assert.ok(foldedFlags().includes("--no-nvd"));
	assert.ok(foldedFlags().includes("--licenses"));
	assert.equal(foldedFlags().length, Object.keys(DISABLE).length + Object.keys(ACTIVATE).length);
});

test("-d turns things off and -a turns things on", () => {
	const o = {};
	assert.deepEqual(applyGroups(o, { disable: "eol,nvd", activate: "licenses, snyk" }).errors, []);
	assert.deepEqual(o, { eol: false, nvd: false, licenses: true, snyk: true });
});

test("a token is tolerant about spacing and case, because a human types it", () => {
	assert.deepEqual(parseList(" EOL , nvd\tosv "), ["eol", "nvd", "osv"]);
	const o = {}; applyGroups(o, { disable: "EOL" });
	assert.equal(o.eol, false);
});

test("an unknown token is a hard error, never silently ignored", () => {
	// A dropped "-d nvd" would produce a report claiming coverage the run did not have.
	const { errors } = applyGroups({}, { disable: "nvd,nope", activate: "alsonope" });
	assert.equal(errors.length, 2);
	assert.match(errors[0], /unknown --disable value "nope"/);
	assert.match(errors[0], /expected one of: .*nvd/);
	assert.match(errors[1], /unknown --activate value "alsonope"/);
	const out = help(["-s", "test/fixtures/polyglot", "-d", "nope"]);
	assert.match(out, /unknown --disable value "nope"/);
});

test("osv-db is in both lists: it is tri-state, forced on or forced off", () => {
	assert.ok(DISABLE["osv-db"] && ACTIVATE["osv-db"]);
	const off = {}; applyGroups(off, { disable: "osv-db" });
	const on = {}; applyGroups(on, { activate: "osv-db" });
	assert.equal(off.osvDb, false);
	assert.equal(on.osvDb, true);
});

test("-r selects exactly the outputs named, and never overrides an explicit path", () => {
	const o = {};
	assert.deepEqual(applyReports(o, "sbom,sarif").errors, []);
	assert.deepEqual(o, { reportSbom: true, reportSarif: true });
	const explicit = { reportJson: "/tmp/mine.json" };
	applyReports(explicit, "json");
	assert.equal(explicit.reportJson, "/tmp/mine.json", "an explicit --report-json path wins");
	const excel = {}; applyReports(excel, "xlsx");
	assert.equal(excel.reportXlsx, true);
	assert.match(applyReports({}, "nope").errors[0], /unknown --report value "nope"/);
	assert.deepEqual(applyReports({}, "").errors, [], "an empty list selects nothing and is not an error");
	assert.deepEqual(REPORTS, ["html", "doc", "xlsx", "sbom", "csaf", "json", "sarif"]);
});

test("every -d and -a token names a real option", () => {
	const src = require("fs").readFileSync(CLI, "utf8");
	for (const tok of Object.keys(DISABLE)) {
		assert.ok(src.includes(`"--no-${tok}"`), `-d ${tok} has no --no-${tok} behind it`);
	}
	for (const tok of Object.keys(ACTIVATE)) {
		assert.ok(new RegExp(`"--${tok}[ "<]`).test(src), `-a ${tok} has no --${tok} behind it`);
	}
});
