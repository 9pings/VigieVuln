const { test } = require("node:test");
const assert = require("node:assert");
const { execFileSync } = require("child_process");
const fs = require("fs"); const os = require("os"); const path = require("path");
const CLI = path.join(__dirname, "..", "vigievuln.js");

function run(args, env = {}) {
	return execFileSync("node", [CLI, ...args], { env: { ...process.env, ...env }, encoding: "utf8" });
}

test("add-repo + list-repos + remove-repo round-trip (temp HOME)", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "fad-home-"));
	const env = { HOME: home, USERPROFILE: home };
	run(["--add-repo", "npm", "verda", "https://npm.acme/", "--token", "T"], env);
	const list = run(["--list-repos"], env);
	assert.match(list, /npm/); assert.match(list, /verda/); assert.match(list, /\[auth\]/);
	const cfg = JSON.parse(fs.readFileSync(path.join(home, ".fad-checker", "config.json"), "utf8"));
	assert.strictEqual(cfg.registries.npm[0].token, "T");
	run(["--remove-repo", "npm", "verda"], env);
	assert.match(run(["--list-repos"], env), /No custom registries/);
	fs.rmSync(home, { recursive: true, force: true });
});

test("add-repo rejects unknown ecosystem", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "fad-home-"));
	assert.throws(() => run(["--add-repo", "cargo", "x", "https://y/"], { HOME: home, USERPROFILE: home }));
	fs.rmSync(home, { recursive: true, force: true });
});

test("add-repo requires <eco> <name> <url>", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "fad-home-"));
	assert.throws(() => run(["--add-repo", "npm", "only-name"], { HOME: home, USERPROFILE: home }));
	fs.rmSync(home, { recursive: true, force: true });
});

test("--source is accepted as a source alias (read-only scan succeeds)", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "fad-home-"));
	const src = path.join(__dirname, "fixtures", "simple");
	const out = run(["--source", src, "--offline", "--no-report"], { HOME: home, USERPROFILE: home, FORCE_COLOR: "0" });
	assert.match(out, /source\s+/);
	fs.rmSync(home, { recursive: true, force: true });
});

test("--config JSON file supplies the source + options", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "fad-home-"));
	const src = path.join(__dirname, "fixtures", "simple");
	const cfgPath = path.join(home, "fad.json");
	fs.writeFileSync(cfgPath, JSON.stringify({ source: src, report: false, offline: true }));
	const out = run(["--config", cfgPath], { HOME: home, USERPROFILE: home, FORCE_COLOR: "0" });
	assert.match(out, /no files written|scan \+ gate only/i);
	fs.rmSync(home, { recursive: true, force: true });
});

test("FAD_CHECKER_ENV supplies default flags (CLI-flag string)", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "fad-home-"));
	const src = path.join(__dirname, "fixtures", "simple");
	const out = run(["-s", src], { HOME: home, USERPROFILE: home, FORCE_COLOR: "0", FAD_CHECKER_ENV: "--offline --no-report" });
	assert.match(out, /offline/);
	fs.rmSync(home, { recursive: true, force: true });
});
