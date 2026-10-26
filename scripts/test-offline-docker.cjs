#!/usr/bin/env node
// Opt-in integration check: requires Docker, a local Node image, installed
// dependencies, and network access ONLY for warming public fixture coordinates.
// Run: node scripts/test-offline-docker.cjs
// Evidence is kept in the printed temporary directory. No host cache is mounted.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const assert = require("node:assert/strict");

const repo = path.resolve(__dirname, "..");
const image = process.env.FAD_DOCKER_IMAGE || "node:22-bookworm";
const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-docker-cycle-"));
fs.chmodSync(root, 0o755);
const write = (name, text) => fs.writeFileSync(path.join(root, name), text);
const run = (cmd, args, opts = {}) => {
	const result = spawnSync(cmd, args, { cwd: repo, encoding: "utf8", timeout: 600000, ...opts });
	assert.ifError(result.error);
	assert.equal(result.status, 0, `${cmd} failed: ${result.stderr || ""}\nEvidence: ${root}`);
	return result.stdout;
};
console.log(`Evidence: ${root}`);
run("docker", ["image", "inspect", image]);
const packed = JSON.parse(run("npm", ["pack", "--json", "--pack-destination", root]))[0];
run("tar", ["-xzf", path.join(root, packed.filename), "-C", root]);
fs.cpSync(path.join(repo, "node_modules"), path.join(root, "package/node_modules"), { recursive: true });
// npm tarballs can contain owner-only source files. Normalize this test copy
// for containers that drop DAC_OVERRIDE; the working tree stays unchanged.
function readable(dir) {
	for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
		const file = path.join(dir, item.name);
		if (item.isSymbolicLink()) continue;
		fs.chmodSync(file, fs.statSync(file).mode | (item.isDirectory() ? 0o555 : 0o444));
		if (item.isDirectory()) readable(file);
	}
}
readable(path.join(root, "package"));
fs.mkdirSync(path.join(root, "transfer"), { mode: 0o777 });
fs.chmodSync(path.join(root, "transfer"), 0o777);
fs.mkdirSync(path.join(root, "fixture"));
write("fixture/pom.xml", `<project><modelVersion>4.0.0</modelVersion>
<groupId>example.offline.test</groupId><artifactId>offline-test</artifactId><version>1.0</version>
<dependencies>
<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
<dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>
</dependencies></project>`);
write("audit.cjs", `
const fs = require("node:fs");
const calls = [];
function trace(obj, key) {
	const original = obj[key];
	obj[key] = function(...args) { calls.push(key); return original.apply(this, args); };
}
trace(globalThis, "fetch");
trace(require("node:net").Socket.prototype, "connect");
for (const mod of ["node:http", "node:https"]) {
	trace(require(mod), "request"); trace(require(mod), "get");
}
trace(require("node:dns"), "lookup");
process.on("exit", () => fs.writeFileSync("/out/network-" + process.pid + ".json", JSON.stringify(calls)));
`);
write("phase.cjs", `
const fs = require("node:fs"), assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const phase = process.argv[2], offline = phase !== "warm";
assert.equal(fs.existsSync("/root/.fad-checker"), false, "each phase starts with no cache");
function cli(args, status = 0) {
	const preload = offline ? ["--require", "/audit.cjs"] : [];
	const r = spawnSync(process.execPath, [...preload, "/app/vigievuln.js", ...args],
		{ stdio: "inherit", timeout: 500000 });
	assert.ifError(r.error); assert.equal(r.status, status, args.join(" "));
}
const flags = ["--cve-offline", "--no-certfr", "--no-euvd", "--retries", "0"];
async function main() {
	if (offline) {
		assert.deepEqual(Object.keys(require("node:os").networkInterfaces()), ["lo"]);
		await new Promise((resolve, reject) => {
			const s = require("node:net").connect({ host: "1.1.1.1", port: 443 });
			s.setTimeout(2000);
			s.on("connect", () => { s.destroy(); reject(new Error("External network reachable")); });
			s.on("timeout", () => { s.destroy(); reject(new Error("Expected immediate ENETUNREACH")); });
			s.on("error", e => { if (e.code === "ENETUNREACH") resolve(); else reject(e); });
		});
		console.log("ISOLATION_OK: loopback only, external TCP ENETUNREACH, empty cache");
	}
	if (phase === "export") {
		cli(["-s", "/fixture", "--export-anonymized", "/out/deps.json"]);
		assert.equal(JSON.parse(fs.readFileSync("/out/deps.json")).summary.total, 2);
	} else if (phase === "warm") {
		cli(["--import-anonymized", "/out/deps.json", ...flags, "--report-json", "/out/online.json"]);
		cli(["--export-cache", "/out/cache.tar.gz"]);
	} else {
		cli(["--import-cache", "/out/cache.tar.gz"]);
		// Exercise the expired-KEV regression with a real fetched catalogue.
		const kevPath = "/root/.fad-checker/kev-cache.json";
		const kev = JSON.parse(fs.readFileSync(kevPath));
		kev._fetchedAt = Date.now() - 72 * 3600e3;
		fs.writeFileSync(kevPath, JSON.stringify(kev));
		const before = fs.readFileSync(kevPath, "utf8"), modified = fs.statSync(kevPath).mtimeMs;
		cli(["-s", "/fixture", "--offline", ...flags, "--fail-on", "kev",
			"--report-output", "/out/report", "--report-json", "--report-html",
			"--report-doc", "--report-xlsx", "--report-sbom", "--report-sarif", "--report-csaf"], 1);
		assert.equal(fs.readFileSync(kevPath, "utf8"), before);
		assert.equal(fs.statSync(kevPath).mtimeMs, modified);
		const online = JSON.parse(fs.readFileSync("/out/online.json"));
		const result = JSON.parse(fs.readFileSync("/out/report/findings.json"));
		const evidence = d => d.cve.map(c => JSON.stringify([
			c.id, c.dep.ecosystem, c.dep.coord, c.dep.version, c.dep.scope, c.dep.isDev,
			c.severity, c.kev, c.kevDueDate, c.cvss, c.epss, c.fixVersion,
		])).sort();
		assert.deepEqual(evidence(result), evidence(online), "findings survive the offline transfer");
		assert.ok(result.cve.some(c => c.id === "CVE-2021-44228" && c.kev));
		assert.ok(!result.warnings.some(w => ["private-libs", "osv-coverage", "unresolved-versions"].includes(w.type)));
		assert.ok(result.cve.some(c => c.dep.coord === "org.apache.commons:commons-lang3" && c.dep.scope === "transitive"),
			"the offline source scan resolves and scans transitive dependencies");
		for (const file of ["cve-report.html", "cve-report.doc", "findings.xlsx", "sbom.cdx.json", "fad.sarif", "csaf-vex.json"])
			assert.ok(fs.statSync("/out/report/" + file).size > 0, file);
		console.log("CYCLE_OK", JSON.stringify({ cve: result.cve.length, kev: result.cve.filter(c => c.kev).length }));
	}
	if (offline) {
		const traces = fs.readdirSync("/out").filter(n => /^network-.*\\.json$/.test(n));
		assert.ok(traces.length > 0);
		for (const name of traces) assert.deepEqual(JSON.parse(fs.readFileSync("/out/" + name)), [], name);
		console.log("NETWORK_ATTEMPTS: 0");
	}
}
main().catch(e => { console.error(e); process.exitCode = 1; });
`);

function phase(name) {
	const args = ["run", "--rm", "--pull", "never", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"];
	if (name !== "warm") args.push("--network", "none");
	const mounts = [["package", "/app", true], ["transfer", "/out", false], ["phase.cjs", "/phase.cjs", true]];
	if (name !== "warm") mounts.push(["fixture", "/fixture", true], ["audit.cjs", "/audit.cjs", true]);
	for (const [local, target, readonly] of mounts)
		args.push("--mount", `type=bind,src=${path.join(root, local)},dst=${target}${readonly ? ",readonly" : ""}`);
	args.push(image, "node", "/phase.cjs", name);
	const log = fs.openSync(path.join(root, `${name}.log`), "w");
	try { run("docker", args, { stdio: ["ignore", log, log] }); }
	finally { fs.closeSync(log); }
	console.log(`${name}: PASS (${path.join(root, `${name}.log`)})`);
}
phase("export");
phase("warm");
phase("scan");
console.log(`PASS: packaged vigievuln ${packed.version}; fresh containers; offline transfer; stale KEV gate; zero offline network attempts.`);
