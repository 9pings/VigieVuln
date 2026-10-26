const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { spawnSync } = require("child_process");

const CLI = path.join(__dirname, "..", "vigievuln.js");
const FIX = n => path.join(__dirname, "fixtures", n);
const tmp = name => path.join(os.tmpdir(), `fad-anon-${process.pid}-${name}`);

function run(args) {
	return spawnSync("node", [CLI, ...args], { encoding: "utf8" });
}

test("--export-anonymized writes a valid, path-free descriptor (offline, no report)", () => {
	const out = tmp("deps.json");
	try {
		const r = run(["-s", FIX("python-pyproject"), "--export-anonymized", out]);
		assert.strictEqual(r.status, 0, r.stderr);
		assert.ok(fs.existsSync(out), "descriptor file should be written");
		const raw = fs.readFileSync(out, "utf8");
		const d = JSON.parse(raw);
		assert.strictEqual(d.schema, "fad-deps/1");
		assert.ok(d.summary.total > 0, "should have collected deps");
		assert.ok(d.deps.some(x => x.name === "requests"));
		// anonymization: the descriptor must not leak the fixture path
		assert.ok(!raw.includes("fixtures"), "no path fragment should leak");
		assert.ok(!/https?:\/\//.test(raw), "no URLs");
	} finally { fs.rmSync(out, { force: true }); }
});

test("--export-anonymized respects -e exclusions", () => {
	const out = tmp("excl.json");
	try {
		const r = run(["-s", FIX("python-pyproject"), "-e", "^requests$", "--export-anonymized", out]);
		assert.strictEqual(r.status, 0, r.stderr);
		const d = JSON.parse(fs.readFileSync(out, "utf8"));
		assert.ok(!d.deps.some(x => x.name === "requests"), "excluded dep must be absent from the descriptor");
		assert.ok(d.deps.some(x => x.name === "django"), "non-excluded deps remain");
	} finally { fs.rmSync(out, { force: true }); }
});

test("missing --src without --import-anonymized errors out", () => {
	const r = run(["--no-report"]);
	assert.notStrictEqual(r.status, 0);
	assert.match(r.stderr + r.stdout, /--src/);
});

test("--import-anonymized rejects an incompatible schema", () => {
	const bad = tmp("bad.json");
	fs.writeFileSync(bad, JSON.stringify({ schema: "fad-deps/999", deps: [] }));
	try {
		const r = run(["--import-anonymized", bad, "--offline"]);
		assert.notStrictEqual(r.status, 0);
		assert.match(r.stderr + r.stdout, /schema/i);
	} finally { fs.rmSync(bad, { force: true }); }
});

test("--import-anonymized warms caches but writes NO report by default", () => {
	const desc = tmp("warm.json");
	const outDir = tmp("warm-report");
	try {
		const e = run(["-s", FIX("python-pyproject"), "--export-anonymized", desc]);
		assert.strictEqual(e.status, 0, e.stderr);
		// import is a cache-warming step (here offline → no-op warm) — it must NOT emit a report.
		const r = run(["--import-anonymized", desc, "--offline", "--report-output", outDir]);
		assert.strictEqual(r.status, 0, r.stderr);
		const wrote = fs.existsSync(outDir) ? fs.readdirSync(outDir) : [];
		assert.deepStrictEqual(wrote, [], `import-anonymized must write no report files, wrote: [${wrote.join(", ")}]`);
	} finally { fs.rmSync(desc, { force: true }); fs.rmSync(outDir, { recursive: true, force: true }); }
});

test("export → import round-trip: descriptor re-imports to the same coordinates", () => {
	const out = tmp("rt.json");
	try {
		const e = run(["-s", FIX("python-pyproject"), "--export-anonymized", out]);
		assert.strictEqual(e.status, 0, e.stderr);
		const { deserializeDeps } = require("../lib/deps-descriptor");
		const back = deserializeDeps(JSON.parse(fs.readFileSync(out, "utf8")));
		assert.ok(back.resolved.has("pypi:requests"));
		assert.strictEqual(back.runMaven, false);
	} finally { fs.rmSync(out, { force: true }); }
});
