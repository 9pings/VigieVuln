const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const os = require("os");
const R = require("../lib/retire");

test("retire signature cache lives INSIDE ~/.fad-checker/ (so --export-cache carries it)", () => {
	const fadDir = path.join(os.homedir(), ".fad-checker");
	assert.ok(R.RETIRE_SIG_DIR.startsWith(fadDir), `${R.RETIRE_SIG_DIR} should be under ${fadDir}`);
	assert.ok(R.RETIRE_SIG_FILE.startsWith(R.RETIRE_SIG_DIR));
	assert.ok(R.RETIRE_CACHE_DIR.startsWith(fadDir));
});

test("buildRetireArgs uses --ignorefile (path-anchored) and adds --jsrepo only when a signature file is given", () => {
	const withRepo = R.buildRetireArgs({ srcDir: "/s", outPath: "/o.json", ignoreFile: "/ig.txt", jsRepo: "/sig.json" });
	assert.deepStrictEqual(withRepo, ["--verbose", "--outputformat", "json", "--outputpath", "/o.json", "--jspath", "/s", "--ignorefile", "/ig.txt", "--jsrepo", "/sig.json"]);
	const withoutRepo = R.buildRetireArgs({ srcDir: "/s", outPath: "/o.json", ignoreFile: "/ig.txt" });
	assert.ok(!withoutRepo.includes("--jsrepo"));
	assert.ok(withoutRepo.includes("--verbose"), "--verbose listed so retire reports ALL identified libs, not just vulnerable");
	assert.deepStrictEqual(withoutRepo.slice(0, 5), ["--verbose", "--outputformat", "json", "--outputpath", "/o.json"]);
	// No ignore file (nothing to exclude) → no --ignorefile flag at all.
	const noIgnore = R.buildRetireArgs({ srcDir: "/s", outPath: "/o.json" });
	assert.ok(!noIgnore.includes("--ignorefile"));
});

test("ensureSignatures offline never reaches the network — returns existence boolean", async () => {
	const fs = require("fs");
	const present = fs.existsSync(R.RETIRE_SIG_FILE);
	const r = await R.ensureSignatures({ offline: true });
	assert.strictEqual(typeof r, "boolean");
	assert.strictEqual(r, present);   // offline only reports what's already on disk
});

test("extractVendoredInventory lists ALL identified libs (vulnerable or not), sorted by severity", () => {
	const raw = { data: [
		{ file: "/proj/web/js/jquery-3.7.1.min.js", results: [{ component: "jquery", version: "3.7.1", detection: "filename", vulnerabilities: [] }] },
		{ file: "/proj/web/js/jquery-1.6.1.min.js", results: [{ component: "jquery", version: "1.6.1", detection: "filename", vulnerabilities: [{ severity: "medium" }, { severity: "high" }] }] },
		{ file: "/proj/web/bootstrap.min.js", results: [{ component: "bootstrap", version: "5.3.3", detection: "filecontent", vulnerabilities: [] }] },
	] };
	const inv = R.extractVendoredInventory(raw, "/proj");
	assert.strictEqual(inv.length, 3);
	// vulnerable jquery sorts first (max severity HIGH)
	assert.strictEqual(inv[0].component, "jquery");
	assert.strictEqual(inv[0].version, "1.6.1");
	assert.strictEqual(inv[0].vulnerable, true);
	assert.strictEqual(inv[0].vulnCount, 2);
	assert.strictEqual(inv[0].maxSeverity, "HIGH");
	// relToSrc uses path.relative, which yields NATIVE separators — backslashes on Windows.
	// That is deliberate: only the SARIF export normalises to "/" (its spec requires a URI);
	// the report and the JSON export show native paths a user can paste into their shell.
	assert.strictEqual(inv[0].file, path.join("web", "js", "jquery-1.6.1.min.js"));
	// non-vulnerable libs are present (the whole point)
	const safe = inv.filter(e => !e.vulnerable).map(e => e.component).sort();
	assert.deepStrictEqual(safe, ["bootstrap", "jquery"]);
});

test("extractVendoredInventory tolerates empty / missing input", () => {
	assert.deepStrictEqual(R.extractVendoredInventory(null, "/p"), []);
	assert.deepStrictEqual(R.extractVendoredInventory({ data: [] }, "/p"), []);
});

test("vendored paths are relative to --src even when -s is a relative path", () => {
	const cwd = process.cwd();
	const abs = path.join(cwd, "sub", "rel-src");
	const raw = { data: [
		{ file: path.join(abs, "web/js/jquery-1.6.1.min.js"), results: [{ component: "jquery", version: "1.6.1", detection: "filename", vulnerabilities: [{ severity: "high", identifiers: { CVE: ["CVE-X"] } }] }] },
	] };
	// relative srcDir (what -s ./sub/rel-src yields)
	const relSrc = path.join("sub", "rel-src");
	const inv = R.extractVendoredInventory(raw, relSrc);
	assert.strictEqual(inv[0].file, path.join("web", "js", "jquery-1.6.1.min.js"));
	const matches = R.normaliseRetireResults(raw, relSrc);
	assert.strictEqual(matches[0].dep.vendoredFile, path.join("web", "js", "jquery-1.6.1.min.js"));
});

test("retire findings cache is versioned: legacy entry (no _schema) is a cache MISS, _schema:2 round-trips", () => {
	const fs = require("fs");
	// Unique src path so the md5 cache key never collides with a real run.
	const srcDir = "/tmp/fad-cache-version-test-" + process.pid;
	const cachePath = path.join(R.RETIRE_CACHE_DIR, R.cacheKey(srcDir));
	const body = { data: [{ file: "/x/jquery.js", results: [{ component: "jquery", version: "3.7.1", vulnerabilities: [] }] }] };
	try {
		// (1) A legacy entry written by a pre-verbose version: fresh timestamp, NO _schema.
		fs.mkdirSync(R.RETIRE_CACHE_DIR, { recursive: true });
		fs.writeFileSync(cachePath, JSON.stringify({ _fetchedAt: Date.now(), body }));
		assert.strictEqual(R.readCache(srcDir), null, "legacy (no _schema) entry must be a cache miss");

		// (2) writeCache stamps _schema:2 and the entry round-trips.
		R.writeCache(srcDir, body);
		const onDisk = JSON.parse(fs.readFileSync(cachePath, "utf8"));
		assert.strictEqual(onDisk._schema, 2, "writeCache stamps _schema:2");
		assert.deepStrictEqual(R.readCache(srcDir), body, "_schema:2 entry round-trips");
	} finally {
		try { fs.unlinkSync(cachePath); } catch { /* best effort */ }
	}
});

test("scanWithRetireFull surfaces a scan failure instead of silently returning empty", async () => {
	const fs = require("fs");
	// Needs local signatures to actually reach the scan path (offline). Mirrors the
	// conditional style of the ensureSignatures test above.
	if (!fs.existsSync(R.RETIRE_SIG_FILE)) return;
	// A non-existent source dir makes retire crash (walkdir ENOENT) → empty output.
	// That must be reported, not turned into a clean "nothing found" (the bug that
	// hid a vendored-JS chapter when the scan actually died).
	const r = await R.scanWithRetireFull("/no/such/path-" + process.pid + "-" + process.ppid, { offline: true, force: true });
	assert.strictEqual(r.inventory.length, 0);
	assert.strictEqual(r.matches.length, 0);
	assert.ok(r.error, "a retire scan failure must be reported in the result, not swallowed");
});

test("retireFailureReason extracts the meaningful error line, not a stack frame", () => {
	const stderr = [
		"Exception caught:  Error: error reading first path in the walk /proj/cnaps",
		"Error: ENOENT: no such file or directory, lstat '/proj/cnaps'",
		"    at EventEmitter.<anonymous> (/x/walkdir.js:265:28)",
		"    at FSReqCallback.oncomplete (node:fs:195:21)",
	].join("\n");
	const reason = R.retireFailureReason(stderr, "fallback");
	assert.match(reason, /ENOENT|no such file/i);
	assert.ok(!/^\s*at /.test(reason), "must not be a stack frame");
	// Empty stderr → fallback.
	assert.strictEqual(R.retireFailureReason("", "the-fallback"), "the-fallback");
	assert.strictEqual(R.retireFailureReason("   \n  \n", "fb"), "fb");
});

// Faithfully replay how retire ITSELF turns ignore lines into match decisions, so
// these tests prove real behavior (not our reading of it). Mirrors, verbatim:
//   - cli.js plain-text ignorefile: an `@`-line is kept literal, any other line is
//     path.resolve()'d against retire's cwd;
//   - cli.js:179-182: escape regex specials, expand `*`→[^/]* and `**`→.*, new RegExp;
//   - scanner.js:103: a file is ignored if any regex matches the path (or its resolve()).
function retireIgnores(lines, absFile) {
	const regexes = lines
		.map(e => (e[0] === "@" ? e.slice(1) : path.resolve(e)))
		.map(p => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
		.map(p => p.replace(/[*]{1,2}/g, a => (a.length === 2 ? ".*" : "[^/]*")))
		.map(s => new RegExp(s));
	return regexes.some(i => i.test(absFile) || i.test(path.resolve(absFile)));
}

test("buildRetireIgnorePatterns ignores skip dirs at ANY depth (the nested-node_modules bug)", () => {
	const lines = R.buildRetireIgnorePatterns({ srcDir: "/proj" });
	// node_modules buried several levels deep — the exact case plain --ignore missed
	// (retire path.resolve()s "node_modules" against ITS cwd, never the scan root).
	assert.ok(retireIgnores(lines, "/proj/a/b/c/node_modules/jquery/dist/jquery.js"));
	assert.ok(retireIgnores(lines, "/proj/node_modules/x.js"));            // top-level too
	assert.ok(retireIgnores(lines, "/proj/web/target/classes/app.min.js")); // other defaults
	// real vendored source is still scanned
	assert.ok(!retireIgnores(lines, "/proj/web/js/jquery-1.6.1.min.js"));
});

test("buildRetireIgnorePatterns is segment-bounded — does not clip lookalike filenames", () => {
	const lines = R.buildRetireIgnorePatterns({ srcDir: "/proj" });
	// a file merely STARTING with a skip-dir name must NOT be excluded
	assert.ok(!retireIgnores(lines, "/proj/src/node_modules_shim.js"));
	// 'out'/'build'/'dist' are short — segment slashes keep ordinary files safe
	assert.ok(!retireIgnores(lines, "/proj/src/routes/about.js"));   // contains "out"
	assert.ok(!retireIgnores(lines, "/proj/src/rebuild-helper.js")); // contains "build"
});

test("buildRetireIgnorePatterns is independent of retire's cwd (anchored to the scan tree)", () => {
	// srcDir deliberately unrelated to process.cwd() — the original bug surfaced only
	// when vigievuln ran from a different directory than -s.
	const lines = R.buildRetireIgnorePatterns({ srcDir: "/totally/other/proj" });
	assert.ok(retireIgnores(lines, "/totally/other/proj/sub/node_modules/lodash/lodash.js"));
});

test("buildRetireIgnorePatterns honors --exclude-path, anchored to the scan root", () => {
	const lines = R.buildRetireIgnorePatterns({ srcDir: "/proj", excludePath: ["webapp/legacy"] });
	assert.ok(retireIgnores(lines, "/proj/webapp/legacy/old.js"));        // excluded
	assert.ok(!retireIgnores(lines, "/proj/other/webapp/legacy/old.js")); // anchored, NOT any-depth
	// leading ./, leading /, trailing /, and trailing /** all normalise the same
	for (const g of ["./webapp/legacy", "/webapp/legacy", "webapp/legacy/", "webapp/legacy/**"]) {
		assert.ok(retireIgnores(R.buildRetireIgnorePatterns({ srcDir: "/proj", excludePath: [g] }), "/proj/webapp/legacy/x.js"), g);
	}
	// a mid-glob ** expands through retire's own * handling
	assert.ok(retireIgnores(R.buildRetireIgnorePatterns({ srcDir: "/proj", excludePath: ["pkgs/**/legacy"] }), "/proj/pkgs/a/b/legacy/x.js"));
});

test("buildRetireIgnorePatterns: --no-default-excludes drops the defaults but keeps user globs", () => {
	const lines = R.buildRetireIgnorePatterns({ srcDir: "/proj", excludePath: ["vendor"], defaultExcludes: false });
	assert.ok(!retireIgnores(lines, "/proj/node_modules/x.js"), "defaults dropped");
	assert.ok(retireIgnores(lines, "/proj/vendor/x.js"), "user glob kept");
});

test("buildRetireIgnorePatterns resolves a relative srcDir to absolute (matches retire's absolute file paths)", () => {
	const lines = R.buildRetireIgnorePatterns({ srcDir: "./proj", excludePath: ["legacy"] });
	// path.resolve() yields backslashes on Windows; the emitted POSIX line always uses "/"
	// (a native-separator twin is emitted alongside it there — see the Windows tests below).
	const abs = path.resolve("./proj").replace(/\\/g, "/");
	assert.ok(lines.some(l => l === `@${abs}/legacy/`), `expected anchored @${abs}/legacy/ in ${JSON.stringify(lines)}`);
});

test("chooseRetireLauncher: node uses local bin, compiled binary self-invokes, else PATH", () => {
	// node dev (node_modules present) → run the local retire CLI directly, no env flag.
	assert.deepStrictEqual(
		R.chooseRetireLauncher({ localBin: "/p/node_modules/.bin/retire", isBun: false, execPath: "/usr/bin/node" }),
		{ cmd: "/p/node_modules/.bin/retire", env: null });
	// compiled bun binary (no node_modules) → re-exec THIS binary in retire mode.
	assert.deepStrictEqual(
		R.chooseRetireLauncher({ localBin: null, isBun: true, execPath: "/usr/local/bin/fad" }),
		{ cmd: "/usr/local/bin/fad", env: { __FAD_RETIRE__: "1" } });
	// last resort: retire on PATH.
	assert.deepStrictEqual(
		R.chooseRetireLauncher({ localBin: null, isBun: false, execPath: "/usr/bin/node" }),
		{ cmd: "retire", env: null });
});

test("chooseRetireLauncher: the compiled binary self-invokes EVEN when a local bin looks present", () => {
	// The case the other test leaves out, and the only one that breaks: `localBin` comes
	// from `__dirname`, which in the compiled binary still points at the build directory, so
	// on any machine where that path also exists at run time the binary saw a local
	// node_modules. With localBin checked first it then ran a `#!/usr/bin/env node` script
	// and died with "env: 'node': No such file or directory" wherever node is absent, taking
	// the vendored-JS chapter with it. Reproduced with the binary run beside its own
	// checkout, node off PATH: failed scan before, 14 findings after. A container, having
	// never held the checkout, does NOT show it — which is exactly why the order must not
	// depend on what happens to be on disk.
	assert.deepStrictEqual(
		R.chooseRetireLauncher({ localBin: "/$bunfs/root/node_modules/.bin/retire", isBun: true, execPath: "/opt/vigievuln" }),
		{ cmd: "/opt/vigievuln", env: { __FAD_RETIRE__: "1" } });
});

// Windows: retire turns each ignorefile line into a REGEX and tests it against the file path
// AND path.resolve(file). Both use backslashes on Windows, so a forward-slash pattern like
// `D:/proj/node_modules/` never matches `D:\proj\node_modules\x.js` — every exclusion,
// including the DEFAULT ones, was silently inert there. Caught by CI on windows-latest.
// `sep` is injectable so the Windows shape is testable from any platform.
test("buildRetireIgnorePatterns emits a native-separator variant on Windows", () => {
	// A POSIX-absolute srcDir, because path.resolve() is platform-bound: on Linux
	// "C:/proj" would be treated as RELATIVE and prefixed with cwd. The drive-letter
	// shape cannot be simulated off-Windows; the separator handling is what is under test.
	const root = path.resolve("/proj").replace(/\\/g, "/");
	const lines = R.buildRetireIgnorePatterns({ srcDir: "/proj", excludePath: ["webapp/legacy"], sep: "\\" });
	assert.ok(lines.includes(`@${root}/webapp/legacy/`), `posix form kept: ${JSON.stringify(lines)}`);
	assert.ok(lines.includes(`@${root.split("/").join("\\")}\\webapp\\legacy\\`), `native form added: ${JSON.stringify(lines)}`);
	// defaults too — these are what keep retire out of node_modules
	assert.ok(lines.includes("@/node_modules/"));
	assert.ok(lines.includes("@\\node_modules\\"));
});

test("a Windows-shaped path is actually excluded by the generated patterns", () => {
	const lines = R.buildRetireIgnorePatterns({ srcDir: "/proj", excludePath: ["webapp/legacy"], sep: "\\" });
	const win = path.resolve("/proj").replace(/\//g, "\\");
	// retire's own regex build + test, against the backslash paths Windows produces
	const hits = f => lines
		.map(e => e.slice(1))
		.map(p => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
		.map(p => p.replace(/[*]{1,2}/g, a => (a.length === 2 ? ".*" : "[^/]*")))
		.some(s => new RegExp(s).test(f));
	assert.ok(hits(`${win}\\webapp\\legacy\\old.js`), "user glob must exclude a backslash path");
	assert.ok(hits(`${win}\\node_modules\\lodash\\lodash.js`), "defaults must exclude node_modules on Windows");
	assert.ok(!hits(`${win}\\src\\app.js`), "a normal source file must NOT be excluded");
});

test("POSIX output is unchanged — no duplicate lines when the separator is /", () => {
	const lines = R.buildRetireIgnorePatterns({ srcDir: "/proj", excludePath: ["vendor"], sep: "/" });
	assert.equal(new Set(lines).size, lines.length, "no duplicates");
	assert.ok(lines.every(l => !l.includes("\\")), `no backslash lines on POSIX: ${JSON.stringify(lines)}`);
});
