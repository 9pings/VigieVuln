const { test } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { makeDirFilter, compileGlobs, collectExcludedDirs, DEFAULT_EXCLUDE_DIRS } = require("../lib/inventory/path-filter");

const root = "/proj";
const abs = rel => path.join(root, rel);

test("default skip set prunes by basename", () => {
	const skip = makeDirFilter({ srcRoot: root, defaultSkip: new Set(["node_modules", "target"]) });
	assert.strictEqual(skip(abs("a/node_modules")), true);
	assert.strictEqual(skip(abs("target")), true);
	assert.strictEqual(skip(abs("src/main")), false);
});

test("useDefaults=false ignores the default skip set", () => {
	const skip = makeDirFilter({ srcRoot: root, defaultSkip: new Set(["node_modules"]), useDefaults: false });
	assert.strictEqual(skip(abs("node_modules")), false);
});

test("exclude-path glob matches the relative path AND its subtree", () => {
	const skip = makeDirFilter({ srcRoot: root, excludePath: ["packages/legacy/**", "**/fixtures/**", "vendored"] });
	assert.strictEqual(skip(abs("packages/legacy")), true);          // the dir itself
	assert.strictEqual(skip(abs("packages/legacy/sub")), true);      // subtree
	assert.strictEqual(skip(abs("apps/web/fixtures/data")), true);   // **/ middle
	assert.strictEqual(skip(abs("vendored")), true);                 // bare name as path
	assert.strictEqual(skip(abs("vendored/x")), true);               // bare name subtree
	assert.strictEqual(skip(abs("packages/active")), false);
	assert.strictEqual(skip(abs("src")), false);
});

test("globs combine with default skips", () => {
	const skip = makeDirFilter({ srcRoot: root, defaultSkip: new Set([".git"]), excludePath: ["e2e/**"] });
	assert.strictEqual(skip(abs(".git")), true);
	assert.strictEqual(skip(abs("e2e/specs")), true);
	assert.strictEqual(skip(abs("lib")), false);
});

test("compileGlobs trims and drops empties", () => {
	assert.strictEqual(compileGlobs([" a ", "", null, "b"]).length, 2);
});

test("leading / and ./ are equivalent to bare (all anchored to srcRoot)", () => {
	for (const g of ["truc", "/truc", "./truc", "/truc/**", "./truc/**"]) {
		const skip = makeDirFilter({ srcRoot: root, excludePath: [g] });
		assert.strictEqual(skip(abs("truc")), true, `${g} should match the dir`);
		assert.strictEqual(skip(abs("truc/x")), true, `${g} should match the subtree`);
		assert.strictEqual(skip(abs("other")), false, `${g} must not over-match`);
	}
});

test("makeDirFilter fires onSkip with the reason (default basename vs which exclude-path glob)", () => {
	const seen = [];
	const skip = makeDirFilter({
		srcRoot: root,
		defaultSkip: new Set(["node_modules"]),
		excludePath: ["packages/legacy/**"],
		onSkip: (abs, reason) => seen.push({ abs, reason }),
	});
	skip(abs("a/node_modules"));
	skip(abs("packages/legacy"));
	skip(abs("src/main"));   // not skipped → no callback
	assert.strictEqual(seen.length, 2);
	assert.deepStrictEqual(seen[0].reason, { type: "default", name: "node_modules" });
	assert.deepStrictEqual(seen[1].reason, { type: "exclude-path", glob: "packages/legacy/**" });
});

test("DEFAULT_EXCLUDE_DIRS is the union of the walkers' skip sets (covers node_modules, vendor, __pycache__, …)", () => {
	for (const d of ["node_modules", "target", "build", "dist", "out", ".git", "vendor", "__pycache__", ".gradle", "bin", "obj"]) {
		assert.ok(DEFAULT_EXCLUDE_DIRS.has(d), `expected ${d} in the default-exclude union`);
	}
});

test("collectExcludedDirs lists the ACTUAL pruned dirs (relative to root), from BOTH defaults and --exclude-path", () => {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-excl-"));
	try {
		// real tree: a deeply-nested node_modules (default), a build dir (default),
		// a CLI-excluded dir, and genuine source that must NOT be listed.
		for (const d of ["a/b/c/node_modules/jquery", "web/build", "legacy/old", "src/main"]) {
			fs.mkdirSync(path.join(tmp, d), { recursive: true });
		}
		const res = collectExcludedDirs({ srcRoot: tmp, excludePath: ["legacy"] });
		const byDir = Object.fromEntries(res.map(e => [e.dir, e]));
		// nested node_modules pruned at its own level, relative to the scan root
		assert.ok(byDir["a/b/c/node_modules"], `node_modules should be listed: ${JSON.stringify(res)}`);
		assert.strictEqual(byDir["a/b/c/node_modules"].type, "default");
		assert.ok(byDir["web/build"], "build should be listed");
		// the CLI --exclude-path dir is listed, tagged to the glob that excluded it
		assert.ok(byDir["legacy"], "the --exclude-path dir should be listed");
		assert.strictEqual(byDir["legacy"].type, "exclude-path");
		assert.match(byDir["legacy"].reason, /legacy/);
		// genuine source is NOT listed; and we never descend INTO a pruned dir
		assert.ok(!byDir["src/main"]);
		assert.ok(!byDir["a/b/c/node_modules/jquery"], "must not descend into a pruned dir");
	} finally {
		fs.rmSync(tmp, { recursive: true, force: true });
	}
});

test("collectExcludedDirs: --no-default-excludes keeps ONLY the --exclude-path matches", () => {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-excl-"));
	try {
		fs.mkdirSync(path.join(tmp, "node_modules/x"), { recursive: true });
		fs.mkdirSync(path.join(tmp, "skipme/y"), { recursive: true });
		const res = collectExcludedDirs({ srcRoot: tmp, excludePath: ["skipme"], defaultExcludes: false });
		const dirs = res.map(e => e.dir);
		assert.ok(dirs.includes("skipme"), "the CLI exclude is kept");
		assert.ok(!dirs.includes("node_modules"), "defaults are off");
	} finally {
		fs.rmSync(tmp, { recursive: true, force: true });
	}
});
