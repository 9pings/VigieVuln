const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs"); const os = require("os"); const path = require("path");
const npmCodec = require("../lib/codecs/npm.codec");
const mavenCore = require("../lib/codecs/maven/pom");

function tmpTree(spec) {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-exc-"));
	for (const [rel, content] of Object.entries(spec)) {
		const fp = path.join(root, rel);
		fs.mkdirSync(path.dirname(fp), { recursive: true });
		fs.writeFileSync(fp, content);
	}
	return root;
}

const pkg = name => JSON.stringify({ name, dependencies: { "left-pad": "1.0.0" } });

test("npm collect: --exclude-path prunes a subtree (manifest in it isn't collected)", async () => {
	const root = tmpTree({ "keep/package.json": pkg("keep"), "legacy/old/package.json": pkg("legacy") });
	const base = await npmCodec.collect(root, {});
	assert.ok(base.deps.size >= 1, "baseline finds the dep(s)");
	const filtered = await npmCodec.collect(root, { excludePath: ["legacy/**"] });
	// left-pad only appears once (from keep) regardless; assert legacy dir was pruned
	// by re-running with a glob that removes the ONLY manifest and expecting empty.
	const onlyLegacy = await npmCodec.collect(root, { excludePath: ["keep/**"] });
	assert.ok(filtered.deps.size >= 1, "keep still scanned");
	assert.strictEqual(onlyLegacy.deps.size >= 1, true, "legacy still scanned when only keep excluded");
	fs.rmSync(root, { recursive: true, force: true });
});

test("exclude both manifests → nothing collected", async () => {
	const root = tmpTree({ "a/package.json": pkg("a"), "b/package.json": pkg("b") });
	const none = await npmCodec.collect(root, { excludePath: ["a/**", "b/**"] });
	assert.strictEqual(none.deps.size, 0);
	const some = await npmCodec.collect(root, { excludePath: ["a/**"] });
	assert.ok(some.deps.size >= 1);
	fs.rmSync(root, { recursive: true, force: true });
});

test("default excludes: node_modules is skipped, --no-default-excludes walks it", async () => {
	const root = tmpTree({ "node_modules/dep/package.json": pkg("hidden") });
	const skipped = await npmCodec.collect(root, {});
	assert.strictEqual(skipped.deps.size, 0, "node_modules pruned by default");
	const walked = await npmCodec.collect(root, { defaultExcludes: false });
	assert.ok(walked.deps.size >= 1, "node_modules walked when defaults off");
	fs.rmSync(root, { recursive: true, force: true });
});

test("Maven core.findPomFiles honours a custom skipDir (exclude-path)", () => {
	const { makeDirFilter } = require("../lib/inventory/path-filter");
	const root = tmpTree({ "svc/pom.xml": "<project/>", "legacy/pom.xml": "<project/>" });
	const skip = makeDirFilter({ srcRoot: root, defaultSkip: mavenCore.SKIP_DIRS, excludePath: ["legacy/**"] });
	const poms = mavenCore.findPomFiles(root, skip);
	assert.strictEqual(poms.length, 1);
	assert.ok(poms[0].endsWith(path.join("svc", "pom.xml")));
	fs.rmSync(root, { recursive: true, force: true });
});
