const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { normaliseNpmVersion } = require("../lib/codecs/npm/parse");
const { cacheKey } = require("../lib/providers/osv/query");

/* ---------------- the crash ---------------- */

test("an OSV cache key is always ONE path segment, whatever the version holds", () => {
	// A package-lock v1 entry for a dep installed by URL records the URL as its "version".
	// Unsanitised it became .../osv-cache/npm____javascript.util__https:/registry.npmjs.org/…
	// and the scan died on ENOENT mid-step.
	const url = "https://registry.npmjs.org/javascript.util/-/javascript.util-0.12.5.tgz";
	for (const v of [url, "../../etc/passwd", "1.0.0", "file:../local", "git+ssh://git@h/x.git#abc", "a\\b", null]) {
		const k = cacheKey("", "javascript.util", v, "npm");
		assert.equal(path.basename(k), k, `"${v}" must not introduce a separator`);
		assert.doesNotMatch(k, /[/\\]/);
		assert.match(k, /\.json$/);
	}
});

test("cache keys stay distinct after sanitising, so two versions never share a file", () => {
	const a = cacheKey("", "x", "https://r/x/-/x-1.0.0.tgz", "npm");
	const b = cacheKey("", "x", "https://r/x/-/x-2.0.0.tgz", "npm");
	assert.notEqual(a, b);
	assert.notEqual(cacheKey("", "x", "1.0.0", "npm"), cacheKey("", "x", "2.0.0", "npm"));
});

/* ---------------- the cause ---------------- */

test("a registry tarball URL yields the real semver, so the dep is actually scannable", () => {
	assert.equal(normaliseNpmVersion("https://registry.npmjs.org/javascript.util/-/javascript.util-0.12.5.tgz"), "0.12.5");
	assert.equal(normaliseNpmVersion("https://registry.npmjs.org/@acme/pkg/-/pkg-1.2.3.tgz"), "1.2.3");
	assert.equal(normaliseNpmVersion("https://nexus.corp/repo/npm/-/lodash-4.17.21.tgz"), "4.17.21");
	assert.equal(normaliseNpmVersion("https://r/x/-/x-1.2.3-beta.1.tgz"), "1.2.3-beta.1");
});

test("a URL with no recoverable version resolves to null, never a fabricated one", () => {
	// The repo's rule: only CONCRETE versions are matched. An unresolved dep is reported as
	// unresolved, never assumed vulnerable to everything its coordinate ever had.
	for (const v of [
		"git+ssh://git@github.com/acme/thing.git#4f2c1a",
		"github:acme/thing#semver:^1.0.0",
		"file:../sibling",
		"https://example.com/tarballs/nightly.tgz",
		"link:../pkg",
	]) assert.equal(normaliseNpmVersion(v), null, v);
});

test("a plain semver, a range and junk are left exactly as they were", () => {
	for (const v of ["1.2.3", "^1.0.0", "~2.3.4", "1.2.3-rc.1+build", "latest", "*"]) {
		assert.equal(normaliseNpmVersion(v), v);
	}
	assert.equal(normaliseNpmVersion(null), null);
	assert.equal(normaliseNpmVersion(""), null);
});

/* ---------------- end to end ---------------- */

test("collectNpmDeps turns a URL-versioned lockfile entry into a scannable record", () => {
	const fs = require("fs"), os = require("os");
	const { collectNpmDeps } = require("../lib/codecs/npm/collect");
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-npmurl-"));
	fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", dependencies: { "javascript.util": "*", "weird": "*" } }));
	fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({
		lockfileVersion: 1,
		dependencies: {
			"javascript.util": { version: "https://registry.npmjs.org/javascript.util/-/javascript.util-0.12.5.tgz" },
			"weird": { version: "git+ssh://git@github.com/acme/weird.git#4f2c1a" },
		},
	}));
	const deps = collectNpmDeps(dir, {});          // returns the Map itself
	assert.equal(deps.get("npm:javascript.util").version, "0.12.5", "the tarball URL became its semver");
	assert.equal(deps.get("npm:weird").version, null, "a git ref is not a version");
	fs.rmSync(dir, { recursive: true, force: true });
});

/* ---------------- the same class of bug, elsewhere ---------------- */

test("the Maven pom cache filename is also one segment, and warm caches stay valid", () => {
	const { pomCachePath } = require("../lib/codecs/maven/transitive");
	const dir = "/c";
	// Normal coordinates must be byte-identical to before, or 3400 cached poms are orphaned.
	assert.equal(path.basename(pomCachePath("org.apache.commons", "commons-lang3", "3.14.0", dir)),
		"org.apache.commons__commons-lang3__3.14.0.pom");
	assert.equal(path.basename(pomCachePath("com.acme_x", "a_b", "1.0.0_1", dir)),
		"com.acme_x__a_b__1.0.0_1.pom", "underscores are legal in coordinates and must survive");
	// And nothing can walk out of the cache directory. The comparison normalises the dir:
	// cachePath builds with path.join, so on Windows it spells the SAME directory "\\c"
	// rather than "/c", and asserting the raw spelling tests the separator, not the escape.
	for (const v of ["../../etc/passwd", "1.0/2.0", "a\\b"]) {
		const k = path.basename(pomCachePath("g", "a", v, dir));
		assert.equal(path.dirname(pomCachePath("g", "a", v, dir)), path.normalize(dir));
		assert.doesNotMatch(k, /[/\\]/);
	}
});
