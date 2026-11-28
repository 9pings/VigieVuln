/**
 * Composer constraint semantics of the Packagist-advisory evaluator, checked against
 * composer/semver (VersionParser::parseConstraints + Comparator = version_compare on
 * normalized versions) and getcomposer.org/doc/articles/versions.md:
 *
 *  - `^1.0` = `>=1.0.0.0-dev <2.0.0.0-dev`; `~1.2` = `<2.0.0.0-dev`; `~1.2.3` =
 *    `<1.3.0.0-dev`; wildcard `1.2.*` = `<1.3.0.0-dev` — an upper bound a range
 *    operator DERIVES excludes every pre-release of that bound.
 *  - `<2.0` and `>=1.0` with no stability suffix get `-dev` appended by the parser
 *    (`<2.0.0.0-dev`, `>=1.0.0.0-dev`); `<=`, `>`, `=` do not.
 *  - stability order: dev < alpha < beta < RC < stable < patch (`-p1`, `-pl1`,
 *    `-patch1`) — a patch release ranks ABOVE its base version.
 *  - whitespace between operator and version is allowed (`< 3.4.6`).
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const {
	satisfiesComposerConstraint: sat,
	cmpComposerVersions: cmp,
	fixVersionFromConstraint,
	collectPackagistMatches,
} = require("../lib/providers/packagist/audit");
const { makeDepRecord } = require("../lib/inventory/dep-record");

test("A1: a range-derived upper bound excludes the pre-releases of that bound", () => {
	assert.equal(sat("2.0.0-alpha", "^1.0"), false);
	assert.equal(sat("2.0.0-beta1", "^1.0"), false);
	assert.equal(sat("2.0.0-RC1", "^1.0"), false);
	assert.equal(sat("1.9.9", "^1.0"), true);
	assert.equal(sat("2.0.0-beta1", "~1.2"), false);
	assert.equal(sat("1.3.0-beta1", "~1.2.3"), false);
	assert.equal(sat("1.2.9", "~1.2.3"), true);
	assert.equal(sat("1.3.0-RC1", "1.2.*"), false);
	// An explicit `<2.0` is normalized to `<2.0.0.0-dev`.
	assert.equal(sat("2.0.0-beta", "<2.0"), false);
	assert.equal(sat("2.0.0-beta", "<2.0.0"), false);
	// ...unless the bound names its own stability.
	assert.equal(sat("2.0.0-beta1", "<2.0.0-RC1"), true);
	// `>=1.0` = `>=1.0.0.0-dev`: the 1.0.0 pre-releases are in.
	assert.equal(sat("1.0.0-beta1", ">=1.0"), true);
	assert.equal(sat("1.0.0-beta1", "^1.0"), true);
	// `<=` and `>` take the version verbatim.
	assert.equal(sat("2.0.0-beta", "<=2.0.0"), true);
	assert.equal(sat("2.0.0-beta", ">2.0.0"), false);
});

test("A2: stability order is dev < alpha < beta < RC < stable < patch", () => {
	assert.equal(cmp("1.2.3-p1", "1.2.3"), 1);
	assert.equal(cmp("1.2.3-patch1", "1.2.3"), 1);
	assert.equal(cmp("1.2.3-pl2", "1.2.3-p1"), 1);
	assert.equal(cmp("1.2.3-p1", "1.2.4"), -1);
	assert.equal(cmp("1.0.0-dev", "1.0.0-alpha1"), -1);
	assert.equal(cmp("1.0.0-alpha2", "1.0.0-beta1"), -1);
	assert.equal(cmp("1.0.0-beta2", "1.0.0-beta10"), -1);   // numeric, not lexical
	assert.equal(cmp("1.0.0-RC1", "1.0.0-beta9"), 1);
	assert.equal(cmp("1.0.0-RC1", "1.0.0"), -1);
	assert.equal(cmp("1.0.0-b1", "1.0.0-beta1"), 0);         // Composer aliases a/b
	assert.equal(cmp("1.0.0.RC1", "1.0.0-rc1"), 0);
	assert.equal(cmp("v1.0.0", "1.0.0.0"), 0);
	// Constraint consequences.
	assert.equal(sat("1.2.3-p1", "<1.2.3"), false);
	assert.equal(sat("1.2.3", "<1.2.3-p2"), true);           // the stable release precedes its patch
	assert.equal(sat("1.2.3-p2", "<1.2.3-p2"), false);
	assert.equal(sat("1.2.3-p1", ">=1.2.3,<1.2.3-p2"), true);
	// An unknown suffix is not a Composer version: undecidable, never a verdict.
	assert.equal(cmp("1.0.0-foo", "1.0.0"), null);
	assert.equal(sat("1.0.0-foo", "<2.0"), null);
});

test("A3: every documented Composer constraint form parses", () => {
	// operator followed by whitespace
	assert.equal(sat("3.4.5", "< 3.4.6"), true);
	assert.equal(sat("3.4.6", "< 3.4.6"), false);
	assert.equal(sat("2.1.0", ">= 2.0.0, < 2.3.2"), true);
	assert.equal(sat("2.3.2", ">= 2.0.0 < 2.3.2"), false);
	// the real Packagist shape
	const real = ">=2.0.0,<2.3.2|>=3.0.0,<3.0.1";
	assert.equal(sat("2.3.1", real), true);
	assert.equal(sat("2.3.2", real), false);
	assert.equal(sat("3.0.0", real), true);
	assert.equal(sat("3.0.1", real), false);
	// || and spaced |
	assert.equal(sat("3.0.0", ">=2.0.0,<2.3.2 || >=3.0.0,<3.0.1"), true);
	assert.equal(sat("3.0.0", ">=2.0.0 <2.3.2 | >=3.0.0 <3.0.1"), true);
	// caret / tilde / wildcards
	assert.equal(sat("1.5.0", "^1.2"), true);
	assert.equal(sat("0.3.9", "^0.3"), true);
	assert.equal(sat("0.4.0", "^0.3"), false);
	assert.equal(sat("1.9.0", "~1.2"), true);
	assert.equal(sat("1.2.9", "1.2.*"), true);
	assert.equal(sat("1.2.9", "1.2.x"), true);
	assert.equal(sat("1.9.0", "1.*"), true);
	assert.equal(sat("2.0.0", "1.*"), false);
	// hyphen range: partial upper → <next-dev, full upper → <=
	assert.equal(sat("2.0.9", "1.0 - 2.0"), true);
	assert.equal(sat("2.1.0-beta1", "1.0 - 2.0"), false);
	assert.equal(sat("2.0.0", "1.0.0 - 2.0.0"), true);
	assert.equal(sat("2.0.1", "1.0.0 - 2.0.0"), false);
	assert.equal(sat("1.0.0-beta1", "1.0 - 2.0"), true);     // lower gets -dev
	// != / <>
	assert.equal(sat("1.5.0", ">=1.0,!=1.5.0"), false);
	assert.equal(sat("1.5.1", ">=1.0, != 1.5.0"), true);
	assert.equal(sat("1.5.0", ">=1.0,<>1.5.0"), false);
	// stability flags are accepted and v prefixes stripped
	assert.equal(sat("1.5.0", ">=1.0@dev,<2.0@stable"), true);
	assert.equal(sat("1.5.0", ">=v1.0.0,<v2.0.0"), true);
	assert.equal(sat("v1.5.0", "^v1.0"), true);
	// exact versions (3 and 4 parts) are equality
	assert.equal(sat("1.2.3", "1.2.3"), true);
	assert.equal(sat("1.2.3", "=1.2.3"), true);
	assert.equal(sat("1.2.3", "==1.2.3.0"), true);
	assert.equal(sat("1.2.4", "1.2.3"), false);
	assert.equal(sat("1.7.0.1", "1.7.0.1"), true);
	// a branch name is not a version: undecidable
	assert.equal(sat("1.0.0", "dev-master"), null);
	assert.equal(sat("1.0.0", ">=banana"), null);
});

test("fixVersionFromConstraint reads spaced `<` bounds", () => {
	assert.equal(fixVersionFromConstraint("3.4.5", ">= 3.0.0, < 3.4.6"), "3.4.6");
	assert.equal(fixVersionFromConstraint("1.2.3", "<1.2.3-p2"), "1.2.3-p2");
});

test("a composer.lock pre-release / patch version is evaluated, not silently skipped", () => {
	const dep = makeDepRecord({ ecosystem: "composer", namespace: "acme", name: "lib", version: "2.0.0-beta1", manifestPath: "composer.lock" });
	const resolved = new Map([[dep.coordKey, dep]]);
	const adv = { advisoryId: "PKSA-1", cve: "CVE-2026-0001", title: "x", affectedVersions: ">=1.0.0,<2.0.0-RC1" };
	assert.equal(collectPackagistMatches(resolved, { "acme/lib": [adv] }).length, 1);
	// a -dev build is still not concrete
	const devDep = { ...dep, version: "2.0.0-dev", versions: ["2.0.0-dev"] };
	assert.equal(collectPackagistMatches(new Map([[dep.coordKey, devDep]]), { "acme/lib": [adv] }).length, 0);
});
