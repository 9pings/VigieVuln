const { test } = require("node:test");
const assert = require("node:assert/strict");
const { assessDrupalAdvisories, affectedComposerVersion, validateSnapshot } = require("../lib/application-providers/drupal-advisories");

const core = { id: "drupal:site:core", applicationId: "drupal:site", kind: "core", coord: "drupal/core",
	version: "8.4.4", visibility: "public", evidence: [{ path: "site/composer.lock" }] };
const advisory = { advisoryId: "SA-CORE-2018-001", packageName: "drupal/core", title: "Drupal core - Critical - Example",
	link: "https://www.drupal.org/sa-core-2018-001", cve: null,
	affectedVersions: ">=7.0 <7.57 || >=8.0.0 <8.4.5", reportedAt: "2018-02-21 17:10:55" };

test("Drupal refuses an advisory array even when it is empty", () => {
	const invalid = { queriedPackages: ["drupal/core"], advisories: [] };
	assert.throws(() => validateSnapshot(invalid), /advisories object/);
	assert.throws(() => assessDrupalAdvisories(invalid, [core]), /advisories object/);
});

test("Drupal Composer advisory snapshot matches exact package and OR version ranges", () => {
	const result = assessDrupalAdvisories({ queriedPackages: ["drupal/core"], advisories: { "drupal/core": [advisory] } },
		[core, { ...core, id: "drupal:other:core", applicationId: "drupal:other", version: "8.4.5" }]);
	assert.equal(result.matches.length, 1);
	assert.equal(result.matches[0].cve.id, "SA-CORE-2018-001");
	assert.deepEqual(result.coverage.map(c => c.result), ["affected", "no-match"]);
	assert.equal(affectedComposerVersion("6.0.1", "<5.25.0 || 6.0.0 || 6.0.1"), "affected");
	assert.equal(affectedComposerVersion("6.0.5", ">=6.0.0 <6.0.5"), "no-match");
});

test("Drupal private, legacy and unqueried components stay indeterminate", () => {
	const components = [
		{ ...core, id: "private", visibility: "private" },
		{ ...core, id: "legacy", version: "7.56" },
		{ ...core, id: "module", coord: "drupal/webform", version: "5.10.0", kind: "module" },
	];
	const result = assessDrupalAdvisories({ queriedPackages: ["drupal/core"], advisories: { "drupal/core": [advisory] } }, components);
	assert.equal(result.matches.length, 0);
	assert.ok(result.coverage.every(c => c.execution === "not-run"));
});

test("unknown Drupal constraints never become a no-match", () => {
	// "^1.2" used to be indeterminate here; the Composer evaluator decides it (>=1.2.0.0-dev <2.0.0.0-dev)
	assert.equal(affectedComposerVersion("1.2.3", "^1.2"), "affected");
	assert.equal(affectedComposerVersion("1.2.3", "~>1.2"), "indeterminate");
	assert.equal(affectedComposerVersion("1.2.3", ">=1.0 foo"), "indeterminate");
	assert.equal(affectedComposerVersion("1.2.3", ">=2.0 ||"), "indeterminate");
	assert.equal(affectedComposerVersion("7.x-1.2", "<1.3.0"), "indeterminate");
	assert.equal(affectedComposerVersion("10.3.x-dev", "<10.3.9"), "indeterminate");
});

test("Drupal constraints follow Composer pre-release rules (B3)", () => {
	// Composer reads "<10.3.0" as "<10.3.0.0-dev" and "10.2.*" as ">=10.2.0.0-dev <10.3.0.0-dev":
	// a 10.3.0 pre-release is OUTSIDE both; ">=10.3.0" is ">=10.3.0.0-dev", so it is inside.
	assert.equal(affectedComposerVersion("10.3.0-rc1", ">=10.2.0 <10.3.0"), "no-match");
	assert.equal(affectedComposerVersion("10.3.0-beta1", "10.2.*"), "no-match");
	assert.equal(affectedComposerVersion("10.3.0-rc1", "<10.3.0"), "no-match");
	assert.equal(affectedComposerVersion("10.3.0-rc1", ">=8.0.0 <10.2.11 || >=10.3.0 <10.3.9"), "affected");
	const { satisfiesComposerConstraint } = require("../lib/packagist-audit");
	for (const [v, c] of [["10.3.0-rc1", ">=10.2.0 <10.3.0"], ["10.3.0-beta1", "10.2.*"], ["10.3.0-rc1", "<10.3.0"], ["10.3.0-rc1", ">=8.0.0 <10.2.11 || >=10.3.0 <10.3.9"]])
		assert.equal(affectedComposerVersion(v, c), satisfiesComposerConstraint(v, c) ? "affected" : "no-match", `${v} ${c}`);
});

test("wildcard branches from the official Drupal API are decided, not indeterminate", () => {
	// Real published constraints (packages.drupal.org/8/security-advisories, 2026-09-23).
	// SA-CORE-2026-011: ">=11.3.0 <11.3.14 || >=11.4.0 <11.4.4 || 11.2.*" — drupal/core 8.5.0
	// belongs to NO branch, and that is decidable: a `X.Y.*` branch is an interval.
	assert.equal(affectedComposerVersion("8.5.0", ">=11.3.0 <11.3.14 || >=11.4.0 <11.4.4 || 11.2.*"), "no-match");
	assert.equal(affectedComposerVersion("11.2.5", ">=11.3.0 <11.3.14 || >=11.4.0 <11.4.4 || 11.2.*"), "affected");
	assert.equal(affectedComposerVersion("11.0.9", "11.0.*"), "affected");
	assert.equal(affectedComposerVersion("10.4.0", "11.0.*"), "no-match");
	// SA-CORE-2026-012: "<10.6.13 || >=11.3.0 <11.3.14 || >=11.4.0 <11.4.4 || 11.0.*" — a
	// drupal 8.x core is covered by the first branch alone.
	assert.equal(affectedComposerVersion("8.5.0", "<10.6.13 || >=11.3.0 <11.3.14 || >=11.4.0 <11.4.4 || 11.0.*"), "affected");
	assert.equal(affectedComposerVersion("10.6.13", "<10.6.13 || >=11.3.0 <11.3.14 || >=11.4.0 <11.4.4 || 11.0.*"), "no-match");
});

test("a decidable wildcard advisory completes coverage without a constraint diagnostic", () => {
	// The 2026-09-23 live run of the real drupal/drupal 8.5.0 scan ended `partial /
	// indeterminate` with CMS_CONSTRAINT_UNSUPPORTED purely because of `11.2.*`/`11.0.*`
	// branches; once decided, coverage completes.
	const adv = { ...advisory, advisoryId: "SA-CORE-2026-012",
		affectedVersions: "<10.6.13 || >=11.3.0 <11.3.14 || >=11.4.0 <11.4.4 || 11.0.*" };
	const result = assessDrupalAdvisories({ queriedPackages: ["drupal/core"], advisories: { "drupal/core": [adv] } }, [core]);
	assert.equal(result.coverage[0].execution, "completed");
	assert.equal(result.coverage[0].result, "affected");
	assert.equal(result.diagnostics.length, 0);
});
