const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { validateSnapshot, assessGithubAdvisories, prestashopRangeGrammar, typo3RangeGrammar } = require("../lib/application-providers/github-advisories");

// Fixtures reduced from the publishers' real GitHub security-advisory records (2026-09-23):
//   PrestaShop/PrestaShop GHSA-xrwj-pq6w-f8m4 — two-branch range, no CVE, CVSS 8.2
//   PrestaShop/PrestaShop GHSA-cvjj-grfv-f56w CVE-2020-5293 — 2020 record whose package
//     identity is empty in the official feed, lossy unbounded range "> 1.7.0.0"
//   TYPO3/typo3 GHSA-8jw7-8qw5-gqr3 CVE-2026-85400 — spaceless hyphen interval, null CVSS
const FEED = [
	{ ghsa_id: "GHSA-xrwj-pq6w-f8m4", cve_id: null,
		summary: "Server-Side Request Forgery through image URLs in the CSV import",
		severity: "high",
		cvss: { vector_string: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:L", score: 8.2 },
		vulnerabilities: [
			{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
				vulnerable_version_range: ">= 9.0.0, < 9.1.5", patched_versions: "9.1.5", vulnerable_functions: [] },
			{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
				vulnerable_version_range: ">= 8.0.0, < 8.2.8", patched_versions: "8.2.8", vulnerable_functions: [] },
		],
		published_at: "2026-08-18T12:48:34Z", updated_at: "2026-08-18T12:48:34Z",
		html_url: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-xrwj-pq6w-f8m4" },
	{ ghsa_id: "GHSA-cvjj-grfv-f56w", cve_id: "CVE-2020-5293",
		summary: "Improper access control on product page with combinations, attachments and specific prices",
		severity: "moderate",
		cvss: { vector_string: null, score: null },
		vulnerabilities: [
			{ package: { ecosystem: "", name: "" },
				vulnerable_version_range: "> 1.7.0.0", patched_versions: "1.7.6.5", vulnerable_functions: [] },
		],
		published_at: "2020-06-23T14:17:39Z", updated_at: "2020-06-23T14:17:39Z",
		html_url: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-cvjj-grfv-f56w" },
	{ ghsa_id: "GHSA-8jw7-8qw5-gqr3", cve_id: "CVE-2026-85400",
		summary: "TYPO3 CMS - Missing Authorization in lowlevel commands",
		severity: "high",
		cvss: { vector_string: null, score: null },
		vulnerabilities: [
			{ package: { ecosystem: "composer", name: "typo3/cms-lowlevel" },
				vulnerable_version_range: "14.2.0-14.3.6", patched_versions: "14.3.7", vulnerable_functions: [] },
		],
		published_at: "2026-09-08T09:33:31Z", updated_at: "2026-09-08T09:33:31Z",
		html_url: "https://github.com/TYPO3/typo3/security/advisories/GHSA-8jw7-8qw5-gqr3" },
];
const snapshot = body => ({ ...body, _fadSnapshot: { collectedAt: "2026-09-23T10:00:00Z", completeness: "tool-fetched" } });
const component = (over = {}) => ({ id: "prestashop:.:core", applicationId: "prestashop:.", kind: "core",
	coord: "prestashop/prestashop", version: "8.2.1", visibility: "public",
	evidence: [{ path: "config/settings.inc.php", field: "_PS_VERSION_" }], ...over });

test("validateSnapshot accepts a bare API array and the stamped snapshot form", () => {
	for (const feed of [FEED, snapshot({ advisories: FEED })]) {
		const { index, unattributable } = validateSnapshot(feed);
		assert.equal(index.get("prestashop/prestashop").length, 2);
		assert.equal(index.get("typo3/cms-lowlevel").length, 1);
		assert.equal(unattributable, 1);
	}
});

test("validateSnapshot rejects malformed feeds instead of guessing", () => {
	assert.throws(() => validateSnapshot(null), /Github advisory snapshot/);
	assert.throws(() => validateSnapshot({ advisories: {} }), /advisories array/);
	assert.throws(() => validateSnapshot({ advisories: [{ cve_id: "CVE-1-1" }] }), /ghsa_id/);
	assert.throws(() => validateSnapshot({ advisories: [{ ghsa_id: "GHSA-x", vulnerabilities: "no" }] }), /vulnerabilities/);
	assert.throws(() => validateSnapshot({ advisories: [{ ghsa_id: "GHSA-x", vulnerabilities: [
		{ package: { ecosystem: "composer", name: "a/b" }, vulnerable_version_range: 12 }] }] }), /invalid vulnerability/);
});

test("publisher CWE identifiers survive analysis and both GitHub representations count once", () => {
	const advisory = {...FEED[0],cwe_ids:["CWE-918","invalid"],cwes:[{cwe_id:"CWE-918"},{cwe_id:"CWE-20"},null]};
	const {matches} = assessGithubAdvisories([advisory],[component()],{sourceId:"github-prestashop-advisories"});
	assert.deepEqual(matches[0].cve.cwes,["CWE-918","CWE-20"]);
});

test("the empty-package PrestaShop record attributes to the configured core coordinate", () => {
	const { index } = validateSnapshot(FEED, { fallbackCoord: "prestashop/prestashop" });
	assert.equal(index.get("prestashop/prestashop").length, 3);
	assert.equal([...index.keys()].length, 2, "typo3 entry stays separate");
});

test("an affected locked core produces a finding with the publisher's CVSS and fix", () => {
	const { matches, coverage, diagnostics } = assessGithubAdvisories(snapshot({ advisories: FEED }),
		[component()], { sourceId: "github-prestashop-advisories", fallbackCoord: "prestashop/prestashop" });
	assert.equal(matches.length, 1);
	const [finding] = matches;
	assert.equal(finding.cve.id, "GHSA-xrwj-pq6w-f8m4");
	assert.deepEqual(finding.cve.aliases, ["GHSA-xrwj-pq6w-f8m4"]);
	assert.equal(finding.cve.severity, "HIGH");
	assert.equal(finding.cve.score, 8.2);
	assert.equal(finding.cve.fixVersion, "8.2.8");
	assert.equal(finding.cve.published, "2026-08-18T12:48:34Z");
	assert.equal(finding.source, "github-prestashop-advisories");
	assert.equal(finding.applicationRelation, "direct");
	assert.equal(finding.attributionStatus, "confirmed");
	assert.equal(finding.dep.ecosystem, "composer");
	assert.equal(finding.dep.coordKey, "composer:prestashop/prestashop");
	assert.equal(finding.dep.version, "8.2.1");
	assert.equal(finding.dep.manifestPaths[0], "config/settings.inc.php");
	assert.match(finding.findingId, /^fad-advisory-[0-9a-f]{24}$/);
	const check = coverage[0];
	assert.equal(check.execution, "completed");
	assert.equal(check.result, "affected");
	assert.equal(check.sourceId, "github-prestashop-advisories");
	assert.deepEqual(diagnostics, []);
});

test("the patched refinement keeps lossy unbounded ranges from flagging fixed versions", () => {
	const assessed = version => assessGithubAdvisories(snapshot({ advisories: [FEED[1]] }),
		[component({ version })], { sourceId: "github-prestashop-advisories", fallbackCoord: "prestashop/prestashop" });
	const affected = assessed("1.7.6.3");
	assert.equal(affected.matches.length, 1);
	assert.equal(affected.matches[0].cve.id, "CVE-2020-5293");
	assert.equal(affected.matches[0].cve.fixVersion, "1.7.6.5");
	assert.equal(affected.coverage[0].result, "affected");
	const patched = assessed("1.7.6.5");
	assert.deepEqual(patched.matches, []);
	assert.equal(patched.coverage[0].execution, "completed");
	assert.equal(patched.coverage[0].result, "no-match");
	// far above the lossy range: refined away by the patched bound, not flagged
	assert.deepEqual(assessed("8.2.1").matches, []);
	assert.equal(assessed("8.2.1").coverage[0].result, "no-match");
});

test("a TYPO3 system extension matches its spaceless hyphen interval exactly", () => {
	const assessed = version => assessGithubAdvisories(snapshot({ advisories: [FEED[2]] }),
		[{ id: "typo3:.:ext:lowlevel", applicationId: "typo3:.", kind: "framework-component",
			coord: "typo3/cms-lowlevel", version, visibility: "public",
			evidence: [{ path: "typo3/sysext/lowlevel/ext_emconf.php", field: "version" }] }],
		{ sourceId: "github-typo3-advisories" });
	const affected = assessed("14.3.6");
	assert.equal(affected.matches.length, 1);
	assert.equal(affected.matches[0].cve.id, "CVE-2026-85400");
	assert.equal(affected.matches[0].cve.severity, "HIGH");
	assert.equal(affected.matches[0].cve.score, null);
	assert.equal(affected.matches[0].cve.fixVersion, "14.3.7");
	assert.deepEqual(assessed("14.3.7").matches, []);
	assert.equal(assessed("14.3.7").coverage[0].result, "no-match");
	assert.deepEqual(assessed("14.1.9").matches, []);
});

test("without a fallback coordinate the unattributable record is skipped but well-formed ones still match", () => {
	const { matches, coverage, diagnostics } = assessGithubAdvisories(snapshot({ advisories: FEED }),
		[component()], { sourceId: "github-prestashop-advisories" });
	assert.equal(matches.length, 1);
	assert.equal(matches[0].cve.id, "GHSA-xrwj-pq6w-f8m4");
	assert.equal(coverage[0].result, "affected");
	assert.ok(diagnostics.some(d => d.code === "CMS_ADVISORY_UNATTRIBUTABLE"));
});

test("unattributable records surface as one diagnostic, never as silent coverage", () => {
	const { matches, coverage, diagnostics } = assessGithubAdvisories(snapshot({ advisories: [FEED[1]] }),
		[component()], { sourceId: "github-prestashop-advisories" });
	assert.deepEqual(matches, []);
	assert.equal(coverage[0].result, "no-match");
	assert.equal(diagnostics.length, 1);
	assert.equal(diagnostics[0].code, "CMS_ADVISORY_UNATTRIBUTABLE");
	assert.match(diagnostics[0].message, /1 advisory/);
});

test("undecidable, unversioned, unidentified and private components keep explicit gaps", () => {
	const components = [
		component({ id: "a", version: "1.2.3", coord: null }),
		component({ id: "b", version: null }),
		component({ id: "c", visibility: "private" }),
		component({ id: "d", version: "8.2.1" }),
	];
	const feed = [{ ghsa_id: "GHSA-u", cve_id: null, summary: "s", severity: "high", cvss: { score: 1 },
		vulnerabilities: [{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
			vulnerable_version_range: ">= banana", patched_versions: "", vulnerable_functions: [] }],
		published_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", html_url: "u" }];
	const { matches, coverage, diagnostics } = assessGithubAdvisories(snapshot({ advisories: feed }),
		components, { sourceId: "github-prestashop-advisories" });
	assert.deepEqual(matches, []);
	const byId = Object.fromEntries(coverage.map(c => [c.occurrenceId, c]));
	assert.equal(byId.a.diagnostic, "CMS_IDENTITY_UNVERIFIED");
	assert.equal(byId.b.diagnostic, "CMS_VERSION_UNKNOWN");
	assert.equal(byId.c.sourceId, "internal-advisories");
	assert.equal(byId.c.diagnostic, "CMS_PRIVATE_COMPONENT");
	assert.equal(byId.d.execution, "partial");
	assert.equal(byId.d.diagnostic, "CMS_CONSTRAINT_UNSUPPORTED");
	assert.ok(diagnostics.some(d => d.code === "CMS_CONSTRAINT_UNSUPPORTED"));
});

test("finding ids are stable per advisory and component", () => {
	const one = assessGithubAdvisories(snapshot({ advisories: FEED }), [component()],
		{ sourceId: "github-prestashop-advisories", fallbackCoord: "prestashop/prestashop" });
	const two = assessGithubAdvisories(snapshot({ advisories: FEED }), [component()],
		{ sourceId: "github-prestashop-advisories", fallbackCoord: "prestashop/prestashop" });
	assert.equal(one.matches[0].findingId, two.matches[0].findingId);
	const expected = `fad-advisory-${crypto.createHash("sha256").update(`GHSA-xrwj-pq6w-f8m4\0${component().id}`).digest("hex").slice(0, 24)}`;
	assert.equal(one.matches[0].findingId, expected);
});

test("the PrestaShop grammar reads '< A and < B' as two affected branches with their own fixes", () => {
	// GHSA-w9f3-qc75-qgx9 / CVE-2026-44212 (critical), exactly as published 2026-09-23.
	const feed = [{ ghsa_id: "GHSA-w9f3-qc75-qgx9", cve_id: "CVE-2026-44212",
		summary: "SQL injection in the back office", severity: "critical",
		cvss: { vector_string: null, score: null },
		vulnerabilities: [{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
			vulnerable_version_range: "< 8.2.6 and < 9.1.1", patched_versions: "8.2.6 & 9.1.1", vulnerable_functions: [] }],
		published_at: "2026-08-11T00:00:00Z", updated_at: "2026-08-11T00:00:00Z", html_url: "u" }];
	const assess = version => assessGithubAdvisories({ advisories: feed }, [component({ version })],
		{ sourceId: "github-prestashop-advisories", fallbackCoord: "prestashop/prestashop", normalizeRange: prestashopRangeGrammar });
	const nine = assess("9.0.5");
	assert.equal(nine.matches.length, 1, "9.0.5 sits in the < 9.1.1 branch");
	assert.equal(nine.matches[0].cve.severity, "CRITICAL");
	assert.equal(nine.matches[0].cve.fixVersion, "9.1.1", "the fix names the 9.x branch, not the smallest token");
	assert.equal(nine.coverage[0].execution, "completed");
	const eight = assess("8.1.0");
	assert.equal(eight.matches.length, 1);
	assert.equal(eight.matches[0].cve.fixVersion, "8.2.6");
	assert.deepEqual(assess("8.2.6").matches, [], "the 8.x fix is clean");
	assert.deepEqual(assess("9.1.1").matches, [], "the 9.x fix is clean");
	assert.deepEqual(assess("8.3.0").matches, [], "a version between the branches is in neither");
});

test("the PrestaShop grammar keeps '>= A and < B' as one proper interval", () => {
	// GHSA-75p5-jwx4-qw9h / CVE-2023-39524, exactly as published.
	const feed = [{ ghsa_id: "GHSA-75p5-jwx4-qw9h", cve_id: "CVE-2023-39524",
		summary: "SQL injection in product page", severity: "high",
		cvss: { vector_string: null, score: null },
		vulnerabilities: [{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
			vulnerable_version_range: ">= 8.0.0 and < 8.1.1", patched_versions: "8.1.1", vulnerable_functions: [] }],
		published_at: "2023-07-27T00:00:00Z", updated_at: "2023-07-27T00:00:00Z", html_url: "u" }];
	const assess = version => assessGithubAdvisories({ advisories: feed }, [component({ version })],
		{ sourceId: "github-prestashop-advisories", fallbackCoord: "prestashop/prestashop", normalizeRange: prestashopRangeGrammar });
	assert.equal(assess("8.0.5").matches.length, 1, "inside the interval");
	assert.equal(assess("8.0.5").matches[0].cve.fixVersion, "8.1.1");
	assert.deepEqual(assess("8.1.1").matches, [], "the upper bound is the fix");
	assert.deepEqual(assess("8.2.1").matches, [], "above the interval is unaffected, not 'fixed late'");
	assert.deepEqual(assess("7.9.0").matches, [], "below the interval is unaffected");
	assert.equal(assess("8.0.5").coverage[0].execution, "completed");
});

test("the TYPO3 grammar reads comma-joined hyphen intervals as alternative branches", () => {
	// GHSA-68jx-f42c-7599 / CVE-2026-19418 (high), exactly as published 2026-09-23.
	const feed = [{ ghsa_id: "GHSA-68jx-f42c-7599", cve_id: "CVE-2026-19418",
		summary: "Missing Authorization", severity: "high", cvss: { vector_string: null, score: null },
		vulnerabilities: [
			{ package: { ecosystem: "composer", name: "typo3/cms-core" },
				vulnerable_version_range: "13.0.0-13.4.33, 14.0.0-14.3.5", patched_versions: "13.4.34, 14.3.6", vulnerable_functions: [] },
		], published_at: "2026-09-02T00:00:00Z", updated_at: "2026-09-02T00:00:00Z", html_url: "u" }];
	const assess = version => assessGithubAdvisories({ advisories: feed },
		[{ id: "typo3:.:core", applicationId: "typo3:.", kind: "core", coord: "typo3/cms-core", version, visibility: "public", evidence: [] }],
		{ sourceId: "github-typo3-advisories", normalizeRange: typo3RangeGrammar });
	assert.equal(assess("13.4.2").matches.length, 1);
	assert.equal(assess("13.4.2").matches[0].cve.fixVersion, "13.4.34");
	assert.equal(assess("14.1.0").matches.length, 1, "the second comma branch is an affected alternative, not an AND");
	assert.equal(assess("14.3.4").matches[0].cve.fixVersion, "14.3.6");
	assert.deepEqual(assess("12.4.48").matches, [], "below both branches");
	assert.deepEqual(assess("14.4.0").matches, [], "above both branches");
	// a comma interval with AND semantics (PrestaShop style) is left as one AND branch,
	// only the generic GitHub spellings (spaced operators) are normalized
	assert.equal(typo3RangeGrammar(">= 9.0.0, < 9.1.5"), ">=9.0.0,<9.1.5");
});

test("bare multi-part product versions are decided as equalities without touching the shared evaluator", () => {
	// GHSA-mc98-xjm3-c4fm / CVE-2020-15082: the real 2020 record pins the bare exact
	// "1.6.0.1" with no operator at all, and the shared Packagist evaluator only
	// equality-matches three-part tokens.
	const feed = [{ ghsa_id: "GHSA-mc98-xjm3-c4fm", cve_id: "CVE-2020-15082",
		summary: "External control of configuration setting in the dashboard", severity: "moderate",
		cvss: { vector_string: null, score: null },
		vulnerabilities: [{ package: { ecosystem: "", name: "" },
			vulnerable_version_range: "1.6.0.1", patched_versions: "1.7.6.6", vulnerable_functions: [] }],
		published_at: "2020-09-02T00:00:00Z", updated_at: "2020-09-02T00:00:00Z", html_url: "u" }];
	const assess = version => assessGithubAdvisories({ advisories: feed }, [component({ version })],
		{ sourceId: "github-prestashop-advisories", fallbackCoord: "prestashop/prestashop", normalizeRange: prestashopRangeGrammar });
	assert.equal(assess("1.6.0.1").matches.length, 1, "exactly the pinned version is affected");
	assert.deepEqual(assess("1.6.0.2").matches, []);
	assert.deepEqual(assess("1.6.0.0").matches, []);
	assert.equal(assess("1.6.0.1").coverage[0].execution, "completed");
	// a bare prerelease token is never mistaken for an interval bound: undecidable, partial
	const pre = [{ ...feed[0], ghsa_id: "GHSA-pre", vulnerabilities: [{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
		vulnerable_version_range: "1.0.0-beta1", patched_versions: "", vulnerable_functions: [] }] }];
	const undecided = assessGithubAdvisories({ advisories: pre }, [component({ version: "1.0.0" })],
		{ sourceId: "github-prestashop-advisories", normalizeRange: prestashopRangeGrammar });
	assert.deepEqual(undecided.matches, []);
	assert.equal(undecided.coverage[0].execution, "partial");
	assert.equal(undecided.coverage[0].diagnostic, "CMS_CONSTRAINT_UNSUPPORTED");
});
