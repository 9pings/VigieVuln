const { test } = require("node:test");
const assert = require("node:assert/strict");
const { assessWordfenceFeed, compareWordPressVersions, indexFeed } = require("../lib/application-providers/wordfence-v3");

const advisory = {
	"123e4567-e89b-12d3-a456-426614174000": {
		id: "123e4567-e89b-12d3-a456-426614174000", title: "Example issue", cve: null,
		cvss: { score: 7.5, rating: "High", vector: "CVSS:3.1/AV:N" },
		software: [{ type: "plugin", slug: "example", name: "Example", affected_versions: {
			"1.0 - 1.2": { from_version: "1.0", from_inclusive: true, to_version: "1.2", to_inclusive: true },
		}, patched_versions: ["1.2.1"] }],
		references: ["https://www.wordfence.com/threat-intel/vulnerabilities/example"],
		copyrights: { defiant: { notice: "Copyright Wordfence fixture" } },
	},
};
const component = (id, version, extra = {}) => ({ id, applicationId: "wordpress:site", kind: "plugin",
	slug: "example", name: "Example", version, path: `site/wp-content/plugins/${id}`,
	visibility: "public", catalogueStatus: "verified", ...extra });

test("Wordfence v3 checks inclusive version ranges and keeps no-CVE advisory identity", () => {
	const assessed = assessWordfenceFeed(advisory, [component("a", "1.2"), component("b", "1.2.1")]);
	assert.equal(assessed.matches.length, 1);
	assert.equal(assessed.matches[0].cve.id, "WF-123e4567-e89b-12d3-a456-426614174000");
	assert.equal(assessed.matches[0].cve.fixVersion, "1.2.1");
	assert.deepEqual(assessed.coverage.map(c => c.result), ["affected", "no-match"]);
	assert.equal(assessWordfenceFeed(indexFeed(advisory), [component("a", "1.2")]).matches.length, 1);
});

test("a private plugin is never matched by public slug; an undeclared one is assessed by its directory slug", () => {
	const privateOnly = assessWordfenceFeed(advisory, [component("private", "1.1", { visibility: "private" })]);
	assert.equal(privateOnly.matches.length, 0);
	assert.deepEqual(privateOnly.coverage.map(c => [c.execution, c.diagnostic]), [["not-run", "CMS_PRIVATE_COMPONENT"]]);
	const byDirectory = assessWordfenceFeed(advisory, [component("unknown", "1.1", { catalogueStatus: "not-queried", visibility: "unknown" })]);
	assert.ok(byDirectory.coverage.every(c => c.execution !== "not-run" || c.diagnostic !== "CMS_IDENTITY_UNVERIFIED"));
});

test("uncomparable versions stay indeterminate; numeric and prerelease ordering is conservative", () => {
	assert.equal(compareWordPressVersions("1.2", "1.2.0"), -1);
	assert.equal(compareWordPressVersions("1.2-rc1", "1.2"), -1);
	assert.equal(compareWordPressVersions("1.02", "1.1"), 1);
	assert.equal(compareWordPressVersions("1.2-pl1", "1.2"), 1);
	assert.equal(compareWordPressVersions("1.2-alpha", "1.2-beta"), -1);
	assert.equal(compareWordPressVersions("1.2.0", "1.2-pl1"), -1);
	assert.equal(compareWordPressVersions("trunk", "1.2"), null);
	const assessed = assessWordfenceFeed(advisory, [component("trunk", "trunk")]);
	assert.equal(assessed.coverage[0].result, "indeterminate");
	assert.equal(assessed.matches.length, 0);
});
