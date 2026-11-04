const { test } = require("node:test");
const assert = require("node:assert/strict");
const { packumentToFindings } = require("../lib/codecs/npm/registry");

const dep = (name, version) => ({ ecosystem: "npm", groupId: "", artifactId: name, version });

test("packumentToFindings flags a deprecated resolved version", () => {
	const packument = {
		name: "request",
		"dist-tags": { latest: "2.88.2" },
		versions: {
			"2.88.2": { deprecated: "request has been deprecated, see https://github.com/request/request/issues/3142" },
		},
		time: { "2.88.2": "2020-02-11T00:00:00.000Z" },
	};
	const { deprecated, outdated } = packumentToFindings(packument, dep("request", "2.88.2"));
	assert.ok(deprecated, "should return a deprecated finding");
	assert.match(deprecated.reason, /has been deprecated/);
	assert.equal(deprecated.source, "npm");
	assert.equal(deprecated.dep.artifactId, "request");
	// Latest === current, so not outdated.
	assert.equal(outdated, null);
});

test("packumentToFindings extracts a replacement URL from the deprecation message", () => {
	const packument = {
		"dist-tags": { latest: "1.0.0" },
		versions: { "1.0.0": { deprecated: "use the foo package instead, see https://example.com/why" } },
	};
	const { deprecated } = packumentToFindings(packument, dep("bar", "1.0.0"));
	assert.equal(deprecated.replacement, "https://example.com/why");
});

test("packumentToFindings reports outdated when latest is newer", () => {
	const packument = {
		"dist-tags": { latest: "3.7.1" },
		versions: { "3.6.0": {} },
		time: { "3.7.1": "2023-08-28T00:00:00.000Z" },
	};
	const { deprecated, outdated } = packumentToFindings(packument, dep("jquery", "3.6.0"));
	assert.equal(deprecated, null, "not deprecated");
	assert.ok(outdated, "should be outdated");
	assert.equal(outdated.latest, "3.7.1");
	assert.equal(outdated.releaseDate, "2023-08-28");
});

test("packumentToFindings returns nothing for an up-to-date, non-deprecated dep", () => {
	const packument = {
		"dist-tags": { latest: "4.18.2" },
		versions: { "4.18.2": {} },
	};
	const { deprecated, outdated } = packumentToFindings(packument, dep("express", "4.18.2"));
	assert.equal(deprecated, null);
	assert.equal(outdated, null);
});

test("packumentToFindings tolerates a missing version entry", () => {
	// Resolved version not present in the registry (e.g. unpublished) — must not throw.
	const packument = { "dist-tags": { latest: "2.0.0" }, versions: { "2.0.0": {} } };
	const { deprecated, outdated } = packumentToFindings(packument, dep("ghost", "1.5.0"));
	assert.equal(deprecated, null);
	assert.ok(outdated, "1.5.0 < 2.0.0 so still outdated");
	assert.equal(outdated.latest, "2.0.0");
});

test('outdated includes prerelease to stable upgrades, but never ranks build metadata', () => {
 const stable={'dist-tags':{latest:'1.0.0'},versions:{'1.0.0':{}}};
 assert.equal(packumentToFindings(stable,dep('lib','1.0.0-rc.1')).outdated.latest,'1.0.0');
 assert.equal(packumentToFindings({'dist-tags':{latest:'1.0.0-rc.1'},versions:{}},dep('lib','1.0.0')).outdated,null);
 assert.equal(packumentToFindings({'dist-tags':{latest:'1.0.0+build.2'},versions:{}},dep('lib','1.0.0+build.1')).outdated,null);
});
