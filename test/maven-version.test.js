const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseMavenVersion, compareMavenVersions, isVersionAffected, parseRange } = require("../lib/codecs/maven/version");

test("parseMavenVersion returns segments", () => {
	const v = parseMavenVersion("2.14.0");
	assert.equal(v.original, "2.14.0");
	assert.deepEqual(v.segments.map(s => s.value), [2, 14, 0]);
});

test("compareMavenVersions basic numeric ordering", () => {
	assert.equal(compareMavenVersions("1.0.0", "1.0.0"), 0);
	assert.equal(compareMavenVersions("1.0.0", "1.0.1"), -1);
	assert.equal(compareMavenVersions("2.0.0", "1.9.9"), 1);
	assert.equal(compareMavenVersions("1.10.0", "1.9.0"), 1);
});

test("compareMavenVersions handles qualifiers", () => {
	assert.equal(compareMavenVersions("1.0.0-SNAPSHOT", "1.0.0"), -1);
	assert.equal(compareMavenVersions("1.0.0-rc1", "1.0.0"), -1);
	assert.equal(compareMavenVersions("1.0.0-alpha", "1.0.0-beta"), -1);
	assert.equal(compareMavenVersions("5.3.20.Final", "5.3.20"), 0);
	assert.equal(compareMavenVersions("5.3.20.RELEASE", "5.3.20.Final"), 0);
});

test("isVersionAffected respects [version, lessThan)", () => {
	const spec = { version: "2.0", status: "affected", lessThan: "2.15.0" };
	assert.equal(isVersionAffected("2.14.0", spec), true);
	assert.equal(isVersionAffected("2.15.0", spec), false, "lessThan is exclusive");
	assert.equal(isVersionAffected("1.5.0", spec), false, "below lower bound");
});

test("isVersionAffected with lessThanOrEqual is inclusive", () => {
	const spec = { version: "1.0", status: "affected", lessThanOrEqual: "1.5.0" };
	assert.equal(isVersionAffected("1.5.0", spec), true);
	assert.equal(isVersionAffected("1.5.1", spec), false);
});

test("isVersionAffected returns false when status != affected", () => {
	const spec = { version: "1.0", lessThan: "2.0", status: "unaffected" };
	assert.equal(isVersionAffected("1.5", spec), false);
});

test("isVersionAffected fail-closed when spec has no version bounds (H1)", () => {
	// CVEProject sometimes emits {status:"affected"} stubs with no version
	// fields. The matcher must NOT fall through to `return true` — that was
	// the H1 cascade.
	assert.equal(isVersionAffected("2.14.0", { status: "affected" }), false);
	assert.equal(isVersionAffected("2.14.0", {}), false);
	assert.equal(isVersionAffected("0.0.1", { status: "affected" }), false);
});

test("parseRange handles Maven range syntax", () => {
	assert.deepEqual(parseRange("1.2.3"), { exact: "1.2.3" });
	assert.deepEqual(parseRange("[1.0,2.0)"), { lower: "1.0", lowerInclusive: true, upper: "2.0", upperInclusive: false });
	assert.deepEqual(parseRange("(,1.5]"), { lower: null, lowerInclusive: false, upper: "1.5", upperInclusive: true });
});

// Regression: a dot-aligned qualifier segment (e.g. "x.y.z.RC1") must rank BELOW
// a numeric segment at the same position. cmpSegments read `.value` (undefined for
// a qual+num segment) and wrongly ranked rc1 as a release. (audit fix #6)
test("qualifier segment dot-aligned with a number ranks below the number", () => {
	assert.equal(compareMavenVersions("1.0.rc1", "1.0.1"), -1);
	assert.equal(compareMavenVersions("1.0.1", "1.0.rc1"), 1);
	assert.equal(compareMavenVersions("5.0.0.RC1", "5.0.0.5"), -1);
	// post-release qualifier (service pack) still ranks ABOVE the number
	assert.equal(compareMavenVersions("5.0.0.sp1", "5.0.0.0"), 1);
});
