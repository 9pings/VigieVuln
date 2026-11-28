/**
 * compareMavenVersions against Maven's own ComparableVersion (maven-artifact 3.9.16).
 *
 * test/fixtures/maven-version-oracle.tsv holds pairs whose expected sign was produced by
 * Maven itself — real versions from Maven Central plus the edge cases that bit us:
 * unknown qualifiers sort AFTER the release (32.0.0-jre > 32.0.0, so guava's fixing
 * release is not "affected" by the CVEs it fixes), a number beats any qualifier, 1.0.1 >
 * 1.0-1, 1-rc < 1-rc1, 1.0a1 = alpha-1, trailing zeros are insignificant but a leading 0
 * is not. A mismatch here means fad orders two versions differently from Maven, which is a
 * false positive or a false negative on every CVE range that boundary touches.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { compareMavenVersions, isVersionAffected } = require("../lib/codecs/maven/version");

test("every oracle pair orders exactly as Maven's ComparableVersion", () => {
	const rows = fs.readFileSync(path.join(__dirname, "fixtures", "maven-version-oracle.tsv"), "utf8")
		.split("\n").filter(l => l && !l.startsWith("#")).map(l => l.split("\t"));
	assert.ok(rows.length > 1000);
	const bad = rows.filter(([a, b, e]) => compareMavenVersions(a, b) !== Number(e)).map(([a, b, e]) => `${a} vs ${b}: maven ${e}, fad ${compareMavenVersions(a, b)}`);
	assert.deepEqual(bad, []);
});

test("guava 32.0.0-jre is NOT affected by a CVE fixed in 32.0.0 (CVE-2023-2976 shape)", () => {
	assert.equal(isVersionAffected("32.0.0-jre", { status: "affected", version: "0", lessThan: "32.0.0" }), false);
	assert.equal(isVersionAffected("31.1-jre", { status: "affected", version: "0", lessThan: "32.0.0" }), true);
});
