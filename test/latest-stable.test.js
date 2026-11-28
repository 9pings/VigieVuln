/**
 * Picking the version to recommend from maven-metadata.xml.
 *
 * Maven's <release> means "latest non-SNAPSHOT", which includes betas, RCs and alphas —
 * measured on a real reactor, 22 of 165 coordinates resolve to a pre-release that way
 * (nacos 3.3.0-BETA, netty-all 5.0.0.Alpha2, archaius 2.0.0-rc.7). Recommending those in
 * an audit report would be worse than the stale answer it replaces.
 */
const test = require("node:test");
const assert = require("node:assert");
const { isPrereleaseVersion, latestStableVersion } = require("../lib/codecs/maven/version");

test("known pre-release qualifiers are recognised, in every spelling Maven allows", () => {
	for (const v of ["3.3.0-BETA", "5.0.0.Alpha2", "2.0.0-rc.7", "2.0.0-rc2", "1.0-M3",
		"3.3.0-beta.1", "1.0-cr1", "2.0-SNAPSHOT", "1.0-milestone-2"]) {
		assert.strictEqual(isPrereleaseVersion(v), true, v);
	}
});

test("an UNKNOWN qualifier is not a pre-release — that distinction is load-bearing", () => {
	// Maven's table ranks unknown qualifiers just below release, so a "rank < release" rule
	// would classify guava's -jre and JBoss's .Final as pre-releases and skip every version.
	for (const v of ["31.1-jre", "31.1-android", "4.2.18.Final", "1.2.3.GA", "1.0.0.RELEASE",
		"3.2.1-2026.03.30", "1.0.0-redhat-1", "2.5"]) {
		assert.strictEqual(isPrereleaseVersion(v), false, v);
	}
});

test("picks the highest STABLE version, not the highest version", () => {
	assert.strictEqual(
		latestStableVersion(["3.2.2", "3.2.3", "3.2.4", "3.3.0-BETA"]), "3.2.4");
	assert.strictEqual(
		latestStableVersion(["4.2.1.Final", "4.2.18.Final", "5.0.0.Alpha2"]), "4.2.18.Final");
	assert.strictEqual(
		latestStableVersion(["0.7.12", "2.0.0-rc.7"]), "0.7.12");
});

test("Maven ordering, not string ordering", () => {
	assert.strictEqual(latestStableVersion(["1.9", "1.10", "1.11"]), "1.11");
	assert.strictEqual(latestStableVersion(["2.9.9", "2.9.9.1"]), "2.9.9.1");
});

test("when the dep is ALREADY on a pre-release, staying there beats a downgrade", () => {
	// Suggesting 3.2.20 to someone running 3.3.0-beta.4 is a downgrade, not an upgrade.
	assert.strictEqual(
		latestStableVersion(["3.2.20", "3.3.0-beta.1", "3.3.0-beta.4"], { current: "3.3.0-beta.1" }),
		"3.3.0-beta.4");
	// but a stable release that supersedes the pre-release still wins
	assert.strictEqual(
		latestStableVersion(["3.3.0-beta.4", "3.3.0"], { current: "3.3.0-beta.1" }), "3.3.0");
});

test("all pre-releases and nothing else: return the newest rather than nothing", () => {
	assert.strictEqual(latestStableVersion(["1.0-alpha1", "1.0-beta2"]), "1.0-beta2");
});

test("empty or junk input does not throw", () => {
	assert.strictEqual(latestStableVersion([]), null);
	assert.strictEqual(latestStableVersion(null), null);
	assert.strictEqual(isPrereleaseVersion(null), false);
});
