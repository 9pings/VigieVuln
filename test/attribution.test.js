/**
 * attributeMatchOrigins (lib/findings/attribution.js).
 *
 * A depRecord is coord-wide: versions[] and manifestPaths[] are both whole-scan sets
 * with no link between them, and scope is a single merged value. A match carries ONE
 * version. Unattributed, every version is reported against every manifest holding the
 * coord — the real-world audit root holds SEVERAL INDEPENDENT projects, so that mixes
 * unrelated projects' versions and their CVEs together.
 *
 * Covers both provenance sources: versionPaths{} (declared) and maskedVersions[]
 * (recovered by the per-module overlay).
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { attributeMatchOrigins } = require("../lib/findings/attribution");
const composer = require("../lib/codecs/composer.codec");
const path = require("node:path");

/** projA declares jackson-databind 2.15.3; projB declares 2.17.0. One merged record. */
function declaredRecord() {
	const paths = ["projB/pom.xml", "projA/pom.xml"];
	return {
		groupId: "com.fasterxml.jackson.core", artifactId: "jackson-databind",
		coordKey: "com.fasterxml.jackson.core:jackson-databind",
		ecosystem: "maven", scope: "compile",
		version: "2.17.0", versions: ["2.17.0", "2.15.3"],
		manifestPaths: paths, pomPaths: paths,
		versionPaths: { "2.17.0": ["projB/pom.xml"], "2.15.3": ["projA/pom.xml"] },
	};
}

/** projA declares commons-compress 1.27.1; the overlay recovered projB's transitive 1.24.0. */
function maskedRecord() {
	const paths = ["projA/pom.xml"];
	return {
		groupId: "org.apache.commons", artifactId: "commons-compress",
		coordKey: "org.apache.commons:commons-compress",
		ecosystem: "maven", scope: "compile",
		version: "1.27.1", versions: ["1.27.1", "1.24.0"],
		manifestPaths: paths, pomPaths: paths,
		versionPaths: { "1.27.1": ["projA/pom.xml"] },
		maskedVersions: [{ version: "1.24.0", via: ["org.apache.poi:poi-ooxml"], viaPaths: [["org.apache.poi:poi-ooxml"]], module: "projB/pom.xml", depth: 1 }],
	};
}

test("each declared version is filed only under the pom that declares it", () => {
	const rec = declaredRecord();
	const matches = [
		{ dep: { ...rec, version: "2.15.3" }, cve: { id: "CVE-OLD" } },
		{ dep: { ...rec, version: "2.17.0" }, cve: { id: "CVE-NEW" } },
	];
	assert.equal(attributeMatchOrigins(matches), 2);
	assert.deepEqual(matches[0].dep.manifestPaths, ["projA/pom.xml"], "2.15.3 is projA's, not projB's");
	assert.deepEqual(matches[1].dep.manifestPaths, ["projB/pom.xml"], "2.17.0 is projB's, not projA's");
	// pomPaths must stay the SAME array as manifestPaths (dep-record.js invariant).
	assert.equal(matches[0].dep.pomPaths, matches[0].dep.manifestPaths);
});

test("a version declared in several poms keeps all of them", () => {
	const rec = declaredRecord();
	rec.versionPaths["2.15.3"] = ["projA/pom.xml", "projC/pom.xml"];
	const matches = [{ dep: { ...rec, version: "2.15.3" }, cve: { id: "CVE-OLD" } }];
	attributeMatchOrigins(matches);
	assert.deepEqual(matches[0].dep.manifestPaths, ["projA/pom.xml", "projC/pom.xml"]);
});

test("an overlay-recovered version becomes a transitive of its resolving module", () => {
	const rec = maskedRecord();
	const matches = [{ dep: { ...rec, version: "1.24.0" }, cve: { id: "CVE-2024-25710" } }];
	assert.equal(attributeMatchOrigins(matches), 1);
	const d = matches[0].dep;
	assert.equal(d.scope, "transitive", "1.24.0 is a transitive, not projA's direct declaration");
	assert.deepEqual(d.via, ["org.apache.poi:poi-ooxml"]);
	assert.equal(d.depth, 1);
	assert.deepEqual(d.manifestPaths, ["projB/pom.xml"], "filed under the module that resolves it");
});

test("the record's own declared version stays direct and untouched", () => {
	const rec = maskedRecord();
	const matches = [{ dep: { ...rec, version: "1.27.1" }, cve: { id: "CVE-X" } }];
	attributeMatchOrigins(matches);
	assert.equal(matches[0].dep.scope, "compile", "1.27.1 really is projA's direct declaration");
	assert.deepEqual(matches[0].dep.manifestPaths, ["projA/pom.xml"]);
});

test("the shared resolvedDeps record is never mutated", () => {
	const shared = { ...maskedRecord(), version: "1.24.0" };
	const before = shared.manifestPaths;
	attributeMatchOrigins([{ dep: shared, cve: { id: "CVE-2024-25710" } }]);
	assert.equal(shared.scope, "compile", "re-stamping must clone (other matches share the record)");
	assert.equal(shared.manifestPaths, before);
	assert.deepEqual(shared.manifestPaths, ["projA/pom.xml"]);
});

test("versions with no provenance (global-pass transitive, other ecosystems) are no-ops", () => {
	const trans = { groupId: "g", artifactId: "b", version: "2.0", scope: "transitive", via: ["g:root"], manifestPaths: [] };
	const npm = { ecosystem: "npm", name: "left-pad", version: "1.0.0", scope: "compile", manifestPaths: ["a/package.json"] };
	const matches = [{ dep: trans, cve: { id: "C1" } }, { dep: npm, cve: { id: "C2" } }];
	assert.equal(attributeMatchOrigins(matches), 0);
	assert.equal(matches[0].dep.scope, "transitive");
	assert.deepEqual(matches[1].dep.manifestPaths, ["a/package.json"]);
});

test("Composer matches are attributed to the site and scope holding each version", async () => {
	const root = path.join(__dirname, "fixtures", "composer-multisite");
	const { deps } = await composer.collect(root);
	const dep = deps.get("composer:symfony/console");
	const matches = [
		{ dep: { ...dep, version: "5.4.47" } },
		{ dep: { ...dep, version: "6.2.10" } },
	];
	attributeMatchOrigins(matches);
	assert.deepStrictEqual(new Set(matches[0].dep.manifestPaths), new Set([
		path.join(root, "site-a", "composer.lock"), path.join(root, "site-b", "composer.lock"),
	]));
	assert.strictEqual(matches[0].dep.isDev, false);
	assert.deepStrictEqual(new Set(matches[0].dep.occurrences.map(o => o.scope)), new Set(["prod", "dev"]));
	assert.deepStrictEqual(matches[1].dep.manifestPaths, [path.join(root, "site-c", "composer.lock")]);
	assert.strictEqual(matches[1].dep.isDev, true);
	assert.strictEqual(matches[1].dep.scope, "dev");
	assert.deepStrictEqual(matches[1].dep.occurrences.map(o => o.version), ["6.2.10"]);
	assert.strictEqual(matches[1].dep.pomPaths, matches[1].dep.manifestPaths);
});
