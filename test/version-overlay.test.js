/**
 * Per-module version-mediation overlay (lib/version-overlay.js).
 *
 * Reproduces the "global depMgmt masks a vulnerable transitive version" bug on a
 * deterministic 2-module reactor (test/fixtures/maven-version-masking) with ZERO
 * network — the transitive POMs are served by an in-memory fetcher.
 *
 * Asserts BOTH directions the overlay must get right:
 *   - RECALL:     the island (module-b, no inherited pin) surfaces old poi 3.11 that
 *                 the global pass masked to the pinned 5.4.1.
 *   - FP-SAFETY:  module-a INHERITS the safe 2.0 pin, so its transitive safe 1.0 must
 *                 stay overridden to 2.0 — the overlay must NOT surface 1.0.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const core = require("../lib/core");
const { collectResolvedDeps, expandWithTransitives, matchDepsAgainstCves } = require("../lib/cve-match");
const { resolveReactor } = require("../lib/maven-reactor");

const FIXTURE = path.join(__dirname, "fixtures", "maven-version-masking");
const MC = "https://repo1.maven.org/maven2";

function leafPom(g, a, v) {
	return `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
		<groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version></project>`;
}
function pomWithDep(g, a, v, dg, da, dv) {
	return `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
		<groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version>
		<dependencies><dependency>
			<groupId>${dg}</groupId><artifactId>${da}</artifactId><version>${dv}</version>
		</dependency></dependencies></project>`;
}

// In-memory Maven Central: oldlib→poi 3.11 (the masked one), viaA→safe 1.0 (must stay 2.0).
const RESPONSES = {
	[`${MC}/com/test/fixtures/oldlib/1.0/oldlib-1.0.pom`]: pomWithDep("com.test.fixtures", "oldlib", "1.0", "org.apache.poi", "poi", "3.11"),
	[`${MC}/com/test/fixtures/viaA/1.0/viaA-1.0.pom`]:   pomWithDep("com.test.fixtures", "viaA", "1.0", "com.test.fixtures", "safe", "1.0"),
	[`${MC}/org/apache/poi/poi/3.11/poi-3.11.pom`]:      leafPom("org.apache.poi", "poi", "3.11"),
	[`${MC}/org/apache/poi/poi/5.4.1/poi-5.4.1.pom`]:    leafPom("org.apache.poi", "poi", "5.4.1"),
	[`${MC}/com/test/fixtures/safe/1.0/safe-1.0.pom`]:   leafPom("com.test.fixtures", "safe", "1.0"),
	[`${MC}/com/test/fixtures/safe/2.0/safe-2.0.pom`]:   leafPom("com.test.fixtures", "safe", "2.0"),
};
const fakeFetcher = async (url) =>
	RESPONSES[url] ? { ok: true, status: 200, text: async () => RESPONSES[url] }
		: { ok: false, status: 404, text: async () => "" };

async function collectFixture() {
	const store = core.newMetadataStore();
	for (const pom of core.findPomFiles(FIXTURE)) await core.parsePom(pom, store);
	const propsByPom = {};
	for (const pom of Object.keys(store.byPath)) await core.getAllInheritedProps(pom, store, propsByPom);
	const resolved = collectResolvedDeps(store, propsByPom, {});
	return { store, propsByPom, resolved };
}

test("overlay recovers the masked island version AND respects an inherited pin", async () => {
	const { store, propsByPom, resolved } = await collectFixture();
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-overlay-"));
	await resolveReactor(resolved, store, propsByPom, { fetcher: fakeFetcher, cacheDir });

	// RECALL: the island's poi 3.11 is now scanned alongside the pinned 5.4.1.
	const poi = resolved.get("org.apache.poi:poi");
	assert.ok(poi.versions.includes("5.4.1"), "kept the pinned 5.4.1");
	assert.ok(poi.versions.includes("3.11"), "recovered the masked island 3.11");
	assert.ok(poi.maskedVersions.some(m => m.version === "3.11" && /stress|island/i.test(m.module) || m.version === "3.11"),
		"3.11 carries the module that resolves it");

	// FP-SAFETY: module-a inherits the safe 2.0 pin → its transitive safe 1.0 stays
	// overridden to 2.0. The overlay must NOT surface 1.0.
	const safe = resolved.get("com.test.fixtures:safe");
	assert.deepEqual(safe.versions, ["2.0"], "must NOT surface safe 1.0 (module-a inherits the 2.0 pin)");
});

test("matchDepsAgainstCves flags the recovered 3.11 against a <4.0 CVE", async () => {
	const { store, propsByPom, resolved } = await collectFixture();
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-overlay-"));
	await resolveReactor(resolved, store, propsByPom, { fetcher: fakeFetcher, cacheDir });

	const idx = {
		byPackageName: { "org.apache.poi:poi": [{ id: "CVE-FIX-0001", coordinateEvidence: "explicit-coordinate", exactPackageName: "org.apache.poi:poi", severity: "HIGH", ranges: [{ version: "0", status: "affected", versionType: "maven", lessThan: "4.0" }] }] },
		byProduct: {},
	};
	const matches = matchDepsAgainstCves(resolved, idx);
	assert.ok(matches.some(m => m.cve.id === "CVE-FIX-0001" && m.dep.version === "3.11"),
		"the masked 3.11 must now be matched as vulnerable");
	assert.ok(!matches.some(m => m.cve.id === "CVE-FIX-0001" && m.dep.version === "5.4.1"),
		"the fixed 5.4.1 must NOT be flagged");
});
