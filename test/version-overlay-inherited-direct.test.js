/**
 * Per-module overlay must honour INHERITED direct dependencies (lib/version-overlay.js).
 *
 * Maven inherits a parent's <dependencies> into every child, where they stay DIRECT
 * (depth-0) deps and win nearest-wins over any transitive of the same coord. But
 * core.js#getAllInheritedProps deliberately does NOT merge parent <dependencies> into
 * propsByPom[child] (collectResolvedDeps merges them globally by g:a instead). So a
 * per-module pass that reads only propsByPom[child].dependencies sees the child as if
 * it never declared the coord — and happily "recovers" the transitive version the
 * inherited declaration actually overrides.
 *
 * Real-world shape (test/fixtures/maven-inherited-direct, ZERO network — in-memory
 * fetcher): the parent bumps commons-compress to 1.27.1 to remediate the vulnerable
 * 1.24.0 that module-c's minio:8.5.6 pulls in. 1.24.0 never reaches a classpath, so
 * scanning it fabricates CVEs against a version the build does not use.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const core = require("../lib/codecs/maven/pom");
const { collectResolvedDeps, expandWithTransitives, matchDepsAgainstCves } = require("../lib/advisories/cve-match");
const { resolveReactor } = require("../lib/codecs/maven/reactor");

const FIXTURE = path.join(__dirname, "fixtures", "maven-inherited-direct");
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

// In-memory Maven Central: minio 8.5.6 → the old commons-compress 1.24.0.
const RESPONSES = {
	[`${MC}/io/minio/minio/8.5.6/minio-8.5.6.pom`]:
		pomWithDep("io.minio", "minio", "8.5.6", "org.apache.commons", "commons-compress", "1.24.0"),
	[`${MC}/org/apache/commons/commons-compress/1.24.0/commons-compress-1.24.0.pom`]:
		leafPom("org.apache.commons", "commons-compress", "1.24.0"),
	[`${MC}/org/apache/commons/commons-compress/1.27.1/commons-compress-1.27.1.pom`]:
		leafPom("org.apache.commons", "commons-compress", "1.27.1"),
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

test("overlay must NOT surface a transitive that an INHERITED direct dep overrides", async () => {
	const { store, propsByPom, resolved } = await collectFixture();
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-inherited-"));
	await resolveReactor(resolved, store, propsByPom, { fetcher: fakeFetcher, cacheDir });

	const cc = resolved.get("org.apache.commons:commons-compress");
	assert.ok(cc, "commons-compress should be in the resolved set");
	assert.deepEqual(cc.versions, ["1.27.1"],
		"module-c inherits the parent's direct commons-compress:1.27.1, so minio's transitive 1.24.0 is never on its classpath");
});

test("no CVE is fabricated against the overridden 1.24.0", async () => {
	const { store, propsByPom, resolved } = await collectFixture();
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-inherited-"));
	await resolveReactor(resolved, store, propsByPom, { fetcher: fakeFetcher, cacheDir });

	const idx = {
		byPackageName: { "org.apache.commons:commons-compress": [{ id: "CVE-FIX-0002", severity: "HIGH", ranges: [{ lessThan: "1.26.0" }] }] },
		byProduct: {},
	};
	const matches = matchDepsAgainstCves(resolved, idx);
	assert.ok(!matches.some(m => m.cve.id === "CVE-FIX-0002"),
		"the remediated 1.27.1 is the resolved version — flagging it fabricates a finding");
});
