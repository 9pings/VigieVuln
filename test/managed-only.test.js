/**
 * A <dependencyManagement> entry is a VERSION PIN, not a dependency (lib/cve-match.js).
 *
 * Measured on a real reactor: a module pinning org.codehaus.jackson:jackson-mapper-asl:1.9.13
 * in its depMgmt — and depending on it nowhere — was reported as a DIRECT production dep
 * carrying CVE-2019-10202 (CRITICAL). Maven puts a managed coordinate on a classpath only
 * when a <dependencies> entry or a transitive edge asks for it. Fixture
 * test/fixtures/maven-managed-only, ZERO network (in-memory Maven Central).
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const core = require("../lib/core");
const { collectResolvedDeps, expandWithTransitives, settleManagedOnly, matchDepsAgainstCves } = require("../lib/cve-match");
const { makeDepRecord } = require("../lib/dep-record");

const FIXTURE = path.join(__dirname, "fixtures", "maven-managed-only");
const MC = "https://repo1.maven.org/maven2";
const leaf = (g, a, v) => `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version></project>`;
const RESPONSES = {
	// lib-a pulls an OLDER c3p0; the root depMgmt pins it to 0.11.0.
	[`${MC}/com/acme/ext/lib-a/2.0/lib-a-2.0.pom`]: `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
		<groupId>com.acme.ext</groupId><artifactId>lib-a</artifactId><version>2.0</version>
		<dependencies><dependency><groupId>com.mchange</groupId><artifactId>c3p0</artifactId><version>0.9.5</version></dependency></dependencies></project>`,
	[`${MC}/com/mchange/c3p0/0.11.0/c3p0-0.11.0.pom`]: leaf("com.mchange", "c3p0", "0.11.0"),
	[`${MC}/com/mchange/c3p0/0.9.5/c3p0-0.9.5.pom`]: leaf("com.mchange", "c3p0", "0.9.5"),
	[`${MC}/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom`]: leaf("org.apache.commons", "commons-lang3", "3.12.0"),
};
const requested = [];
const fakeFetcher = async url => {
	requested.push(String(url));
	return RESPONSES[url] ? { ok: true, status: 200, text: async () => RESPONSES[url] } : { ok: false, status: 404, text: async () => "" };
};

async function collect() {
	const store = core.newMetadataStore();
	for (const pom of core.findPomFiles(FIXTURE)) await core.parsePom(pom, store);
	const propsByPom = {};
	for (const pom of Object.keys(store.byPath)) await core.getAllInheritedProps(pom, store, propsByPom);
	return collectResolvedDeps(store, propsByPom, {});
}

test("collect: a depMgmt-only coord is flagged managedOnly; one also declared is a normal direct dep", async () => {
	const r = await collect();
	assert.equal(r.get("org.codehaus.jackson:jackson-mapper-asl").managedOnly, true);
	assert.equal(r.get("com.mchange:c3p0").managedOnly, true);
	const lang = r.get("org.apache.commons:commons-lang3");
	assert.equal(lang.managedOnly, undefined, "declared in <dependencies> → a real direct dep");
	assert.equal(lang.version, "3.12.0", "its version still comes from the depMgmt pin");
	assert.deepEqual(lang.exclusionSets, [["org.example:unwanted"]], "the managed <exclusions> travel with the declaration");
});

test("resolution: an unused pin is never a root and leaves the scan set; a reached pin becomes a transitive at the pinned version", async () => {
	const r = await collect();
	requested.length = 0;
	await expandWithTransitives(r, { fetcher: fakeFetcher, cacheDir: fs.mkdtempSync(path.join(os.tmpdir(), "fad-mgmt-")) });
	assert.ok(!requested.some(u => u.includes("jackson-mapper-asl")), "an unused pin must not seed the graph");
	const c3p0 = r.get("com.mchange:c3p0");
	assert.equal(c3p0.scope, "transitive");
	assert.deepEqual(c3p0.versions, ["0.11.0"], "root depMgmt wins over lib-a's 0.9.5 (Maven semantics)");
	assert.deepEqual(c3p0.via, ["com.acme.ext:lib-a"]);
	assert.deepEqual(c3p0.manifestPaths, [], "the pinning pom does not DECLARE it");
	assert.equal(c3p0.pomPaths, c3p0.manifestPaths, "pomPaths stays the SAME array object");
	assert.ok(c3p0.managedIn[0].endsWith("pom.xml"), "where to bump the pin is kept");

	const { dropped } = settleManagedOnly(r);
	assert.deepEqual(dropped, ["org.codehaus.jackson:jackson-mapper-asl:1.9.13"]);
	assert.ok(!r.has("org.codehaus.jackson:jackson-mapper-asl"));

	const idx = { byPackageName: {
		"org.codehaus.jackson:jackson-mapper-asl": [{ id: "CVE-2019-10202", coordinateEvidence: "explicit-coordinate", exactPackageName: "org.codehaus.jackson:jackson-mapper-asl", severity: "CRITICAL", ranges: [{ version: "0", status: "affected", versionType: "maven", lessThanOrEqual: "1.9.13" }] }],
		"com.mchange:c3p0": [{ id: "CVE-C3P0", coordinateEvidence: "explicit-coordinate", exactPackageName: "com.mchange:c3p0", severity: "HIGH", ranges: [{ version: "0", status: "affected", versionType: "maven", lessThan: "0.12.0" }] }],
	}, byProduct: {} };
	const ids = matchDepsAgainstCves(r, idx).map(m => m.cve.id);
	assert.ok(!ids.includes("CVE-2019-10202"), "no CVE against a jar no classpath holds");
	assert.ok(ids.includes("CVE-C3P0"), "the pin that IS on the classpath keeps its finding");
});

test("settle: without any resolution pass, an unproven pin is dropped; one the per-module overlay reached is kept at the reached version(s)", () => {
	const unused = { ...makeDepRecord({ ecosystem: "maven", namespace: "g", name: "unused", version: "1.0", manifestPath: "/p/pom.xml" }), managedOnly: true };
	const reached = { ...makeDepRecord({ ecosystem: "maven", namespace: "g", name: "reached", version: "2.0", manifestPath: "/p/pom.xml" }), managedOnly: true,
		maskedVersions: [{ version: "1.5", via: ["g:root"], viaPaths: [["g:root"]], module: "/p/m/pom.xml", depth: 1, scope: "compile" }] };
	const m = new Map([["g:unused", unused], ["g:reached", reached]]);
	const out = settleManagedOnly(m);
	assert.deepEqual(out.dropped, ["g:unused:1.0"]);
	assert.equal(out.promoted, 1);
	assert.deepEqual(m.get("g:reached").versions, ["1.5"], "the reached version, not the unproven pin");
	assert.equal(m.get("g:reached").scope, "transitive");
});

test("an npm record is never a Maven resolution root (no `undefined:<name>` lookups)", async () => {
	const r = new Map([["npm:left-pad", makeDepRecord({ ecosystem: "npm", name: "left-pad", version: "1.3.0", manifestPath: "/p/package-lock.json" })]]);
	requested.length = 0;
	await expandWithTransitives(r, { fetcher: fakeFetcher, cacheDir: fs.mkdtempSync(path.join(os.tmpdir(), "fad-mgmt-")) });
	assert.deepEqual(requested, []);
});
