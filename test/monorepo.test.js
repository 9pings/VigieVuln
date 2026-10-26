/**
 * End-to-end test against fixtures/monorepo-mixed:
 *   - 1 parent pom + 1 BOM module + 2 Maven submodules
 *   - 1 npm package (package-lock v3) with prod/dev/peer deps
 *   - 1 yarn-v1 package with prod/dev deps + a private @acme/* dep
 *
 * Drives the same code paths as `vigievuln --report` minus the network calls.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const core = require("../lib/core");
const { collectResolvedDeps } = require("../lib/cve-match");
const { collectNpmDeps, hasJsManifests } = require("../lib/codecs/npm/collect");

const FIX = path.join(__dirname, "fixtures", "monorepo-mixed");

async function loadMavenTree(src) {
	const pomFiles = core.findPomFiles(src);
	const meta = core.newMetadataStore();
	const propsByPom = {};
	for (const pom of pomFiles) await core.parsePom(pom, meta);
	for (const pom of Object.keys(meta.byPath)) {
		await core.getAllInheritedProps(pom, meta, propsByPom);
	}
	return { meta, propsByPom, pomFiles };
}

test("hasJsManifests detects the JS packages under the monorepo", () => {
	assert.equal(hasJsManifests(FIX), true);
});

test("Maven side: parses parent + BOM + submodules", async () => {
	const { meta, pomFiles } = await loadMavenTree(FIX);
	assert.equal(pomFiles.length, 4); // root + bom + api + worker
	assert.ok(meta.byId["com.acme:monorepo-parent"]);
	assert.ok(meta.byId["com.acme:common-bom"]);
	assert.ok(meta.byId["com.acme:api"]);
	assert.ok(meta.byId["com.acme:worker"]);
});

test("Maven side: BOM-imported versions surface in api's resolved deps", async () => {
	const { meta, propsByPom } = await loadMavenTree(FIX);
	const resolved = collectResolvedDeps(meta, propsByPom, {});
	const databind = resolved.get("com.fasterxml.jackson.core:jackson-databind");
	assert.ok(databind, "jackson-databind should be resolved via BOM");
	// Version arrives through ${jackson.version} property defined on the root parent
	assert.equal(databind.version, "2.9.10");
	assert.equal(databind.ecosystem, "maven");
});

test("Maven side: exclude regex strips com.acme.private but keeps public deps", async () => {
	const { meta, propsByPom } = await loadMavenTree(FIX);
	const resolved = collectResolvedDeps(meta, propsByPom, {
		deps2Exclude: /^com\.acme\.private/,
	});
	assert.equal(resolved.has("com.acme.private:internal-auth"), false);
	assert.ok(resolved.has("com.fasterxml.jackson.core:jackson-databind"));
});

test("Maven side: --ignore-test drops junit test scope", async () => {
	const { meta, propsByPom } = await loadMavenTree(FIX);
	const withTest = collectResolvedDeps(meta, propsByPom, {});
	const noTest = collectResolvedDeps(meta, propsByPom, { ignoreTest: true });
	assert.ok(withTest.has("junit:junit"));
	assert.equal(noTest.has("junit:junit"), false);
});

test("JS side: both packages discovered, namespaced keys, no Maven collision", () => {
	const npm = collectNpmDeps(FIX, {});
	assert.ok(npm.has("npm:axios"));
	assert.ok(npm.has("npm:chalk"));
	assert.ok(npm.has("npm:@acme/private-utils"));
	// No accidental collision with Maven g:a keys
	for (const key of npm.keys()) assert.ok(key.startsWith("npm:"), `${key} should be namespaced`);
});

test("Combined: merged Map preserves both ecosystems and is queryable as one", async () => {
	const { meta, propsByPom } = await loadMavenTree(FIX);
	const combined = collectResolvedDeps(meta, propsByPom, {});
	const npm = collectNpmDeps(FIX, {});
	for (const [k, v] of npm) combined.set(k, v);

	// Maven and npm coords coexist
	assert.ok(combined.get("com.fasterxml.jackson.core:jackson-databind"));
	assert.ok(combined.get("npm:axios"));
	// Distinct ecosystems
	assert.equal(combined.get("com.fasterxml.jackson.core:jackson-databind").ecosystem, "maven");
	assert.equal(combined.get("npm:axios").ecosystem, "npm");
	// Total deps from both sides
	assert.ok(combined.size >= 10, `expected ≥10 combined deps, got ${combined.size}`);
});

test("Combined: shared exclusion regex applies per-ecosystem appropriately", async () => {
	// Maven private prefix
	const { meta, propsByPom } = await loadMavenTree(FIX);
	const mvn = collectResolvedDeps(meta, propsByPom, { deps2Exclude: /^com\.acme\.private/ });
	assert.equal(mvn.has("com.acme.private:internal-auth"), false);

	// npm uses a different convention (@scope) — own regex matches it
	const npm = collectNpmDeps(FIX, { deps2Exclude: /^@acme\// });
	assert.equal(npm.has("npm:@acme/private-utils"), false);
});

test("Combined: a sample CVE match flow runs without throwing on a mixed Map", async () => {
	const { matchDepsAgainstCves } = require("../lib/cve-match");
	const { meta, propsByPom } = await loadMavenTree(FIX);
	const combined = collectResolvedDeps(meta, propsByPom, {});
	const npm = collectNpmDeps(FIX, {});
	for (const [k, v] of npm) combined.set(k, v);

	// Tiny stub CVE index. Only Maven-relevant — npm should be silently skipped by matchDepsAgainstCves.
	const idx = {
		byPackageName: {
			"org.apache.logging.log4j:log4j-core": [{
				id: "CVE-2021-44228",
				severity: "CRITICAL",
				score: 10.0,
				description: "Log4Shell",
				fixVersion: "2.15.0",
				ranges: [{ status: "affected", version: "2.0.0", lessThan: "2.15.0", versionType: "maven" }],
				vendor: "apache",
				product: "log4j-core",
			}],
		},
		byProduct: {},
	};
	const matches = matchDepsAgainstCves(combined, idx);
	assert.ok(matches.length >= 1);
	const log4shell = matches.find(m => m.cve.id === "CVE-2021-44228");
	assert.ok(log4shell, "log4-core 2.14.0 should match CVE-2021-44228");
});
