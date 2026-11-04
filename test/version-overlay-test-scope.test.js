/**
 * The per-module overlay must recover TEST-scope masked versions too.
 *
 * The global transitive pass dedupes by `g:a` across the WHOLE reactor: one version wins and
 * every other version of that coord disappears. The overlay exists precisely to recover the
 * ones a different module really holds — but it hardcoded
 * `includedScopes: ["compile","runtime","provided"]`, so a version reachable only through a
 * test-scoped dependency could never be recovered. Maven says `test → compile = test`: those
 * versions ARE on that module's test classpath.
 *
 * Measured on Apache Dubbo 2.7.8, this single gap accounted for **all 78** findings
 * OSV-Scanner reported that fad missed — `jackson-databind:2.8.4:test` in
 * dubbo-registry-sofa, `hibernate-validator:5.2.4.Final:test` in dubbo-filter-validation,
 * `okhttp:3.11.0:test` in dubbo-configcenter-apollo, `commons-compress:1.18:test` in
 * dubbo-remoting-etcd3. Each verified against `mvn dependency:tree`.
 *
 * The fixture is that shape, minimised: module-a pulls the safe app:2.0.0 at compile scope
 * (so the global pass resolves com.acme:lib to 2.0.0), module-b pulls a test-only harness
 * that drags the vulnerable lib:1.0.0 onto its TEST classpath.
 *
 * The recovered version must be reported as **dev**, never production: it is on a test
 * classpath only, and letting it inflate the production count (or trip `--fail-on`) trades
 * one class of wrong answer for another.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const core = require("../lib/core");
const { collectResolvedDeps, expandWithTransitives, matchDepsAgainstCves } = require("../lib/cve-match");
const { resolveReactor } = require("../lib/maven-reactor");
const { attributeMatchOrigins } = require("../lib/attribution");

const FIXTURE = path.join(__dirname, "fixtures", "maven-test-scope-masking");
const MC = "https://repo1.maven.org/maven2";

const leaf = (g, a, v) =>
	`<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
		<groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version></project>`;
const withDep = (g, a, v, dg, da, dv, scope) =>
	`<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
		<groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version>
		<dependencies><dependency>
			<groupId>${dg}</groupId><artifactId>${da}</artifactId><version>${dv}</version>
			${scope ? `<scope>${scope}</scope>` : ""}
		</dependency></dependencies></project>`;

// In-memory Maven Central, zero network.
//   app:2.0.0     (compile, module-a) → lib:2.0.0   ← safe, wins the global pass
//   harness:1.0.0 (test,    module-b) → lib:1.0.0   ← vulnerable, masked
const RESPONSES = {
	[`${MC}/com/acme/app/2.0.0/app-2.0.0.pom`]: withDep("com.acme", "app", "2.0.0", "com.acme", "lib", "2.0.0"),
	[`${MC}/com/acme/harness/1.0.0/harness-1.0.0.pom`]: withDep("com.acme", "harness", "1.0.0", "com.acme", "lib", "1.0.0"),
	[`${MC}/com/acme/lib/2.0.0/lib-2.0.0.pom`]: leaf("com.acme", "lib", "2.0.0"),
	[`${MC}/com/acme/lib/1.0.0/lib-1.0.0.pom`]: leaf("com.acme", "lib", "1.0.0"),
	// lib 1.5.0 is masked from BOTH a compile module (module-c) and a test module (module-d)
	[`${MC}/com/acme/other/1.0.0/other-1.0.0.pom`]: withDep("com.acme", "other", "1.0.0", "com.acme", "lib", "1.5.0"),
	[`${MC}/com/acme/probe/1.0.0/probe-1.0.0.pom`]: withDep("com.acme", "probe", "1.0.0", "com.acme", "lib", "1.5.0"),
	[`${MC}/com/acme/lib/1.5.0/lib-1.5.0.pom`]: leaf("com.acme", "lib", "1.5.0"),
};
const fetcher = async (url) => RESPONSES[url]
	? { ok: true, status: 200, text: async () => RESPONSES[url] }
	: { ok: false, status: 404, text: async () => "" };

async function run() {
	const store = core.newMetadataStore();
	for (const pom of core.findPomFiles(FIXTURE)) await core.parsePom(pom, store);
	const propsByPom = {};
	for (const pom of Object.keys(store.byPath)) await core.getAllInheritedProps(pom, store, propsByPom);
	const resolved = collectResolvedDeps(store, propsByPom, {});
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-testscope-mask-"));
	const opts = { fetcher, cacheDir, includeTestDeps: true };
	const overlay = await resolveReactor(resolved, store, propsByPom, opts);
	return { resolved, overlay };
}

test("every per-module version is recovered, none is lost", async () => {
	const { resolved } = await run();
	const lib = resolved.get("com.acme:lib");
	assert.ok(lib, "lib must be resolved");
	for (const v of ["2.0.0", "1.0.0", "1.5.0"]) {
		assert.ok(lib.versions.includes(v),
			`each module holds its own version of lib; missing ${v} in ${JSON.stringify(lib.versions)}`);
	}
});

test("the overlay recovers a version masked behind a TEST-scoped dependency", async () => {
	const { resolved } = await run();
	const lib = resolved.get("com.acme:lib");
	assert.ok(lib.versions.includes("1.0.0"),
		`module-b really holds lib 1.0.0 on its test classpath; got versions=${JSON.stringify(lib.versions)}`);
});

test("a masked version reached at COMPILE scope by ANY module stays production", async () => {
	const { resolved } = await run();
	const idx = {
		byPackageName: { "com.acme:lib": [{ id: "CVE-TEST-0002", coordinateEvidence: "explicit-coordinate", exactPackageName: "com.acme:lib", severity: "HIGH", ranges: [{ version: "0", status: "affected", versionType: "maven", lessThan: "2.0.0" }] }] },
		byProduct: {},
	};
	const matches = matchDepsAgainstCves(resolved, idx);
	attributeMatchOrigins(matches);
	const hit = matches.find(m => m.cve.id === "CVE-TEST-0002" && m.dep.version === "1.5.0");
	assert.ok(hit, "lib 1.5.0 must be scanned");
	// module-b holds it at test scope, module-c at compile scope. Taking the first
	// maskedVersions entry would call it dev and drop a genuine production finding out of
	// the count and out of --fail-on. Real shape: on Dubbo, jackson-databind:2.10.4 is test
	// in dubbo-config-spring but COMPILE in dubbo-configcenter-nacos.
	assert.notEqual(hit.dep.isDev, true,
		"module-d holds 1.5.0 at test scope but module-c holds it at COMPILE scope, so it is a PRODUCTION finding");
});

test("a version masked ONLY behind test scope is flagged dev", async () => {
	const { resolved } = await run();
	const idx = {
		byPackageName: { "com.acme:lib": [{ id: "CVE-TEST-0001", coordinateEvidence: "explicit-coordinate", exactPackageName: "com.acme:lib", severity: "HIGH", ranges: [{ version: "0", status: "affected", versionType: "maven", lessThan: "2.0.0" }] }] },
		byProduct: {},
	};
	const matches = matchDepsAgainstCves(resolved, idx);
	attributeMatchOrigins(matches);

	const hit = matches.filter(m => m.cve.id === "CVE-TEST-0001" && m.dep.version === "1.0.0");
	assert.equal(hit.length, 1, "the vulnerable 1.0.0 must match");
	assert.ok(!matches.some(m => m.cve.id === "CVE-TEST-0001" && m.dep.version === "2.0.0"),
		"the safe 2.0.0 must not match");
	assert.equal(hit[0].dep.isDev, true,
		"lib 1.0.0 is reachable only through a test-scoped dep — reporting it as production would inflate the production count and trip --fail-on");
	assert.ok((hit[0].dep.manifestPaths || []).some(p => p.includes("module-b")),
		`the finding belongs to module-b, got ${JSON.stringify(hit[0].dep.manifestPaths)}`);
});

test("the production version stays production and is not downgraded", async () => {
	const { resolved } = await run();
	const lib = resolved.get("com.acme:lib");
	assert.ok(lib.versions.includes("2.0.0"), "the compile-scope version must still be scanned");
	assert.notEqual(lib.isDev, true, "the coord is on module-a's compile classpath — it is production");
});

// Regression: a version that a manifest DECLARES outright must not be re-stamped by a
// transitive provenance for the same version. Real shape: xstream:1.4.10 is declared in
// dubbo-registry-eureka's pom, and the overlay also reaches 1.4.10 as a test-scoped
// transitive of dubbo-config-api. Letting the masked entry win demoted a declared
// production dependency (35 findings, one of them KEV) into the dev chapter.
test("a DECLARED version wins over a test-scoped transitive provenance for the same version", async () => {
	const { resolved } = await run();
	const lib = resolved.get("com.acme:lib");
	// Simulate the shape: the coord is declared at 1.0.0 by a manifest, while the overlay
	// also recorded 1.0.0 as a test-scoped transitive of module-b.
	lib.versionPaths = { ...(lib.versionPaths || {}), "1.0.0": ["module-x/pom.xml"] };
	const idx = {
		byPackageName: { "com.acme:lib": [{ id: "CVE-TEST-0003", coordinateEvidence: "explicit-coordinate", exactPackageName: "com.acme:lib", severity: "HIGH", ranges: [{ version: "0", status: "affected", versionType: "maven", lessThan: "2.0.0" }] }] },
		byProduct: {},
	};
	const matches = matchDepsAgainstCves(resolved, idx);
	attributeMatchOrigins(matches);
	const hit = matches.find(m => m.cve.id === "CVE-TEST-0003" && m.dep.version === "1.0.0");
	assert.ok(hit, "the declared 1.0.0 must be scanned");
	assert.notEqual(hit.dep.isDev, true,
		"1.0.0 is declared by a manifest — a transitive provenance must not demote it to dev");
	assert.ok((hit.dep.manifestPaths || []).some(p => p.includes("module-x")),
		`the declaring manifest must win the attribution, got ${JSON.stringify(hit.dep.manifestPaths)}`);
});
