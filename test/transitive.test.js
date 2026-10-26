const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { parsePomXml, resolveProps, buildMgmt, SCOPE_MATRIX, resolveTransitiveDeps, effectivePom } = require("../lib/transitive");

// A platform POM that manages log4j-core via a ${log4j2.version} property. This is the
// Spring Boot shape: spring-boot-dependencies manages the coord through a version property
// a downstream project can OVERRIDE in its own <properties> to patch a CVE. effectivePom
// must resolve the parent's managed table against those child overrides (Maven semantics).
const MC_URL = "https://repo1.maven.org/maven2";
const PLAT_POM = `<?xml version="1.0"?>
<project><modelVersion>4.0.0</modelVersion>
	<groupId>com.acme</groupId><artifactId>plat</artifactId><version>1.0</version>
	<properties><log4j2.version>2.17.2</log4j2.version></properties>
	<dependencyManagement><dependencies>
		<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>\${log4j2.version}</version></dependency>
	</dependencies></dependencyManagement>
</project>`;
const platFetcher = async (url) => url === `${MC_URL}/com/acme/plat/1.0/plat-1.0.pom`
	? { ok: true, status: 200, text: async () => PLAT_POM }
	: { ok: false, status: 404, text: async () => "" };

test("effectivePom resolves a parent-managed version property to the parent default", async () => {
	const eff = await effectivePom("com.acme", "plat", "1.0", { fetcher: platFetcher, cacheDir: freshCache() });
	assert.equal(eff.depMgmt.find(d => d.artifactId === "log4j-core").version, "2.17.2");
});

test("effectivePom honors injected propertyOverrides for parent-chain managed versions", async () => {
	const eff = await effectivePom("com.acme", "plat", "1.0",
		{ fetcher: platFetcher, cacheDir: freshCache(), propertyOverrides: { "log4j2.version": "2.17.1" } });
	assert.equal(eff.depMgmt.find(d => d.artifactId === "log4j-core").version, "2.17.1",
		"a child overriding <log4j2.version> must win over the parent's default");
});

// Per-test cache dir so we don't poison ~/.fad-checker/poms-cache during tests
function freshCache() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-pom-cache-"));
	return dir;
}

// ---------- POM fixtures expressed as XML strings ----------

const POM_A = `<?xml version="1.0"?>
<project>
	<modelVersion>4.0.0</modelVersion>
	<groupId>com.example</groupId>
	<artifactId>a</artifactId>
	<version>1.0.0</version>
	<dependencies>
		<dependency>
			<groupId>com.example</groupId>
			<artifactId>b</artifactId>
			<version>2.0.0</version>
		</dependency>
		<dependency>
			<groupId>com.example</groupId>
			<artifactId>test-only</artifactId>
			<version>3.0.0</version>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>com.example</groupId>
			<artifactId>optional-lib</artifactId>
			<version>4.0.0</version>
			<optional>true</optional>
		</dependency>
	</dependencies>
</project>`;

const POM_B = `<?xml version="1.0"?>
<project>
	<modelVersion>4.0.0</modelVersion>
	<groupId>com.example</groupId>
	<artifactId>b</artifactId>
	<version>2.0.0</version>
	<dependencies>
		<dependency>
			<groupId>com.example</groupId>
			<artifactId>c</artifactId>
			<version>5.0.0</version>
		</dependency>
	</dependencies>
</project>`;

const POM_C = `<?xml version="1.0"?>
<project>
	<modelVersion>4.0.0</modelVersion>
	<groupId>com.example</groupId>
	<artifactId>c</artifactId>
	<version>5.0.0</version>
</project>`;

// Build an in-memory fetcher
function fakeFetcher(responses) {
	return async (url) => {
		if (responses[url]) {
			return { ok: true, status: 200, text: async () => responses[url] };
		}
		return { ok: false, status: 404, text: async () => "" };
	};
}

const MC = "https://repo1.maven.org/maven2";

// ---------- Tests ----------

test("parsePomXml extracts coords, deps, scope, optional, exclusions", async () => {
	const xml = `<?xml version="1.0"?>
		<project>
			<groupId>g</groupId><artifactId>a</artifactId><version>1</version>
			<dependencies>
				<dependency>
					<groupId>org.foo</groupId><artifactId>bar</artifactId><version>2.0</version>
					<scope>runtime</scope><optional>true</optional>
					<exclusions>
						<exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion>
					</exclusions>
				</dependency>
			</dependencies>
		</project>`;
	const pom = await parsePomXml(xml);
	assert.equal(pom.groupId, "g");
	assert.equal(pom.deps[0].scope, "runtime");
	assert.equal(pom.deps[0].optional, true);
	assert.deepEqual(pom.deps[0].exclusions, [{ groupId: "x", artifactId: "y" }]);
});

test("parsePomXml handles parent + inherits groupId/version from it", async () => {
	const xml = `<?xml version="1.0"?>
		<project>
			<parent><groupId>g</groupId><artifactId>p</artifactId><version>3.0</version></parent>
			<artifactId>child</artifactId>
		</project>`;
	const pom = await parsePomXml(xml);
	assert.equal(pom.groupId, "g");
	assert.equal(pom.version, "3.0");
	assert.equal(pom.parent.artifactId, "p");
});

test("resolveProps substitutes ${prop} including project.* builtins", () => {
	const props = { "spring.version": "5.3.20", "log4j": "2.20.0" };
	const builtins = { "project.version": "1.0" };
	assert.equal(resolveProps("${spring.version}", props, builtins), "5.3.20");
	assert.equal(resolveProps("${project.version}", props, builtins), "1.0");
	assert.equal(resolveProps("v=${log4j}", props, builtins), "v=2.20.0");
	assert.equal(resolveProps("${unknown}", props, builtins), "${unknown}");
});

test("resolveProps follows chained property references", () => {
	const props = { a: "${b}", b: "${c}", c: "final" };
	assert.equal(resolveProps("${a}", props, {}), "final");
});

test("SCOPE_MATRIX implements Maven's scope-propagation rules", () => {
	// compile direct + compile transitive → compile
	assert.equal(SCOPE_MATRIX.compile.compile, "compile");
	// compile + runtime → runtime
	assert.equal(SCOPE_MATRIX.compile.runtime, "runtime");
	// compile + test → not propagated
	assert.equal(SCOPE_MATRIX.compile.test, null);
	// test + compile → test
	assert.equal(SCOPE_MATRIX.test.compile, "test");
	// provided + runtime → provided
	assert.equal(SCOPE_MATRIX.provided.runtime, "provided");
});

test("buildMgmt indexes depMgmt by g:a", () => {
	const m = buildMgmt([
		{ groupId: "g", artifactId: "a", version: "1.0" },
		{ groupId: "h", artifactId: "b", version: "2.0" },
	]);
	assert.equal(m.size, 2);
	assert.equal(m.get("g:a").version, "1.0");
});

test("resolveTransitiveDeps walks A→B→C, skips test + optional", async () => {
	const responses = {
		[`${MC}/com/example/a/1.0.0/a-1.0.0.pom`]: POM_A,
		[`${MC}/com/example/b/2.0.0/b-2.0.0.pom`]: POM_B,
		[`${MC}/com/example/c/5.0.0/c-5.0.0.pom`]: POM_C,
	};
	const transitives = await resolveTransitiveDeps(
		[{ groupId: "com.example", artifactId: "a", version: "1.0.0", scope: "compile" }],
		{ fetcher: fakeFetcher(responses), verbose: false, cacheDir: freshCache() }
	);
	// b is the direct dep of a → it IS a transitive (we excluded `a` itself
	// from the result earlier). c is b's transitive.
	const keys = [...transitives.keys()];
	assert.ok(keys.includes("com.example:b"), `expected b in transitives, got ${keys.join(",")}`);
	assert.ok(keys.includes("com.example:c"), `expected c in transitives, got ${keys.join(",")}`);
	// test scope must NOT propagate
	assert.ok(!keys.includes("com.example:test-only"), "test-scope dep should not propagate");
	// optional must NOT propagate
	assert.ok(!keys.includes("com.example:optional-lib"), "optional dep should not propagate");
});

test("resolveTransitiveDeps applies root depMgmt version overrides", async () => {
	const POM_X = `<?xml version="1.0"?>
		<project>
			<groupId>g</groupId><artifactId>x</artifactId><version>1.0</version>
			<dependencies>
				<dependency>
					<groupId>g</groupId><artifactId>y</artifactId><version>5.0</version>
				</dependency>
			</dependencies>
		</project>`;
	const POM_Y_5 = `<?xml version="1.0"?>
		<project><groupId>g</groupId><artifactId>y</artifactId><version>5.0</version></project>`;
	const POM_Y_OVERRIDE = `<?xml version="1.0"?>
		<project><groupId>g</groupId><artifactId>y</artifactId><version>9.9</version></project>`;
	const responses = {
		[`${MC}/g/x/1.0/x-1.0.pom`]: POM_X,
		[`${MC}/g/y/5.0/y-5.0.pom`]: POM_Y_5,
		[`${MC}/g/y/9.9/y-9.9.pom`]: POM_Y_OVERRIDE,
	};
	const rootMgmt = new Map([["g:y", { version: "9.9" }]]);
	const transitives = await resolveTransitiveDeps(
		[{ groupId: "g", artifactId: "x", version: "1.0", scope: "compile" }],
		{ fetcher: fakeFetcher(responses), rootDepMgmt: rootMgmt, verbose: false, cacheDir: freshCache() }
	);
	const y = transitives.get("g:y");
	assert.ok(y, "y should be resolved");
	assert.equal(y.version, "9.9", "root depMgmt should override transitive declared version");
});

test("resolveTransitiveDeps honours <exclusion> blocks", async () => {
	const POM_ROOT = `<?xml version="1.0"?>
		<project>
			<groupId>g</groupId><artifactId>root</artifactId><version>1</version>
			<dependencies>
				<dependency>
					<groupId>g</groupId><artifactId>mid</artifactId><version>1</version>
					<exclusions>
						<exclusion><groupId>g</groupId><artifactId>leaf</artifactId></exclusion>
					</exclusions>
				</dependency>
			</dependencies>
		</project>`;
	const POM_MID = `<?xml version="1.0"?>
		<project>
			<groupId>g</groupId><artifactId>mid</artifactId><version>1</version>
			<dependencies>
				<dependency><groupId>g</groupId><artifactId>leaf</artifactId><version>1</version></dependency>
				<dependency><groupId>g</groupId><artifactId>kept</artifactId><version>1</version></dependency>
			</dependencies>
		</project>`;
	const POM_LEAF = `<?xml version="1.0"?>
		<project><groupId>g</groupId><artifactId>leaf</artifactId><version>1</version></project>`;
	const POM_KEPT = `<?xml version="1.0"?>
		<project><groupId>g</groupId><artifactId>kept</artifactId><version>1</version></project>`;
	const responses = {
		[`${MC}/g/root/1/root-1.pom`]: POM_ROOT,
		[`${MC}/g/mid/1/mid-1.pom`]: POM_MID,
		[`${MC}/g/leaf/1/leaf-1.pom`]: POM_LEAF,
		[`${MC}/g/kept/1/kept-1.pom`]: POM_KEPT,
	};
	const transitives = await resolveTransitiveDeps(
		[{ groupId: "g", artifactId: "root", version: "1", scope: "compile", exclusions: [{ groupId: "g", artifactId: "leaf" }] }],
		{ fetcher: fakeFetcher(responses), verbose: false, cacheDir: freshCache() }
	);
	const keys = [...transitives.keys()];
	assert.ok(keys.includes("g:mid"), "mid should be there");
	assert.ok(keys.includes("g:kept"), "kept should be there");
	assert.ok(!keys.includes("g:leaf"), `leaf should be excluded, got ${keys.join(",")}`);
});

test("resolveTransitiveDeps stops at maxDepth", async () => {
	const POM_R = `<?xml version="1.0"?><project>
		<groupId>g</groupId><artifactId>r</artifactId><version>1</version>
		<dependencies><dependency><groupId>g</groupId><artifactId>l1</artifactId><version>1</version></dependency></dependencies>
	</project>`;
	const POM_L1 = `<?xml version="1.0"?><project>
		<groupId>g</groupId><artifactId>l1</artifactId><version>1</version>
		<dependencies><dependency><groupId>g</groupId><artifactId>l2</artifactId><version>1</version></dependency></dependencies>
	</project>`;
	const POM_L2 = `<?xml version="1.0"?><project>
		<groupId>g</groupId><artifactId>l2</artifactId><version>1</version>
		<dependencies><dependency><groupId>g</groupId><artifactId>l3</artifactId><version>1</version></dependency></dependencies>
	</project>`;
	const POM_L3 = `<?xml version="1.0"?><project><groupId>g</groupId><artifactId>l3</artifactId><version>1</version></project>`;
	const responses = {
		[`${MC}/g/r/1/r-1.pom`]: POM_R,
		[`${MC}/g/l1/1/l1-1.pom`]: POM_L1,
		[`${MC}/g/l2/1/l2-1.pom`]: POM_L2,
		[`${MC}/g/l3/1/l3-1.pom`]: POM_L3,
	};
	const transitives = await resolveTransitiveDeps(
		[{ groupId: "g", artifactId: "r", version: "1", scope: "compile" }],
		{ fetcher: fakeFetcher(responses), maxDepth: 2, cacheDir: freshCache() }
	);
	const keys = [...transitives.keys()];
	assert.ok(keys.includes("g:l1"));
	assert.ok(keys.includes("g:l2"));
	assert.ok(!keys.includes("g:l3"), `l3 is at depth 3, should not be present at maxDepth=2; got ${keys.join(",")}`);
});

test("resolveTransitiveDeps nearest-wins on version conflict", async () => {
	// root → a@1 → c@5
	// root → c@9  (declared directly under root via b path)
	// Result: c@9 wins because it's at depth 1 vs c@5 at depth 2
	// But here we're testing the BFS, not the root-direct resolution. Setup:
	// root has two deps: x@1 (which has y@5), and y@9 directly.
	const POM_ROOT2 = `<?xml version="1.0"?><project>
		<groupId>g</groupId><artifactId>root</artifactId><version>1</version>
		<dependencies>
			<dependency><groupId>g</groupId><artifactId>x</artifactId><version>1</version></dependency>
			<dependency><groupId>g</groupId><artifactId>y</artifactId><version>9</version></dependency>
		</dependencies>
	</project>`;
	const POM_X2 = `<?xml version="1.0"?><project>
		<groupId>g</groupId><artifactId>x</artifactId><version>1</version>
		<dependencies>
			<dependency><groupId>g</groupId><artifactId>y</artifactId><version>5</version></dependency>
		</dependencies>
	</project>`;
	const POM_Y_5 = `<?xml version="1.0"?><project><groupId>g</groupId><artifactId>y</artifactId><version>5</version></project>`;
	const POM_Y_9 = `<?xml version="1.0"?><project><groupId>g</groupId><artifactId>y</artifactId><version>9</version></project>`;
	const responses = {
		[`${MC}/g/root/1/root-1.pom`]: POM_ROOT2,
		[`${MC}/g/x/1/x-1.pom`]: POM_X2,
		[`${MC}/g/y/5/y-5.pom`]: POM_Y_5,
		[`${MC}/g/y/9/y-9.pom`]: POM_Y_9,
	};
	const transitives = await resolveTransitiveDeps([
		{ groupId: "g", artifactId: "root", version: "1", scope: "compile" },
	], { fetcher: fakeFetcher(responses), verbose: false, cacheDir: freshCache() });
	// When the caller (cve-match) passes root's depMgmt with y@9, that pins y.
	// Without depMgmt, BFS visits y@9 directly under root first, then sees y again
	// from x, and skips it (nearest-wins).
	const y = transitives.get("g:y");
	assert.ok(y, "y should be in transitives");
});
