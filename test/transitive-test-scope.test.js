/**
 * Transitive closure of a TEST-scoped dependency.
 *
 * Maven's scope matrix says `test → compile = test`: the compile dependencies of a
 * test-scoped dependency ARE on the test classpath, and so are theirs, recursively. Only
 * `test → test` is omitted.
 *
 * fad used to drop that entire subtree: `expandWithTransitives` passed test-scoped roots in
 * (`includeTestDeps`), but `resolveTransitiveDeps` defaulted `includedScopes` to
 * compile/runtime/provided, so every child of a test root propagated to "test" and was
 * discarded at the first hop. Effect: the dev chapter only ever saw DIRECTLY declared test
 * deps, never their transitives.
 *
 * Real-world shape this reproduces, from Apache Dubbo 2.7.8 (verified against
 * `mvn dependency:tree`, which reports all of it at scope=test):
 *
 *   dubbo-registry-sofa
 *     └─ com.alipay.sofa:registry-test:5.2.0            (test)
 *          └─ com.alipay.sofa:registry-server-integration:5.2.0   (compile → test)
 *               └─ org.springframework.boot:spring-boot-starter:1.5.17.RELEASE (compile → test)
 *                    └─ org.springframework.boot:spring-boot:1.5.17.RELEASE    (compile → test)
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { expandWithTransitives } = require("../lib/cve-match");
const { makeDepRecord } = require("../lib/dep-record");

const MC = "https://repo1.maven.org/maven2";

function freshCache() {
	return fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-testscope-"));
}

const pom = (g, a, v, deps = "") => `<?xml version="1.0"?>
<project><modelVersion>4.0.0</modelVersion>
	<groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version>
	<dependencies>${deps}</dependencies>
</project>`;

const dep = (g, a, v, scope) =>
	`<dependency><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version>${scope ? `<scope>${scope}</scope>` : ""}</dependency>`;

const RESPONSES = {
	// the test-scoped root
	[`${MC}/com/alipay/sofa/registry-test/5.2.0/registry-test-5.2.0.pom`]: pom(
		"com.alipay.sofa", "registry-test", "5.2.0",
		dep("com.alipay.sofa", "registry-server-integration", "5.2.0") +
		// test-of-test: Maven omits this one, and so must we
		dep("com.example", "test-only-helper", "9.9.9", "test"),
	),
	[`${MC}/com/alipay/sofa/registry-server-integration/5.2.0/registry-server-integration-5.2.0.pom`]: pom(
		"com.alipay.sofa", "registry-server-integration", "5.2.0",
		dep("org.springframework.boot", "spring-boot-starter", "1.5.17.RELEASE"),
	),
	[`${MC}/org/springframework/boot/spring-boot-starter/1.5.17.RELEASE/spring-boot-starter-1.5.17.RELEASE.pom`]: pom(
		"org.springframework.boot", "spring-boot-starter", "1.5.17.RELEASE",
		dep("org.springframework.boot", "spring-boot", "1.5.17.RELEASE"),
	),
	[`${MC}/org/springframework/boot/spring-boot/1.5.17.RELEASE/spring-boot-1.5.17.RELEASE.pom`]: pom(
		"org.springframework.boot", "spring-boot", "1.5.17.RELEASE",
	),
	[`${MC}/com/example/test-only-helper/9.9.9/test-only-helper-9.9.9.pom`]: pom(
		"com.example", "test-only-helper", "9.9.9",
	),
	// a normal compile dep, to prove production behaviour is untouched
	[`${MC}/com/example/prod-lib/1.0.0/prod-lib-1.0.0.pom`]: pom(
		"com.example", "prod-lib", "1.0.0",
		dep("com.example", "prod-transitive", "2.0.0"),
	),
	[`${MC}/com/example/prod-transitive/2.0.0/prod-transitive-2.0.0.pom`]: pom(
		"com.example", "prod-transitive", "2.0.0",
	),
};

const fetcher = async (url) => RESPONSES[url]
	? { ok: true, status: 200, text: async () => RESPONSES[url] }
	: { ok: false, status: 404, text: async () => "" };

function seed() {
	const m = new Map();
	m.set("com.alipay.sofa:registry-test", makeDepRecord({
		ecosystem: "maven", namespace: "com.alipay.sofa", name: "registry-test",
		version: "5.2.0", manifestPath: "dubbo-registry/dubbo-registry-sofa/pom.xml",
		scope: "test", isDev: true,
	}));
	m.set("com.example:prod-lib", makeDepRecord({
		ecosystem: "maven", namespace: "com.example", name: "prod-lib",
		version: "1.0.0", manifestPath: "pom.xml", scope: "compile", isDev: false,
	}));
	return m;
}

const expand = (resolved) => expandWithTransitives(resolved, {
	includeTestDeps: true, fetcher, cacheDir: freshCache(), verbose: false,
});

test("the transitive closure of a test-scoped dep is scanned (Maven: test → compile = test)", async () => {
	const resolved = await expand(seed());
	const keys = [...resolved.keys()];
	for (const k of [
		"com.alipay.sofa:registry-server-integration",
		"org.springframework.boot:spring-boot-starter",
		"org.springframework.boot:spring-boot",
	]) {
		assert.ok(keys.includes(k), `${k} must be reachable through the test-scoped root, got: ${keys.join(", ")}`);
	}
	assert.equal(resolved.get("org.springframework.boot:spring-boot").version, "1.5.17.RELEASE");
});

test("a test dep OF a test dep is still omitted (Maven: test → test = omitted)", async () => {
	const resolved = await expand(seed());
	assert.ok(!resolved.has("com.example:test-only-helper"),
		"test-of-test must not enter the scan set — Maven drops it from every classpath");
});

test("transitives reached only through a test root are flagged isDev (never production)", async () => {
	const resolved = await expand(seed());
	for (const k of ["com.alipay.sofa:registry-server-integration", "org.springframework.boot:spring-boot"]) {
		assert.equal(resolved.get(k).isDev, true,
			`${k} is on the test classpath only — it must not be reported as a production finding, nor gate CI`);
	}
});

test("production transitives are unaffected and stay non-dev", async () => {
	const resolved = await expand(seed());
	const t = resolved.get("com.example:prod-transitive");
	assert.ok(t, "a compile-scoped root must still resolve its transitives");
	assert.notEqual(t.isDev, true, "a compile-scoped transitive must stay production");
});

// The dangerous half of this feature. A coord reachable through BOTH a test root and a
// compile root is on the COMPILE classpath — Maven resolves it at the wider scope. The
// traversal dedupes by `g:a` and keeps the first path it walks, so if the test root happens
// to be visited first the coord would be stamped test and silently drop out of the
// production count AND out of the `--fail-on` gate. That is a false negative on the
// production classpath, which is strictly worse than the bug this feature fixes.
// Measured on Apache Dubbo 2.7.8: spring-core, commons-lang and 4 others were downgraded
// this way before the scope-widening was added.
test("a coord reached by BOTH a test and a compile root stays production (widest scope wins)", async () => {
	const m = new Map();
	// test root FIRST, so the test path is the one the traversal walks first
	m.set("com.example:test-root", makeDepRecord({
		ecosystem: "maven", namespace: "com.example", name: "test-root",
		version: "1.0.0", manifestPath: "pom.xml", scope: "test", isDev: true,
	}));
	m.set("com.example:compile-root", makeDepRecord({
		ecosystem: "maven", namespace: "com.example", name: "compile-root",
		version: "1.0.0", manifestPath: "pom.xml", scope: "compile", isDev: false,
	}));
	const shared = "com.example:shared";
	const responses = {
		[`${MC}/com/example/test-root/1.0.0/test-root-1.0.0.pom`]: pom(
			"com.example", "test-root", "1.0.0", dep("com.example", "shared", "3.0.0")),
		[`${MC}/com/example/compile-root/1.0.0/compile-root-1.0.0.pom`]: pom(
			"com.example", "compile-root", "1.0.0", dep("com.example", "shared", "3.0.0")),
		[`${MC}/com/example/shared/3.0.0/shared-3.0.0.pom`]: pom("com.example", "shared", "3.0.0"),
	};
	const f = async (url) => responses[url]
		? { ok: true, status: 200, text: async () => responses[url] }
		: { ok: false, status: 404, text: async () => "" };

	const resolved = await expandWithTransitives(m, {
		includeTestDeps: true, fetcher: f, cacheDir: freshCache(), verbose: false,
	});
	assert.ok(resolved.has(shared), "the shared transitive must be resolved");
	assert.notEqual(resolved.get(shared).isDev, true,
		"reachable from a compile root, so it is a PRODUCTION dep — marking it dev would hide it from the CI gate");
});

test("--ignore-test (includeTestDeps=false) still skips the whole test subtree", async () => {
	const resolved = await expandWithTransitives(seed(), {
		includeTestDeps: false, fetcher, cacheDir: freshCache(), verbose: false,
	});
	assert.ok(!resolved.has("org.springframework.boot:spring-boot"),
		"with --ignore-test nothing under a test root may be scanned");
	assert.ok(resolved.has("com.example:prod-transitive"),
		"but production transitives must still resolve");
});
