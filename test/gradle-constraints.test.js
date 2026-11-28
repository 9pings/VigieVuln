/**
 * Gradle version constraints, forces and excludes (lib/codecs/gradle/*).
 *
 * A `constraints { }` entry and a `resolutionStrategy.force(...)` are VERSION CONSTRAINTS,
 * not dependencies (docs.gradle.org "Dependency constraints", "Customizing resolution"):
 * they apply only when something actually brings that module in. They used to be collected
 * as DIRECT dependencies — `constraints { implementation("org.apache.commons:commons-text:1.10.0") }`
 * came out as a direct `commons-text:1.10.0 [implementation]` carrying its CVEs on a project
 * that may not ship commons-text at all. Same class as the Maven <dependencyManagement>-only
 * bug (test/managed-only.test.js): such a coordinate is now a `managedOnly` record that pins
 * versions and is kept only if the transitive graph reaches it.
 *
 * `exclude(...)` (per dependency and per configuration) used to be dropped, so the excluded
 * transitive was reported anyway. ZERO network (in-memory Maven Central).
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { parseBuildScript } = require("../lib/codecs/gradle/parse");
const gradle = require("../lib/codecs/gradle.codec");
const { expandWithTransitives, settleManagedOnly } = require("../lib/advisories/cve-match");

function tree(files) {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-gradle-"));
	for (const [rel, body] of Object.entries(files)) {
		const fp = path.join(root, rel);
		fs.mkdirSync(path.dirname(fp), { recursive: true });
		fs.writeFileSync(fp, body);
	}
	return root;
}

// ---------------------------------------------------------------------------
// constraints { } / force(...) are not dependencies
// ---------------------------------------------------------------------------

test("parse: a constraints { } entry is a constraint, not a dependency (Kotlin + Groovy)", () => {
	const kts = parseBuildScript(`
dependencies {
    implementation("com.google.guava:guava:32.1.3-jre")
    constraints {
        implementation("org.apache.commons:commons-text:1.10.0") {
            because("CVE-2022-42889")
        }
    }
}
`, { kotlin: true });
	assert.equal(kts.deps.find(d => d.name === "commons-text"), undefined, "constraint must not be a dep");
	assert.ok(kts.deps.find(d => d.name === "guava"), "the real dep is still read");
	const c = kts.constraints.find(x => x.name === "commons-text");
	assert.ok(c, "constraint surfaced separately");
	assert.equal(c.version, "1.10.0");
	assert.equal(c.kind, "constraint");

	const groovy = parseBuildScript(`
dependencies {
    constraints {
        implementation 'org.yaml:snakeyaml:2.2'
        implementation group: 'com.foo', name: 'bar', version: '1.2.3'
    }
}
`, { kotlin: false });
	assert.equal(groovy.deps.length, 0);
	assert.deepEqual(groovy.constraints.map(x => `${x.group}:${x.name}:${x.version}`).sort(), ["com.foo:bar:1.2.3", "org.yaml:snakeyaml:2.2"]);
});

test("parse: resolutionStrategy.force(...) is a force pin, not a dependency", () => {
	const kts = parseBuildScript(`
configurations.all {
    resolutionStrategy {
        force("io.netty:netty-handler:4.1.100.Final")
    }
}
configurations.all { resolutionStrategy.force("com.fasterxml.jackson.core:jackson-databind:2.15.3", "org.yaml:snakeyaml:2.2") }
dependencies { implementation("com.google.guava:guava:32.1.3-jre") }
`, { kotlin: true });
	assert.deepEqual(kts.deps.map(d => d.name), ["guava"]);
	assert.deepEqual(kts.constraints.filter(c => c.kind === "force").map(c => `${c.name}:${c.version}`).sort(),
		["jackson-databind:2.15.3", "netty-handler:4.1.100.Final", "snakeyaml:2.2"]);

	const groovy = parseBuildScript(`
configurations.all {
    resolutionStrategy {
        force 'io.netty:netty-handler:4.1.100.Final', 'org.yaml:snakeyaml:2.2'
    }
}
`, { kotlin: false });
	assert.equal(groovy.deps.length, 0);
	assert.equal(groovy.constraints.length, 2);
});

test("parse: a dependency with force = true / strictly stays a dep AND is a force pin", () => {
	const r = parseBuildScript(`
dependencies {
    implementation("io.netty:netty-codec:4.1.90.Final") { isForce = true }
    implementation("org.slf4j:slf4j-api") { version { strictly("1.7.36") } }
}
`, { kotlin: true });
	assert.ok(r.deps.find(d => d.name === "netty-codec"), "a forced declaration is still a dependency");
	assert.ok(r.constraints.some(c => c.name === "netty-codec" && c.kind === "force" && c.version === "4.1.90.Final"));
	const slf = r.deps.find(d => d.name === "slf4j-api");
	assert.equal(slf.version, "1.7.36", "strictly supplies the version");
	assert.ok(r.constraints.some(c => c.name === "slf4j-api" && c.kind === "force"));
});

test("codec: a constraint-only / force-only coordinate is managedOnly, never a direct dep", async () => {
	const root = tree({
		"build.gradle.kts": `
dependencies {
    implementation("com.google.guava:guava:32.1.3-jre")
    constraints { implementation("org.apache.commons:commons-text:1.10.0") }
}
configurations.all { resolutionStrategy { force("io.netty:netty-handler:4.1.100.Final") } }
`,
	});
	const { deps } = await gradle.collect(root);
	const text = deps.get("org.apache.commons:commons-text");
	assert.ok(text, "the pin is kept (it pins transitive versions)");
	assert.equal(text.managedOnly, true);
	assert.equal(text.version, "1.10.0");
	assert.equal(text.ecosystem, "maven");
	assert.equal(text.ecosystemType, "gradle");
	const netty = deps.get("io.netty:netty-handler");
	assert.equal(netty.managedOnly, true);
	assert.equal(netty.version, "4.1.100.Final");
	assert.equal(deps.get("com.google.guava:guava").managedOnly, undefined);
});

test("codec: constraint on a declared dep → normal direct dep at the highest of declared/constrained", async () => {
	const root = tree({
		"build.gradle.kts": `
dependencies {
    implementation("org.apache.commons:commons-text:1.9")
    implementation("org.yaml:snakeyaml:2.2")
    implementation("org.springframework:spring-core")
    constraints {
        implementation("org.apache.commons:commons-text:1.10.0")
        implementation("org.yaml:snakeyaml:1.33")
        implementation("org.springframework:spring-core:6.1.14")
    }
}
`,
	});
	const { deps } = await gradle.collect(root);
	const text = deps.get("org.apache.commons:commons-text");
	assert.equal(text.managedOnly, undefined, "declared → a real direct dep");
	assert.equal(text.version, "1.10.0", "the constraint upgrades 1.9 (Gradle picks the highest)");
	assert.deepEqual(text.versions, ["1.10.0"], "1.9 is on no classpath — must not be scanned");
	assert.equal(deps.get("org.yaml:snakeyaml").version, "2.2", "a lower constraint does not downgrade");
	assert.equal(deps.get("org.springframework:spring-core").version, "6.1.14", "a constraint supplies a missing version");
});

test("codec: force wins over the declared version (even a downgrade)", async () => {
	const root = tree({
		"build.gradle": `
configurations.all {
    resolutionStrategy.force 'com.fasterxml.jackson.core:jackson-databind:2.15.3'
}
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.17.0'
}
`,
	});
	const { deps } = await gradle.collect(root);
	const j = deps.get("com.fasterxml.jackson.core:jackson-databind");
	assert.equal(j.managedOnly, undefined);
	assert.equal(j.version, "2.15.3");
	assert.deepEqual(j.versions, ["2.15.3"]);
});

test("codec: a subprojects { } force applies to sub-modules; a module-local constraint does not bleed", async () => {
	const root = tree({
		"settings.gradle.kts": `include("a", "b")`,
		"build.gradle.kts": `
subprojects {
    configurations.all { resolutionStrategy.force("org.yaml:snakeyaml:2.2") }
}
`,
		"a/build.gradle.kts": `
dependencies {
    implementation("org.yaml:snakeyaml:1.30")
    implementation("org.apache.commons:commons-text:1.9")
}
`,
		"b/build.gradle.kts": `
dependencies {
    constraints { implementation("org.apache.commons:commons-text:1.10.0") }
}
`,
	});
	const { deps } = await gradle.collect(root);
	assert.deepEqual(deps.get("org.yaml:snakeyaml").versions, ["2.2"], "global force reaches module a");
	assert.deepEqual(deps.get("org.apache.commons:commons-text").versions, ["1.9"], "b's constraint is b's alone");
	assert.equal(deps.get("org.apache.commons:commons-text").managedOnly, undefined);
});

test("pipeline: an unused constraint is never a root and is dropped; a reached one becomes a transitive at the pinned version", async () => {
	const MC = "https://repo1.maven.org/maven2";
	const leaf = (g, a, v) => `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version></project>`;
	const RESPONSES = {
		[`${MC}/com/acme/lib-a/2.0/lib-a-2.0.pom`]: `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
			<groupId>com.acme</groupId><artifactId>lib-a</artifactId><version>2.0</version>
			<dependencies><dependency><groupId>io.netty</groupId><artifactId>netty-handler</artifactId><version>4.1.80.Final</version></dependency></dependencies></project>`,
		[`${MC}/io/netty/netty-handler/4.1.100.Final/netty-handler-4.1.100.Final.pom`]: leaf("io.netty", "netty-handler", "4.1.100.Final"),
		[`${MC}/io/netty/netty-handler/4.1.80.Final/netty-handler-4.1.80.Final.pom`]: leaf("io.netty", "netty-handler", "4.1.80.Final"),
	};
	const requested = [];
	const fetcher = async url => {
		requested.push(String(url));
		return RESPONSES[url] ? { ok: true, status: 200, text: async () => RESPONSES[url] } : { ok: false, status: 404, text: async () => "" };
	};
	const root = tree({
		"build.gradle.kts": `
dependencies {
    implementation("com.acme:lib-a:2.0")
    constraints { implementation("org.apache.commons:commons-text:1.10.0") }
}
configurations.all { resolutionStrategy.force("io.netty:netty-handler:4.1.100.Final") }
`,
	});
	const { deps } = await gradle.collect(root);
	await expandWithTransitives(deps, { fetcher, cacheDir: fs.mkdtempSync(path.join(os.tmpdir(), "fad-gradle-mc-")) });
	assert.ok(!requested.some(u => u.includes("commons-text")), "an unused constraint must not seed the graph");
	const netty = deps.get("io.netty:netty-handler");
	assert.equal(netty.scope, "transitive");
	assert.deepEqual(netty.versions, ["4.1.100.Final"], "the force pins lib-a's 4.1.80");
	assert.equal(netty.ecosystemType, "gradle");
	const { dropped } = settleManagedOnly(deps);
	assert.deepEqual(dropped, ["org.apache.commons:commons-text:1.10.0"]);
	assert.ok(!deps.has("org.apache.commons:commons-text"));
});

// ---------------------------------------------------------------------------
// exclude(...) is carried as exclusionSets
// ---------------------------------------------------------------------------

test("parse: dependency-level exclude (Kotlin named args, Groovy map, positional) → exclusionSets", () => {
	const kts = parseBuildScript(`
dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web:3.2.0") {
        exclude(group = "org.springframework.boot", module = "spring-boot-starter-tomcat")
        exclude(group = "ch.qos.logback")
    }
    implementation("com.acme:lib:1.0") { exclude("org.foo", "bar") }
    implementation("com.acme:plain:1.0")
}
`, { kotlin: true });
	assert.deepEqual(kts.deps.find(d => d.name === "spring-boot-starter-web").exclusionSets,
		[["org.springframework.boot:spring-boot-starter-tomcat", "ch.qos.logback:*"]]);
	assert.deepEqual(kts.deps.find(d => d.name === "lib").exclusionSets, [["org.foo:bar"]]);
	assert.deepEqual(kts.deps.find(d => d.name === "plain").exclusionSets, [[]], "one (empty) set per declaration");

	const groovy = parseBuildScript(`
dependencies {
    implementation('org.apache.poi:poi-ooxml:5.2.3') {
        exclude group: 'org.apache.commons', module: 'commons-compress'
        exclude module: 'xmlbeans'
    }
}
`, { kotlin: false });
	assert.deepEqual(groovy.deps[0].exclusionSets, [["org.apache.commons:commons-compress", "*:xmlbeans"]]);
});

test("parse: configuration-level excludes apply per configuration; file/task excludes are ignored", () => {
	const r = parseBuildScript(`
configurations.all {
    exclude(group = "commons-logging", module = "commons-logging")
}
configurations {
    implementation { exclude group: 'log4j', module: 'log4j' }
    testImplementation { exclude(module = "hamcrest-core") }
}
configurations.runtimeClasspath { exclude(group = "org.slf4j", module = "slf4j-simple") }
tasks.jar { exclude("META-INF/*.SF") }
sourceSets { main { java { exclude '**/Generated*.java' } } }
dependencies {
    implementation("com.acme:app-lib:1.0")
    testImplementation("junit:junit:4.13.2")
}
`, { kotlin: true });
	const app = r.deps.find(d => d.name === "app-lib");
	assert.deepEqual(app.exclusionSets, [["commons-logging:commons-logging", "log4j:log4j", "org.slf4j:slf4j-simple"]]);
	const junit = r.deps.find(d => d.name === "junit");
	// testRuntimeClasspath extends testImplementation extends implementation → it inherits
	// all/implementation excludes, but not runtimeClasspath's.
	assert.deepEqual(junit.exclusionSets, [["commons-logging:commons-logging", "log4j:log4j", "*:hamcrest-core"]]);
});

test("codec: a subprojects { configurations.all { exclude } } reaches sub-module declarations", async () => {
	const root = tree({
		"build.gradle": `
subprojects {
    configurations.all { exclude group: 'commons-logging', module: 'commons-logging' }
}
`,
		"a/build.gradle": `
dependencies { implementation 'org.apache.httpcomponents:httpclient:4.5.13' }
`,
	});
	const { deps } = await gradle.collect(root);
	assert.deepEqual(deps.get("org.apache.httpcomponents:httpclient").exclusionSets, [["commons-logging:commons-logging"]]);
});

test("pipeline: a Gradle exclude prunes the transitive", async () => {
	const MC = "https://repo1.maven.org/maven2";
	const RESPONSES = {
		[`${MC}/com/acme/lib-a/2.0/lib-a-2.0.pom`]: `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
			<groupId>com.acme</groupId><artifactId>lib-a</artifactId><version>2.0</version>
			<dependencies><dependency><groupId>log4j</groupId><artifactId>log4j</artifactId><version>1.2.17</version></dependency></dependencies></project>`,
	};
	const fetcher = async url => RESPONSES[url] ? { ok: true, status: 200, text: async () => RESPONSES[url] } : { ok: false, status: 404, text: async () => "" };
	const root = tree({
		"build.gradle.kts": `
dependencies {
    implementation("com.acme:lib-a:2.0") { exclude(group = "log4j", module = "log4j") }
}
`,
	});
	const { deps } = await gradle.collect(root);
	await expandWithTransitives(deps, { fetcher, cacheDir: fs.mkdtempSync(path.join(os.tmpdir(), "fad-gradle-mc-")) });
	assert.ok(!deps.has("log4j:log4j"), "the excluded log4j 1.x must not be reported");
});

// ---------------------------------------------------------------------------
// widest scope wins
// ---------------------------------------------------------------------------

test("parse: testImplementation listed before implementation → production scope wins", () => {
	const r = parseBuildScript(`
dependencies {
    testImplementation("com.google.guava:guava:32.1.3-jre")
    implementation("com.google.guava:guava:32.1.3-jre")
}
`, { kotlin: true });
	const g = r.deps.filter(d => d.name === "guava");
	assert.equal(g.length, 1);
	assert.equal(g[0].isDev, false);
	assert.equal(g[0].scope, "compile");
	assert.equal(g[0].configuration, "implementation");
	assert.equal(g[0].exclusionSets.length, 2, "one exclusion set per declaration");
});

test("codec: a test-scoped declaration in one module and a prod one in another → compile scope", async () => {
	const root = tree({
		// The walk is a stack: the last directory listed is visited first, so "z" (test
		// scope) is merged BEFORE "a" (production) — the order that used to keep "test".
		"a/build.gradle.kts": `dependencies { implementation("com.google.guava:guava:32.1.3-jre") }`,
		"z/build.gradle.kts": `dependencies { testImplementation("com.google.guava:guava:32.1.3-jre") }`,
	});
	const { deps } = await gradle.collect(root);
	const g = deps.get("com.google.guava:guava");
	assert.equal(g.isDev, false);
	assert.equal(g.scope, "compile", "scope must follow isDev — prod wins");
});

// ---------------------------------------------------------------------------
// gradle.lockfile stays authoritative
// ---------------------------------------------------------------------------

test("codec: a lock-governed build script contributes no constraint/force records (lockfile already applied them)", async () => {
	const root = tree({
		"gradle.lockfile": "com.google.guava:guava:32.1.3-jre=compileClasspath,runtimeClasspath\nempty=\n",
		"build.gradle.kts": `
dependencies {
    implementation("com.google.guava:guava:32.0.0-jre")
    constraints { implementation("org.apache.commons:commons-text:1.10.0") }
}
configurations.all { resolutionStrategy.force("com.google.guava:guava:31.0-jre") }
`,
	});
	const { deps } = await gradle.collect(root);
	assert.deepEqual(deps.get("com.google.guava:guava").versions, ["32.1.3-jre"], "lockfile versions untouched");
	assert.ok(!deps.has("org.apache.commons:commons-text"), "no constraint record next to a lockfile");
});

// ---------------------------------------------------------------------------
// Follow-ups: a constraint is a FLOOR, a lockfile is not a set of roots, -e is a groupId
// ---------------------------------------------------------------------------

const MC2 = "https://repo1.maven.org/maven2";
const leafPom = (g, a, v, deps = "") => `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version>${deps}</project>`;
function memFetcher(R, log = []) {
	return async url => { log.push(String(url)); return R[url] ? { ok: true, status: 200, text: async () => R[url] } : { ok: false, status: 404, text: async () => "" }; };
}

test("pipeline: a constraint BELOW the requested transitive version does not downgrade it (Gradle keeps the higher)", async () => {
	const R = {
		[`${MC2}/com/acme/lib-a/2.0/lib-a-2.0.pom`]: leafPom("com.acme", "lib-a", "2.0", `<dependencies><dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>2.2</version></dependency></dependencies>`),
		[`${MC2}/org/yaml/snakeyaml/2.2/snakeyaml-2.2.pom`]: leafPom("org.yaml", "snakeyaml", "2.2"),
		[`${MC2}/org/yaml/snakeyaml/2.0/snakeyaml-2.0.pom`]: leafPom("org.yaml", "snakeyaml", "2.0"),
	};
	const root = tree({ "build.gradle.kts": `dependencies {\n    implementation("com.acme:lib-a:2.0")\n    constraints { implementation("org.yaml:snakeyaml:2.0") }\n}\n` });
	const { deps } = await gradle.collect(root);
	await expandWithTransitives(deps, { fetcher: memFetcher(R), cacheDir: fs.mkdtempSync(path.join(os.tmpdir(), "fad-gradle-mc-")) });
	assert.deepEqual(deps.get("org.yaml:snakeyaml").versions, ["2.2"]);
});

test("pipeline: gradle.lockfile entries are not re-walked as resolution roots", async () => {
	const log = [];
	const root = tree({ "build.gradle": "dependencies { implementation 'com.acme:lib-a:2.0' }\n", "gradle.lockfile": "com.acme:lib-a:2.0=runtimeClasspath\nempty=\n" });
	const { deps } = await gradle.collect(root);
	await expandWithTransitives(deps, { fetcher: memFetcher({}, log), cacheDir: fs.mkdtempSync(path.join(os.tmpdir(), "fad-gradle-mc-")) });
	assert.ok(deps.has("com.acme:lib-a"));
	assert.deepEqual(log, [], "the lockfile already IS the resolved graph");
});

test("codec: -e excludes by groupId (as the Maven collector does), not by artifact name", async () => {
	const root = tree({ "build.gradle": "dependencies {\n implementation 'com.private:core:1.0'\n implementation 'org.public:private-looking:1.0'\n}\n" });
	const { deps } = await gradle.collect(root, { deps2Exclude: /^com\.private/ });
	assert.ok(!deps.has("com.private:core"));
	assert.ok(deps.has("org.public:private-looking"));
});
