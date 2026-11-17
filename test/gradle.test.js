const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const {
	parseVersionCatalog,
	resolveLibraryAccessor,
	findCatalogVersion,
} = require("../lib/codecs/gradle/catalog");
const {
	parseGradleLockfile,
	parseGradleProperties,
	parseBuildScript,
} = require("../lib/codecs/gradle/parse");

test("Groovy top-level ext literals resolve dependencies without guessing mutable values", () => {
	const result = parseBuildScript(`
ext {
  guiceVersion = "7.0.0"
  jettyVersion = '11.0.24' // comment
  changing = "1.0"
  dynamic = "2.$missing"
  computed = "1.0" + suffix
}
if (condition) { changing = "2.0" }
tasks.register("fixture") { localOnly = "3.0" }
dependencies {
 implementation "example:guice:$guiceVersion"
 implementation "example:jetty:$jettyVersion"
 implementation "example:changing:$changing"
 implementation "example:dynamic:$dynamic"
 implementation "example:computed:$computed"
 implementation "example:local:$localOnly"
 implementation "example:composite:4.$guiceVersion"
}`);
	const versions = Object.fromEntries(result.deps.map(d => [d.name, d.version]));
	assert.deepEqual(versions, { guice: "7.0.0", jetty: "11.0.24", changing: null, dynamic: null, computed: null, local: null, composite: null });
});

test("nested ext blocks, comments and strings cannot supply project ext versions", () => {
	const result = parseBuildScript(`
// ext { aVersion = "1.0" }
def text = 'ext { bVersion = "1.0" }'
subprojects { ext { cVersion = "1.0" } }
ext { dVersion = "1.0" }
project.ext.dVersion = provider.get()
dependencies { implementation "example:a:$aVersion"; implementation "example:b:$bVersion"; implementation "example:c:$cVersion"; implementation "example:d:$dVersion" }
`);
	assert.deepEqual(result.deps.map(d => d.version), [null, null, null, null]);
});

test("Groovy ext mutations through operators or computed property writes remain unknown", () => {
	for (const mutation of ["version++", "++version", "--version", "++project.ext.version", "version %= 2", "version <<= 1", "version >>= 1", "version >>>= 1", "version &= 1", "version |= 1", "version ^= 1", "version **= 2", "project.ext.version += '.1'", "ext.set('version', provider.get())", "ext[provider.get()] = '2.0'"]) {
		const result = parseBuildScript(`ext { version = "1.0" }\n${mutation}\ndependencies { implementation "example:library:$version" }`);
		assert.equal(result.deps[0].version, null, mutation);
	}
	const relative = parseBuildScript('ext { version += "1.0" }\ndependencies { implementation "example:library:$version" }');
	assert.equal(relative.deps[0].version, null);
});

// ---------------------------------------------------------------------------
// Version catalog (gradle/libs.versions.toml)
// ---------------------------------------------------------------------------

test("parseVersionCatalog reads [versions] and [libraries] with version.ref", () => {
	const cat = parseVersionCatalog(`
[versions]
spring-boot = "4.0.6"
commons-codec = "1.21.0"

[libraries]
commons-codec = { module = "commons-codec:commons-codec", version.ref = "commons-codec" }
`);
	assert.equal(cat.versions["spring-boot"], "4.0.6");
	const lib = cat.libraries["commons-codec"];
	assert.equal(lib.group, "commons-codec");
	assert.equal(lib.name, "commons-codec");
	assert.equal(lib.version, "1.21.0"); // resolved from version.ref
});

test("parseVersionCatalog reads inline version and group/name form", () => {
	const cat = parseVersionCatalog(`
[libraries]
picocli = { module = "info.picocli:picocli", version = "4.7.6" }
guava = { group = "com.google.guava", name = "guava", version = "33.0.0-jre" }
`);
	assert.equal(cat.libraries.picocli.version, "4.7.6");
	assert.equal(cat.libraries.picocli.group, "info.picocli");
	assert.equal(cat.libraries.guava.group, "com.google.guava");
	assert.equal(cat.libraries.guava.name, "guava");
	assert.equal(cat.libraries.guava.version, "33.0.0-jre");
});

test("parseVersionCatalog handles a library with no resolvable version (returns null version)", () => {
	const cat = parseVersionCatalog(`
[libraries]
managed = { module = "org.springframework.boot:spring-boot-starter-web" }
`);
	assert.equal(cat.libraries.managed.group, "org.springframework.boot");
	assert.equal(cat.libraries.managed.name, "spring-boot-starter-web");
	assert.equal(cat.libraries.managed.version, null);
});

test("resolveLibraryAccessor maps dotted accessor to kebab alias", () => {
	const cat = parseVersionCatalog(`
[versions]
clamav = "2.1.2"
[libraries]
clamav-client = { module = "xyz.capybara:clamav-client", version.ref = "clamav" }
`);
	// build.gradle.kts: implementation(libs.clamav.client)
	const lib = resolveLibraryAccessor(cat, "clamav.client");
	assert.equal(lib.group, "xyz.capybara");
	assert.equal(lib.name, "clamav-client");
	assert.equal(lib.version, "2.1.2");
});

test("resolveLibraryAccessor returns null for an unknown accessor", () => {
	const cat = parseVersionCatalog(`[libraries]\nfoo = { module = "a:b", version = "1" }\n`);
	assert.equal(resolveLibraryAccessor(cat, "does.not.exist"), null);
});

test("findCatalogVersion resolves a version alias (libs.findVersion)", () => {
	const cat = parseVersionCatalog(`[versions]\nspring-boot = "4.0.6"\n`);
	assert.equal(findCatalogVersion(cat, "spring-boot"), "4.0.6");
	assert.equal(findCatalogVersion(cat, "nope"), null);
});

// ---------------------------------------------------------------------------
// gradle.lockfile (authoritative when present)
// ---------------------------------------------------------------------------

test("parseGradleLockfile reads g:a:v=configs, ignores comments and empty=", () => {
	const { deps } = parseGradleLockfile(`# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
com.google.guava:guava:32.1.3-jre=compileClasspath,runtimeClasspath
org.junit.jupiter:junit-jupiter:5.10.0=testCompileClasspath,testRuntimeClasspath
empty=annotationProcessor
`);
	assert.equal(deps.length, 2);
	const guava = deps.find(d => d.name === "guava");
	assert.equal(guava.group, "com.google.guava");
	assert.equal(guava.version, "32.1.3-jre");
	assert.equal(guava.isDev, false);
	const junit = deps.find(d => d.name === "junit-jupiter");
	assert.equal(junit.isDev, true); // only test* configurations
});

// ---------------------------------------------------------------------------
// gradle.properties
// ---------------------------------------------------------------------------

test("parseGradleProperties reads key=value, skips comments/blanks", () => {
	const p = parseGradleProperties(`# comment
group=fr.gouv.diplomatie.promoliv
version=1.4.0

guavaVersion = 32.1.3-jre
`);
	assert.equal(p.group, "fr.gouv.diplomatie.promoliv");
	assert.equal(p.version, "1.4.0");
	assert.equal(p.guavaVersion, "32.1.3-jre");
});

// ---------------------------------------------------------------------------
// build.gradle / build.gradle.kts DSL (best-effort)
// ---------------------------------------------------------------------------

test("parseBuildScript (Kotlin) reads string-notation deps with and without version", () => {
	const { deps } = parseBuildScript(`
dependencies {
    implementation("com.google.guava:guava:32.1.3-jre")
    implementation("org.springframework.boot:spring-boot-starter-web")
}
`, { kotlin: true });
	const guava = deps.find(d => d.name === "guava");
	assert.equal(guava.group, "com.google.guava");
	assert.equal(guava.version, "32.1.3-jre");
	assert.equal(guava.isDev, false);
	const web = deps.find(d => d.name === "spring-boot-starter-web");
	assert.equal(web.version, null); // BOM-managed → version unresolved (not assumed vulnerable)
});

test("parseBuildScript (Groovy) reads single-quote string notation", () => {
	const { deps } = parseBuildScript(`
dependencies {
    implementation 'org.apache.commons:commons-lang3:3.14.0'
}
`, { kotlin: false });
	const d = deps.find(x => x.name === "commons-lang3");
	assert.equal(d.group, "org.apache.commons");
	assert.equal(d.version, "3.14.0");
});

test("parseBuildScript reads map notation (Groovy)", () => {
	const { deps } = parseBuildScript(`
dependencies {
    implementation group: 'com.foo', name: 'bar', version: '1.2.3'
}
`, { kotlin: false });
	const d = deps.find(x => x.name === "bar");
	assert.equal(d.group, "com.foo");
	assert.equal(d.version, "1.2.3");
});

test("parseBuildScript resolves catalog accessor libs.foo.bar", () => {
	const cat = parseVersionCatalog(`
[versions]
clamav = "2.1.2"
[libraries]
clamav-client = { module = "xyz.capybara:clamav-client", version.ref = "clamav" }
`);
	const { deps } = parseBuildScript(`
dependencies {
    implementation(libs.clamav.client)
}
`, { kotlin: true, catalog: cat });
	const d = deps.find(x => x.name === "clamav-client");
	assert.equal(d.group, "xyz.capybara");
	assert.equal(d.version, "2.1.2");
});

test("parseBuildScript resolves $var version from properties and local val", () => {
	const { deps } = parseBuildScript(`
val lombokVersion = "1.18.30"
dependencies {
    implementation("org.projectlombok:lombok:$lombokVersion")
    implementation("com.foo:bar:\${barVersion}")
}
`, { kotlin: true, properties: { barVersion: "9.9.9" } });
	assert.equal(deps.find(d => d.name === "lombok").version, "1.18.30");
	assert.equal(deps.find(d => d.name === "bar").version, "9.9.9");
});

test("parseBuildScript resolves a catalog findVersion embedded in a string coord (nested quotes)", () => {
	const cat = parseVersionCatalog(`[versions]\nmapstruct = "1.6.3"\n`);
	const { deps } = parseBuildScript(`
dependencies {
    annotationProcessor("org.mapstruct:mapstruct-processor:\${libs.findVersion("mapstruct").get()}")
}
`, { kotlin: true, catalog: cat });
	const d = deps.find(x => x.name === "mapstruct-processor");
	assert.ok(d, "mapstruct-processor parsed despite nested quotes in the version template");
	assert.equal(d.group, "org.mapstruct");
	assert.equal(d.version, "1.6.3");
});

test("parseBuildScript marks test configurations as dev", () => {
	const { deps } = parseBuildScript(`
dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    intTestImplementation("org.assertj:assertj-core:3.25.0")
}
`, { kotlin: true });
	assert.equal(deps.find(d => d.name === "junit-jupiter").isDev, true);
	assert.equal(deps.find(d => d.name === "assertj-core").isDev, true); // contains "Test"
});

test("parseBuildScript extracts platform() BOMs separately, not as normal deps", () => {
	const cat = parseVersionCatalog(`[versions]\nspring-boot = "4.0.6"\n`);
	const r = parseBuildScript(`
dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:\${libs.findVersion("spring-boot").get()}"))
    implementation("org.springframework.boot:spring-boot-starter-web")
}
`, { kotlin: true, catalog: cat });
	assert.equal(r.platformBoms.length, 1);
	assert.equal(r.platformBoms[0].group, "org.springframework.boot");
	assert.equal(r.platformBoms[0].name, "spring-boot-dependencies");
	assert.equal(r.platformBoms[0].version, "4.0.6"); // resolved via catalog findVersion
	// the platform line must NOT also appear as a normal dependency
	assert.equal(r.deps.find(d => d.name === "spring-boot-dependencies"), undefined);
});

test("parseBuildScript ignores plugin ids and project() deps", () => {
	const { deps } = parseBuildScript(`
plugins {
    id("org.springframework.boot")
    kotlin("jvm")
}
dependencies {
    implementation(project(":shared"))
    implementation("real.group:real-artifact:1.0.0")
}
`, { kotlin: true });
	assert.equal(deps.length, 1);
	assert.equal(deps[0].name, "real-artifact");
});

// ---------------------------------------------------------------------------
// gradle codec (collect over fixtures)
// ---------------------------------------------------------------------------

const gradle = require("../lib/codecs/gradle.codec");

test("gradle codec detects + collects the kotlin-catalog fixture", async () => {
	const root = path.join(__dirname, "fixtures", "gradle-kotlin-catalog");
	assert.equal(gradle.detect(root), true);
	const { deps, warnings, _gradle } = await gradle.collect(root);

	const clam = deps.get("xyz.capybara:clamav-client");
	assert.ok(clam, "clamav-client resolved via catalog");
	assert.equal(clam.version, "2.1.2");
	assert.equal(clam.ecosystem, "maven");      // Maven keyspace + services
	assert.equal(clam.ecosystemType, "gradle"); // dedicated report chapter/recipe
	assert.equal(clam.isDev, false);

	assert.equal(deps.get("commons-codec:commons-codec").version, "1.21.0");

	const web = deps.get("org.springframework.boot:spring-boot-starter-web");
	assert.ok(web, "BOM-managed starter present");
	assert.equal(web.version, null); // version comes from the platform() BOM, backfilled later

	assert.equal(deps.get("org.springframework.boot:spring-boot-starter-test").isDev, true);

	assert.ok(_gradle.platformBoms.some(b =>
		b.group === "org.springframework.boot" && b.name === "spring-boot-dependencies" && b.version === "4.0.6"),
		"platform() BOM surfaced with catalog-resolved version");

	const warning = warnings.find(w => w.type === "no-lockfile");
	assert.ok(warning, "best-effort warning emitted");
	assert.match(warning.message, /POM-based transitive resolution can choose different versions than Gradle/);
	assert.match(warning.message, /incorrect alerts and omissions/);
	assert.match(warning.message, /dependency locking/);
});

test("gradle codec: lockfile is authoritative when present", async () => {
	const root = path.join(__dirname, "fixtures", "gradle-groovy-lockfile");
	const { deps, warnings } = await gradle.collect(root);
	assert.equal(deps.get("com.google.guava:guava").version, "32.1.3-jre");
	assert.equal(deps.get("org.apache.commons:commons-lang3").version, "3.14.0");
	assert.equal(deps.get("junit:junit").isDev, true);
	assert.ok(!warnings.some(w => w.type === "no-lockfile"), "lockfile present → no best-effort warning");
});

test("gradle coord helpers use the bare Maven g:a keyspace", () => {
	const d = { ecosystem: "maven", ecosystemType: "gradle", namespace: "com.google.guava", name: "guava", version: "32" };
	assert.equal(gradle.coordKey(d), "com.google.guava:guava");
	assert.equal(gradle.formatCoord(d), "com.google.guava:guava");
	assert.equal(gradle.osvPackageName(d), "com.google.guava:guava");
	assert.equal(gradle.osvEcosystem, "Maven");
});

test("gradle + maven coexist on a hybrid project without keyspace collision", async () => {
	const root = path.join(__dirname, "fixtures", "gradle-hybrid");
	const maven = require("../lib/codecs/maven.codec");
	assert.equal(gradle.detect(root), true);
	assert.equal(maven.detect(root), true);
	const { deps } = await gradle.collect(root);
	assert.ok(deps.get("com.google.guava:guava"), "gradle's build.gradle dep");
	assert.ok(!deps.get("org.apache.commons:commons-lang3"), "the pom.xml dep is not the gradle codec's job");
});

// ---------------------------------------------------------------------------
// Regression: real-world edge cases from promoliv-batch
// ---------------------------------------------------------------------------

test("parseBuildScript ignores non-coordinate string args (jvmArgs(\"-Xshare:off\"))", () => {
	const { deps } = parseBuildScript(`
testTask {
    jvmArgs("-Xshare:off")
}
dependencies {
    implementation("real.group:artifact:1.0.0")
}
`, { kotlin: true });
	assert.equal(deps.find(d => d.name === "off"), undefined, "'off' is not a dependency");
	assert.ok(!deps.some(d => d.group === "-Xshare"), "a group never starts with '-'");
	assert.equal(deps.length, 1);
	assert.equal(deps[0].name, "artifact");
});

const { inheritEcoType } = require("../lib/cve-match");

test("transitive ecosystemType inherits 'gradle' when all reaching roots are gradle", () => {
	const roots = new Map([["g:gradleRoot", "gradle"], ["g:mavenRoot", "maven"]]);
	assert.equal(inheritEcoType([["g:gradleRoot", "g:mid"]], roots), "gradle");
	assert.equal(inheritEcoType([["g:mavenRoot"]], roots), "maven");
	// mixed roots (hybrid project, shared transitive) → keep maven
	assert.equal(inheritEcoType([["g:gradleRoot"], ["g:mavenRoot"]], roots), "maven");
	// unknown / missing root → maven default
	assert.equal(inheritEcoType([["g:unknown"]], roots), "maven");
	assert.equal(inheritEcoType([], roots), "maven");
});
