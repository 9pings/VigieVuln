const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { parseBuildScript } = require("../lib/codecs/gradle/parse");
const { parseVersionCatalog } = require("../lib/codecs/gradle/catalog");
const gradle = require("../lib/codecs/gradle.codec");
const { resolveBomManagedVersions, backfillVersions } = require("../lib/maven-bom");

const boot = 'id("org.springframework.boot") version "4.1.1"';
const management = 'id("io.spring.dependency-management") version "1.1.7"';
const expectedBom = { group: "org.springframework.boot", name: "spring-boot-dependencies", version: "4.1.1", inferred: true };

test("real-world single-script Spring Boot fixture supplies a scoped implicit BOM", async () => {
	const root = path.join(__dirname, "fixtures", "gradle-spring-boot-implicit");
	const { deps, _gradle } = await gradle.collect(root);
	assert.deepEqual(_gradle.platformBoms, [{ ...expectedBom, manifestPath: path.join(root, "build.gradle.kts") }]);
	assert.equal(deps.get("org.apache.tika:tika-core").version, "4.1.0");
	assert.equal(deps.get("org.postgresql:postgresql").version, null);
});

test("implicit plugin BOMs never leak between Gradle scripts or collapse two Boot versions", async t => {
	for (const secondPlugins of ["", `plugins { ${boot.replace("4.1.1", "3.5.0")}; ${management} }`]) {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-gradle-boot-scope-"));
		t.after(() => fs.rmSync(root, { recursive: true, force: true }));
		for (const [dir, plugins] of [["a", `plugins { ${boot}; ${management} }`], ["b", secondPlugins]]) {
			fs.mkdirSync(path.join(root, dir));
			fs.writeFileSync(path.join(root, dir, "build.gradle.kts"), `${plugins}\ndependencies { implementation("org.postgresql:postgresql") }`);
		}
		const result = await gradle.collect(root);
		assert.deepEqual(result._gradle.platformBoms, []);
		assert.equal(result.deps.get("org.postgresql:postgresql").version, null);
		assert.ok(result.warnings.some(w => w.type === "dependency-coverage" && /multiple Gradle scripts/.test(w.message)));
	}
});

test("a scoped plugin BOM cannot backfill Maven or another Gradle module", async () => {
	const { makeDepRecord } = require("../lib/dep-record");
	const records = new Map();
	for (const [id, type, manifest] of [["a", "gradle", "/a/build.gradle.kts"], ["b", "gradle", "/b/build.gradle.kts"], ["maven", "maven", "/pom.xml"]]) {
		records.set(id, makeDepRecord({ ecosystem: "maven", ecosystemType: type, namespace: "org.postgresql", name: "postgresql", manifestPath: manifest }));
	}
	const mgmt = await resolveBomManagedVersions([{ groupId: "org.springframework.boot", artifactId: "spring-boot-dependencies", version: "4.1.1", manifestPath: "/a/build.gradle.kts" }], {
		effectivePom: async () => ({ depMgmt: [{ groupId: "org.postgresql", artifactId: "postgresql", version: "42.7.8" }] }),
	});
	assert.equal(backfillVersions(records, mgmt), 1);
	assert.equal(records.get("a").version, "42.7.8");
	assert.equal(records.get("b").version, null);
	assert.equal(records.get("maven").version, null);
});

test("Spring Boot plugins import the matching BOM in Kotlin and Groovy", () => {
	for (const plugins of [
		`${boot}\n${management}`,
		`${management}; ${boot}`,
		`id 'org.springframework.boot' version '4.1.1'\nid 'io.spring.dependency-management' version '1.1.7'`,
		`id("org.springframework.boot").version("4.1.1")\n${management}`,
	]) {
		const result = parseBuildScript(`plugins { ${plugins} }\ndependencies { implementation("org.springframework.boot:spring-boot-starter-jdbc") }`);
		assert.deepEqual(result.platformBoms, [expectedBom]);
		assert.equal(result.deps.length, 1);
		assert.equal(result.deps[0].version, null, "versions still come from the fetched BOM, not the plugin version directly");
	}
});

test("Spring Boot plugin versions can come from properties or catalog plugin aliases", () => {
	const properties = { bootVersion: "4.1.1" };
	assert.deepEqual(parseBuildScript(`plugins { id("org.springframework.boot") version "\${bootVersion}"; ${management} }`, { properties }).platformBoms, [expectedBom]);
	assert.deepEqual(parseBuildScript(`plugins { id("org.springframework.boot") version "4.\${patch}"; ${management} }`, { properties: { patch: "1" } }).platformBoms, []);
	assert.deepEqual(parseBuildScript(`plugins { id("org.springframework.boot") version "$bootVersion"; ${management} }`, { properties: { bootVersion: "4.+" } }).platformBoms, []);
	const catalog = parseVersionCatalog(`
[versions]
boot = "4.1.1"
[plugins]
spring-boot = { id = "org.springframework.boot", version.ref = "boot" }
spring-management = { id = "io.spring.dependency-management", version = "1.1.7" }
`);
	assert.deepEqual(parseBuildScript(`plugins { alias(libs.plugins.spring.boot); alias(libs.plugins.spring.management) }`, { catalog }).platformBoms, [expectedBom]);
	assert.deepEqual(parseBuildScript(`plugins { alias(libs.plugins.spring.boot) apply false; alias(libs.plugins.spring.management) }`, { catalog }).platformBoms, []);
});

test("Spring Boot BOM inference requires both plugins applied with a concrete version", () => {
	for (const source of [
		`plugins { ${boot} }`,
		`plugins { ${management} }`,
		`plugins { ${boot} apply false; ${management} }`,
		`plugins { ${boot}\napply(false)\n${management} }`,
		`plugins { ${boot}; ${management} apply false }`,
		`plugins { id("org.springframework.boot"); ${management} }`,
		`plugins { id("org.springframework.boot") version "$missing"; ${management} }`,
		`plugins { id("org.springframework.boot") version "4.+"; ${management} }`,
		`plugins { id("org.springframework.boot") version "latest.release"; ${management} }`,
		`pluginManagement { plugins { ${boot}; ${management} } }`,
		`/* plugins { ${boot}; ${management} } */`,
		`val example = """plugins { ${boot}; ${management} }"""`,
		`plugins { ${boot}\n// ${management}\n }`,
		`plugins { ${boot}; val example = """${management}""" }`,
	]) assert.deepEqual(parseBuildScript(source).platformBoms, [], source);
});

test("Spring Boot automatic BOM does not duplicate or replace an explicit platform", () => {
	const result = parseBuildScript(`plugins { ${boot}; ${management} }
dependencies { implementation(platform("org.springframework.boot:spring-boot-dependencies:4.1.2")) }`);
	assert.deepEqual(result.platformBoms, [{ group: "org.springframework.boot", name: "spring-boot-dependencies", version: "4.1.2" }]);
	assert.equal(result.deps.length, 0);
});

test("Spring Boot collector feeds BOM backfill, preserves pins, test scopes and lockfile versions", async t => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-gradle-boot-"));
	t.after(() => fs.rmSync(root, { recursive: true, force: true }));
	fs.mkdirSync(path.join(root, "gradle"));
	fs.writeFileSync(path.join(root, "gradle", "libs.versions.toml"), '[versions]\ntika = "4.1.0"\n');
	fs.writeFileSync(path.join(root, "build.gradle.kts"), `plugins { ${boot}; ${management} }
dependencies {
 implementation("org.springframework.boot:spring-boot-starter-jdbc")
 implementation("org.postgresql:postgresql")
 implementation("org.apache.tika:tika-core:\${libs.findVersion("tika").get()}")
 testImplementation("org.springframework.boot:spring-boot-starter-test")
 implementation("example:unmanaged")
}`);
	const { deps, _gradle } = await gradle.collect(root);
	assert.deepEqual(_gradle.platformBoms, [{ ...expectedBom, manifestPath: path.join(root, "build.gradle.kts") }]);
	let calls = 0;
	const managed = await resolveBomManagedVersions(_gradle.platformBoms.map(b => ({ groupId: b.group, artifactId: b.name, version: b.version })), {
		effectivePom: async (group, name, version) => {
			calls++;
			assert.equal(`${group}:${name}:${version}`, "org.springframework.boot:spring-boot-dependencies:4.1.1");
			// Controlled BOM data: test wiring without depending on a live repository.
			return { depMgmt: [
				{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-jdbc", version: "4.1.1" },
				{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-test", version: "4.1.1" },
				{ groupId: "org.postgresql", artifactId: "postgresql", version: "42.7.8" },
				{ groupId: "org.apache.tika", artifactId: "tika-core", version: "3.2.3" },
			] };
		},
	});
	assert.equal(calls, 1);
	assert.equal(backfillVersions(deps, managed), 3);
	assert.equal(deps.get("org.springframework.boot:spring-boot-starter-jdbc").version, "4.1.1");
	assert.equal(deps.get("org.postgresql:postgresql").version, "42.7.8");
	assert.deepEqual(deps.get("org.postgresql:postgresql").versionSource, { via: "bom", bom: "org.springframework.boot:spring-boot-dependencies:4.1.1" });
	assert.equal(deps.get("org.springframework.boot:spring-boot-starter-test").isDev, true);
	assert.equal(deps.get("org.apache.tika:tika-core").version, "4.1.0");
	assert.equal(deps.get("example:unmanaged").version, null);
	assert.ok(!deps.has("org.springframework.boot:spring-boot-dependencies"));
	fs.writeFileSync(path.join(root, "gradle.lockfile"), "org.postgresql:postgresql:42.7.7=runtimeClasspath\n");
	const locked = await gradle.collect(root);
	assert.equal(backfillVersions(locked.deps, managed), 0);
	assert.equal(locked.deps.size, 1);
	assert.equal(locked.deps.get("org.postgresql:postgresql").version, "42.7.7");
});
