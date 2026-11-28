/**
 * Maven mediation rules the transitive resolver must honour — each one, when missed,
 * put a jar on a "production classpath" that `mvn dependency:tree` does not have, and
 * scanned it for CVEs. Measured on a real reactor against `mvn dependency:tree` + Snyk.
 * ZERO network: in-memory Maven Central.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { resolveTransitiveDeps } = require("../lib/codecs/maven/transitive");
const { expandWithTransitives, commonExclusions } = require("../lib/advisories/cve-match");
const { makeDepRecord } = require("../lib/inventory/dep-record");

const MC = "https://repo1.maven.org/maven2";
const url = (g, a, v) => `${MC}/${g.replace(/\./g, "/")}/${a}/${v}/${a}-${v}.pom`;
const pom = (g, a, v, body = "") => `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version>${body}</project>`;
const dep = (g, a, v, extra = "") => `<dependency><groupId>${g}</groupId><artifactId>${a}</artifactId>${v ? `<version>${v}</version>` : ""}${extra}</dependency>`;
const R = {
	// lib declares logback BARE; its parent manages it at <scope>test</scope> (uadetector shape).
	[url("x", "parent", "1")]: pom("x", "parent", "1", `<packaging>pom</packaging><dependencyManagement><dependencies>${dep("ch.qos.logback", "logback-classic", "1.1.2", "<scope>test</scope>")}</dependencies></dependencyManagement>`),
	[url("x", "lib", "1")]: pom("x", "lib", "1", `<parent><groupId>x</groupId><artifactId>parent</artifactId><version>1</version></parent><dependencies>${dep("ch.qos.logback", "logback-classic", "")}${dep("x", "util", "1")}</dependencies>`),
	[url("x", "util", "1")]: pom("x", "util", "1"),
	[url("ch.qos.logback", "logback-classic", "1.1.2")]: pom("ch.qos.logback", "logback-classic", "1.1.2"),
	// less4j pulls gson + protobuf; the project's depMgmt excludes both.
	[url("com.github.sommeri", "less4j", "1.17.2")]: pom("com.github.sommeri", "less4j", "1.17.2", `<dependencies>${dep("com.google.code.gson", "gson", "2.5")}${dep("com.google.protobuf", "protobuf-java", "2.5.0")}</dependencies>`),
	[url("com.google.code.gson", "gson", "2.5")]: pom("com.google.code.gson", "gson", "2.5"),
	[url("com.google.protobuf", "protobuf-java", "2.5.0")]: pom("com.google.protobuf", "protobuf-java", "2.5.0"),
	// reactor-netty declares netty 4.1.135; the project imports netty-bom 4.1.137.
	[url("io.projectreactor.netty", "reactor-netty-http", "1.2.18")]: pom("io.projectreactor.netty", "reactor-netty-http", "1.2.18", `<dependencies>${dep("io.netty", "netty-codec-http", "4.1.135.Final")}</dependencies>`),
	[url("io.netty", "netty-codec-http", "4.1.135.Final")]: pom("io.netty", "netty-codec-http", "4.1.135.Final"),
	[url("io.netty", "netty-codec-http", "4.1.137.Final")]: pom("io.netty", "netty-codec-http", "4.1.137.Final"),
};
const fetcher = async u => R[u] ? { ok: true, status: 200, text: async () => R[u] } : { ok: false, status: 404, text: async () => "" };
const cacheDir = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-mediation-"));

test("a bare dependency takes the scope its POM's dependencyManagement gives it (test → not on the compile classpath)", async () => {
	const out = await resolveTransitiveDeps([{ groupId: "x", artifactId: "lib", version: "1", scope: "compile" }], { fetcher, cacheDir: cacheDir() });
	assert.ok(out.has("x:util"), "an ordinary compile child is still resolved");
	assert.ok(!out.has("ch.qos.logback:logback-classic"), "managed <scope>test</scope> must be applied");
});

test("a managed version given as a bare STRING (per-module overlay shape) pins the child instead of skipping it", async () => {
	const out = await resolveTransitiveDeps([{ groupId: "io.projectreactor.netty", artifactId: "reactor-netty-http", version: "1.2.18" }],
		{ fetcher, cacheDir: cacheDir(), rootDepMgmt: new Map([["io.netty:netty-codec-http", "4.1.137.Final"]]) });
	assert.equal(out.get("io.netty:netty-codec-http")?.version, "4.1.137.Final");
});

test("global pass: <dependencyManagement> exclusions are applied, and external import-BOM versions pin transitives", async () => {
	const less = makeDepRecord({ ecosystem: "maven", namespace: "com.github.sommeri", name: "less4j", version: "1.17.2", manifestPath: "/p/a/pom.xml" });
	less.exclusionSets = [["com.google.code.gson:gson", "com.google.protobuf:protobuf-java"]];
	const rn = makeDepRecord({ ecosystem: "maven", namespace: "io.projectreactor.netty", name: "reactor-netty-http", version: "1.2.18", manifestPath: "/p/a/pom.xml" });
	const m = new Map([["com.github.sommeri:less4j", less], ["io.projectreactor.netty:reactor-netty-http", rn]]);
	await expandWithTransitives(m, { fetcher, cacheDir: cacheDir(),
		bomDepMgmt: new Map([["io.netty:netty-codec-http", { version: "4.1.137.Final", bom: "io.netty:netty-bom:4.1.137.Final" }]]) });
	assert.ok(!m.has("com.google.code.gson:gson"));
	assert.ok(!m.has("com.google.protobuf:protobuf-java"));
	assert.deepEqual(m.get("io.netty:netty-codec-http").versions, ["4.1.137.Final"], "netty-bom wins over reactor-netty's declared 4.1.135");
});

test("exclusions merged across modules: only what EVERY declaration excludes is excluded", () => {
	assert.deepEqual(commonExclusions([["a:b", "c:d"], ["c:d"]]), [{ groupId: "c", artifactId: "d" }]);
	assert.deepEqual(commonExclusions([["a:b"], []]), [], "one module without the exclusion ships the dep");
	assert.deepEqual(commonExclusions(undefined), []);
});
