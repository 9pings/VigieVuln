const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

test("CLI resolves implicit Spring BOM and graph versions offline without leaking into Maven", t => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-gradle-cli-"));
	t.after(() => { require("../lib/cache/db").closeCacheDbs(); fs.rmSync(root, { recursive: true, force: true }); });
	const src = path.join(root, "src"), home = path.join(root, "home");
	fs.mkdirSync(src); fs.mkdirSync(home);
	fs.writeFileSync(path.join(src, "build.gradle.kts"), `plugins {
 id("org.springframework.boot") version "4.1.1"
 id("io.spring.dependency-management") version "1.1.7"
}
dependencies {
 implementation("example:starter")
 implementation("example:child")
}`);
	const pom = (group, name, version, body = "") => `<project><modelVersion>4.0.0</modelVersion><groupId>${group}</groupId><artifactId>${name}</artifactId><version>${version}</version>${body}</project>`;
	const dependency = (name, version) => `<dependency><groupId>example</groupId><artifactId>${name}</artifactId><version>${version}</version></dependency>`;
	const cache = require("../lib/providers/maven/cache");
	for (const [group, name, version, body] of [
		["org.springframework.boot", "spring-boot-dependencies", "4.1.1", `<dependencyManagement><dependencies>${dependency("starter", "1.0")}</dependencies></dependencyManagement>`],
		["example", "starter", "1.0", `<dependencies>${dependency("child", "2.0")}</dependencies>`],
		["example", "child", "2.0", ""],
	]) cache.write(path.join(home, ".vigie-vuln", "poms-cache", `${group}__${name}__${version}.pom`), pom(group, name, version, body));
	require("../lib/cache/db").closeCacheDbs();
	const preload = path.join(root, "offline.cjs");
	fs.writeFileSync(preload, `require('node:os').homedir=()=>process.env.VV_GRADLE_TEST_HOME;
const blocked=()=>{require('node:fs').appendFileSync(process.env.VV_GRADLE_TEST_CALLS,'network\\n');throw Error('network forbidden')};
globalThis.fetch=blocked;for(const p of ['node:http','node:https'])for(const m of ['request','get'])require(p)[m]=blocked;require('node:net').Socket.prototype.connect=blocked;`);
	const run = name => {
		const report = path.join(root, `${name}.json`), sbom = path.join(root, `${name}-sbom.json`), calls = path.join(root, "calls.txt");
		const result = spawnSync(process.execPath, ["--require", preload, path.join(__dirname, "../vigievuln.js"), "scan", src,
			"--offline", "--cve-offline", "--no-osv", "--no-nvd", "--no-eol", "--no-retire", "--no-all-libs", "--no-binaries", "--no-jars", "--no-certs",
			"--no-gcve", "--no-euvd", "--no-certfr", "--no-epss", "--no-kev", "--report-json", report, "--report-sbom", sbom, "--report-html", path.join(root, `${name}.html`)],
		{ encoding: "utf8", timeout: 30000, cwd: root, env: { ...process.env, VV_GRADLE_TEST_HOME: home, VV_GRADLE_TEST_CALLS: calls, NO_COLOR: "1", FAD_CHECKER_ENV: "", VIGIEVULN_ENV: "" } });
		assert.ifError(result.error);
		assert.equal(result.status, 2, result.stdout + result.stderr);
		assert.equal(fs.existsSync(calls), false, "offline scan never tries network access");
		return require('./helpers/cancelled-scan')(result,[report,sbom,path.join(root,name+'.html')]);
	};
	assert.doesNotMatch(run("gradle"),/\[unresolved-versions\]/);
	fs.mkdirSync(path.join(src, "maven"));
	fs.writeFileSync(path.join(src, "maven", "pom.xml"), pom("example", "unrelated", "1.0", "<dependencies><dependency><groupId>example</groupId><artifactId>starter</artifactId></dependency></dependencies>"));
	assert.match(run("mixed"),/version/i);
});
