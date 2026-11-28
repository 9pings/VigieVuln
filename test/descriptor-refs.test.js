const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { findInText, findDeclarations } = require("../lib/inventory/descriptor-refs");
const { generateHtmlReport, generateWordReport } = require("../lib/reports/cve-report");
const { makeDepRecord } = require("../lib/inventory/dep-record");

const POM = `<project>
  <groupId>com.acme</groupId>
  <artifactId>spring-core</artifactId>
  <dependencies>
    <dependency>
      <groupId>other.vendor</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>\${spring.version}</version>
    </dependency>
  </dependencies>
</project>`;

test("pom.xml: the line of the <artifactId> inside the block whose groupId AND artifactId match", () => {
	const r = findInText("/x/pom.xml", POM, { ecosystem: "maven", namespace: "org.springframework", name: "spring-core" });
	assert.equal(r.length, 1, "neither the project's own artifactId nor another vendor's homonym");
	assert.equal(r[0].line, 11);
	assert.match(r[0].text, /<groupId>org\.springframework<\/groupId>.*\$\{spring\.version\}/);
});

test("pom.xml: a ${project.groupId} reactor sibling still matches on artifactId", () => {
	const xml = `<project>\n<dependencies>\n<dependency>\n<groupId>\${project.groupId}</groupId>\n<artifactId>core</artifactId>\n</dependency>\n</dependencies>\n</project>`;
	assert.deepEqual(findInText("pom.xml", xml, { ecosystem: "maven", namespace: "com.acme", name: "core" }).map(h => h.line), [5]);
});

test("each descriptor kind: the declaration line, never a mere mention", () => {
	const cases = [
		["package.json", `{\n  "name": "app",\n  "dependencies": {\n    "angular": "1.8.3"\n  }\n}`, { ecosystem: "npm", name: "angular" }, [4]],
		["package-lock.json", `{\n "packages": {\n  "node_modules/angular": {\n   "version": "1.8.3"\n  },\n  "node_modules/x/node_modules/angular": {}\n }\n}`, { ecosystem: "npm", name: "angular" }, [3, 6]],
		["yarn.lock", `"angular@^1.8.0":\n  version "1.8.3"\nangular-route@1.0:\n  version "1"`, { ecosystem: "npm", name: "angular" }, [1]],
		["composer.lock", `{\n "packages": [\n  {\n   "name": "symfony/yaml",\n   "version": "v5.4.45"\n  }\n ]\n}`, { ecosystem: "composer", namespace: "symfony", name: "yaml" }, [4]],
		["composer.json", `{\n "require": {\n  "php": "^7.4",\n  "symfony/yaml": "^5.4"\n }\n}`, { ecosystem: "composer", namespace: "", name: "php" }, [3]],
		["requirements.txt", `# django is great\nDjango==3.2.1\ndjango-extensions==1`, { ecosystem: "pypi", name: "django" }, [2]],
		["poetry.lock", `[[package]]\nname = "django"\nversion = "3.2.1"`, { ecosystem: "pypi", name: "Django" }, [2]],
		["app.csproj", `<Project>\n <ItemGroup>\n  <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />\n </ItemGroup>\n</Project>`, { ecosystem: "nuget", name: "Newtonsoft.Json" }, [3]],
		["go.mod", `module x\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n)`, { ecosystem: "go", name: "github.com/gin-gonic/gin" }, [3]],
		["Gemfile.lock", `GEM\n  specs:\n    rails (6.0.0)\n      actionpack (= 6.0.0)\n    railsx (1.0)`, { ecosystem: "ruby", name: "rails" }, [3]],
		["build.gradle.kts", `dependencies {\n  implementation("org.springframework:spring-core:5.3.0")\n}`, { ecosystem: "maven", namespace: "org.springframework", name: "spring-core" }, [2]],
		["gradle.lockfile", `org.springframework:spring-core:5.3.0=runtimeClasspath`, { ecosystem: "maven", namespace: "org.springframework", name: "spring-core" }, [1]],
	];
	for (const [file, text, dep, lines] of cases) {
		assert.deepEqual(findInText(file, text, dep).map(h => h.line), lines, file);
	}
});

test("an unknown descriptor kind or an unreadable file yields no line (never a guessed one)", () => {
	assert.deepEqual(findInText("notes.md", "angular 1.8.3", { ecosystem: "npm", name: "angular" }), []);
	assert.deepEqual(findDeclarations("/does/not/exist/pom.xml", { ecosystem: "maven", namespace: "g", name: "a" }), []);
});

test("EOL row is click-to-expand: the detail panel names the descriptor, the file:line and the declaration", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-eol-refs-"));
	fs.mkdirSync(path.join(dir, "web"));
	const pom = path.join(dir, "web", "pom.xml");
	fs.writeFileSync(pom, POM);
	const dep = makeDepRecord({ ecosystem: "maven", namespace: "org.springframework", name: "spring-core", version: "4.3.16.RELEASE", manifestPath: pom });
	const finding = { dep, product: "Spring Framework", productSlug: "spring-framework", cycle: "4.3", status: "eol", eol: "2020-12-31", latest: "4.3.30" };
	const payload = { cveMatches: [], eolResults: [finding], obsoleteResults: [], outdatedResults: [], resolvedDeps: new Map([["org.springframework:spring-core", dep]]), projectInfo: { name: "demo", src: dir, generatedAt: "2026-10-02" } };
	const html = generateHtmlReport(payload);
	const i = html.indexOf("<td class=\"dep\">Spring Framework</td>");
	assert.ok(i > 0);
	assert.ok(html.lastIndexOf('<tr class="cve-row">', i) > html.lastIndexOf("</tr>", i), "the EOL row is a clickable cve-row");
	assert.ok(html.includes("<code>web/pom.xml:11</code>"), "exact descriptor reference file:line");
	assert.ok(html.includes("&lt;artifactId&gt;spring-core&lt;/artifactId&gt;"), "the declaration itself, escaped");
	const doc = generateWordReport(payload);
	assert.ok(doc.includes("web/pom.xml:11"), "Word force-opens the panel, so the reference is not lost");
	fs.rmSync(dir, { recursive: true, force: true });
});

test("EOL detail: a transitive finding lists every chain and where the root direct dep is declared", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-eol-refs-"));
	const pom = path.join(dir, "pom.xml");
	fs.writeFileSync(pom, `<project>\n<dependencies>\n<dependency>\n<groupId>com.x</groupId>\n<artifactId>starter</artifactId>\n</dependency>\n</dependencies>\n</project>`);
	const root = makeDepRecord({ ecosystem: "maven", namespace: "com.x", name: "starter", version: "1.0", manifestPath: pom });
	const dep = { ...makeDepRecord({ ecosystem: "maven", namespace: "org.springframework", name: "spring-core", version: "4.3.1" }), scope: "transitive", via: ["com.x:starter"], viaPaths: [["com.x:starter"], ["com.x:starter", "com.y:mid"]] };
	const html = generateHtmlReport({ cveMatches: [], eolResults: [{ dep, product: "Spring Framework", productSlug: "spring-framework", cycle: "4.3", status: "eol", eol: "2020-12-31" }], obsoleteResults: [], outdatedResults: [], resolvedDeps: new Map([["com.x:starter", root]]), projectInfo: { name: "demo", src: dir, generatedAt: "2026-10-02" } });
	assert.ok(html.includes("Pulled in via"));
	assert.ok(html.includes("<code>com.y:mid</code>"), "the second chain is listed too");
	assert.ok(html.includes("Direct dependency to update, declared in"));
	assert.ok(html.includes("<code>pom.xml:5</code>"));
	fs.rmSync(dir, { recursive: true, force: true });
});

test("EOL detail: a grouped TRANSITIVE component shows its chain, never the anchor's pom", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-eol-refs-"));
	const pom = path.join(dir, "pom.xml");
	fs.writeFileSync(pom, `<project>\n<dependencies>\n<dependency>\n<groupId>org.springframework</groupId>\n<artifactId>spring-web</artifactId>\n</dependency>\n</dependencies>\n</project>`);
	const dep = makeDepRecord({ ecosystem: "maven", namespace: "org.springframework", name: "spring-web", version: "5.3.20", manifestPath: pom });
	const components = [
		{ name: "org.springframework:spring-core", version: "5.3.20", scope: "transitive", via: ["org.springframework:spring-web"] },
		{ name: "org.springframework:spring-web", version: "5.3.20", manifestPaths: [pom] },
	];
	const html = generateHtmlReport({ cveMatches: [], eolResults: [{ dep, components, product: "Spring Framework", productSlug: "spring-framework", cycle: "5.3", status: "eol", eol: "2024-08-31" }], obsoleteResults: [], outdatedResults: [], resolvedDeps: new Map(), projectInfo: { name: "demo", src: dir, generatedAt: "2026-10-02" } });
	assert.ok(html.includes("<code>pom.xml:5</code>"), "the declared component is located");
	assert.equal((html.match(/<code>pom\.xml:/g) || []).length, 1, "the transitive one is not filed under the anchor's pom");
	assert.ok(html.includes("<code>org.springframework:spring-web</code> → <code>org.springframework:spring-core</code>"));
	assert.ok(!html.includes("declaration line not located"));
	fs.rmSync(dir, { recursive: true, force: true });
});

test("EOL detail: a transitive component that names its RESOLVING modules (per-module resolution) still shows its chain", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-eol-refs-"));
	const pom = path.join(dir, "pom.xml");
	fs.writeFileSync(pom, `<project>\n<dependencies>\n<dependency>\n<groupId>org.springframework</groupId>\n<artifactId>spring-web</artifactId>\n</dependency>\n</dependencies>\n</project>`);
	const dep = makeDepRecord({ ecosystem: "maven", namespace: "org.springframework", name: "spring-web", version: "6.2.19", manifestPath: pom });
	const components = [
		{ name: "org.springframework:spring-aop", version: "6.2.19", scope: "transitive", via: ["org.springframework:spring-web"], manifestPaths: [pom] },
		{ name: "org.springframework:spring-web", version: "6.2.19", manifestPaths: [pom] },
	];
	const html = generateHtmlReport({ cveMatches: [], eolResults: [{ dep, components, product: "Spring Framework", cycle: "6.2", status: "eol", eol: "2026-06-30" }], obsoleteResults: [], outdatedResults: [], projectInfo: { name: "d", src: dir, generatedAt: "x" } });
	assert.ok(!html.includes("no declaration in this POM"), "the resolving module is not where a transitive is declared");
	assert.ok(html.includes("<code>org.springframework:spring-web</code> → <code>org.springframework:spring-aop</code>"));
	fs.rmSync(dir, { recursive: true, force: true });
});
