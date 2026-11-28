const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { moduleNameFor, resolveModuleNames } = require("../lib/inventory/module-names");

// The library builds its lookups with path.join / path.dirname, which yield "\\" on Windows
// while these in-memory trees are keyed with "/". Normalising on the way IN keeps the
// fixtures readable as POSIX paths and lets them answer the same question on every
// platform — the separator is the OS's business, not the fixture's. Without this the whole
// sibling-manifest family (package-lock → package.json, Gemfile.lock → .gemspec,
// build.gradle → settings.gradle, packages.config → .csproj) silently missed on Windows and
// every one of those descriptors came back unnamed.
const key = p => String(p).replace(/\\/g, "/");

// Injected reader: these are the project's OWN descriptors, never a dependency.
const files = {
	"/p/pom.xml": `<project><parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.7.18</version></parent><groupId>com.acme</groupId><artifactId>acme-gateway</artifactId></project>`,
	"/p/api/pom.xml": `<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n  <artifactId>acme-api</artifactId>\n</project>`,
	"/p/web/package.json": `{"name":"@acme/web","version":"1.0.0"}`,
	"/p/web/package-lock.json": `{"lockfileVersion":3}`,
	"/p/php/composer.json": `{"name":"acme/billing"}`,
	"/p/php/composer.lock": `{"packages":[]}`,
	"/p/svc/go.mod": `module github.com/acme/svc\n\ngo 1.22\n`,
	"/p/py/pyproject.toml": `[project]\nname = "acme-jobs"\nversion = "0.1.0"\n`,
	"/p/py2/pyproject.toml": `[tool.poetry]\nname = "acme-legacy"\n`,
	"/p/rb/Gemfile.lock": `GEM\n  specs:\n`,
	"/p/cs/App.csproj": `<Project Sdk="Microsoft.NET.Sdk"></Project>`,
	"/p/broken/pom.xml": `<project><parent><artifactId>only-a-parent</artifactId></parent></project>`,
	"/p/bad/package.json": `{ not json `,
};
const readFile = p => { const k = key(p); if (!(k in files)) throw new Error("ENOENT"); return files[k]; };
const nameOf = p => moduleNameFor(p, { readFile });

test("the injected tree answers the same whether it is asked with / or \\", () => {
	// This is precisely what broke on windows-latest: the library reaches a sibling with
	// path.join, which yields a backslash path there, and a tree keyed with "/" answered
	// ENOENT — so package-lock.json, Gemfile.lock, build.gradle and packages.config all came
	// back unnamed, and the report labelled those modules by their path instead. The library
	// is right (a real Windows walk hands it backslashes all the way down); it was the
	// fixture that assumed POSIX. Asserted here so the fixture cannot drift back.
	assert.equal(readFile("\\p\\web\\package.json"), files["/p/web/package.json"]);
	assert.equal(io2.readDir("\\r\\gem").join(","), dirs["/r/gem"].join(","));
});

test("Maven: the PROJECT artifactId, never the <parent> one", () => {
	// The parent block also carries an artifactId; taking the first match in the file
	// would label every Spring Boot module "spring-boot-starter-parent".
	assert.equal(nameOf("/p/pom.xml"), "acme-gateway");
	assert.equal(nameOf("/p/api/pom.xml"), "acme-api");
	assert.equal(nameOf("/p/broken/pom.xml"), null, "a pom with only a parent artifactId yields no name");
});

test("npm / composer / go / python read their own manifest name", () => {
	assert.equal(nameOf("/p/web/package.json"), "@acme/web");
	assert.equal(nameOf("/p/php/composer.json"), "acme/billing");
	assert.equal(nameOf("/p/svc/go.mod"), "github.com/acme/svc");
	assert.equal(nameOf("/p/py/pyproject.toml"), "acme-jobs");
	assert.equal(nameOf("/p/py2/pyproject.toml"), "acme-legacy");
});

test("a lockfile borrows the name from its sibling manifest", () => {
	assert.equal(nameOf("/p/web/package-lock.json"), "@acme/web");
	assert.equal(nameOf("/p/php/composer.lock"), "acme/billing");
});

test("no name anywhere → null, and the caller falls back to the path", () => {
	assert.equal(nameOf("/p/rb/Gemfile.lock"), null, "no .gemspec beside it");
	assert.equal(nameOf("/p/bad/package.json"), null, "malformed JSON must not throw");
	assert.equal(nameOf("/p/missing/pom.xml"), null, "unreadable must not throw");
});

test("resolveModuleNames labels every descriptor, falling back to the path relative to the root", () => {
	const m = resolveModuleNames(
		[{ path: "/p/pom.xml" }, { path: "/p/web/package-lock.json" }, { path: "/p/rb/Gemfile.lock" }],
		{ srcRoot: "/p", readFile });
	assert.equal(m.get("/p/pom.xml"), "acme-gateway");
	assert.equal(m.get("/p/web/package-lock.json"), "@acme/web");
	// The fallback is a real relative path, so it carries the platform's own separator.
	assert.equal(m.get("/p/rb/Gemfile.lock"), path.join("rb", "Gemfile.lock"), "no name → relative path");
	assert.equal(m.size, 3);
});

test("resolveModuleNames is robust to junk input", () => {
	assert.equal(resolveModuleNames(null, { srcRoot: "/p", readFile }).size, 0);
	assert.equal(resolveModuleNames([{}, { path: "" }], { srcRoot: "/p", readFile }).size, 0);
});

/* ---------------- every ecosystem, not just the easy five ---------------- */

const eco = {
	// .NET: the project name IS the file name; AssemblyName/PackageId override it when set.
	"/n/plain/App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`,
	"/n/named/Legacy.vbproj": `<Project><PropertyGroup><AssemblyName>Acme.Billing</AssemblyName></PropertyGroup></Project>`,
	"/n/pkg/Lib.fsproj": `<Project><PropertyGroup><PackageId>Acme.Lib.Core</PackageId></PropertyGroup></Project>`,
	"/n/plain/packages.config": `<packages></packages>`,
	"/n/plain/packages.lock.json": `{"version":1}`,
	// Gradle: settings.gradle names the root; a subproject is named after its directory.
	"/g/root/build.gradle": `plugins { id 'java' }`,
	"/g/root/settings.gradle": `rootProject.name = 'acme-platform'\ninclude 'svc'`,
	"/g/root/svc/build.gradle.kts": `plugins { kotlin("jvm") }`,
	"/g/root/svc/gradle.lockfile": `org.x:y:1.0=compileClasspath`,
	"/g/kts/settings.gradle.kts": `rootProject.name = "acme-kts"`,
	"/g/kts/build.gradle.kts": `plugins { java }`,
	// Ruby: Gemfile.lock has no name; a gemspec beside it does.
	"/r/gem/Gemfile.lock": `GEM\n  specs:\n`,
	"/r/gem/acme.gemspec": `Gem::Specification.new do |s|\n  s.name = "acme-billing"\n  s.version = "1.0"\nend`,
	"/r/bare/Gemfile.lock": `GEM\n  specs:\n`,
	// Python: requirements/Pipfile carry no project name at all.
	"/p/req/requirements.txt": `lodash==1\n`,
	"/p/req/Pipfile": `[packages]\n`,
};
const dirs = {};
for (const f of Object.keys(eco)) {
	const d = f.slice(0, f.lastIndexOf("/"));
	(dirs[d] = dirs[d] || []).push(f.slice(f.lastIndexOf("/") + 1));
}
const io2 = {
	readFile: p => { const k = key(p); if (!(k in eco)) throw new Error("ENOENT"); return eco[k]; },
	readDir: d => { const k = key(d); if (!(k in dirs)) throw new Error("ENOENT"); return dirs[k]; },
};
const n2 = p => moduleNameFor(p, io2);

test("NuGet: the file name is the project name, AssemblyName and PackageId win when present", () => {
	assert.equal(n2("/n/plain/App.csproj"), "App");
	assert.equal(n2("/n/named/Legacy.vbproj"), "Acme.Billing");
	assert.equal(n2("/n/pkg/Lib.fsproj"), "Acme.Lib.Core");
});

test("NuGet: packages.config and packages.lock.json borrow the project file beside them", () => {
	assert.equal(n2("/n/plain/packages.config"), "App");
	assert.equal(n2("/n/plain/packages.lock.json"), "App");
});

test("Gradle: settings.gradle names the root, a subproject is named after its directory", () => {
	assert.equal(n2("/g/root/build.gradle"), "acme-platform");
	assert.equal(n2("/g/kts/build.gradle.kts"), "acme-kts", "settings.gradle.kts is read too");
	assert.equal(n2("/g/root/svc/build.gradle.kts"), "svc", "no settings file here: Gradle's own default is the directory name");
	assert.equal(n2("/g/root/svc/gradle.lockfile"), "svc", "the lockfile borrows its build script's name");
});

test("Ruby: a gemspec beside Gemfile.lock names the module; without one there is no name", () => {
	assert.equal(n2("/r/gem/Gemfile.lock"), "acme-billing");
	assert.equal(n2("/r/bare/Gemfile.lock"), null);
});

test("Python: requirements.txt and Pipfile genuinely carry no project name", () => {
	// Inventing one from the directory would be a guess, not a deduction: these files are
	// routinely in a repo root or a deps/ folder that names nothing.
	assert.equal(n2("/p/req/requirements.txt"), null);
	assert.equal(n2("/p/req/Pipfile"), null);
});

test("every descriptor kind the codecs parse is either named or knowingly left to the path", () => {
	const named = ["pom.xml","package.json","composer.json","go.mod","pyproject.toml",
		"App.csproj","Legacy.vbproj","Lib.fsproj","packages.config","packages.lock.json",
		"build.gradle","build.gradle.kts","gradle.lockfile","Gemfile.lock"];
	const byPath = ["requirements.txt","Pipfile"];
	for (const f of Object.keys(eco)) {
		const base = f.slice(f.lastIndexOf("/") + 1);
		if (base.startsWith("settings.gradle") || base.endsWith(".gemspec")) continue;
		if (f.startsWith("/r/bare/")) continue;   // deliberately has no gemspec: covered above
		const got = n2(f);
		if (named.includes(base)) assert.ok(got, `${base} must resolve a name, got ${got}`);
		if (byPath.includes(base)) assert.equal(got, null, `${base} must stay null`);
	}
});
