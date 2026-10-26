const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { parseStringPromise } = require("xml2js");

const core = require("../lib/core");

const FIXTURES = path.join(__dirname, "fixtures");
const SIMPLE = path.join(FIXTURES, "simple");
const COMPLEX = path.join(FIXTURES, "complex-enterprise");
const PRIVATE_FIX = path.join(FIXTURES, "private-lib-detection");

async function pipeline(src, { deps2Exclude } = {}) {
	const store = core.newMetadataStore();
	const props = {};
	const pomFiles = core.findPomFiles(src);
	for (const f of pomFiles) await core.parsePom(f, store);
	for (const f of pomFiles) await core.getAllInheritedProps(f, store, props);
	return { store, props, pomFiles };
}

test("findPomFiles skips target/.git/node_modules", () => {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-test-"));
	fs.mkdirSync(path.join(tmp, "target"));
	fs.writeFileSync(path.join(tmp, "target", "pom.xml"), "<project/>");
	fs.writeFileSync(path.join(tmp, "pom.xml"), "<project/>");
	const found = core.findPomFiles(tmp);
	assert.equal(found.length, 1, "target/ should be skipped");
	assert.equal(found[0], path.join(tmp, "pom.xml"));
	fs.rmSync(tmp, { recursive: true, force: true });
});

test("parsePom extracts groupId/artifactId/version + parent + profiles", async () => {
	const { store } = await pipeline(SIMPLE);
	const root = store.byPath[path.join(SIMPLE, "pom.xml")];
	assert.equal(root.groupId, "com.example.simple");
	assert.equal(root.artifactId, "simple-parent");
	assert.equal(root.version, "1.0.0");
	assert.equal(root.parentInfo, null);

	const app = store.byPath[path.join(SIMPLE, "app", "pom.xml")];
	assert.equal(app.parentInfo.groupId, "com.example.simple");
	assert.equal(app.parentInfo.artifactId, "simple-parent");
});

test("byId does not get polluted with undefined keys", async () => {
	const { store } = await pipeline(SIMPLE);
	for (const key of Object.keys(store.byId)) {
		assert.ok(!key.includes("undefined"), `byId key has 'undefined': ${key}`);
		assert.ok(!key.includes("null"), `byId key has 'null': ${key}`);
	}
});

test("relativePath as directory resolves to dir/pom.xml", async () => {
	const { store } = await pipeline(SIMPLE);
	const app = store.byPath[path.join(SIMPLE, "app", "pom.xml")];
	// resolveParentPath populates parentDescr
	core.resolveParentPath(app.pomPath, app.parentInfo, store);
	assert.ok(app.parentDescr, "parent descriptor should be resolved");
	assert.equal(app.parentDescr.artifactId, "simple-parent");
});

test("activeByDefault profile is detected and used for property overrides", async () => {
	const { store, props } = await pipeline(COMPLEX);
	const root = store.byPath[path.join(COMPLEX, "pom.xml")];
	assert.equal(root.defaultProfileId, "dev");
	const merged = props[path.join(COMPLEX, "pom.xml")];
	// env.profile should be 'dev' (from activeByDefault) — but properties are
	// stored as xml2js arrays; unwrap when reading.
	const envProfile = merged.properties["env.profile"];
	const val = Array.isArray(envProfile) ? envProfile[0] : envProfile;
	assert.equal(val, "dev");
});

test("all-profile merge picks up deps from every profile", async () => {
	const { props } = await pipeline(COMPLEX);
	const root = props[path.join(COMPLEX, "pom.xml")];
	const ids = root.dependencies.map(d => `${d.groupId?.[0]}:${d.artifactId?.[0]}`);
	// Each profile contributed a dep — all three must be present.
	assert.ok(ids.includes("com.h2database:h2"), "dev profile (h2) missing");
	assert.ok(ids.includes("org.postgresql:postgresql"), "prod profile (postgres) missing");
	assert.ok(ids.includes("com.acme.private:acme-oracle-driver"), "oracle profile (private) missing");
});

test("BOM import (scope=import) pulls in managed deps from local BOM", async () => {
	const { props } = await pipeline(COMPLEX);
	const api = props[path.join(COMPLEX, "api", "pom.xml")];
	const mgmtIds = api.dependencyManagement.map(d => `${d.groupId?.[0]}:${d.artifactId?.[0]}`);
	assert.ok(mgmtIds.includes("org.hibernate:hibernate-core"), "BOM hibernate not imported");
	assert.ok(mgmtIds.includes("com.fasterxml.jackson.core:jackson-databind"), "BOM jackson not imported");
});

test("rewritePoms writes a clean tree in --target mode, target ≠ src", async () => {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-target-"));
	const { store, props, pomFiles } = await pipeline(COMPLEX);
	const opts = {
		srcRoot: COMPLEX, targetRoot: tmp,
		deps2Exclude: /^com\.acme\.private$/, verbose: false, readOnly: false,
	};
	let wrote = 0;
	for (const f of pomFiles) if (await core.rewritePoms(f, store, props, opts)) wrote++;
	assert.ok(wrote >= 4, `expected ≥4 POMs written, got ${wrote}`);
	const apiPomOut = path.join(tmp, "api", "pom.xml");
	assert.ok(fs.existsSync(apiPomOut));
	const apiOut = await parseStringPromise(fs.readFileSync(apiPomOut, "utf8"));
	const deps = apiOut.project?.dependencies?.[0]?.dependency || [];
	const ids = deps.map(d => `${d.groupId?.[0]}:${d.artifactId?.[0]}`);
	// Private dep must be filtered out
	assert.ok(!ids.includes("com.acme.private:acme-commons"), "private dep should be excluded");
	// Public dep must remain
	assert.ok(ids.includes("com.fasterxml.jackson.core:jackson-databind"), "public dep dropped unexpectedly");
	// And excludedById must contain the private coord
	assert.ok(store.excludedById["com.acme.private:acme-commons"], "excluded coord not flagged");
	fs.rmSync(tmp, { recursive: true, force: true });
});

test("rewritePoms in --test (readOnly) mode does not crash with undefined target", async () => {
	const { store, props, pomFiles } = await pipeline(SIMPLE);
	const opts = { srcRoot: SIMPLE, targetRoot: undefined, deps2Exclude: null, verbose: false, readOnly: true };
	// Should not throw despite target being undefined
	for (const f of pomFiles) await core.rewritePoms(f, store, props, opts);
});

test("missing external parent is flagged in missingById", async () => {
	const { store, props, pomFiles } = await pipeline(PRIVATE_FIX);
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-priv-"));
	const opts = {
		srcRoot: PRIVATE_FIX, targetRoot: tmp,
		deps2Exclude: /^(com\.client\.private|org\.megacorp)/,
		verbose: false, readOnly: false,
	};
	for (const f of pomFiles) await core.rewritePoms(f, store, props, opts);
	// The root pom's external parent org.megacorp.parents:megacorp-super-parent must be in missingById
	assert.ok(
		store.missingById["org.megacorp.parents:megacorp-super-parent"] ||
		store.missingById["org.megacorp.parents:megacorp-super-parent:9.9.9-PRIVATE"],
		"external private parent not tracked as missing"
	);
	fs.rmSync(tmp, { recursive: true, force: true });
});

test("parent version in rewritten POM uses parent's version, not child's", async () => {
	// Simple has child app with no own <version>; the rewritten parent ref should be 1.0.0
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-pv-"));
	const { store, props, pomFiles } = await pipeline(SIMPLE);
	const opts = { srcRoot: SIMPLE, targetRoot: tmp, deps2Exclude: null, verbose: false, readOnly: false };
	for (const f of pomFiles) await core.rewritePoms(f, store, props, opts);
	const appOut = await parseStringPromise(fs.readFileSync(path.join(tmp, "app", "pom.xml"), "utf8"));
	assert.equal(appOut.project.parent[0].version[0], "1.0.0", "parent.version must equal parent's version");
	fs.rmSync(tmp, { recursive: true, force: true });
});

test("rewritePoms interpolates ${project.groupId} in dep coords (no false 'private' lib)", async () => {
	// Reactor: module-a depends on sibling module-b via ${project.groupId}. The private-lib
	// classifier reads store.anyMissingById — a literal "${project.groupId}:module-b" there
	// would be mis-reported as absent-from-Central/private. Regression for outTest's
	// "${project.groupId}:cnaps-core".
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-projgid-core-"));
	const W = (rel, xml) => { fs.mkdirSync(path.join(dir, path.dirname(rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), xml); };
	W("parent/pom.xml", `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
		<groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version><packaging>pom</packaging></project>`);
	W("module-a/pom.xml", `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
		<parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version><relativePath>../parent/pom.xml</relativePath></parent>
		<artifactId>module-a</artifactId>
		<dependencies><dependency><groupId>\${project.groupId}</groupId><artifactId>module-b</artifactId><version>\${project.version}</version></dependency></dependencies></project>`);
	W("module-b/pom.xml", `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
		<parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version><relativePath>../parent/pom.xml</relativePath></parent>
		<artifactId>module-b</artifactId></project>`);

	const { store, props, pomFiles } = await pipeline(dir);
	for (const f of pomFiles) await core.rewritePoms(f, store, props, { srcRoot: dir, targetRoot: undefined, deps2Exclude: null, readOnly: true });

	assert.ok(!Object.keys(store.anyMissingById).some(k => k.includes("${")), "no unresolved ${...} coord indexed as missing/private");
	assert.ok(store.byId["com.acme:module-b"], "sibling module-b is known locally → would be filtered from the private-lib list");
	fs.rmSync(dir, { recursive: true, force: true });
});
