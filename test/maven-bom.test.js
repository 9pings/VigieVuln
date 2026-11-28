const { test } = require("node:test");
const assert = require("node:assert/strict");
const { collectImportBoms, backfillVersions, resolveBomManagedVersions, resolveAndBackfill, collectExternalParents, collectPropertyOverrides } = require("../lib/codecs/maven/bom");

test("collectPropertyOverrides reads each pom's OWN declared properties, dropping builtins and unresolved values", () => {
	const store = {
		byPath: {
			// raw xml2js <properties> shape: { name: [value] }
			"/proj/pom.xml": { properties: { "log4j2.version": ["2.17.1"], "java.version": ["17"] } },
			"/proj/mod/pom.xml": { properties: { "snakeyaml.version": ["2.2"], "project.build.sourceEncoding": ["UTF-8"], "bad": ["${x}"] } },
		},
	};
	const ov = collectPropertyOverrides(store);
	assert.equal(ov["log4j2.version"], "2.17.1");
	assert.equal(ov["snakeyaml.version"], "2.2");
	assert.equal(ov["java.version"], "17");
	// project.*/pom.* builtins and unresolved ${…} values are not overrides.
	assert.ok(!("project.build.sourceEncoding" in ov));
	assert.ok(!("bad" in ov));
});

// xml2js-shaped dependencyManagement entry helper.
const dm = (g, a, v, scope) => ({ groupId: [g], artifactId: [a], version: [v], ...(scope ? { scope: [scope] } : {}) });

test("collectExternalParents extracts distinct external parent coords, skipping local parents", () => {
	// A 2-module reactor: mod inherits the LOCAL root (com.example:demo), which itself
	// inherits the EXTERNAL spring-boot-starter-parent (absent from the tree). Only the
	// external one should be collected, deduped across both climb paths.
	const store = {
		byPath: {
			"/proj/pom.xml": { parentInfo: { groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent", version: "2.7.18" } },
			"/proj/mod/pom.xml": { parentInfo: { groupId: "com.example", artifactId: "demo", version: "1.0.0" } },
		},
		byId: {
			"com.example:demo:1.0.0": { pomPath: "/proj/pom.xml" },
			"com.example:demo": { pomPath: "/proj/pom.xml" },
		},
	};
	const parents = collectExternalParents(store);
	assert.equal(parents.length, 1);
	assert.deepEqual(parents[0], { groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent", version: "2.7.18" });
});

test("collectExternalParents ignores a fully-local parent chain and unresolved-version parents", () => {
	const store = {
		byPath: {
			"/proj/pom.xml": { parentInfo: null },                                                             // no parent
			"/proj/mod/pom.xml": { parentInfo: { groupId: "com.example", artifactId: "demo", version: "1.0.0" } }, // local
			"/proj/bad/pom.xml": { parentInfo: { groupId: "g", artifactId: "a", version: "${x.version}" } },    // unresolved → skip
		},
		byId: { "com.example:demo:1.0.0": { pomPath: "/proj/pom.xml" }, "com.example:demo": { pomPath: "/proj/pom.xml" } },
	};
	assert.deepEqual(collectExternalParents(store), []);
});

test("collectImportBoms extracts distinct import BOMs, resolving ${prop} versions", () => {
	const propsByPom = {
		"super-pom/pom.xml": {
			properties: { "spring-boot.version": "3.5.3" },
			dependencyManagement: [
				dm("org.springframework.boot", "spring-boot-dependencies", "${spring-boot.version}", "import"),
				dm("commons-io", "commons-io", "2.20.0"), // not import → ignored
			],
		},
		// a module that inherited the same import entry → must dedupe
		"cnaps-core/pom.xml": {
			properties: { "spring-boot.version": "3.5.3" },
			dependencyManagement: [dm("org.springframework.boot", "spring-boot-dependencies", "${spring-boot.version}", "import")],
		},
	};
	const boms = collectImportBoms(propsByPom);
	assert.equal(boms.length, 1);
	assert.deepEqual(boms[0], { groupId: "org.springframework.boot", artifactId: "spring-boot-dependencies", version: "3.5.3" });
});

test("collectImportBoms skips entries whose version stays unresolved", () => {
	const propsByPom = { "p/pom.xml": { properties: {}, dependencyManagement: [dm("g", "bom", "${missing.version}", "import")] } };
	assert.equal(collectImportBoms(propsByPom).length, 0);
});

test("resolveBomManagedVersions builds a g:a→{version,bom} map via (injected) effectivePom", async () => {
	const fakeEffectivePom = async (g, a, v) => {
		assert.equal(`${g}:${a}:${v}`, "org.springframework.boot:spring-boot-dependencies:3.5.3");
		return { depMgmt: [
			{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: "3.5.3" },
			{ groupId: "com.fasterxml.jackson.core", artifactId: "jackson-databind", version: "2.19.0" },
		] };
	};
	const map = await resolveBomManagedVersions(
		[{ groupId: "org.springframework.boot", artifactId: "spring-boot-dependencies", version: "3.5.3" }],
		{ effectivePom: fakeEffectivePom });
	// Value carries the resolved version AND the top-level BOM coordinate that supplied it,
	// so backfill can record provenance ("version managed by <bom>").
	assert.deepEqual(map.get("org.springframework.boot:spring-boot-starter-web"),
		{ version: "3.5.3", bom: "org.springframework.boot:spring-boot-dependencies:3.5.3" });
	assert.deepEqual(map.get("com.fasterxml.jackson.core:jackson-databind"),
		{ version: "2.19.0", bom: "org.springframework.boot:spring-boot-dependencies:3.5.3" });
});

test("resolveBomManagedVersions records the FIRST (top-level) BOM that manages a coord", async () => {
	// Two platform BOMs both manage commons-io; first declared wins (Maven order) and is the
	// coord surfaced as provenance — not the nested/second one.
	const boms = [
		{ groupId: "com.acme", artifactId: "platform-a", version: "1.0.0" },
		{ groupId: "com.acme", artifactId: "platform-b", version: "2.0.0" },
	];
	const fakeEffectivePom = async (g, a) => a === "platform-a"
		? { depMgmt: [{ groupId: "commons-io", artifactId: "commons-io", version: "2.20.0" }] }
		: { depMgmt: [{ groupId: "commons-io", artifactId: "commons-io", version: "2.11.0" }] };
	const map = await resolveBomManagedVersions(boms, { effectivePom: fakeEffectivePom });
	assert.deepEqual(map.get("commons-io:commons-io"), { version: "2.20.0", bom: "com.acme:platform-a:1.0.0" });
});

test("resolveBomManagedVersions tags entries with a non-default source kind (via:parent)", async () => {
	// External <parent> (spring-boot-starter-parent) fed through the same resolver as an
	// import BOM, but tagged via:"parent" so the report says "managed by parent", not BOM.
	const fakeEff = async (g, a, v) => {
		assert.equal(`${g}:${a}:${v}`, "org.springframework.boot:spring-boot-starter-parent:2.7.18");
		return { depMgmt: [{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-actuator", version: "2.7.18" }] };
	};
	const map = await resolveBomManagedVersions(
		[{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent", version: "2.7.18" }],
		{ effectivePom: fakeEff, via: "parent" });
	assert.deepEqual(map.get("org.springframework.boot:spring-boot-starter-actuator"),
		{ version: "2.7.18", bom: "org.springframework.boot:spring-boot-starter-parent:2.7.18", via: "parent" });
});

test("backfillVersions carries the entry's via into versionSource (parent-managed)", () => {
	const map = new Map([
		["org.springframework.boot:spring-boot-starter-actuator", { version: "2.7.18", bom: "org.springframework.boot:spring-boot-starter-parent:2.7.18", via: "parent" }],
	]);
	const deps = new Map([["a", { ecosystem: "maven", groupId: "org.springframework.boot", artifactId: "spring-boot-starter-actuator", version: null, versions: [] }]]);
	backfillVersions(deps, map);
	assert.equal(deps.get("a").version, "2.7.18");
	assert.deepEqual(deps.get("a").versionSource, { via: "parent", bom: "org.springframework.boot:spring-boot-starter-parent:2.7.18" });
});

test("backfillVersions fills ONLY versionless/unresolved Maven deps, leaving concrete ones", () => {
	const map = new Map([
		["org.springframework.boot:spring-boot-starter-web", { version: "3.5.3", bom: "org.springframework.boot:spring-boot-dependencies:3.5.3" }],
		["com.acme:lib", { version: "9.9.9", bom: "com.acme:bom:1.0.0" }],
	]);
	const deps = new Map([
		["a", { ecosystem: "maven", groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: null, versions: [] }],
		["b", { ecosystem: "maven", groupId: "com.acme", artifactId: "lib", version: "1.0.0", versions: ["1.0.0"] }], // concrete → untouched
		["c", { ecosystem: "maven", groupId: "x", artifactId: "y", version: "${unresolved}", versions: [] }], // not in map → stays
	]);
	const filled = backfillVersions(deps, map);
	assert.equal(filled, 1);
	assert.equal(deps.get("a").version, "3.5.3");
	assert.deepEqual(deps.get("a").versions, ["3.5.3"]);
	assert.equal(deps.get("b").version, "1.0.0");
	assert.equal(deps.get("c").version, "${unresolved}");
});

test("backfillVersions stamps versionSource on backfilled deps only", () => {
	const map = new Map([
		["org.springframework.batch:spring-batch-integration", { version: "6.0.3", bom: "org.springframework.boot:spring-boot-dependencies:4.0.6" }],
		["com.acme:lib", { version: "9.9.9", bom: "com.acme:bom:1.0.0" }],
	]);
	const deps = new Map([
		["a", { ecosystem: "maven", groupId: "org.springframework.batch", artifactId: "spring-batch-integration", version: null, versions: [] }],
		["b", { ecosystem: "maven", groupId: "com.acme", artifactId: "lib", version: "1.0.0", versions: ["1.0.0"] }], // concrete → not stamped
		["c", { ecosystem: "maven", groupId: "x", artifactId: "y", version: "${unresolved}", versions: [] }], // unmanaged → not stamped
	]);
	backfillVersions(deps, map);
	assert.deepEqual(deps.get("a").versionSource, { via: "bom", bom: "org.springframework.boot:spring-boot-dependencies:4.0.6" });
	assert.equal(deps.get("b").versionSource, undefined);
	assert.equal(deps.get("c").versionSource, undefined);
});

test("external-parent backfill end-to-end: versionless deps get the parent-managed version, honoring an override", async () => {
	// The whole Fix-1 chain wired together with an injected effectivePom that (like the real
	// one) honors propertyOverrides: collect parent + overrides from a store, resolve, backfill.
	const store = {
		byPath: { "/p/pom.xml": {
			parentInfo: { groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent", version: "2.7.18" },
			properties: { "snakeyaml.version": ["1.33"] },   // patch override
		} },
		byId: {},
	};
	const parents = collectExternalParents(store);
	const overrides = collectPropertyOverrides(store);
	const fakeEff = async (g, a, v, opts) => ({ depMgmt: [
		{ groupId: "org.yaml", artifactId: "snakeyaml", version: (opts.propertyOverrides && opts.propertyOverrides["snakeyaml.version"]) || "1.30" },
		{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: "2.7.18" },
	] });
	const mgmt = await resolveBomManagedVersions(parents, { effectivePom: fakeEff, via: "parent", propertyOverrides: overrides });
	const resolved = new Map([
		["org.yaml:snakeyaml", { ecosystem: "maven", groupId: "org.yaml", artifactId: "snakeyaml", version: null, versions: [] }],
		["org.springframework.boot:spring-boot-starter-web", { ecosystem: "maven", groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: null, versions: [] }],
	]);
	assert.equal(backfillVersions(resolved, mgmt), 2);
	assert.equal(resolved.get("org.yaml:snakeyaml").version, "1.33", "override wins over parent default 1.30");
	assert.equal(resolved.get("org.springframework.boot:spring-boot-starter-web").version, "2.7.18");
	assert.equal(resolved.get("org.yaml:snakeyaml").versionSource.via, "parent");
});

test("resolveAndBackfill end-to-end (injected effectivePom): spring-boot starters get versions", async () => {
	const propsByPom = { "p/pom.xml": { properties: { "spring-boot.version": "3.5.3" },
		dependencyManagement: [dm("org.springframework.boot", "spring-boot-dependencies", "${spring-boot.version}", "import")] } };
	const resolved = new Map([
		["org.springframework.boot:spring-boot-starter-web", { ecosystem: "maven", groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: null, versions: [] }],
	]);
	const fakeEffectivePom = async () => ({ depMgmt: [{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: "3.5.3" }] });
	const r = await resolveAndBackfill(propsByPom, resolved, { effectivePom: fakeEffectivePom });
	assert.equal(r.filled, 1);
	assert.equal(resolved.get("org.springframework.boot:spring-boot-starter-web").version, "3.5.3");
	assert.deepEqual(resolved.get("org.springframework.boot:spring-boot-starter-web").versionSource,
		{ via: "bom", bom: "org.springframework.boot:spring-boot-dependencies:3.5.3" });
});
