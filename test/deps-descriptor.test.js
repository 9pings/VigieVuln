const test = require("node:test");
const assert = require("node:assert");
const { serializeDeps, deserializeDeps, SCHEMA } = require("../lib/deps-descriptor");
const { makeDepRecord } = require("../lib/dep-record");

// Build a resolved map carrying sensitive environment fields.
function sampleMap() {
	const m = new Map();
	const npm = makeDepRecord({ ecosystem: "npm", namespace: "", name: "lodash", version: "4.17.21", manifestPath: "/home/secretuser/proj-x/package-lock.json", scope: "prod" });
	npm.resolved = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
	npm.integrity = "sha512-SECRETHASH";
	npm.from = "root>app>lodash";
	npm.lockType = "package-lock-v3";
	m.set(npm.coordKey, npm);

	const mvn = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.commons", name: "commons-lang3", version: "3.12.0", manifestPath: "/home/secretuser/proj-x/pom.xml", scope: "compile" });
	mvn.versions = ["3.12.0", "3.13.0"];          // multi-version
	m.set(mvn.coordKey, mvn);

	const pypi = makeDepRecord({ ecosystem: "pypi", namespace: "", name: "requests", version: "2.31.0", manifestPath: "/x/requirements.txt", scope: "dev", isDev: true });
	m.set(pypi.coordKey, pypi);
	return m;
}

test("serializeDeps produces the fad-deps/1 schema with per-ecosystem summary", () => {
	const d = serializeDeps(sampleMap(), { generator: "fad-checker test", generatedAt: "2026-01-01T00:00:00Z" });
	assert.strictEqual(d.schema, SCHEMA);
	assert.strictEqual(d.generatedAt, "2026-01-01T00:00:00Z");
	assert.strictEqual(d.summary.total, 3);
	assert.deepStrictEqual(d.summary.byEcosystem, { npm: 1, maven: 1, pypi: 1 });
});

test("serializeDeps strips ALL environment-identifying fields (anonymization guarantee)", () => {
	const json = JSON.stringify(serializeDeps(sampleMap(), {}));
	assert.ok(!/\/home/.test(json), "no filesystem paths");
	assert.ok(!/secretuser/.test(json), "no usernames");
	assert.ok(!/proj-x/.test(json), "no project dir names");
	assert.ok(!/https?:\/\//.test(json), "no URLs");
	assert.ok(!/integrity|sha512|SECRETHASH/.test(json), "no integrity hashes");
	assert.ok(!/manifestPath|pomPaths|lockType|"from"/.test(json), "no path/lock/parent fields");
	// kept fields ARE present
	const d = JSON.parse(json);
	const keys = Object.keys(d.deps[0]).sort();
	assert.deepStrictEqual(keys, ["ecosystem", "ecosystemType", "isDev", "name", "namespace", "scope", "version", "versions"]);
});

test("serializeDeps carries maven resolution hints (external parents, import BOMs, property overrides)", () => {
	const d = serializeDeps(sampleMap(), {
		generator: "t",
		externalParents: [{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent", version: "2.7.18" }],
		importBoms: [{ groupId: "org.springframework.boot", artifactId: "spring-boot-dependencies", version: "2.7.18" }],
		propertyOverrides: { "log4j2.version": "2.17.1" },
	});
	assert.deepStrictEqual(d.maven.externalParents, [{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent", version: "2.7.18" }]);
	assert.deepStrictEqual(d.maven.importBoms, [{ groupId: "org.springframework.boot", artifactId: "spring-boot-dependencies", version: "2.7.18" }]);
	assert.deepStrictEqual(d.maven.propertyOverrides, { "log4j2.version": "2.17.1" });
});

test("serializeDeps omits the maven hints block when there are none", () => {
	assert.strictEqual(serializeDeps(sampleMap(), {}).maven, undefined);
});

test("descriptor properties keep version overrides but not paths, URLs, secrets or unrelated values", () => {
	const { collectPropertyOverrides, collectVersionPropertyNames } = require("../lib/maven-bom");
	const store = { byPath: { "pom.xml": {
		properties: {
			"log4j2.version": ["2.17.1"], "java.version": ["17"], customPin: ["1.2.3"],
			"server.password": ["DO_NOT_EXPORT"], "server.token.version": ["123456"],
			"build.path": ["/home/private/project"], "internal.url": ["https://internal.invalid/"],
			"bogus.version": ["C:\\private\\secret"], "another.version": ["https://internal.invalid/"],
			"unexpected.version": ["SECRET_VALUE"], "app.class": ["org.internal.Secret"],
		},
		dependencies: { dependency: [{ version: ["${customPin}"] }] },
	} } };
	let omitted = 0;
	const descriptor = serializeDeps(sampleMap(), {
		propertyOverrides: collectPropertyOverrides(store), versionPropertyNames: collectVersionPropertyNames(store),
		onOmittedProperties: n => { omitted = n; },
	});
	assert.deepStrictEqual(descriptor.maven.propertyOverrides, {
		"log4j2.version": "2.17.1", "java.version": "17", customPin: "1.2.3",
	});
	assert.equal(omitted, 8);
	assert.ok(!/DO_NOT_EXPORT|SECRET_VALUE|internal.invalid|123456|Secret/.test(JSON.stringify(descriptor)));
});

test("descriptor preserves standard version ranges and Maven revision hints", () => {
	const { filterVersionProperties } = require("../lib/deps-descriptor");
	const properties = { "library.version": "[1.0,2.0)", revision: "1.2.3-SNAPSHOT", changelist: "",
		mavenVersion: "3.9.9", "version.jackson": "2.17.1" };
	assert.deepStrictEqual(filterVersionProperties(properties), properties);
});

test("URL/file versions are omitted while coordinates and other concrete versions survive", () => {
	const deps = sampleMap(), npm = deps.get("npm:lodash");
	npm.version = "https://user:SECRET@private.invalid/pkg.tgz";
	npm.versions = [npm.version, "file:C:\\private\\pkg", "4.17.21"];
	const descriptor = serializeDeps(deps);
	const serialized = descriptor.deps.find(d => d.name === "lodash");
	assert.equal(serialized.version, "4.17.21");
	assert.deepEqual(serialized.versions, ["4.17.21"]);
	assert.ok(!/SECRET|private.invalid|C:\\/.test(JSON.stringify(descriptor)));
});

test("filtered overrides still backfill versions inherited from an external Maven parent", async () => {
	const { resolveBomManagedVersions, backfillVersions } = require("../lib/maven-bom");
	const descriptor = serializeDeps(new Map(), {
		externalParents: [{ groupId: "org.example", artifactId: "parent", version: "1.0" }],
		propertyOverrides: { "snakeyaml.version": "2.2", "server.password": "SECRET" },
	});
	const imported = deserializeDeps(descriptor);
	const mgmt = await resolveBomManagedVersions(imported.externalParents, {
		via: "parent", propertyOverrides: imported.propertyOverrides,
		effectivePom: async (_g, _a, _v, opts) => ({ depMgmt: [
			{ groupId: "org.yaml", artifactId: "snakeyaml", version: opts.propertyOverrides["snakeyaml.version"] || "1.30" },
		] }),
	});
	const deps = new Map([["org.yaml:snakeyaml", { ecosystem: "maven", groupId: "org.yaml", artifactId: "snakeyaml", version: null, versions: [] }]]);
	assert.equal(backfillVersions(deps, mgmt), 1);
	assert.equal(deps.get("org.yaml:snakeyaml").version, "2.2");
});

test("deserializeDeps round-trips the maven resolution hints, defaulting absent ones to empty", () => {
	const d = serializeDeps(sampleMap(), {
		externalParents: [{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent", version: "2.7.18" }],
		propertyOverrides: { "log4j2.version": "2.17.1" },
	});
	const back = deserializeDeps(d);
	assert.deepStrictEqual(back.externalParents, [{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent", version: "2.7.18" }]);
	assert.deepStrictEqual(back.propertyOverrides, { "log4j2.version": "2.17.1" });
	assert.deepStrictEqual(back.importBoms, []);
	// A legacy descriptor with no maven block deserializes to empty hints (no throw).
	const legacy = deserializeDeps(serializeDeps(sampleMap(), {}));
	assert.deepStrictEqual(legacy.externalParents, []);
	assert.deepStrictEqual(legacy.propertyOverrides, {});
});

test("round-trip serialize → deserialize preserves coordinates, versions, scope", () => {
	const d = serializeDeps(sampleMap(), {});
	const { resolved } = deserializeDeps(d);
	assert.strictEqual(resolved.size, 3);
	const lod = resolved.get("npm:lodash");
	assert.strictEqual(lod.version, "4.17.21");
	assert.strictEqual(lod.scope, "prod");
	assert.strictEqual(lod.ecosystem, "npm");
	const req = resolved.get("pypi:requests");
	assert.strictEqual(req.isDev, true);
	assert.strictEqual(req.scope, "dev");
});

test("deserialize rebuilds maven groupId/artifactId + bare g:a coordKey, multi-version", () => {
	const { resolved } = deserializeDeps(serializeDeps(sampleMap(), {}));
	const mvn = resolved.get("org.apache.commons:commons-lang3");
	assert.ok(mvn, "maven dep keyed by bare g:a");
	assert.strictEqual(mvn.groupId, "org.apache.commons");
	assert.strictEqual(mvn.artifactId, "commons-lang3");
	assert.deepStrictEqual(mvn.versions, ["3.12.0", "3.13.0"]);
});

test("deserialize yields empty manifestPaths/pomPaths (paths never travelled)", () => {
	const { resolved } = deserializeDeps(serializeDeps(sampleMap(), {}));
	for (const dep of resolved.values()) {
		assert.deepStrictEqual(dep.manifestPaths, []);
		assert.deepStrictEqual(dep.pomPaths, []);
	}
});

test("deserialize derives activeIds / runMaven / runNpm", () => {
	const r = deserializeDeps(serializeDeps(sampleMap(), {}));
	assert.deepStrictEqual(r.activeIds.sort(), ["maven", "npm", "pypi"]);
	assert.strictEqual(r.runMaven, true);
	assert.strictEqual(r.runNpm, true);
});

test("runNpm is true when only a yarn ecosystemType is present", () => {
	const m = new Map();
	const y = makeDepRecord({ ecosystem: "npm", ecosystemType: "yarn", namespace: "", name: "chalk", version: "4.1.2", manifestPath: "/x/yarn.lock", scope: "prod" });
	m.set(y.coordKey, y);
	const r = deserializeDeps(serializeDeps(m, {}));
	assert.strictEqual(r.runNpm, true);
	assert.strictEqual(r.runMaven, false);
});

test("empty map → valid descriptor with zero deps; round-trips", () => {
	const d = serializeDeps(new Map(), {});
	assert.strictEqual(d.summary.total, 0);
	assert.deepStrictEqual(d.deps, []);
	const r = deserializeDeps(d);
	assert.strictEqual(r.resolved.size, 0);
	assert.deepStrictEqual(r.activeIds, []);
});

test("deserialize throws on schema mismatch", () => {
	assert.throws(() => deserializeDeps({ schema: "fad-deps/999", deps: [] }), /unsupported descriptor schema/);
	assert.throws(() => deserializeDeps(null), /invalid descriptor/);
});

test("serializeDeps output is stably ordered (reproducible for review/diff)", () => {
	const a = JSON.stringify(serializeDeps(sampleMap(), { generatedAt: "x" }).deps);
	const b = JSON.stringify(serializeDeps(sampleMap(), { generatedAt: "x" }).deps);
	assert.strictEqual(a, b);
});

test("nuget/composer coordinates round-trip (case-insensitive key)", () => {
	const m = new Map();
	const ng = makeDepRecord({ ecosystem: "nuget", namespace: "", name: "Newtonsoft.Json", version: "13.0.1", manifestPath: "/x/a.csproj", scope: "prod" });
	m.set(ng.coordKey, ng);
	const cp = makeDepRecord({ ecosystem: "composer", namespace: "symfony", name: "console", version: "6.0.0", manifestPath: "/x/composer.lock", scope: "prod" });
	m.set(cp.coordKey, cp);
	const { resolved } = deserializeDeps(serializeDeps(m, {}));
	assert.ok(resolved.get("nuget:newtonsoft.json"));
	assert.strictEqual(resolved.get("nuget:newtonsoft.json").name, "Newtonsoft.Json");   // display case kept
	assert.ok(resolved.get("composer:symfony/console"));
});
