const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const composer = require("../lib/codecs/composer.codec");
const { versionRelationsFor } = require("../lib/codecs/composer/relations");

function project(t, files) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "composer-relations-"));
	t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
	for (const [name, body] of Object.entries(files)) {
		const file = path.join(dir, name);
		fs.mkdirSync(path.dirname(file), { recursive: true });
		fs.writeFileSync(file, typeof body === "string" ? body : JSON.stringify(body));
	}
	return dir;
}

test("Composer: direct and transitive versions stay separate when production wins the record", async t => {
	const dir = project(t, {
		"a/composer.json": { "require-dev": { "ACME/Target": "^2" } },
		"a/composer.lock": { "packages-dev": [{ name: "acme/target", version: "v2.0.0" }] },
		"b/composer.json": { require: { "acme/parent": "^1" } },
		"b/composer.lock": { packages: [
			{ name: "acme/parent", version: "1.0.0", require: { "acme/target": "^1" } },
			{ name: "acme/target", version: "1.0.0" },
		] },
	});
	const { deps } = await composer.collect(dir);
	const dep = deps.get("composer:acme/target");
	assert.deepEqual(dep.versionRelations, { "2.0.0": ["direct"], "1.0.0": ["transitive"] });
	assert.equal(dep.version, "1.0.0");
	assert.deepEqual(dep.versions, ["2.0.0", "1.0.0"]);
	assert.equal(dep.isDev, false);
	assert.equal(dep.scope, "prod");
	assert.deepEqual(dep.versionScopes, { "2.0.0": ["dev"], "1.0.0": ["prod"] });
	assert.deepEqual(dep.versionPaths, {
		"2.0.0": [path.join(dir, "a/composer.lock")],
		"1.0.0": [path.join(dir, "b/composer.lock")],
	});
	assert.equal(dep.pomPaths, dep.manifestPaths);
	assert.deepEqual(dep.occurrences.map(o => [o.version, o.managerRelation, o.isDev]),
		[["2.0.0", "direct", true], ["1.0.0", "transitive", false]]);

	const filtered = (await composer.collect(dir, { ignoreTest: true })).deps.get(dep.coordKey);
	assert.deepEqual(filtered.versionRelations, { "1.0.0": ["transitive"] });
	assert.deepEqual(filtered.versions, ["1.0.0"]);
	assert.equal(filtered.occurrences.length, 1);
	assert.equal((await composer.collect(dir, { deps2Exclude: /\/target$/ })).deps.has(dep.coordKey), false);
});

test("Composer: same-version evidence is deduplicated without losing unknown sites or depending on order", async t => {
	const dir = project(t, {
		"a/composer.json": { require: { "acme/target": "1.0.0" } },
		"b/composer.lock": { packages: [{ name: "acme/target", version: "1.0.0" }] },
		"c/composer.json": { "require-dev": { "acme/target": "v1.0.0" } },
		"d/composer.json": { require: { "acme/parent": "1.0.0" } },
		"d/composer.lock": { packages: [
			{ name: "acme/parent", version: "1.0.0", require: { "acme/target": "^1" } },
			{ name: "acme/target", version: "1.0.0" },
		] },
	});
	const dep = (await composer.collect(dir)).deps.get("composer:acme/target");
	assert.deepEqual(dep.versionRelations, { "1.0.0": ["direct", "unknown", "transitive"] });
	assert.equal(dep.occurrences.length, 4);
	assert.equal(dep.versionPaths["1.0.0"].length, 4);
	const reverse = versionRelationsFor({ ...dep, occurrences: [...dep.occurrences].reverse() });
	assert.deepEqual(new Set(reverse["1.0.0"]), new Set(dep.versionRelations["1.0.0"]));
});

for (const isDev of [false, true]) {
	test(`Composer: direct and transitive are independent of isDev=${isDev}`, async t => {
		const dir = project(t, {
			"composer.json": { [isDev ? "require-dev" : "require"]: { "acme/parent": "^1" } },
			"composer.lock": { [isDev ? "packages-dev" : "packages"]: [
				{ name: "acme/parent", version: "1.0.0", require: { "acme/leaf": "^1" } },
				{ name: "acme/leaf", version: "1.0.0" },
			] },
		});
		const { deps } = await composer.collect(dir);
		assert.deepEqual(deps.get("composer:acme/parent").versionRelations, { "1.0.0": ["direct"] });
		assert.deepEqual(deps.get("composer:acme/leaf").versionRelations, { "1.0.0": ["transitive"] });
		for (const dep of deps.values()) {
			assert.equal(dep.isDev, isDev);
			assert.equal(dep.scope, isDev ? "dev" : "prod");
		}
	});
}

for (const malformed of [false, true]) {
	test(`Composer: ${malformed ? "unreadable" : "missing"} root declarations retain unknown for prod and dev`, async t => {
		const dir = project(t, {
			...(malformed ? { "composer.json": "{ broken" } : {}),
			"composer.lock": {
				packages: [{ name: "acme/prod", version: "v1.0.0" }],
				"packages-dev": [{ name: "acme/dev", version: "1.0.0" }],
			},
		});
		const { deps, warnings } = await composer.collect(dir);
		assert.equal(deps.size, 2);
		for (const dep of deps.values()) assert.deepEqual(dep.versionRelations, { "1.0.0": ["unknown"] });
		assert.equal(warnings.length, malformed ? 1 : 0);
		if (malformed) assert.equal(warnings[0].type, "parse-error");
	});
}

test("Composer: pinned fallback stays direct in both scopes, ranges and platform requirements stay skipped", async t => {
	const dir = project(t, { "composer.json": {
		require: { "acme/shared": "v1.0.0", "acme/range": "^2", php: "8.2.0", "ext-json": "*" },
		"require-dev": { "acme/shared": "1.0.0", "acme/dev": "2.0.0", "acme/wildcard": "1.0.x-dev" },
	} });
	const { deps, warnings } = await composer.collect(dir);
	assert.deepEqual([...deps.keys()], ["composer:acme/shared", "composer:acme/dev"]);
	const shared = deps.get("composer:acme/shared");
	assert.deepEqual(shared.versionRelations, { "1.0.0": ["direct"] });
	assert.equal(shared.occurrences.length, 2);
	assert.deepEqual(shared.versionScopes, { "1.0.0": ["prod", "dev"] });
	assert.equal(shared.isDev, false);
	assert.deepEqual(deps.get("composer:acme/dev").versionRelations, { "2.0.0": ["direct"] });
	assert.equal(warnings.length, 1);
	assert.equal(warnings[0].type, "no-lockfile");
	assert.match(warnings[0].message, /3 pinned, 2 range\(s\) skipped/);
	assert.deepEqual([...(await composer.collect(dir, { ignoreTest: true })).deps.keys()], ["composer:acme/shared"]);
});

test("Composer: absent or unresolved versions do not acquire relation keys; locked branches keep their existing keys", async t => {
	const dir = project(t, { "composer.lock": { packages: [
		{ name: "acme/missing" },
		{ name: "acme/unresolved", version: "${version}" },
		{ name: "acme/branch", version: "dev-main" },
	] } });
	const { deps } = await composer.collect(dir);
	for (const name of ["missing", "unresolved"]) {
		const dep = deps.get(`composer:acme/${name}`);
		assert.deepEqual(dep.versions, []);
		assert.deepEqual(dep.versionRelations, {});
		assert.equal(dep.occurrences.length, 1);
	}
	assert.deepEqual(deps.get("composer:acme/branch").versionRelations, { "dev-main": ["unknown"] });
});

test("Composer: missing or unsupported occurrence evidence never falls back to coordinate or scope", () => {
	const dep = {
		version: "1.0.0", versions: ["1.0.0", "2.0.0", "3.0.0", "4.0.0"],
		managerRelation: "direct", scope: "transitive", isDev: false,
		occurrences: [
			{ version: "1.0.0", managerRelation: "direct" },
			{ version: "2.0.0", scope: "prod", isDev: false },
			{ version: "3.0.0", managerRelation: "optional", isDev: true },
			{ version: null, managerRelation: "transitive" },
			{ version: "5.0.0", managerRelation: "direct" },
		],
	};
	const before = structuredClone(dep);
	assert.deepEqual(versionRelationsFor(dep), {
		"1.0.0": ["direct"], "2.0.0": ["unknown"], "3.0.0": ["unknown"], "4.0.0": ["unknown"],
	});
	assert.deepEqual(dep, before);
	assert.deepEqual(versionRelationsFor({ versions: ["1.0.0"], scope: "prod", isDev: true }), { "1.0.0": ["unknown"] });
});
