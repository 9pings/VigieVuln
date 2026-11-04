const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { collectNpmDeps } = require("../lib/codecs/npm/collect");

function project(t, files) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "npm-relations-"));
	t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
	for (const [name, body] of Object.entries(files)) {
		const file = path.join(dir, name);
		fs.mkdirSync(path.dirname(file), { recursive: true });
		fs.writeFileSync(file, typeof body === "string" ? body : JSON.stringify(body));
	}
	return dir;
}

for (const lockfileVersion of [1, 2, 3]) {
	test(`npm v${lockfileVersion}: relations survive version/name merges independently of isDev`, t => {
		const pkg = { dependencies: { parent: "1.0.0" }, devDependencies: { target: "2.0.0" } };
		const lock = lockfileVersion === 1 ? {
			dependencies: {
				target: { version: "2.0.0", dev: true },
				parent: { version: "1.0.0", dependencies: {
					target: { version: "1.0.0" },
					inner: { version: "1.0.0", dependencies: { target: { version: "2.0.0" } } },
				} },
			},
		} : {
			packages: {
				"": pkg,
				"node_modules/target": { version: "2.0.0", dev: true },
				"node_modules/parent": { version: "1.0.0" },
				"node_modules/parent/node_modules/target": { version: "1.0.0" },
				"node_modules/parent/node_modules/inner": { version: "1.0.0" },
				"node_modules/parent/node_modules/inner/node_modules/target": { version: "2.0.0" },
			},
		};
		const dir = project(t, { "package.json": pkg, "package-lock.json": { lockfileVersion, ...lock } });
		const dep = collectNpmDeps(dir).get("npm:target");
		assert.deepEqual(dep.versionRelations, { "2.0.0": ["direct", "transitive"], "1.0.0": ["transitive"] });
		assert.equal(dep.isDev, false);
		assert.equal(dep.version, "2.0.0");
		assert.deepEqual(dep.versions, ["2.0.0", "1.0.0"]);
		assert.deepEqual(dep.versionScopes["2.0.0"], ["dev", "transitive"]);
		// Filtering still operates on the original occurrence scopes/dev flags.
		const filtered = collectNpmDeps(dir, { ignoreTest: true }).get("npm:target");
		assert.deepEqual(filtered.versionRelations, { "1.0.0": ["transitive"], "2.0.0": ["transitive"] });
		assert.equal(collectNpmDeps(dir, { deps2Exclude: /^target$/ }).has("npm:target"), false);
	});
}

test("npm: A direct and B transitive remain separate even when B wins the record version", t => {
	const dir = project(t, { "package-lock.json": {
		lockfileVersion: 3,
		packages: {
			"": { dependencies: { target: "1.0.0" } },
			"node_modules/target": { version: "1.0.0" },
			"node_modules/parent/node_modules/target": { version: "2.0.0", dev: true },
		},
	} });
	const dep = collectNpmDeps(dir).get("npm:target");
	assert.deepEqual(dep.versionRelations, { "1.0.0": ["direct"], "2.0.0": ["transitive"] });
	assert.equal(dep.version, "2.0.0");
	assert.equal(dep.scope, "prod");
	assert.equal(dep.isDev, false);
});

for (const lockfileVersion of [1, 3]) {
	test(`npm v${lockfileVersion}: hoisted edges prove transitive use, flags alone do not`, t => {
		const pkg = { dependencies: { parent: "1.0.0", shared: "1.0.0" } };
		const entries = {
			parent: { version: "1.0.0", [lockfileVersion === 1 ? "requires" : "dependencies"]: { shared: "1.0.0", leaf: "1.0.0" } },
			shared: { version: "1.0.0" },
			leaf: { version: "1.0.0", dev: true },
			orphan: { version: "1.0.0", dev: true },
		};
		const lock = lockfileVersion === 1 ? { dependencies: entries } : {
			packages: { "": pkg, ...Object.fromEntries(Object.entries(entries).map(([name, entry]) => [`node_modules/${name}`, entry])) },
		};
		const dir = project(t, { "package.json": pkg, "package-lock.json": { lockfileVersion, ...lock } });
		const deps = collectNpmDeps(dir);
		assert.deepEqual(deps.get("npm:shared").versionRelations, { "1.0.0": ["direct", "transitive"] });
		assert.deepEqual(deps.get("npm:leaf").versionRelations, { "1.0.0": ["transitive"] });
		assert.deepEqual(deps.get("npm:orphan").versionRelations, { "1.0.0": ["unknown"] });
	});

	test(`npm v${lockfileVersion}: standalone locks cannot prove top-level packages are direct`, t => {
		const lock = lockfileVersion === 1
			? { dependencies: { target: { version: "1.0.0" } } }
			: { packages: { "node_modules/target": { version: "1.0.0" } } };
		const dir = project(t, { "package-lock.json": { lockfileVersion, ...lock } });
		assert.deepEqual(collectNpmDeps(dir).get("npm:target").versionRelations, { "1.0.0": ["unknown"] });
	});
}

test("npm: pinned manifest dependencies are direct for every scope; ranges stay skipped", t => {
	const dir = project(t, { "package.json": {
		dependencies: { prod: "1.0.0", range: "^1.0.0" },
		devDependencies: { dev: "1.0.0" },
		optionalDependencies: { optional: "1.0.0" },
		peerDependencies: { peer: "1.0.0" },
	} });
	const deps = collectNpmDeps(dir);
	assert.equal(deps.size, 4);
	for (const dep of deps.values()) assert.deepEqual(dep.versionRelations, { "1.0.0": ["direct"] });
	assert.equal(deps.warnings[0].type, "no-lockfile");
});

test('npm optional and devOptional packages can run in production', t => {
	const root={dependencies:{prod:'1.0.0'},optionalDependencies:{optional:'1.0.0'},devDependencies:{devonly:'1.0.0'}};
	const dir=project(t,{'package.json':root,'package-lock.json':{lockfileVersion:3,packages:{
		'':root,
		'node_modules/prod':{version:'1.0.0'},
		'node_modules/optional':{version:'1.0.0',optional:true},
		'node_modules/mixed':{version:'1.0.0',devOptional:true},
		'node_modules/devonly':{version:'1.0.0',dev:true},
		'node_modules/devoptional':{version:'1.0.0',dev:true,optional:true},
	}}});
	const all=collectNpmDeps(dir),prod=collectNpmDeps(dir,{ignoreTest:true});
	assert.equal(all.get('npm:optional').isDev,false);
	assert.equal(all.get('npm:mixed').isDev,false);
	assert.equal(all.get('npm:mixed').scope,'transitive');
	assert.equal(all.get('npm:devoptional').isDev,true);
	assert.ok(prod.has('npm:optional'));assert.ok(prod.has('npm:mixed'));
	assert.ok(!prod.has('npm:devonly'));assert.ok(!prod.has('npm:devoptional'));
});

test('npm devOptional production evidence survives per-version attribution', t => {
	const root={dependencies:{parent:'1.0.0'},devDependencies:{mixed:'1.0.0'}};
	const dir=project(t,{'package.json':root,'package-lock.json':{lockfileVersion:3,packages:{
		'':root,
		'node_modules/parent':{version:'1.0.0',optionalDependencies:{mixed:'1.0.0'}},
		'node_modules/mixed':{version:'1.0.0',devOptional:true},
	}}});
	const dep=collectNpmDeps(dir).get('npm:mixed');
	assert.equal(dep.isDev,false);
	assert.equal(dep.scope,'transitive');
	assert.deepEqual([...dep.versionRelations['1.0.0']].sort(),['direct','transitive']);
	const finding={dep,cve:{id:'CVE-2099-1234'}};
	require('../lib/attribution').attributeMatchOrigins([finding]);
	assert.equal(finding.dep.isDev,false);
});

test("npm: aliases, normalized URLs and unresolved versions use the existing version keys", t => {
	const dir = project(t, { "package-lock.json": {
		lockfileVersion: 3,
		packages: {
			"": { dependencies: { alias: "1.0.0", url: "1.0.0", git: "git+https://example.test/repo" } },
			"node_modules/alias": { name: "target", version: "1.0.0" },
			"node_modules/parent/node_modules/other-alias": { name: "target", version: "2.0.0" },
			"node_modules/url": { version: "https://registry.npmjs.org/url/-/url-1.0.0.tgz" },
			"node_modules/git": { version: "git+https://example.test/repo" },
		},
	} });
	const deps = collectNpmDeps(dir);
	assert.deepEqual(deps.get("npm:target").versionRelations, { "1.0.0": ["direct"], "2.0.0": ["transitive"] });
	assert.deepEqual(deps.get("npm:url").versionRelations, { "1.0.0": ["direct"] });
	assert.deepEqual(deps.get("npm:git").versionRelations, {});
	assert.deepEqual(deps.get("npm:git").versions, []);
});

test("npm: cross-manifest evidence is deduplicated without discarding unknown occurrences", t => {
	const dir = project(t, {
		"a/package.json": { dependencies: { target: "1.0.0" } },
		"b/package-lock.json": { lockfileVersion: 1, dependencies: { target: { version: "1.0.0" } } },
		"c/package.json": { devDependencies: { target: "1.0.0" } },
	});
	const groups = ["a", "b", "c"].map(name => name === "b"
		? { packageLock: path.join(dir, name, "package-lock.json") }
		: { packageJson: path.join(dir, name, "package.json") });
	for (const manifestGroups of [groups, [...groups].reverse()]) {
		const dep = collectNpmDeps(dir, { manifestGroups }).get("npm:target");
		assert.deepEqual([...dep.versionRelations["1.0.0"]].sort(), ["direct", "unknown"]);
		assert.equal(dep.versionPaths["1.0.0"].length, 3);
	}
});

test("npm: workspace roots and scoped hoisted edges resolve to their installed occurrences", t => {
	const dir = project(t, { "package-lock.json": {
		lockfileVersion: 3,
		packages: {
			"": {},
			"packages/app": { dependencies: { "@scope/target": "2.0.0", parent: "1.0.0" } },
			"node_modules/@scope/target": { version: "1.0.0" },
			"packages/app/node_modules/@scope/target": { version: "2.0.0" },
			"packages/app/node_modules/parent": { version: "1.0.0", dependencies: { "@scope/target": "2.0.0" } },
		},
	} });
	const dep = collectNpmDeps(dir).get("npm:@scope/target");
	assert.deepEqual(dep.versionRelations, { "1.0.0": ["unknown"], "2.0.0": ["direct", "transitive"] });
});
