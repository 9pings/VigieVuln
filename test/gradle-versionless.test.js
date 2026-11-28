const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const gradle = require("../lib/codecs/gradle.codec");
const { expandWithTransitives } = require("../lib/advisories/cve-match");
const { makeDepRecord } = require("../lib/inventory/dep-record");
const { detectScanCompletenessWarnings } = require("../lib/scan/completeness");

// A local fake Maven repository: exercise real POM parsing and graph traversal.
async function fixture(t, script, graph, otherFiles = {}) {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-gradle-versionless-"));
	t.after(() => { require("../lib/cache/db").closeCacheDbs(); fs.rmSync(root, { recursive: true, force: true }); });
	for (const [name, text] of Object.entries({ "build.gradle.kts": script, ...otherFiles })) {
		fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
		fs.writeFileSync(path.join(root, name), text);
	}
	const { deps } = await gradle.collect(root);
	const requested = [];
	const fetcher = async url => {
		const p = new URL(url).pathname.split("/");
		const key = `${p.at(-3)}:${p.at(-2)}`;
		requested.push(key);
		const children = graph[key];
		if (!children) return { ok: false, status: 404, text: async () => "" };
		const body = `<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>${p.at(-3)}</artifactId><version>${p.at(-2)}</version><dependencies>${children.map(([name, version, scope]) =>
			`<dependency><groupId>example</groupId><artifactId>${name}</artifactId>${version ? `<version>${version}</version>` : ""}${scope ? `<scope>${scope}</scope>` : ""}</dependency>`).join("")}</dependencies></project>`;
		return { ok: true, status: 200, text: async () => body };
	};
	return { deps, root, requested, opts: { fetcher, cacheDir: path.join(root, "cache"), maxDepth: 10, includeTestDeps: true } };
}

test("Gradle versionless direct gets a graph version and retains direct attribution", async t => {
	const f = await fixture(t, `dependencies { implementation("example:parent:1.0"); implementation("example:child") }`, {
		"parent:1.0": [["child", "2.0"]], "child:2.0": [],
	});
	const original = f.deps.get("example:child");
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child"), original);
	assert.equal(original.version, "2.0");
	assert.deepEqual(original.versions, ["2.0"]);
	assert.equal(original.scope, "compile");
	assert.equal(original.isDev, false);
	assert.equal(original.ecosystemType, "gradle");
	assert.deepEqual(original.versionPaths, { "2.0": [path.join(f.root, "build.gradle.kts")] });
	assert.deepEqual(original.versionSource, { via: "gradle-graph", paths: [["example:parent"]] });
	assert.equal(detectScanCompletenessWarnings(f.deps).some(w => w.type === "unresolved-versions"), false);
});

test("Gradle takes the higher numeric request even when it is further away or declared later", async t => {
	for (const roots of ['implementation("example:near:1.0"); implementation("example:far:1.0")', 'implementation("example:far:1.0"); implementation("example:near:1.0")']) {
		const f = await fixture(t, `dependencies { ${roots}; implementation("example:child") }`, {
			"near:1.0": [["child", "1.9"]], "far:1.0": [["middle", "1.0"]], "middle:1.0": [["child", "1.10"]],
			"child:1.9": [["old-only", "1.0"]], "child:1.10": [["new-only", "1.0"]], "old-only:1.0": [], "new-only:1.0": [],
		});
		await expandWithTransitives(f.deps, f.opts);
		assert.equal(f.deps.get("example:child").version, "1.10");
		assert.ok(f.deps.has("example:new-only"));
		assert.ok(!f.deps.has("example:old-only"), "discarded version's children do not enter the scan");
	}
});

test("Maven declarations do not inherit versions from transitive requests", async t => {
	const f = await fixture(t, "", { "parent:1.0": [["child", "2.0"]], "child:2.0": [] });
	for (const [name, version] of [["parent", "1.0"], ["child", null]]) {
		const d = makeDepRecord({ ecosystem: "maven", namespace: "example", name, version, manifestPath: path.join(f.root, "pom.xml") });
		f.deps.set(d.coordKey, d);
	}
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
});

test("Gradle considers an extra numeric version part higher, including zero", async t => {
	for (const versions of [["1.0.0", "1.0"], ["1.0", "1.0.0"]]) {
		const f = await fixture(t, `dependencies { implementation("example:a:1.0"); implementation("example:b:1.0"); implementation("example:child") }`, {
			"a:1.0": [["child", versions[0]]], "b:1.0": [["child", versions[1]]], "child:1.0": [], "child:1.0.0": [],
		});
		await expandWithTransitives(f.deps, f.opts);
		assert.equal(f.deps.get("example:child").version, "1.0.0");
	}
});

test("a test-only request cannot supply a production version", async t => {
	const f = await fixture(t, `dependencies { testImplementation("example:parent:1.0"); implementation("example:child") }`, {
		"parent:1.0": [["child", "2.0"]], "child:2.0": [],
	});
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
	assert.ok(detectScanCompletenessWarnings(f.deps).some(w => w.type === "unresolved-versions"));
});

test("a production request can supply a test declaration without changing its scope", async t => {
	const f = await fixture(t, `dependencies { implementation("example:parent:1.0"); testImplementation("example:child") }`, {
		"parent:1.0": [["child", "2.0"]], "child:2.0": [],
	});
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, "2.0");
	assert.equal(f.deps.get("example:child").scope, "test");
	assert.equal(f.deps.get("example:child").isDev, true);
});

test("a runtime-only request cannot silently resolve a compile classpath", async t => {
	for (const declaration of ['runtimeOnly("example:parent:1.0")', 'implementation("example:parent:1.0")']) {
		const f = await fixture(t, `dependencies { ${declaration}; implementation("example:child") }`, {
			"parent:1.0": [["child", "2.0", "runtime"]], "child:2.0": [],
		});
		await expandWithTransitives(f.deps, f.opts);
		assert.equal(f.deps.get("example:child").version, null);
	}
});

test("another module or annotation processor cannot supply the missing version", async t => {
	for (const setup of [
		{ script: 'dependencies { implementation("example:child") }', files: { "other/build.gradle.kts": 'dependencies { implementation("example:parent:1.0") }' } },
		{ script: 'dependencies { implementation("example:child"); annotationProcessor("example:parent:1.0") }', files: {} },
	]) {
		const f = await fixture(t, setup.script, { "parent:1.0": [["child", "2.0"]], "child:2.0": [] }, setup.files);
		await expandWithTransitives(f.deps, f.opts);
		assert.equal(f.deps.get("example:child").version, null);
	}
});

test("different compile and runtime selections remain explicitly unresolved", async t => {
	const f = await fixture(t, `dependencies { implementation("example:a:1.0"); runtimeOnly("example:b:1.0"); implementation("example:child") }`, {
		"a:1.0": [["child", "1.0"]], "b:1.0": [["child", "2.0"]], "child:1.0": [], "child:2.0": [],
	});
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
	assert.equal(f.deps.get("example:child").versionSource, undefined);
});

test("missing POMs and unstable request graphs do not fabricate versions", async t => {
	for (const graph of [{}, { "parent:1.0": [["child", "1.0"]], "child:1.0": [["child", "2.0"]], "child:2.0": [] }]) {
		const f = await fixture(t, `dependencies { implementation("example:parent:1.0"); implementation("example:child") }`, graph);
		await expandWithTransitives(f.deps, f.opts);
		assert.equal(f.deps.get("example:child").version, null);
		assert.deepEqual(f.deps.get("example:child").versions, []);
	}
});

test("a partially unavailable or depth-limited graph cannot establish the highest request", async t => {
	const script = 'dependencies { implementation("example:a:1.0"); implementation("example:b:1.0"); implementation("example:child") }';
	const f = await fixture(t, script, { "a:1.0": [["child", "1.0"]], "child:1.0": [] });
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
	assert.ok(detectScanCompletenessWarnings(f.deps).some(w => w.type === "unresolved-versions"));
	const limited = await fixture(t, script, {
		"a:1.0": [["child", "1.0"]], "b:1.0": [["middle", "1.0"]],
		"middle:1.0": [["child", "2.0"]], "child:1.0": [], "child:2.0": [],
	});
	await expandWithTransitives(limited.deps, { ...limited.opts, maxDepth: 1 });
	assert.equal(limited.deps.get("example:child").version, null);
});

test("a cyclic imported POM cannot establish a graph version", async t => {
	const f = await fixture(t, 'dependencies { implementation("example:parent:1.0"); implementation("example:child") }', { "child:1.0": [] });
	const fallback = f.opts.fetcher;
	f.opts.fetcher = async url => url.includes("/parent/1.0/parent-1.0.pom") ? {
		ok: true, status: 200, text: async () => `<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>parent</artifactId><version>1.0</version>
		<dependencyManagement><dependencies><dependency><groupId>example</groupId><artifactId>parent</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
		<dependencies><dependency><groupId>example</groupId><artifactId>child</artifactId><version>1.0</version></dependency></dependencies></project>`,
	} : fallback(url);
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
});

test("an intermediate conflict stays unknown unless a root pin settles it", async t => {
	const script = 'dependencies { implementation("example:a:1.0"); implementation("example:b:1.0"); implementation("example:child") }';
	const graph = {
		"a:1.0": [["middle", "1.0"]], "b:1.0": [["middle", "2.0"]],
		"middle:1.0": [["child", "1.0"]], "middle:2.0": [["child", "2.0"]],
		"child:1.0": [], "child:2.0": [],
	};
	const f = await fixture(t, script, graph);
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
	const pinned = await fixture(t, script, graph);
	await expandWithTransitives(pinned.deps, { ...pinned.opts, bomDepMgmt: new Map([["example:middle", { version: "2.0" }]]) });
	assert.equal(pinned.deps.get("example:child").version, "2.0");
});

test("an ordinary direct version does not force an intermediate module", async t => {
	const f = await fixture(t, `dependencies {
 implementation("example:middle:1.0")
 implementation("example:parent:1.0")
 implementation("example:child")
}`, {
		"middle:1.0": [["child", "1.0"]], "middle:2.0": [["child", "2.0"]],
		"parent:1.0": [["middle", "2.0"]], "child:1.0": [], "child:2.0": [],
	});
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
	assert.ok(detectScanCompletenessWarnings(f.deps).some(w => w.type === "unresolved-versions"));
});

test("an intermediate conflict is safe when traversal selected the highest numeric request", async t => {
	for (const [higher, lower] of [["1.85", "1.83"], ["1.0.0", "1.0"]]) {
		const f = await fixture(t, `dependencies {
 implementation("example:middle:${higher}")
 implementation("example:parent:1.0")
 implementation("example:child")
}`, {
			[`middle:${higher}`]: [["child", "2.0"]], [`middle:${lower}`]: [["child", "1.0"]],
			"parent:1.0": [["middle", lower]], "child:1.0": [], "child:2.0": [],
		});
		await expandWithTransitives(f.deps, f.opts);
		assert.equal(f.deps.get("example:child").version, "2.0");
	}
});

test("test declaration exclusions cannot widen the production path", async t => {
	const f = await fixture(t, `dependencies {
 implementation("example:parent:1.0") { exclude(group = "example", module = "child") }
 testImplementation("example:parent:1.0")
 implementation("example:child")
}`, { "parent:1.0": [["child", "2.0"]], "child:2.0": [] });
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
});

test("an unresolved explicit variable is not a versionless declaration", async t => {
	const f = await fixture(t, 'dependencies { implementation("example:parent:1.0"); implementation("example:child:$missing") }', {
		"parent:1.0": [["child", "2.0"]], "child:2.0": [],
	});
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
	assert.equal(f.deps.get("example:child").versionUnresolved, true);
});

test("an unknown root on the same classpath prevents graph inference", async t => {
	const graph = { "parent:1.0": [["child", "2.0"]], "child:2.0": [] };
	const f = await fixture(t, 'dependencies { implementation("example:parent:1.0"); implementation("example:unknown:$missing"); implementation("example:child") }', graph);
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
	const independent = await fixture(t, 'dependencies { implementation("example:parent:1.0"); annotationProcessor("example:unknown:$missing"); implementation("example:child") }', graph);
	await expandWithTransitives(independent.deps, independent.opts);
	assert.equal(independent.deps.get("example:child").version, "2.0");
});

test("an unresolved versionless root blocks other inference on its classpath", async t => {
	const f = await fixture(t, 'dependencies { implementation("example:parent:1.0"); implementation("example:unknown"); implementation("example:child") }', {
		"parent:1.0": [["child", "2.0"]], "child:2.0": [],
	});
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:unknown").version, null);
	assert.equal(f.deps.get("example:child").version, null);
});

test("a merged multi-module root cannot be silently omitted from its own classpath", async t => {
	const f = await fixture(t, 'dependencies { implementation("example:parent:1.0"); implementation("example:ambiguous:1.0"); implementation("example:child") }', {
		"parent:1.0": [["child", "2.0"]], "ambiguous:1.0": [], "child:2.0": [],
	}, { "other/build.gradle.kts": 'dependencies { implementation("example:ambiguous:2.0") }' });
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
});

test("explicit versions and lockfiles remain authoritative", async t => {
	for (const files of [{}, { "gradle.lockfile": "example:parent:1.0=runtimeClasspath\nexample:child:1.0=runtimeClasspath\n" }]) {
		const f = await fixture(t, 'dependencies { implementation("example:parent:1.0"); implementation("example:child:1.0") }', {
			"parent:1.0": [["child", "2.0"]], "child:1.0": [], "child:2.0": [],
		}, files);
		await expandWithTransitives(f.deps, f.opts);
		assert.equal(f.deps.get("example:child").version, "1.0");
		assert.equal(f.deps.get("example:child").versionSource, undefined);
		if (Object.keys(files).length) assert.equal(f.requested.length, 0);
	}
});

test("excluded branches do not supply versions", async t => {
	const f = await fixture(t, `dependencies {
 implementation("example:parent:1.0") { exclude(group = "example", module = "child") }
 implementation("example:child")
}`, { "parent:1.0": [["child", "2.0"]], "child:2.0": [] });
	await expandWithTransitives(f.deps, f.opts);
	assert.equal(f.deps.get("example:child").version, null);
});

test("unknown and conflicting qualified requests remain unresolved", async t => {
	for (const version of [null, "2.0-rc1"]) {
		const f = await fixture(t, `dependencies { implementation("example:a:1.0"); implementation("example:b:1.0"); implementation("example:child") }`, {
			"a:1.0": version ? [["child", "2.0"]] : [], "b:1.0": version ? [["child", version]] : [],
			"child:2.0": [], "child:2.0-rc1": [],
		});
		await expandWithTransitives(f.deps, f.opts);
		assert.equal(f.deps.get("example:child").version, null);
	}
});

test("the only filter also applies to versionless backfill", async t => {
	const f = await fixture(t, `dependencies { implementation("example:parent:1.0"); implementation("example:child") }`, {
		"parent:1.0": [["child", "2.0"]], "child:2.0": [],
	});
	await expandWithTransitives(f.deps, { ...f.opts, only: d => d.name !== "child" });
	assert.equal(f.deps.get("example:child").version, null);
});

test("graph version provenance is retained in JSON and shown safely in HTML and Word", async t => {
	const f = await fixture(t, `dependencies { implementation("example:parent:1.0"); implementation("example:child") }`, {
		"parent:1.0": [["child", "2.0"]], "child:2.0": [],
	});
	await expandWithTransitives(f.deps, f.opts);
	const dep = f.deps.get("example:child");
	const payload = {
		resolvedDeps: f.deps, cveMatches: [{ dep, cve: { id: "CVE-2099-0001", severity: "HIGH", score: 7.5, description: "fixture" }, confidence: "exact" }],
		projectInfo: { name: "fixture", src: f.root },
	};
	const doc = require("../lib/reports/json-export").buildFindings(payload);
	assert.deepEqual(doc.cve[0].dep.versionSource, dep.versionSource);
	assert.equal(doc.cve[0].dep.scope, "compile");
	const { generateHtmlReport, generateWordReport } = require("../lib/reports/cve-report");
	for (const render of [generateHtmlReport, generateWordReport]) {
		const report = render(payload);
		assert.match(report, /version resolved through:/);
		assert.match(report, /<code>example:parent<\/code>/);
		assert.match(report, /build\.gradle\.kts/);
		assert.match(report, /By Gradle descriptor/);
		assert.doesNotMatch(report, /By \*\.versions\.toml/);
		const french = render({ ...payload, locale: "fr" });
		assert.match(french, /version résolue via/);
		assert.match(french, /Par fichier de description Gradle/);
	}
	dep.versionSource.paths = [["example:<script>bad</script>"]];
	const escaped = generateHtmlReport(payload);
	assert.match(escaped, /example:&lt;script&gt;bad&lt;\/script&gt;/);
	assert.ok(!escaped.includes("example:<script>bad</script>"));
});
