/**
 * Maven mediation, module by module (lib/maven-reactor.js + lib/transitive.js), against the
 * truth `mvn dependency:tree` gives for each shape. Every case reproduces a false positive or
 * a false negative an audit found in the previous global-pass design. Zero network.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { G, MC, upstream, writeLocal, run, versionsOf } = require("./helpers/maven-scenario");

const leaf = (a, v, extra = {}) => ({ g: G, a, v, ...extra });
const dep = (a, v, extra = {}) => ({ a, v, ...extra });
const local = (a, extra = {}) => ({ g: "local", a, v: "1", ...extra });

test("nearest wins, deterministically: depth 2 beats depth 3 whatever the fetch latency", async () => {
	const R = upstream([leaf("A", "1", { deps: [dep("C", "1")] }), leaf("C", "1", { deps: [dep("D", "3.0")] }),
		leaf("B", "1", { deps: [dep("D", "2.0")] }), leaf("D", "2.0"), leaf("D", "3.0")]);
	const dir = writeLocal({ "pom.xml": local("proj", { deps: [dep("A", "1"), dep("B", "1")] }) });
	for (const delay of [0, 150]) {
		const r = await run(dir, R, { delays: { [`${MC}/scratch/test/B/1/B-1.pom`]: delay } });
		assert.deepEqual(versionsOf(r, "D"), ["2.0"], `B's POM delayed ${delay} ms`);
	}
});

test("same depth: the FIRST declared keeps its version; a wider later path only widens the scope (and its subtree)", async () => {
	const R = upstream([leaf("TR", "1", { deps: [dep("M", "1.0")] }), leaf("M", "1.0", { deps: [dep("K", "1.0")] }),
		leaf("CR", "1", { deps: [dep("M", "2.0")] }), leaf("M", "2.0", { deps: [dep("K", "2.0")] }), leaf("K", "1.0"), leaf("K", "2.0")]);
	const testFirst = await run(writeLocal({ "pom.xml": local("proj", { deps: [dep("TR", "1", { scope: "test" }), dep("CR", "1")] }) }), R);
	assert.deepEqual(versionsOf(testFirst, "M"), ["1.0"]);
	assert.equal(testFirst.get(`${G}:M`).isDev, false, "widened to compile by CR");
	assert.deepEqual(versionsOf(testFirst, "K"), ["1.0"]);
	assert.equal(testFirst.get(`${G}:K`).isDev, false, "the winner's subtree is widened too");
	const compileFirst = await run(writeLocal({ "pom.xml": local("proj", { deps: [dep("CR", "1"), dep("TR", "1", { scope: "test" })] }) }), R);
	assert.deepEqual(versionsOf(compileFirst, "M"), ["2.0"]);
	assert.deepEqual(versionsOf(compileFirst, "K"), ["2.0"]);
});

test("provided dependencies and their transitives may execute in production", async () => {
	const R = upstream([leaf("P", "1", { deps: [dep("Q", "1")] }), leaf("Q", "1")]);
	const r = await run(writeLocal({ "pom.xml": local("proj", { deps: [dep("P", "1", { scope: "provided" })] }) }), R);
	assert.equal(r.get(`${G}:P`).isDev, false);
	assert.equal(r.get(`${G}:Q`).isDev, false);
});

test("a version RANGE resolves to the highest published version inside it — never scanned as a literal", async () => {
	const R = upstream([leaf("S", "1", { deps: [dep("T", "[1.0,2.0)")] }), leaf("T", "1.2"), leaf("R", "1.5")],
		{ [`${G}:R`]: ["1.0", "1.5", "2.0"], [`${G}:T`]: ["1.0", "1.2", "2.5"] });
	const r = await run(writeLocal({ "pom.xml": local("proj", { deps: [dep("R", "[1.0,2.0)"), dep("S", "1")] }) }), R);
	assert.deepEqual(versionsOf(r, "R"), ["1.5"]);
	assert.deepEqual(versionsOf(r, "T"), ["1.2"]);
	const unresolvable = await run(writeLocal({ "pom.xml": local("proj", { deps: [dep("R", "[1.0,2.0)")] }) }), upstream([]));
	assert.deepEqual(versionsOf(unresolvable, "R"), [], "no metadata → unknown version, not a range-as-version");
	assert.equal(unresolvable.get(`${G}:R`).version, null);
});

test("an upstream child redeclaring an inherited parent dependency overrides it", async () => {
	const R = upstream([leaf("P", "1", { packaging: "pom", deps: [dep("X", "1.0")] }),
		{ parent: { g: G, a: "P", v: "1" }, a: "C", deps: [dep("X", "2.0")] }, leaf("X", "1.0"), leaf("X", "2.0")]);
	const r = await run(writeLocal({ "pom.xml": local("proj", { deps: [dep("C", "1")] }) }), R);
	assert.deepEqual(versionsOf(r, "X"), ["2.0"]);
});

test("upstream depMgmt: an explicit entry beats an imported BOM, and the first imported BOM wins", async () => {
	const R = upstream([
		leaf("BOM1", "1", { packaging: "pom", depMgmt: [dep("X", "1.0"), dep("Y", "1.0")] }),
		leaf("BOM2", "1", { packaging: "pom", depMgmt: [dep("X", "2.0"), dep("Y", "2.0")] }),
		leaf("U", "1", { depMgmt: [dep("X", "1.0"), dep("BOM1", "1", { type: "pom", scope: "import" }), dep("BOM2", "1", { type: "pom", scope: "import" })], deps: [dep("X"), dep("Y")] }),
		leaf("X", "1.0"), leaf("X", "2.0"), leaf("Y", "1.0"), leaf("Y", "2.0")]);
	const r = await run(writeLocal({ "pom.xml": local("proj", { deps: [dep("U", "1")] }) }), R);
	assert.deepEqual(versionsOf(r, "X"), ["1.0"]);
	assert.deepEqual(versionsOf(r, "Y"), ["1.0"]);
});

test("${project.parent.version} in an upstream POM resolves", async () => {
	const R = upstream([leaf("PP", "3", { packaging: "pom" }), { parent: { g: G, a: "PP", v: "3" }, a: "CC", deps: [dep("SIB", "${project.parent.version}")] }, leaf("SIB", "3")]);
	const r = await run(writeLocal({ "pom.xml": local("proj", { deps: [dep("CC", "3")] }) }), R);
	assert.deepEqual(versionsOf(r, "SIB"), ["3"]);
});

test("a module overriding a managed version: the overridden value is on no classpath", async () => {
	const R = upstream([leaf("X", "1.0"), leaf("X", "2.0"), leaf("Z", "1.0"), leaf("Z", "2.0"), leaf("bomlib", "1", { packaging: "pom", depMgmt: [dep("Z", "1.0")] })]);
	const r = await run(writeLocal({
		"pom.xml": local("root", { packaging: "pom", modules: ["m"], depMgmt: [dep("X", "1.0"), dep("bomlib", "1", { type: "pom", scope: "import" })] }),
		"m/pom.xml": { parent: { g: "local", a: "root", v: "1" }, a: "m", depMgmt: [dep("X", "2.0"), dep("Z", "2.0")], deps: [dep("X"), dep("Z")] },
	}), R);
	assert.deepEqual(versionsOf(r, "X"), ["2.0"]);
	assert.deepEqual(versionsOf(r, "Z"), ["2.0"]);
	// path.join: the manifest path is a native path (m\\pom.xml on Windows).
	assert.ok(r.get(`${G}:X`).manifestPaths.every(p => p.endsWith(path.join("m", "pom.xml"))), "defined in m, not in the root that only manages it");
});

test("a local BOM module overridden by a child: only the child's version", async () => {
	const R = upstream([leaf("Z", "1.0"), leaf("Z", "2.0")]);
	const r = await run(writeLocal({
		"pom.xml": local("root", { packaging: "pom", modules: ["bom", "m"], depMgmt: [{ g: "local", a: "bom", v: "1", type: "pom", scope: "import" }] }),
		"bom/pom.xml": local("bom", { packaging: "pom", depMgmt: [dep("Z", "1.0")] }),
		"m/pom.xml": { parent: { g: "local", a: "root", v: "1" }, a: "m", depMgmt: [dep("Z", "2.0")], deps: [dep("Z")] },
	}), R);
	assert.deepEqual(versionsOf(r, "Z"), ["2.0"]);
});

test("independent projects under one root: each external parent versions ITS project only", async () => {
	const R = upstream([leaf("P1", "1", { packaging: "pom", depMgmt: [dep("X", "1.0")] }), leaf("P2", "2", { packaging: "pom", depMgmt: [dep("X", "2.0")] }),
		leaf("X", "1.0"), leaf("X", "2.0"), leaf("L", "1", { deps: [dep("X", "0.5")] }), leaf("X", "0.5")]);
	const r = await run(writeLocal({
		"projA/pom.xml": { parent: { g: G, a: "P1", v: "1", relativePath: "" }, g: "local", a: "projA", v: "1", deps: [dep("X")] },
		"projB/pom.xml": { parent: { g: G, a: "P2", v: "2", relativePath: "" }, g: "local", a: "projB", v: "1", deps: [dep("X")] },
		"projC/pom.xml": local("projC", { deps: [dep("L", "1")] }),
	}), R);
	assert.deepEqual(versionsOf(r, "X"), ["0.5", "1.0", "2.0"]);
	const x = r.get(`${G}:X`);
	assert.ok(x.versionPaths["1.0"].every(p => p.includes("projA")) && x.versionPaths["2.0"].every(p => p.includes("projB")));
});

test("a project's property override reaches its own external parent only", async () => {
	const R = upstream([leaf("P4", "1", { packaging: "pom", props: { "y.version": "1.0" }, depMgmt: [dep("Y", "${y.version}")] }), leaf("Y", "1.0"), leaf("Y", "1.5")]);
	const r = await run(writeLocal({
		"projA/pom.xml": { parent: { g: G, a: "P4", v: "1", relativePath: "" }, g: "local", a: "projA", v: "1", props: { "y.version": "1.5" }, deps: [dep("Y")] },
		"projB/pom.xml": { parent: { g: G, a: "P4", v: "1", relativePath: "" }, g: "local", a: "projB", v: "1", deps: [dep("Y")] },
	}), R);
	assert.deepEqual(versionsOf(r, "Y"), ["1.0", "1.5"]);
});

test("a pin in an unrelated project does not re-version another project's transitive", async () => {
	const R = upstream([leaf("L", "1", { deps: [dep("X", "0.5")] }), leaf("X", "0.5"), leaf("X", "9.0")]);
	const files = {
		"projA/pom.xml": local("projA", { deps: [dep("L", "1")] }),
		"projB/pom.xml": local("projB", { depMgmt: [dep("X", "9.0")], deps: [dep("L", "1", { scope: "test" })] }),
	};
	const all = await run(writeLocal(files), R);
	assert.deepEqual(versionsOf(all, "X"), ["0.5", "9.0"]);
	const noTest = await run(writeLocal(files), R, { includeTestDeps: false });
	assert.deepEqual(versionsOf(noTest, "X"), ["0.5"], "9.0 only exists on projB's test classpath");
});

test("an external parent's own <dependencies> are on the classpath", async () => {
	const R = upstream([leaf("P3", "1", { packaging: "pom", deps: [dep("Y", "1.0")] }), leaf("Y", "1.0"), leaf("W", "1")]);
	const r = await run(writeLocal({ "pom.xml": { parent: { g: G, a: "P3", v: "1", relativePath: "" }, g: "local", a: "proj", v: "1", deps: [dep("W", "1")] } }), R);
	assert.deepEqual(versionsOf(r, "Y"), ["1.0"]);
});

test("a bare local dependency takes the scope its managed entry gives it (test → dev, subtree too)", async () => {
	const R = upstream([leaf("Q", "1", { deps: [dep("Q2", "1")] }), leaf("Q2", "1")]);
	const r = await run(writeLocal({
		"pom.xml": local("root", { packaging: "pom", modules: ["m"], depMgmt: [dep("Q", "1", { scope: "test" })] }),
		"m/pom.xml": { parent: { g: "local", a: "root", v: "1" }, a: "m", deps: [dep("Q")] },
	}), R);
	assert.equal(r.get(`${G}:Q`).isDev, true);
	assert.equal(r.get(`${G}:Q2`).isDev, true);
});

test("an OPTIONAL direct dependency is on its own module's classpath, with its subtree", async () => {
	const R = upstream([leaf("OPT", "1", { deps: [dep("OD", "1.0")] }), leaf("OD", "1.0"), leaf("OD", "2.0"), leaf("OTHER", "1", { deps: [dep("OD", "2.0")] })]);
	const r = await run(writeLocal({
		"projA/pom.xml": local("projA", { deps: [dep("OPT", "1", { optional: true })] }),
		"projB/pom.xml": local("projB", { deps: [dep("OTHER", "1")] }),
	}), R);
	assert.deepEqual(versionsOf(r, "OD"), ["1.0", "2.0"]);
});

test("an activeByDefault profile's property overrides the main <properties>", async () => {
	const R = upstream([leaf("X", "1.0"), leaf("X", "2.0")]);
	const r = await run(writeLocal({ "pom.xml": local("proj", { props: { "x.version": "1.0" }, deps: [dep("X", "${x.version}")],
		profiles: [{ id: "default", activeByDefault: true, props: { "x.version": "2.0" } }] }) }), R);
	assert.deepEqual(versionsOf(r, "X"), ["2.0"]);
});
