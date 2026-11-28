const { test } = require("node:test");
const assert = require("node:assert");
const { detectScanCompletenessWarnings } = require("../lib/scan/completeness");

function mapOf(...deps) {
	const m = new Map();
	deps.forEach((d, i) => m.set(d.coordKey || `k${i}`, d));
	return m;
}

test("flags a Maven dep with no concrete version", () => {
	const w = detectScanCompletenessWarnings(mapOf(
		{ ecosystem: "maven", groupId: "org.acme", artifactId: "lib", version: null },
	));
	assert.strictEqual(w.length, 1);
	assert.strictEqual(w[0].type, "unresolved-versions");
	assert.match(w[0].items[0].id, /org\.acme:lib/);
});

test("unresolved-version items carry WHERE they are defined (manifestPaths), merged across modules", () => {
	const w = detectScanCompletenessWarnings(mapOf(
		{ ecosystem: "maven", groupId: "g", artifactId: "a", version: "${jackson.version}", coordKey: "g:a", pomPaths: ["/p/mod-a/pom.xml"] },
		{ ecosystem: "maven", groupId: "g", artifactId: "a", version: "${jackson.version}", coordKey: "g:a#2", pomPaths: ["/p/mod-b/pom.xml"] },
		{ ecosystem: "maven", groupId: "g", artifactId: "b", version: null, coordKey: "g:b", manifestPaths: ["/p/mod-c/pom.xml"] },
	));
	const item = w[0].items.find(i => i.id.startsWith("g:a"));
	assert.ok(item, "item is an object with an id");
	// both modules that declare g:a are listed, deduped
	assert.deepStrictEqual(item.manifestPaths.sort(), ["/p/mod-a/pom.xml", "/p/mod-b/pom.xml"]);
	const b = w[0].items.find(i => i.id.startsWith("g:b"));
	assert.deepStrictEqual(b.manifestPaths, ["/p/mod-c/pom.xml"]);
});

test("flags an unresolved ${property} version", () => {
	const w = detectScanCompletenessWarnings(mapOf(
		{ ecosystem: "maven", groupId: "g", artifactId: "a", version: "${jackson.version}" },
	));
	assert.strictEqual(w.length, 1);
});

test("does NOT flag native binaries (provenance:binary, no version by design)", () => {
	const w = detectScanCompletenessWarnings(mapOf(
		{ ecosystem: "binary", provenance: "binary", groupId: "", artifactId: "libeay32.dll", version: null },
		{ ecosystem: "binary", provenance: "binary", groupId: "", artifactId: "openssl.exe", version: null },
	));
	assert.strictEqual(w.length, 0);
});

test("does NOT flag non-Maven ecosystems or resolved Maven deps", () => {
	const w = detectScanCompletenessWarnings(mapOf(
		{ ecosystem: "npm", name: "left-pad", version: null },
		{ ecosystem: "pypi", name: "flask", version: null },
		{ ecosystem: "maven", groupId: "g", artifactId: "ok", version: "1.2.3" },
		{ ecosystem: "maven", scope: "import", groupId: "g", artifactId: "bom", version: null },
	));
	assert.strictEqual(w.length, 0);
});
