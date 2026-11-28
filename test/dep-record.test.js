const test = require("node:test");
const assert = require("node:assert");
const { makeDepRecord, coordKeyFor } = require("../lib/inventory/dep-record");

test("maven depRecord builds bare g:a coordKey and keeps groupId/artifactId aliases", () => {
	const d = makeDepRecord({ ecosystem: "maven", namespace: "org.apache", name: "log4j", version: "2.14.0", manifestPath: "/p/pom.xml", scope: "compile" });
	assert.strictEqual(d.coordKey, "org.apache:log4j");   // clé Maven brute (pas de préfixe)
	assert.strictEqual(d.groupId, "org.apache");   // alias rétro-compat
	assert.strictEqual(d.artifactId, "log4j");      // alias rétro-compat
	assert.deepStrictEqual(d.versions, ["2.14.0"]);
	assert.strictEqual(d.isDev, false);
});

test("npm depRecord has empty namespace and npm-prefixed coordKey", () => {
	const d = makeDepRecord({ ecosystem: "npm", namespace: "", name: "lodash", version: "4.17.20", manifestPath: "/p/package-lock.json", scope: "prod" });
	assert.strictEqual(d.coordKey, "npm:lodash");
	assert.strictEqual(d.groupId, "");
	assert.strictEqual(d.artifactId, "lodash");
});

test("coordKeyFor composes ecosystem + namespace + name", () => {
	assert.strictEqual(coordKeyFor("composer", "guzzlehttp", "guzzle"), "composer:guzzlehttp/guzzle");
	assert.strictEqual(coordKeyFor("pypi", "", "requests"), "pypi:requests");
	assert.strictEqual(coordKeyFor("nuget", "", "Newtonsoft.Json"), "nuget:newtonsoft.json");
});

test("pomPaths shares the manifestPaths array reference (push stays in sync)", () => {
	const d = makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0", manifestPath: "/p/pom.xml" });
	d.manifestPaths.push("/q/pom.xml");
	assert.deepStrictEqual(d.pomPaths, ["/p/pom.xml", "/q/pom.xml"]);
});

test("binary provenance is keyed by physical path and carries hashes + declaredName", () => {
	const d = makeDepRecord({
		ecosystem: "binary", name: "libssl.so.1.1", manifestPath: "/p/libssl.so.1.1",
		provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) },
		declaredName: "libssl.so.1.1",
	});
	assert.equal(d.coordKey, "binary:/p/libssl.so.1.1");
	assert.equal(d.provenance, "binary");
	assert.deepEqual(d.hashes, { sha1: "a".repeat(40), sha256: "b".repeat(64) });
	assert.equal(d.declaredName, "libssl.so.1.1");
	assert.deepEqual(d.manifestPaths, ["/p/libssl.so.1.1"]);
});

test("manifest provenance is unchanged (no hashes field bleed)", () => {
	const d = makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0", manifestPath: "/p/pom.xml" });
	assert.equal(d.coordKey, "g:a");
	assert.equal(d.provenance, "manifest");
	assert.equal(d.hashes, null);
	assert.equal(d.declaredName, null);
});
