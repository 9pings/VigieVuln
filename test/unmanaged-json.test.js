const { test } = require("node:test");
const assert = require("node:assert");
const { buildFindings } = require("../lib/reports/json-export");
const { makeDepRecord } = require("../lib/inventory/dep-record");

test("JSON export includes an unmanaged inventory + summary count", () => {
	const resolved = new Map();
	const d = makeDepRecord({ ecosystem: "binary", name: "x.so", manifestPath: "/p/x.so", provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) }, declaredName: "x.so" });
	d.identity = null; d.integrity = "unknown";
	resolved.set("binary:/p/x.so", d);
	const doc = buildFindings({ resolvedDeps: resolved, projectInfo: {} });
	assert.equal(doc.summary.unmanaged, 1);
	assert.equal(doc.unmanaged.length, 1);
	assert.equal(doc.unmanaged[0].declaredName, "x.so");
	assert.equal(doc.unmanaged[0].integrity, "unknown");
});
