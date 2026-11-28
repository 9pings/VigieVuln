const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeSpdx, classify, resolveDepLicense, assessLicenses, splitExpression } = require("../lib/inventory/license-policy");

test("normalizeSpdx maps free-form strings to canonical SPDX ids", () => {
	assert.equal(normalizeSpdx("MIT"), "MIT");
	assert.equal(normalizeSpdx("The Apache Software License, Version 2.0"), "Apache-2.0");
	assert.equal(normalizeSpdx("GPLv3"), "GPL-3.0");
	assert.equal(normalizeSpdx("apache-2.0"), "Apache-2.0");
	assert.equal(normalizeSpdx("GPL-3.0+"), "GPL-3.0");
	assert.equal(normalizeSpdx("Some Custom Proprietary EULA"), null);
});

test("normalizeSpdx handles npm {type} objects", () => {
	assert.equal(normalizeSpdx({ type: "ISC", url: "http://x" }), "ISC");
});

test("classify assigns policy categories", () => {
	assert.equal(classify("MIT"), "permissive");
	assert.equal(classify("LGPL-3.0"), "weak-copyleft");
	assert.equal(classify("GPL-3.0"), "strong-copyleft");
	assert.equal(classify("AGPL-3.0"), "network-copyleft");
	assert.equal(classify("UNLICENSED"), "proprietary");
	assert.equal(classify("Nonsense"), "unknown");
});

test("splitExpression splits SPDX expressions and arrays", () => {
	assert.deepEqual(splitExpression("MIT OR Apache-2.0").sort(), ["Apache-2.0", "MIT"]);
	assert.deepEqual(splitExpression("(MIT AND BSD-3-Clause)").sort(), ["BSD-3-Clause", "MIT"]);
	assert.deepEqual(splitExpression(["MIT", "ISC"]).sort(), ["ISC", "MIT"]);
});

test("resolveDepLicense picks the most restrictive category", () => {
	assert.equal(resolveDepLicense("MIT OR GPL-3.0").category, "strong-copyleft");
	assert.equal(resolveDepLicense("MIT").category, "permissive");
	assert.equal(resolveDepLicense("AGPL-3.0").category, "network-copyleft");
	assert.equal(resolveDepLicense("Weird-Custom-License").category, "unknown");
	assert.equal(resolveDepLicense(null).category, "unknown");
});

test("assessLicenses groups and flags copyleft/unknown", () => {
	const { byCategory, flagged } = assessLicenses([
		{ dep: { name: "a" }, licenses: "MIT", source: "npm" },
		{ dep: { name: "b" }, licenses: "GPL-3.0", source: "npm" },
		{ dep: { name: "c" }, licenses: "AGPL-3.0", source: "pypi" },
		{ dep: { name: "d" }, licenses: "Custom EULA", source: "nuget" },
	]);
	assert.equal(byCategory.permissive.length, 1);
	assert.equal(byCategory["strong-copyleft"].length, 1);
	// b (GPL), c (AGPL), d (unknown) are flagged; a (MIT) is not.
	assert.equal(flagged.length, 3);
	assert.ok(flagged.some(e => e.dep.name === "b"));
	assert.ok(!flagged.some(e => e.dep.name === "a"));
});
