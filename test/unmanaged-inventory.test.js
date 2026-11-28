const { test } = require("node:test");
const assert = require("node:assert");
const { buildInventory, nameMatches } = require("../lib/inventory/unmanaged");
const { makeDepRecord } = require("../lib/inventory/dep-record");

function bin(name, identity, integrity) {
	const d = makeDepRecord({ ecosystem: "binary", name, manifestPath: `/p/${name}`, provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) }, declaredName: name });
	d.identity = identity; d.integrity = integrity; return d;
}

test("nameMatches is lenient on lib-prefix/version, catches clear mismatches", () => {
	assert.equal(nameMatches("libssl.so.1.1", "openssl"), true);
	assert.equal(nameMatches("evil.dll", "openssl"), false);
	assert.equal(nameMatches("commons-lang3.jar", "org.apache.commons:commons-lang3"), true);
});

test("buildInventory derives signals per record and ignores managed deps", () => {
	const resolved = new Map();
	resolved.set("binary:/p/a.dll", bin("a.dll", { ecosystem: "nuget", name: "A.Pkg", version: "2.0", source: "deps.dev" }, "pristine"));
	resolved.set("binary:/p/libssl.so", bin("libssl.so", { ecosystem: null, name: "openssl", version: "3.0", source: "circl:nsrl_modern", knownMalicious: false }, "known-good"));
	resolved.set("binary:/p/x.so", bin("x.so", null, "unknown"));
	resolved.set("binary:/p/evil.dll", bin("evil.dll", { ecosystem: "npm", name: "leftpad", version: "1.0", source: "deps.dev" }, "pristine"));
	resolved.set("g:a", makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0", manifestPath: "/pom.xml" }));

	const inv = buildInventory(resolved);
	assert.equal(inv.length, 4);
	const a = inv.find(e => e.declaredName === "a.dll");
	assert.equal(a.shouldBeManaged, true);          // deps.dev coord with ecosystem
	assert.equal(a.noOnlineInfo, false);
	const ssl = inv.find(e => e.declaredName === "libssl.so");
	assert.equal(ssl.shouldBeManaged, false);       // CIRCL OS file, ecosystem null
	assert.equal(ssl.nameMismatch, false);
	const x = inv.find(e => e.declaredName === "x.so");
	assert.equal(x.noOnlineInfo, true);
	const evil = inv.find(e => e.declaredName === "evil.dll");
	assert.equal(evil.nameMismatch, true);          // "evil" vs "leftpad"
});
