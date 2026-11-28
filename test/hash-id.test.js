const { test } = require("node:test");
const assert = require("node:assert");
const { sha1ToBase64, parseDepsDev, parseCircl, lookupHash } = require("../lib/providers/hashid/identify");

test("sha1ToBase64 converts a hex digest to deps.dev's base64", () => {
	assert.equal(sha1ToBase64("ba55c13d7ac2fd44df9cc8074455719a33f375b9"), "ulXBPXrC/UTfnMgHRFVxmjPzdbk=");
});

test("parseDepsDev extracts the first coordinate, normalizing the ecosystem", () => {
	const body = { results: [{ version: { versionKey: { system: "MAVEN", name: "org.apache.logging.log4j:log4j-core", version: "2.15.0" } } }] };
	assert.deepEqual(parseDepsDev(body), { ecosystem: "maven", name: "org.apache.logging.log4j:log4j-core", version: "2.15.0", source: "deps.dev" });
	assert.equal(parseDepsDev({ results: [] }), null);
	assert.equal(parseDepsDev({}), null);
});

test("parseCircl reads product/db + knownMalicious, null for not-found", () => {
	const known = { FileName: "libz.so.1", ProductCode: { ProductName: "zlib", ProductVersion: "1.2.11" }, db: "nsrl_modern" };
	assert.deepEqual(parseCircl(known), { ecosystem: null, name: "zlib", version: "1.2.11", source: "circl:nsrl_modern", trust: null, knownMalicious: false });
	assert.equal(parseCircl({ message: "Non existing SHA-256" }), null);
	const bad = { FileName: "x", KnownMalicious: ["src"], "hashlookup:trust": 10 };
	assert.equal(parseCircl(bad).knownMalicious, true);
});

test("lookupHash prefers deps.dev, falls back to CIRCL, uses injected fetcher + cache", async () => {
	const calls = [];
	const fetcher = async (url) => {
		calls.push(url);
		if (url.includes("deps.dev")) return { ok: true, json: async () => ({ results: [] }) };
		return { ok: true, json: async () => ({ FileName: "libz.so.1", ProductCode: { ProductName: "zlib", ProductVersion: "1.2.11" }, db: "nsrl_modern" }) };
	};
	const cache = {};
	const id = await lookupHash({ sha1: "a".repeat(40), sha256: "b".repeat(64) }, { fetcher, cache });
	assert.equal(id.source, "circl:nsrl_modern");
	assert.ok(calls.some(u => u.includes("deps.dev")) && calls.some(u => u.includes("circl")));
	const before = calls.length;
	await lookupHash({ sha1: "a".repeat(40), sha256: "b".repeat(64) }, { fetcher, cache });
	assert.equal(calls.length, before);
});

test("lookupHash offline returns cached only, never calls the fetcher", async () => {
	let called = false;
	const fetcher = async () => { called = true; return { ok: true, json: async () => ({}) }; };
	const id = await lookupHash({ sha1: "c".repeat(40), sha256: "d".repeat(64) }, { fetcher, cache: {}, offline: true });
	assert.equal(id, null);
	assert.equal(called, false);
});
