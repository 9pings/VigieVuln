const { test } = require("node:test");
const assert = require("node:assert");
const { matchDepsAgainstCves } = require("../lib/advisories/cve-match");
const { makeDepRecord } = require("../lib/inventory/dep-record");

test("binary-provenance deps are skipped by the Maven CVE-index matcher", () => {
	const deps = new Map();
	deps.set("binary:/openssl.dll", makeDepRecord({
		ecosystem: "binary", name: "openssl.dll", manifestPath: "/openssl.dll",
		provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) },
	}));
	// An index entry that WOULD match a versionless dep by product name (worst case).
	const cveIndex = {
		byPackageName: {},
		byProduct: { "openssl.dll": [{ id: "CVE-0000-0001", severity: "HIGH", vendor: "openssl", product: "openssl.dll", ranges: [{ status: "affected" }] }] },
	};
	const matches = matchDepsAgainstCves(deps, cveIndex, { includePossibleTier: true });
	assert.equal(matches.length, 0);
});
