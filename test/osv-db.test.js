const isolatedTestCache = require('./helpers/isolated-cache')('osv-db');
/**
 * lib/osv-db.js — offline OSV-database matching (Maven).
 * Tests the new logic: OSV range evaluation over Maven ordering, version-set
 * membership, the dep matcher (scans versions[], including embedded Maven
 * coordinates, and skips other ecosystems / native binaries), and ZIP indexing.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { zipSync, strToU8 } = require("fflate");
const { buildIndexFromZip, matchOsvDbDeps, rangeAffects, vulnAffectsVersion } = require("../lib/osv-db");
const { makeDepRecord } = require("../lib/dep-record");

const ECO = (events) => ({ type: "ECOSYSTEM", events });

test("rangeAffects evaluates introduced/fixed intervals over Maven ordering", () => {
	const r = ECO([{ introduced: "0" }, { fixed: "3.17" }]);
	assert.equal(rangeAffects("3.11", r), true, "3.11 < 3.17 → affected");
	assert.equal(rangeAffects("3.17", r), false, "fixed is exclusive");
	assert.equal(rangeAffects("5.4.1", r), false, "5.4.1 ≥ 3.17 → not affected");
});

test("rangeAffects handles a lower bound, last_affected (inclusive) and open intervals", () => {
	assert.equal(rangeAffects("1.5", ECO([{ introduced: "1.0" }, { fixed: "2.0" }])), true);
	assert.equal(rangeAffects("0.9", ECO([{ introduced: "1.0" }, { fixed: "2.0" }])), false, "below introduced");
	assert.equal(rangeAffects("2.0", ECO([{ introduced: "1.0" }, { last_affected: "2.0" }])), true, "last_affected is inclusive");
	assert.equal(rangeAffects("9.9", ECO([{ introduced: "1.0" }])), true, "open interval [1.0,∞)");
	assert.equal(rangeAffects("1.0", { type: "GIT", events: [{ introduced: "0" }] }), false, "GIT ranges are skipped");
});

test("vulnAffectsVersion matches an explicit versions[] list too", () => {
	const v = { affected: [{ versions: ["3.11", "3.12"], ranges: [] }] };
	assert.equal(vulnAffectsVersion("3.11", v), true);
	assert.equal(vulnAffectsVersion("3.13", v), false);
});

function idx(records) { return { byPackage: records }; }

test("matchOsvDbDeps scans EVERY version in versions[] (composes with the overlay)", () => {
	const index = idx({
		"org.apache.poi:poi": [{ id: "GHSA-x", aliases: ["CVE-2017-12626"], affected: [{ package: {ecosystem: "Maven", name: "org.apache.poi:poi"}, ranges: [ECO([{ introduced: "0" }, { fixed: "3.17" }])], versions: [] }] }],
	});
	const poi = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.poi", name: "poi", version: "5.4.1" });
	poi.versions = ["5.4.1", "3.11"]; // the masked 3.11 the per-module overlay recovers
	const m = matchOsvDbDeps(new Map([["org.apache.poi:poi", poi]]), index);
	assert.equal(m.length, 1, "exactly the 3.11 occurrence matches");
	assert.equal(m[0].dep.version, "3.11");
	assert.equal(m[0].cve.id, "CVE-2017-12626", "fad normalizes to the CVE as the primary id");
	assert.equal(m[0].cve.ghsa, "GHSA-x");
	assert.equal(m[0].source, "osv");
});

test("matchOsvDbDeps includes embedded Maven coordinates and skips other ecosystems and native binaries", () => {
	const index = idx({ "g:a": [{ id: "X", affected: [{ package: {ecosystem: "Maven", name: "g:a"}, ranges: [ECO([{ introduced: "0" }])], versions: [] }] }] });
	const npm = makeDepRecord({ ecosystem: "npm", namespace: null, name: "g:a", version: "1.0" });
	const emb = { ...makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0" }), provenance: "embedded" };
	const bin = { ...makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0" }), provenance: "binary" };
	const r = new Map([["npm:g:a", npm], ["embedded:x", emb], ["binary:y", bin]]);
	const matches = matchOsvDbDeps(r, index);
	assert.equal(matches.length, 1);
	assert.equal(matches[0].dep, emb);
	assert.equal(matches[0].cve.id, 'X');
});

test("buildIndexFromZip indexes Maven records, drops withdrawn, ignores other ecosystems", () => {
	const rec1 = { id: "GHSA-1", aliases: ["CVE-1"], affected: [{ package: { name: "org.test:lib", ecosystem: "Maven" }, ranges: [ECO([{ introduced: "1.0" }, { fixed: "2.0" }])] }] };
	const rec2 = { id: "GHSA-withdrawn", withdrawn: "2024-01-01T00:00:00Z", affected: [{ package: { name: "org.test:lib", ecosystem: "Maven" } }] };
	const rec3 = { id: "GHSA-npm", affected: [{ package: { name: "leftpad", ecosystem: "npm" }, ranges: [ECO([{ introduced: "0" }])] }] };
	const zip = zipSync({ "GHSA-1.json": strToU8(JSON.stringify(rec1)), "GHSA-withdrawn.json": strToU8(JSON.stringify(rec2)), "GHSA-npm.json": strToU8(JSON.stringify(rec3)) });
	const index = buildIndexFromZip(Buffer.from(zip), "Maven");
	assert.ok(index.byPackage["org.test:lib"], "Maven package indexed");
	assert.equal(index.byPackage["org.test:lib"].length, 1, "withdrawn record dropped");
	assert.equal(index.byPackage["org.test:lib"][0].id, "GHSA-1");
	assert.ok(!index.byPackage["leftpad"], "npm record not in the Maven index");
});
