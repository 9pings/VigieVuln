/**
 * NVD CPE ranges as an ADDITIVE matching tier — curated coordinates only.
 *
 * Why this exists. OSV/GHSA declare affected ranges per *release branch*: for
 * CVE-2020-9546 they cover 2.9.0–2.9.10.4, the branch where a fix shipped. NVD declares the
 * same CVE as three ranges — `2.0.0 ≤ v < 2.7.9.7`, `2.8.0 ≤ v < 2.8.11.6`,
 * `2.9.0 ≤ v < 2.9.10.4` — so jackson-databind 2.5.2 is affected and was never fixed.
 * Verified against the OSV API directly: it returns 49 vulns for 2.5.2 (without CVE-2020-9546)
 * and 66 for 2.9.4 (with it), and fad reproduced both counts exactly. So fad was not
 * mis-matching, it simply never used NVD's ranges to MATCH — only to filter.
 *
 * Why curated-only. Matching a Maven coordinate to a CPE `vendor:product` by name heuristics
 * is what makes OWASP Dependency-Check noisy. This tier therefore consults ONLY
 * `data/cpe-coord-map.json`; the heuristic fallback in `cpeMatchesDep` is explicitly off. A
 * coordinate with no curated entry gains nothing here, by design.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { matchDepsAgainstNvdCpe, cpeMatchesDep } = require("../lib/providers/nvd/cpe");

const cpe = (vendor, product) => ({
	criteria: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`,
	vulnerable: true,
});
const range = (vendor, product, start, endExcluding) => ({
	...cpe(vendor, product),
	versionStartIncluding: start,
	versionEndExcluding: endExcluding,
});

// The real shape of CVE-2020-9546's NVD configurations, reduced to the jackson branches.
const NVD_9546 = {
	id: "CVE-2020-9546",
	severity: "HIGH",
	score: 8.1,
	description: "jackson-databind mishandles serialization gadgets",
	configurations: [{
		nodes: [{
			operator: "OR",
			cpeMatch: [
				range("fasterxml", "jackson-databind", "2.0.0", "2.7.9.7"),
				range("fasterxml", "jackson-databind", "2.8.0", "2.8.11.6"),
				range("fasterxml", "jackson-databind", "2.9.0", "2.9.10.4"),
			],
		}],
	}],
};

const dep = (groupId, artifactId, version) => ({
	ecosystem: "maven", groupId, artifactId, version,
	coordKey: `${groupId}:${artifactId}`, versions: [version],
});

const JACKSON = "com.fasterxml.jackson.core:jackson-databind";

test("a curated coordinate matches an NVD range OSV's branch-scoped data misses", () => {
	const deps = new Map([[JACKSON, dep("com.fasterxml.jackson.core", "jackson-databind", "2.5.2")]]);
	const out = matchDepsAgainstNvdCpe(deps, { "CVE-2020-9546": NVD_9546 });
	assert.equal(out.length, 1, "2.5.2 falls in NVD's 2.0.0–2.7.9.7 range and must match");
	assert.equal(out[0].cve.id, "CVE-2020-9546");
	assert.equal(out[0].dep.version, "2.5.2");
	assert.equal(out[0].source, "nvd");
});

test("a version outside every NVD range does not match", () => {
	const deps = new Map([[JACKSON, dep("com.fasterxml.jackson.core", "jackson-databind", "2.9.10.4")]]);
	assert.equal(matchDepsAgainstNvdCpe(deps, { "CVE-2020-9546": NVD_9546 }).length, 0,
		"2.9.10.4 is the fixed version — endExcluding must be respected");
});

test("EVERY distinct version of a coordinate is evaluated, not just the highest", () => {
	const d = dep("com.fasterxml.jackson.core", "jackson-databind", "2.9.4");
	d.versions = ["2.9.4", "2.5.2", "2.9.10.4"];
	const out = matchDepsAgainstNvdCpe(new Map([[JACKSON, d]]), { "CVE-2020-9546": NVD_9546 });
	const versions = out.map(m => m.dep.version).sort();
	assert.deepEqual(versions, ["2.5.2", "2.9.4"], "the two vulnerable versions match, the fixed one does not");
});

// The guard that keeps this tier from becoming a false-positive engine.
test("a coordinate with NO curated CPE entry is never matched, even on an exact name hit", () => {
	const NVD_OTHER = {
		id: "CVE-9999-0001", severity: "HIGH", configurations: [{
			nodes: [{ operator: "OR", cpeMatch: [range("acme", "widget", "1.0.0", "9.9.9")] }],
		}],
	};
	// groupId contains the CPE vendor and artifactId IS the CPE product — the heuristic in
	// cpeMatchesDep would accept this. The curated tier must not.
	const d = dep("com.acme", "widget", "2.0.0");
	assert.equal(matchDepsAgainstNvdCpe(new Map([["com.acme:widget", d]]), { "CVE-9999-0001": NVD_OTHER }).length, 0,
		"no entry in data/cpe-coord-map.json means no match, however tempting the name");
	// …and prove the heuristic really would have accepted it, so this test can't silently rot.
	assert.equal(cpeMatchesDep({ part: "a", vendor: "acme", product: "widget" }, d), true,
		"sanity: the heuristic path accepts it, which is exactly what curated-only suppresses");
});

test("a CVE with no CPE configurations is skipped without throwing", () => {
	const deps = new Map([[JACKSON, dep("com.fasterxml.jackson.core", "jackson-databind", "2.5.2")]]);
	assert.equal(matchDepsAgainstNvdCpe(deps, { "CVE-X": { id: "CVE-X" } }).length, 0);
	assert.equal(matchDepsAgainstNvdCpe(deps, {}).length, 0);
	assert.equal(matchDepsAgainstNvdCpe(new Map(), { "CVE-2020-9546": NVD_9546 }).length, 0);
});

test("dev-scoped and unresolved-version deps are handled sanely", () => {
	const noVer = dep("com.fasterxml.jackson.core", "jackson-databind", null);
	noVer.versions = [];
	assert.equal(matchDepsAgainstNvdCpe(new Map([[JACKSON, noVer]]), { "CVE-2020-9546": NVD_9546 }).length, 0,
		"an unresolved version must never be assumed vulnerable");
	const range$ = dep("com.fasterxml.jackson.core", "jackson-databind", "${jackson.version}");
	range$.versions = ["${jackson.version}"];
	assert.equal(matchDepsAgainstNvdCpe(new Map([[JACKSON, range$]]), { "CVE-2020-9546": NVD_9546 }).length, 0,
		"an uninterpolated property is not a version");
});
