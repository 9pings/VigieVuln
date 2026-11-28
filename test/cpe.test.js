const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const {
	parseCpe23,
	matchVersionRange,
	cpeMatchesDep,
	evaluateCveForDep,
	refineMatchesWithCpe,
} = require("../lib/providers/nvd/cpe");

const FIX = path.join(__dirname, "fixtures", "cve-samples");

test("parseCpe23 splits all 13 fields and handles escaping", () => {
	const c = parseCpe23("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*");
	assert.equal(c.part, "a");
	assert.equal(c.vendor, "apache");
	assert.equal(c.product, "log4j");
	assert.equal(c.version, "2.14.0");
});

test("parseCpe23 returns null for malformed URI", () => {
	assert.equal(parseCpe23("not a cpe"), null);
	assert.equal(parseCpe23("cpe:2.3:a:vendor"), null);
	assert.equal(parseCpe23(42), null);
});

test("parseCpe23 handles backslash-escaped colons (e.g. eclipse:vert\\.x)", () => {
	const c = parseCpe23("cpe:2.3:a:vendor:weird\\:name:1.0:*:*:*:*:*:*:*");
	assert.equal(c.product, "weird:name");
});

test("matchVersionRange honours versionStartIncluding + versionEndExcluding", () => {
	const m = {
		criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
		vulnerable: true,
		versionStartIncluding: "2.0.0",
		versionEndExcluding: "2.15.0",
	};
	assert.equal(matchVersionRange("2.14.1", m), true);
	assert.equal(matchVersionRange("2.0.0", m), true);    // lower-inclusive
	assert.equal(matchVersionRange("2.15.0", m), false);  // upper-exclusive
	assert.equal(matchVersionRange("1.9.0", m), false);
	assert.equal(matchVersionRange("2.17.0", m), false);
});

test("matchVersionRange honours hard-pinned criteria version", () => {
	const m = { criteria: "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*", vulnerable: true };
	assert.equal(matchVersionRange("2.14.0", m), true);
	assert.equal(matchVersionRange("2.14.1", m), false);
});

test("matchVersionRange folds CPE update qualifier into the version pin (H5)", () => {
	// CPE 2.3 ":1.0.0:rc1:" describes the 1.0.0-rc1 pre-release. A release dep
	// at 1.0.0 must NOT match — that was the H5 cascade.
	const beta = { criteria: "cpe:2.3:a:apache:foo:1.0.0:beta1:*:*:*:*:*:*", vulnerable: true };
	assert.equal(matchVersionRange("1.0.0", beta), false);
	assert.equal(matchVersionRange("1.0.0-beta1", beta), true);

	const rc = { criteria: "cpe:2.3:a:apache:foo:1.0.0:rc1:*:*:*:*:*:*", vulnerable: true };
	assert.equal(matchVersionRange("1.0.0", rc), false);
	assert.equal(matchVersionRange("1.0.0-rc1", rc), true);
});

test("cpeMatchesDep rejects short-token vendor leak (M4 mirror of H2)", () => {
	const cpe = parseCpe23("cpe:2.3:a:a:log4j-core:*:*:*:*:*:*:*:*");
	const dep = { groupId: "com.unrelated.log4j-core", artifactId: "log4j-core", ecosystem: "maven" };
	assert.equal(cpeMatchesDep(cpe, dep), false);
});

test("matchVersionRange returns true for unknown dep version (conservative)", () => {
	const m = { criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", vulnerable: true, versionEndExcluding: "2.15.0" };
	assert.equal(matchVersionRange(null, m), true);
});

test("cpeMatchesDep — curated map exact maven coord", () => {
	const cpe = parseCpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
	const dep = { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", ecosystem: "maven" };
	assert.equal(cpeMatchesDep(cpe, dep), true);
});

test("cpeMatchesDep — heuristic vendor token in groupId", () => {
	const cpe = parseCpe23("cpe:2.3:a:apache:commons-totally-novel:*:*:*:*:*:*:*:*");
	const dep = { groupId: "org.apache.commons", artifactId: "commons-totally-novel", ecosystem: "maven" };
	assert.equal(cpeMatchesDep(cpe, dep), true);
});

test("cpeMatchesDep — npm bare name", () => {
	const cpe = parseCpe23("cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*");
	const dep = { groupId: "", artifactId: "lodash", ecosystem: "npm" };
	assert.equal(cpeMatchesDep(cpe, dep), true);
});

test("cpeMatchesDep — npm scoped package via vendor split", () => {
	const cpe = parseCpe23("cpe:2.3:a:scope:pkg:*:*:*:*:*:*:*:*");
	const dep = { groupId: "", artifactId: "@scope/pkg", ecosystem: "npm" };
	assert.equal(cpeMatchesDep(cpe, dep), true);
});

test("cpeMatchesDep — wrong artifact does not match", () => {
	const cpe = parseCpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
	const dep = { groupId: "org.apache.commons", artifactId: "commons-io", ecosystem: "maven" };
	assert.equal(cpeMatchesDep(cpe, dep), false);
});

test("evaluateCveForDep — Log4Shell NVD record matches vulnerable log4j-core", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const dep = { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.14.0", ecosystem: "maven" };
	const { affected, confidence } = evaluateCveForDep(cve, dep);
	assert.equal(affected, true);
	assert.equal(confidence, "exact");
});

test("evaluateCveForDep — patched log4j is not affected (version out of range)", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const dep = { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.17.1", ecosystem: "maven" };
	const { affected } = evaluateCveForDep(cve, dep);
	assert.equal(affected, false);
});

test("evaluateCveForDep — unrelated maven dep is not affected", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const dep = { groupId: "com.google.guava", artifactId: "guava", version: "31.0", ecosystem: "maven" };
	const { affected } = evaluateCveForDep(cve, dep);
	assert.equal(affected, false);
});

test("evaluateCveForDep — npm lodash matches the lodash CVE", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-npm-lodash.json"), "utf8"));
	const dep = { groupId: "", artifactId: "lodash", version: "4.17.10", ecosystem: "npm" };
	const { affected, confidence } = evaluateCveForDep(cve, dep);
	assert.equal(affected, true);
	assert.equal(confidence, "exact");
});

test("evaluateCveForDep — patched npm lodash is not affected", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-npm-lodash.json"), "utf8"));
	const dep = { groupId: "", artifactId: "lodash", version: "4.17.20", ecosystem: "npm" };
	const { affected } = evaluateCveForDep(cve, dep);
	assert.equal(affected, false);
});

test("refineMatchesWithCpe upgrades possible→exact when curated map confirms", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const matches = [{
		dep: { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.14.0", ecosystem: "maven" },
		cve: { id: cve.id, configurations: cve.configurations, severity: "HIGH" },
		confidence: "possible",
	}];
	refineMatchesWithCpe(matches);
	assert.equal(matches[0].confidence, "exact");
	assert.equal(matches[0].cpeConfidence, "exact");
	assert.equal(matches[0].cpeFiltered, undefined);
});

test("refineMatchesWithCpe flags out-of-range version as likely FP", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const matches = [{
		dep: { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.17.1", ecosystem: "maven" },
		cve: { id: cve.id, configurations: cve.configurations, severity: "HIGH" },
		confidence: "probable",
	}];
	refineMatchesWithCpe(matches);
	assert.equal(matches[0].cpeFiltered, true);
});

// Regression: the CPE coord-matcher only understands maven + npm coords. A PyPI (or
// composer/nuget/go/ruby) OSV finding must NOT be hidden as a "CPE false positive" just
// because its NVD CPE can't be mapped to the coord — OSV already did a precise,
// ecosystem-native version-range match (e.g. cryptography 46.0.5, fixed in 46.0.6).
test("refineMatchesWithCpe does NOT CPE-filter a non-maven/npm OSV match", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const matches = [{
		dep: { groupId: "", artifactId: "cryptography", version: "46.0.5", ecosystem: "pypi", scope: "prod" },
		cve: { id: "CVE-2026-34073", configurations: cve.configurations, severity: "MEDIUM" },
		source: "osv", confidence: "exact",
	}];
	refineMatchesWithCpe(matches);
	assert.notEqual(matches[0].cpeFiltered, true, "PyPI OSV match must stay in production");
});

// An OSV-confirmed match is authoritative (OSV matched the exact coordinate + version range).
// NVD CPE must never override it — even a maven dep whose version looks out-of-range to NVD
// stays in production when OSV flagged it (NVD/OSV range data can legitimately differ).
test("refineMatchesWithCpe does NOT CPE-filter an OSV-confirmed maven match", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const matches = [{
		dep: { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.17.1", ecosystem: "maven" },
		cve: { id: cve.id, configurations: cve.configurations, severity: "HIGH" },
		source: "osv", confidence: "exact",
	}];
	refineMatchesWithCpe(matches);
	assert.notEqual(matches[0].cpeFiltered, true, "OSV match is authoritative — not a CPE false positive");
});

// A coord the CVE's CPE never names (here a maven dep vs the log4j-only config) is a coverage
// gap, not a false positive — don't filter it (the version-contradiction filter needs the
// product to actually be named first).
test("refineMatchesWithCpe does NOT filter when NVD CPE never names the product", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const matches = [{
		dep: { groupId: "com.example.unrelated", artifactId: "totally-unrelated-lib", version: "1.0.0", ecosystem: "maven" },
		cve: { id: cve.id, configurations: cve.configurations, severity: "HIGH" },
		confidence: "possible",
	}];
	refineMatchesWithCpe(matches);
	assert.notEqual(matches[0].cpeFiltered, true, "product never named → not a CPE false positive");
});

// Regression: an AND configuration of (vulnerable software) AND (vulnerable:false
// platform context) must still flag the dep — the context-only node is ignored,
// not required. Previously .every(Boolean) dropped the finding. (audit fix #3)
test("AND config with a vulnerable:false context node still affects the dep", () => {
	const dep = { ecosystem: "maven", groupId: "org.apache.struts", artifactId: "struts", namespace: "org.apache.struts", name: "struts", version: "2.5.10", coordKey: "org.apache.struts:struts" };
	const vulnNode = { operator: "OR", cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*", versionEndExcluding: "2.5.20" }] };
	const ctxNode = { operator: "OR", cpeMatch: [{ vulnerable: false, criteria: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*" }] };
	const map = { byVendorProduct: {}, byProduct: {} };
	const andCve = { configurations: [{ operator: "AND", nodes: [vulnNode, ctxNode] }] };
	assert.equal(evaluateCveForDep(andCve, dep, map).affected, true);
	// a fixed version (>= 2.5.20) is still NOT affected
	assert.equal(evaluateCveForDep(andCve, { ...dep, version: "2.5.25" }, map).affected, false);
});
