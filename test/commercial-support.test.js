/**
 * Paid support past the open-source end of life (lib/maintenance/commercial-support.js). Zero network:
 * in-memory Maven Central + an in-memory "vendor" repository.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { annotateCommercialSupport } = require("../lib/maintenance/commercial-support");
const { branchFixFromOsvEvents, branchFixFromRanges, stricterBranchFix } = require("../lib/codecs/maven/version");
const { makeDepRecord } = require("../lib/inventory/dep-record");
const { generateHtmlReport } = require("../lib/reports/cve-report");

const CENTRAL = "https://repo1.maven.org/maven2";
const VENDOR = "https://vendor.example/spring-enterprise";
const meta = vs => `<metadata><versioning><versions>${vs.map(v => `<version>${v}</version>`).join("")}</versions></versioning></metadata>`;
const PUBLIC = ["5.3.38", "5.3.39", "6.1.21"];
const R = {
	[`${CENTRAL}/org/springframework/spring-core/maven-metadata.xml`]: meta(PUBLIC),
	[`${VENDOR}/org/springframework/spring-core/maven-metadata.xml`]: meta([...PUBLIC, "5.3.40", "5.3.41", "5.3.45"]),
};
const fetcher = async url => R[String(url)] ? { ok: true, status: 200, text: async () => R[String(url)] } : { ok: false, status: 404, text: async () => "" };
const cacheDir = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-commercial-"));
const spring = v => makeDepRecord({ ecosystem: "maven", namespace: "org.springframework", name: "spring-core", version: v, manifestPath: "/p/pom.xml" });
const finding = v => ({ dep: spring(v), product: "Spring Framework", productSlug: "spring-framework", cycle: "5.3", status: "eol", eol: "2024-08-31", extendedSupport: "2029-06-30", cycleLatest: "5.3.39", latest: "6.2.19" });
const match = (v, id, branchFix) => ({ dep: spring(v), cve: { id, severity: "HIGH", ...(branchFix ? { branchFix } : {}) } });

test("branch fix: the bound of the dep's OWN branch, not the lowest fix anywhere (CVE-2024-38820 shape)", () => {
	const events = [[{ introduced: "6.1.0" }, { fixed: "6.1.14" }], [{ introduced: "0" }, { last_affected: "5.3.40" }]];
	assert.deepEqual(events.map(e => branchFixFromOsvEvents("5.3.39", e)).find(Boolean), { after: "5.3.40" });
	assert.deepEqual(events.map(e => branchFixFromOsvEvents("6.1.10", e)).find(Boolean), { fixed: "6.1.14" });
	assert.deepEqual(branchFixFromOsvEvents("5.3.39", [{ last_affected: "5.3.40" }, { introduced: "0" }]), { after: "5.3.40" }, "event order does not matter");
	assert.deepEqual(branchFixFromRanges("5.3.39", [{ status: "affected", version: "5.3.0", lessThan: "5.3.41" }]), { fixed: "5.3.41" });
	assert.deepEqual(stricterBranchFix({ after: "5.3.40" }, { fixed: "5.3.43" }), { fixed: "5.3.43" });
});

test("on the public 5.3.39: still EOL, with the branch build that fixes the CVEs and the newest vendor build", async () => {
	const e = finding("5.3.39");
	const matches = [match("5.3.39", "CVE-A", { after: "5.3.40" }), match("5.3.39", "CVE-B", { fixed: "5.3.42" }), match("5.3.39", "CVE-C")];
	const { commercialBuilds } = await annotateCommercialSupport([e], matches, { fetcher, cacheDir: cacheDir(), repos: [{ name: "vendor", url: VENDOR + "/" }, { name: "central", url: CENTRAL + "/", central: true }] });
	assert.equal(commercialBuilds.length, 0);
	assert.equal(e.status, "eol");
	assert.deepEqual(e.branchFix, { fixed: "5.3.42", cves: 3, withBound: 2 });
	assert.deepEqual(e.latestCommercial, { version: "5.3.45", meetsBranchFix: true });
	const html = generateHtmlReport({ cveMatches: [], eolResults: [e], obsoleteResults: [], outdatedResults: [], projectInfo: { name: "d", src: "/p", generatedAt: "x" } });
	assert.ok(html.includes("Paid commercial support until 2029-06-30. A 5.3 build ≥ 5.3.42 fixes 2 of the 3 CVEs found. Latest vendor build: 5.3.45."));
});

test("no vendor repository configured: no latest vendor build is invented", async () => {
	const e = finding("5.3.39");
	await annotateCommercialSupport([e], [match("5.3.39", "CVE-A", { after: "5.3.40" })], { fetcher, cacheDir: cacheDir(), repos: [{ name: "central", url: CENTRAL + "/", central: true }] });
	assert.equal(e.latestCommercial, undefined);
	assert.deepEqual(e.branchFix, { after: "5.3.40", cves: 1, withBound: 1 });
});

test("already on a vendor build (beyond the last public release, absent from Central): leaves the EOL list", async () => {
	const e = finding("5.3.41");
	const { commercialBuilds } = await annotateCommercialSupport([e], [], { fetcher, cacheDir: cacheDir() });
	assert.equal(commercialBuilds.length, 1);
	assert.equal(e.status, "commercial");
	assert.deepEqual(e.commercialBuild, { version: "5.3.41", lastPublic: "5.3.39" });
});

test("never a vendor build without proof: a public version, an unknown Central list, or no paid support", async () => {
	const pub = finding("5.3.38");
	await annotateCommercialSupport([pub], [], { fetcher, cacheDir: cacheDir() });
	assert.equal(pub.status, "eol");
	const cold = finding("5.3.41");
	await annotateCommercialSupport([cold], [], { fetcher, cacheDir: cacheDir(), offline: true });
	assert.equal(cold.status, "eol", "offline with no cached Central list: nothing is proven");
	const noPaid = { ...finding("5.3.41"), extendedSupport: null };
	await annotateCommercialSupport([noPaid], [], { fetcher, cacheDir: cacheDir() });
	assert.equal(noPaid.status, "eol");
});

test("the vendor-build note renders in chapter 0, in English and French", () => {
	const w = { type: "commercial-build", product: "Spring Framework", cycle: "5.3", coord: "org.springframework:spring-core", version: "5.3.41", lastPublic: "5.3.39", until: "2029-06-30", message: "x" };
	const p = locale => ({ cveMatches: [], eolResults: [], obsoleteResults: [], outdatedResults: [], warnings: [w], projectInfo: { name: "d", src: "/p", generatedAt: "x" }, locale });
	const en = generateHtmlReport(p("en"));
	assert.ok(en.includes("Vendor builds under paid support"));
	assert.ok(en.includes("is not on Maven Central and is newer than the last public Spring Framework 5.3 release (5.3.39)"));
	const fr = generateHtmlReport(p("fr"));
	assert.ok(fr.includes("Builds d") && fr.includes("absente de Maven Central"));
});
