/**
 * The merge seam contract: every CVE source (CVEProject index, OSV.dev, OSV local DB,
 * NVD CPE ranges, Packagist advisories) funnels through mergeBySource, and the same
 * advisory can arrive under DIFFERENT primary ids. Measured on the real symfony-demo
 * corpus (2026-09-23): OSV keys league/commonmark GHSA-8rr7-cvq3-gmfh by its CVE alias
 * (CVE-2026-86428) while the Packagist audit record for it carries no `cve` field and
 * only the GHSA remoteId — a key-only merge emitted the advisory twice.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { mergeBySource } = require("../lib/merge-sources");

const dep = { coordKey: "composer:league/commonmark", namespace: "league", name: "commonmark", version: "2.4.2", ecosystem: "composer" };
const osvFinding = { dep: { ...dep }, cve: {
	id: "CVE-2026-86428", severity: "MEDIUM", score: 5.3, description: "OSV carries the CVE alias as primary",
	aliases: ["GHSA-8rr7-cvq3-gmfh"], ghsa: "GHSA-8rr7-cvq3-gmfh" }, source: "osv", confidence: "exact" };
const packagistFinding = { dep: { ...dep }, cve: {
	id: "GHSA-8rr7-cvq3-gmfh", severity: "UNKNOWN", score: null, description: "the Packagist record has no cve field",
	aliases: ["PKSA-zyf5-hrxv-hrd7"], ghsa: "GHSA-8rr7-cvq3-gmfh" }, source: "packagist", confidence: "exact" };

test("missing provenance uses the cache fallback instead of fabricating an upstream source", () => {
	const a = { dep: { ...dep }, cve: { id: "CVE-2020-1" } };
	assert.equal(mergeBySource([a], [])[0].source, "cache");
	assert.equal(mergeBySource([], [a])[0].source, "cache");
	const known = { ...a, source: 'osv' };
	assert.equal(mergeBySource([a], [known])[0].source, 'cache+osv');
	assert.equal(mergeBySource([known], [a])[0].source, 'cache+osv');
});

test('merging a source without a fix retains the known advisory fix', () => {
	const a = {dep:{...dep},source:'osv',cve:{id:'CVE-2020-1',fixVersion:'2.5.0'}};
	const b = {dep:{...dep},source:'GCVE:GNA-1',cve:{id:'CVE-2020-1',fixVersion:null}};
	assert.equal(mergeBySource([a],[b])[0].cve.fixVersion,'2.5.0');
});

test("an addition keyed by an existing finding's GHSA merges, never duplicates", () => {
	const merged = mergeBySource([osvFinding], [packagistFinding]);
	assert.equal(merged.length, 1);
	assert.equal(merged[0].cve.id, "CVE-2026-86428", "the existing (CVE-preferred) id wins");
	assert.equal(merged[0].source, "osv+packagist");
	assert.equal(merged[0].cve.severity, "MEDIUM", "non-UNKNOWN severity is preferred over UNKNOWN");
	assert.ok(merged[0].cve.aliases.includes("PKSA-zyf5-hrxv-hrd7"), "aliases union keeps every id the advisory answers to");
});

test("the same primary key still merges and upgrades the source label", () => {
	const a = { dep: { ...dep }, cve: { id: "CVE-2020-1", severity: "HIGH", score: 7.5, description: "long description from OSV", aliases: [] }, source: "osv" };
	const b = { dep: { ...dep }, cve: { id: "CVE-2020-1", severity: "UNKNOWN", score: null, description: "short", aliases: ["GHSA-x"] }, source: "packagist" };
	const merged = mergeBySource([a], [b]);
	assert.equal(merged.length, 1);
	assert.equal(merged[0].source, "osv+packagist");
	assert.equal(merged[0].cve.severity, "HIGH");
	assert.equal(merged[0].cve.description, "long description from OSV");
	assert.ok(merged[0].cve.aliases.includes("GHSA-x"));
});

test("two genuinely distinct advisories on the same dep never merge", () => {
	const a = { dep: { ...dep }, cve: { id: "CVE-2026-1", severity: "HIGH", aliases: ["GHSA-aaaa-1111-2222"] }, source: "osv" };
	const b = { dep: { ...dep }, cve: { id: "GHSA-bbbb-3333-4444", severity: "LOW", aliases: ["PKSA-other"] }, source: "packagist" };
	const merged = mergeBySource([a], [b]);
	assert.equal(merged.length, 2);
});

test("a version mismatch keeps two findings even with a shared advisory id", () => {
	const a = { dep: { ...dep, version: "2.4.2" }, cve: { id: "CVE-2026-86428", severity: "MEDIUM", aliases: [] }, source: "osv" };
	const b = { dep: { ...dep, version: "2.5.0" }, cve: { id: "CVE-2026-86428", severity: "MEDIUM", aliases: [] }, source: "osv" };
	assert.equal(mergeBySource([a], [b]).length, 2);
});

test("an addition whose id matches an existing finding's alias list merges", () => {
	// The mirror of the GHSA case: a source that keys by CVE while the existing finding
	// (OSV, CVE-less GHSA entry) lists that CVE only in its aliases.
	const existing = { dep: { ...dep }, cve: { id: "GHSA-jmmp-vh96-78rm", severity: "MEDIUM", aliases: [], ghsa: null }, source: "osv" };
	const addition = { dep: { ...dep }, cve: { id: "GHSA-jmmp-vh96-78rm", severity: "HIGH", aliases: ["PKSA-ff9b-2qcw-k86n"] }, source: "packagist" };
	const merged = mergeBySource([existing], [addition]);
	assert.equal(merged.length, 1);
	assert.equal(merged[0].source, "osv+packagist");
	assert.equal(merged[0].cve.severity, "MEDIUM");
});

test("a publisher-lane application finding merges with the standard lane's constat", () => {
	// Measured on the official TYPO3 v13.4.2 extract (2026-09-23): the Composer lane
	// reads the exact pin in typo3/sysext/seo/composer.json, the publisher lane reads
	// the observed core marker — the same CVE on the same coord+version must be ONE
	// constat with the union of sources, never two.
	const standard = { dep: { ...dep, version: "13.4.2" },
		cve: { id: "CVE-2026-19418", severity: "HIGH", score: 7.5, aliases: ["GHSA-68jx-f42c-7599"], description: "OSV text" },
		source: "nvd+packagist" };
	const publisher = { dep: { ...dep, version: "13.4.2" }, applicationIds: ["typo3:typo3"],
		ownerComponentIds: ["typo3:typo3:core"], applicationRelation: "direct", attributionStatus: "confirmed",
		cve: { id: "CVE-2026-19418", severity: "HIGH", score: null, aliases: ["GHSA-68jx-f42c-7599"],
			description: "TYPO3's own summary", fixVersion: "13.4.34" },
		source: "github-typo3-advisories" };
	const merged = mergeBySource([standard], [publisher]);
	assert.equal(merged.length, 1, "the same advisory on the same coord+version is one constat");
	assert.equal(merged[0].source, "github-typo3-advisories+nvd+packagist");
	assert.equal(merged[0].cve.fixVersion, "13.4.34", "the publisher's fix version travels with the merge");
	assert.equal(merged[0].cve.score, 7.5, "the enriched score is kept");
	// the standard finding's shape wins: application attribution is reconstructed later
	// from the physical occurrence (expandComposerFindings), never dropped silently
	assert.equal(merged[0].cve.id, "CVE-2026-19418");
});

test("an application finding with no standard counterpart passes through intact", () => {
	// The Drupal core lane: no composer manifest ever carries drupal/core on the
	// scanned tree, so the provider's constat must keep its own attribution.
	const drupal = { dep: { ...dep, coordKey: "composer:drupal/core", version: "8.5.0" },
		applicationIds: ["drupal:drupal-8.5.0"], ownerComponentIds: ["drupal:drupal-8.5.0:core"],
		applicationRelation: "direct", attributionStatus: "confirmed",
		cve: { id: "CVE-2018-7600", severity: "CRITICAL", aliases: ["SA-CORE-2018-002"] },
		source: "drupal-security-advisories" };
	const merged = mergeBySource([], [drupal]);
	assert.equal(merged.length, 1);
	assert.equal(merged[0].source, "drupal-security-advisories");
	assert.deepEqual(merged[0].applicationIds, ["drupal:drupal-8.5.0"]);
	assert.equal(merged[0].ownerComponentIds[0], "drupal:drupal-8.5.0:core");
});

test("absorbing a second packagist constat keeps the source tokens unique", () => {
	// Measured on the extended corpus scan (2026-09-23): guzzlehttp/guzzle 6.3.0 holds
	// CVE-2022-31042 from OSV and Packagist; a second Packagist constat merged into the
	// already-composite record must not render "osv+packagist+packagist".
	const first = { dep: { ...dep, version: "6.3.0" }, cve: { id: "CVE-2022-31042", severity: "HIGH", aliases: [] }, source: "osv" };
	const second = { dep: { ...dep, version: "6.3.0" }, cve: { id: "CVE-2022-31042", severity: "HIGH", aliases: [] }, source: "packagist" };
	const third = { dep: { ...dep, version: "6.3.0" }, cve: { id: "CVE-2022-31042", severity: "HIGH", aliases: [] }, source: "packagist" };
	const merged = mergeBySource(mergeBySource([first], [second]), [third]);
	assert.equal(merged.length, 1);
	assert.equal(merged[0].source, "osv+packagist");
});
