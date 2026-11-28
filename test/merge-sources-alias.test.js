/**
 * mergeBySource must be alias-SYMMETRIC: two findings on the same coord+version are the
 * same advisory when ANY id of one (primary, aliases, ghsa) equals ANY id of the other —
 * regardless of which side arrived first. The first alias-aware version only looked the
 * ADDITION's primary id up in the existing findings' alias index, so an existing record
 * that knew the advisory by its GHSA alone (the Packagist lane emits exactly that: no
 * `cve` field, only the GHSA remoteId) was duplicated by a later CVE-keyed record that
 * listed the same GHSA in its aliases.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { mergeBySource } = require("../lib/findings/merge");

const dep = { coordKey: "composer:league/commonmark", namespace: "league", name: "commonmark", version: "2.4.2", ecosystem: "composer" };
const ghsaOnly = () => ({ dep: { ...dep }, cve: {
	id: "GHSA-8rr7-cvq3-gmfh", severity: "UNKNOWN", score: null, description: "packagist", aliases: [], ghsa: null }, source: "packagist" });
const cveWithAlias = () => ({ dep: { ...dep }, cve: {
	id: "CVE-2026-86428", severity: "MEDIUM", score: 5.3, description: "OSV carries the CVE as primary",
	aliases: ["GHSA-8rr7-cvq3-gmfh"], ghsa: "GHSA-8rr7-cvq3-gmfh" }, source: "osv" });

test("existing GHSA-only finding + later CVE addition aliasing that GHSA → one finding", () => {
	const merged = mergeBySource([ghsaOnly()], [cveWithAlias()]);
	assert.equal(merged.length, 1, "the same advisory must not be emitted twice");
	assert.equal(merged[0].source, "osv+packagist");
	assert.equal(merged[0].cve.severity, "MEDIUM");
	// the documented CVE preference: a CVE id beats a GHSA id as the displayed primary,
	// and the GHSA it replaced stays reachable as an alias
	assert.equal(merged[0].cve.id, "CVE-2026-86428");
	assert.ok(merged[0].cve.aliases.includes("GHSA-8rr7-cvq3-gmfh"));
});

test("the reverse order (existing CVE, GHSA-only addition) also merges", () => {
	const merged = mergeBySource([cveWithAlias()], [ghsaOnly()]);
	assert.equal(merged.length, 1);
	assert.equal(merged[0].cve.id, "CVE-2026-86428");
	assert.equal(merged[0].source, "osv+packagist");
});

test("two findings sharing only a NON-primary alias merge", () => {
	const a = cveWithAlias();
	const b = { dep: { ...dep }, cve: { id: "PKSA-zyf5-hrxv-hrd7", severity: "UNKNOWN", aliases: ["GHSA-8rr7-cvq3-gmfh"] }, source: "packagist" };
	assert.equal(mergeBySource([a], [b]).length, 1);
	assert.equal(mergeBySource([b], [a]).length, 1);
});

test("additions that alias each other merge even with no existing finding", () => {
	assert.equal(mergeBySource([], [ghsaOnly(), cveWithAlias()]).length, 1);
	assert.equal(mergeBySource([], [cveWithAlias(), ghsaOnly()]).length, 1);
});

test("a third same-advisory record after a CVE-promoting merge still lands on the same finding", () => {
	// The merged record's displayed id changed (GHSA → CVE); its map slot must not, or a
	// later record keyed by either id would find a dangling index entry.
	const third = { dep: { ...dep }, cve: { id: "CVE-2026-86428", severity: "MEDIUM", aliases: [] }, source: "nvd" };
	const merged = mergeBySource(mergeBySource([ghsaOnly()], [cveWithAlias()]), [third]);
	assert.equal(merged.length, 1);
	assert.equal(merged[0].source, "nvd+osv+packagist");
	const again = mergeBySource([ghsaOnly()], [cveWithAlias(), third, ghsaOnly()]);
	assert.equal(again.length, 1);
	assert.equal(again[0].source, "nvd+osv+packagist");
});

test("distinct advisories and distinct versions are still kept apart", () => {
	const other = { dep: { ...dep }, cve: { id: "GHSA-bbbb-3333-4444", severity: "LOW", aliases: ["CVE-2026-1"] }, source: "packagist" };
	assert.equal(mergeBySource([ghsaOnly()], [other]).length, 2);
	const otherVer = { ...cveWithAlias(), dep: { ...dep, version: "2.5.0" } };
	assert.equal(mergeBySource([ghsaOnly()], [otherVer]).length, 2);
});
