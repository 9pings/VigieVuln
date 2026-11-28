const { test } = require("node:test");
const assert = require("node:assert/strict");
const { computePriority, attachPriority, sortByPriority } = require("../lib/findings/priority");

test("KEV membership forces the exploited band and floors the score at 90", () => {
	const p = computePriority({ score: 4.0, severity: "MEDIUM", kev: true });
	assert.equal(p.band, "exploited");
	assert.ok(p.score >= 90);
	assert.equal(p.sortKey[0], 1);
});

test("high CVSS without EPSS still ranks high", () => {
	const p = computePriority({ score: 9.8, severity: "CRITICAL" });
	assert.equal(p.band, "critical");
	assert.ok(p.score >= 70);
});

test("EPSS percentile nudges the blended score upward", () => {
	const low = computePriority({ score: 5.0, severity: "MEDIUM", epssPercentile: 0.0 });
	const high = computePriority({ score: 5.0, severity: "MEDIUM", epssPercentile: 0.99 });
	assert.ok(high.score > low.score);
});

test("falls back to severity when no numeric score", () => {
	const p = computePriority({ severity: "HIGH" });
	assert.ok(p.cvss > 0);
});

test("sortByPriority puts KEV first, then EPSS, then CVSS", () => {
	const matches = [
		{ cve: { id: "CVE-1", score: 9.9, severity: "CRITICAL" } },
		{ cve: { id: "CVE-2", score: 3.0, severity: "LOW", kev: true } },
		{ cve: { id: "CVE-3", score: 5.0, severity: "MEDIUM", epssPercentile: 0.97 } },
	];
	attachPriority(matches);
	const sorted = sortByPriority(matches);
	assert.equal(sorted[0].cve.id, "CVE-2"); // KEV wins despite low CVSS
	assert.equal(sorted[1].cve.id, "CVE-1"); // highest CVSS next
});

test("attachPriority mutates in place", () => {
	const matches = [{ cve: { id: "CVE-9", score: 7.0, severity: "HIGH" } }];
	attachPriority(matches);
	assert.ok(matches[0].cve.priority);
	assert.equal(typeof matches[0].cve.priority.score, "number");
});

// Regression: score===0 is a placeholder, not a real CVSS 0.0 — a CRITICAL-labelled
// finding with score 0 must band from its severity, not collapse to "low". (#7)
test("score 0 falls back to the severity label instead of banding as low", () => {
	const p = computePriority({ score: 0, severity: "CRITICAL" });
	assert.equal(p.band, "critical");
	assert.ok(p.cvss > 0);
});

test("missing CVSS, severity and KEV yields unknown priority, even with EPSS", () => {
	const p = computePriority({ severity: "UNKNOWN", epssPercentile: 0.9 });
	assert.equal(p.band, "unknown");
	assert.equal(p.score, null);
	assert.equal(p.cvss, null);
});
