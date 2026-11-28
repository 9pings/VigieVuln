const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createCoverage, summarizeCoverage, requiredCoverageComplete } = require("../lib/scan/coverage");

test("coverage keeps execution separate from the advisory verdict", () => {
	const journal = createCoverage();
	journal.record({ applicationId: "site-a", occurrenceId: "plugin-a", capability: "advisories", sourceId: "provider-a",
		execution: "completed", result: "no-match", expected: 1, executed: 1 });
	journal.record({ applicationId: "site-a", occurrenceId: "plugin-a", capability: "advisories", sourceId: "provider-b",
		execution: "partial", result: "indeterminate", expected: 1, executed: 0, diagnostic: "CMS_CACHE_MISS" });
	assert.equal(journal.records.length, 2, "sources must not overwrite each other's outcome");
	assert.deepEqual(summarizeCoverage(journal.records), {
		checks: 2, completed: 1, partial: 1, failed: 0, notRun: 0, expected: 2, executed: 1,
	});
	assert.equal(requiredCoverageComplete(journal.records, ["advisories"]), false);
});

test("an unavailable check cannot be recorded as no-match", () => {
	const journal = createCoverage();
	assert.throws(() => journal.record({ applicationId: "a", capability: "advisories", execution: "failed", result: "no-match" }), /no-match/);
	assert.throws(() => journal.record({ applicationId: "a", capability: "advisories", execution: "not-run", result: "no-match" }), /no-match/);
	assert.throws(() => journal.record({ applicationId: "a", capability: "advisories", execution: "completed", result: "no-match", expected: 2, executed: 1 }), /completed/);
	assert.equal(journal.records.length, 0);
});

test("coverage gate checks only capabilities requested by the caller", () => {
	const journal = createCoverage();
	journal.record({ applicationId: "a", capability: "inventory", execution: "completed", result: "not-applicable", expected: 1, executed: 1 });
	journal.record({ applicationId: "a", capability: "advisories", execution: "not-run", result: "indeterminate", diagnostic: "CMS_PROVIDER_UNCONFIGURED" });
	assert.equal(requiredCoverageComplete(journal.records, ["inventory"]), true);
	assert.equal(requiredCoverageComplete(journal.records, ["inventory", "advisories"]), false);
	assert.equal(requiredCoverageComplete(journal.records, ["lifecycle"]), false, "an absent required check is incomplete");
});
