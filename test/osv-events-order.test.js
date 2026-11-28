/**
 * OSV range evaluation must follow the schema's "Evaluation" algorithm
 * (https://ossf.github.io/osv-schema/#evaluation): `events` are NOT required to be
 * sorted, so the evaluator sorts them by version ("0" lowest) before walking them, and
 * `limit` events bound the whole range. The first lib/providers/osv/db.js evaluator walked the
 * events in ARRAY order, so an unsorted (but valid) record was mis-evaluated in both
 * directions — a false positive below `introduced`, a false negative inside a branch.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { rangeAffects, vulnAffectsVersion } = require("../lib/providers/osv/db");

const R = (events) => ({ type: "ECOSYSTEM", events });

test("unsorted [fixed, introduced] is the same interval as the sorted one", () => {
	const r = R([{ fixed: "2.0" }, { introduced: "1.0" }]);
	assert.equal(rangeAffects("0.5", r), false, "below introduced → not affected (was a false positive)");
	assert.equal(rangeAffects("1.5", r), true, "inside [1.0, 2.0)");
	assert.equal(rangeAffects("2.0", r), false, "fixed is exclusive");
	assert.equal(rangeAffects("2.5", r), false, "above fixed → not affected (was a false positive)");
});

test("two branches listed out of order are both evaluated correctly", () => {
	// [3.0, 3.2) ∪ [1.0, 1.4), branch with the higher versions listed first
	const r = R([{ introduced: "3.0" }, { introduced: "1.0" }, { fixed: "3.2" }, { fixed: "1.4" }]);
	assert.equal(rangeAffects("1.2", r), true, "inside the low branch (was a false negative)");
	assert.equal(rangeAffects("1.4", r), false);
	assert.equal(rangeAffects("2.0", r), false, "between the branches");
	assert.equal(rangeAffects("3.1", r), true);
	assert.equal(rangeAffects("3.2", r), false);
	const r2 = R([{ introduced: "3.0" }, { fixed: "3.2" }, { introduced: "1.0" }, { fixed: "1.4" }]);
	assert.equal(rangeAffects("1.2", r2), true, "pairs in descending order (was a false negative)");
	assert.equal(rangeAffects("2.0", r2), false);
});

test("introduced \"0\" sorts lowest even against Maven qualifiers below 0", () => {
	const r = R([{ fixed: "1.0" }, { introduced: "0" }]);
	assert.equal(rangeAffects("0-alpha", r), true);
	assert.equal(rangeAffects("0.9", r), true);
	assert.equal(rangeAffects("1.0", r), false);
});

test("last_affected is inclusive when unsorted too", () => {
	const r = R([{ last_affected: "2.0" }, { introduced: "1.0" }]);
	assert.equal(rangeAffects("0.5", r), false);
	assert.equal(rangeAffects("2.0", r), true);
	assert.equal(rangeAffects("2.0.1", r), false);
});

test("limit events bound the range (exclusive upper limit; '*' = unbounded)", () => {
	const r = R([{ introduced: "0" }, { limit: "2.0" }]);
	assert.equal(rangeAffects("1.9", r), true);
	assert.equal(rangeAffects("2.0", r), false, "v >= limit → outside the range");
	assert.equal(rangeAffects("5.0", r), false, "the open [0,∞) interval stops at the limit");
	assert.equal(rangeAffects("5.0", R([{ introduced: "0" }, { limit: "*" }])), true);
	// limit listed first, unsorted relative to the rest
	assert.equal(rangeAffects("3.0", R([{ limit: "2.0" }, { introduced: "1.0" }])), false);
	assert.equal(rangeAffects("1.5", R([{ limit: "2.0" }, { introduced: "1.0" }])), true);
});

test("Maven ordering, not lexical: 1.10 > 1.9 inside an unsorted range", () => {
	const r = R([{ fixed: "1.10" }, { introduced: "1.9" }]);
	assert.equal(rangeAffects("1.9.5", r), true);
	assert.equal(rangeAffects("1.10", r), false);
	assert.equal(rangeAffects("1.10.1", r), false);
});

test("explicit versions[] lists keep matching regardless of ranges", () => {
	const v = { affected: [{ versions: ["3.11"], ranges: [R([{ fixed: "1.0" }, { introduced: "0.5" }])] }] };
	assert.equal(vulnAffectsVersion("3.11", v), true);
	assert.equal(vulnAffectsVersion("0.7", v), true);
	assert.equal(vulnAffectsVersion("0.3", v), false);
});
