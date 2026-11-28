const { test } = require("node:test");
const assert = require("node:assert/strict");
const { evaluateGate } = require("../lib/findings/gate");

const M = (sev, extra = {}) => ({ cve: { severity: sev, ...extra } });

test("none never fails", () => {
	assert.equal(evaluateGate([M("CRITICAL")], "none").failed, false);
});

test("severity threshold fails at or above the level", () => {
	const set = [M("LOW"), M("MEDIUM"), M("HIGH")];
	assert.equal(evaluateGate(set, "critical").failed, false);
	assert.equal(evaluateGate(set, "high").failed, true);
	assert.equal(evaluateGate(set, "high").count, 1);
	assert.equal(evaluateGate(set, "medium").count, 2);
	assert.equal(evaluateGate(set, "low").count, 3);
});

test("kev fails only on a known-exploited finding", () => {
	assert.equal(evaluateGate([M("LOW", { kev: true })], "kev").failed, true);
	assert.equal(evaluateGate([M("CRITICAL")], "kev").failed, false);
});

test("suppressed matches are ignored by the gate", () => {
	const set = [{ cve: { severity: "CRITICAL" }, suppressed: true }];
	assert.equal(evaluateGate(set, "critical").failed, false);
});

test("unknown level does not fail the build", () => {
	assert.equal(evaluateGate([M("CRITICAL")], "bogus").failed, false);
});
