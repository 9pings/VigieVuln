/**
 * Two things an EOL row has to get right, both found on a real report.
 *
 * 1. `org.springframework.batch:spring-batch-core 4.3.x` was reported as "Spring Framework 4.3,
 *    EOL since 2020-12-31". Spring Batch is a different project on a different calendar, and
 *    endoflife.date does not track it — so the correct output is no verdict, not a wrong one.
 * 2. That row then advised "latest 4.3.30", the final patch of the dead branch. Nobody migrating
 *    off an EOL cycle wants its last patch; they want the version to move TO.
 */
const test = require("node:test");
const assert = require("node:assert");
const { findEolProduct, latestSupportedCycle } = require("../lib/maintenance/outdated");

test("org.springframework matches only itself, never its sub-projects", () => {
	assert.strictEqual(findEolProduct({ groupId: "org.springframework", artifactId: "spring-core" }).product, "spring-framework");
	// each of these is its own release train; endoflife.date tracks none of them
	for (const g of ["org.springframework.batch", "org.springframework.integration",
		"org.springframework.data", "org.springframework.amqp", "org.springframework.kafka",
		"org.springframework.ws", "org.springframework.session"]) {
		assert.strictEqual(findEolProduct({ groupId: g, artifactId: "x" }), null, g);
	}
});

test("the sub-projects that DO have their own product still resolve to it", () => {
	assert.strictEqual(findEolProduct({ groupId: "org.springframework.boot", artifactId: "spring-boot" }).product, "spring-boot");
	assert.strictEqual(findEolProduct({ groupId: "org.springframework.security", artifactId: "x" }).product, "spring-security");
	assert.strictEqual(findEolProduct({ groupId: "org.springframework.cloud", artifactId: "x" }).product, "spring-cloud");
});

const CYCLES = [
	{ cycle: "7.0", eol: "2027-07-31", latest: "7.0.9" },
	{ cycle: "6.2", eol: "2026-06-30", latest: "6.2.19" },
	{ cycle: "6.1", eol: "2025-06-30", latest: "6.1.21" },
	{ cycle: "4.3", eol: "2020-12-31", latest: "4.3.30" },
];
const NOW = new Date("2026-09-18");

test("the migration target is the newest cycle still supported", () => {
	assert.strictEqual(latestSupportedCycle(CYCLES, NOW).latest, "7.0.9");
});

test("a cycle whose EOL date has passed is not a target", () => {
	const past = [{ cycle: "6.1", eol: "2025-06-30", latest: "6.1.21" }, { cycle: "4.3", eol: "2020-12-31", latest: "4.3.30" }];
	assert.strictEqual(latestSupportedCycle(past, NOW), null);
});

test("eol:false means supported — endoflife.date uses it for live branches", () => {
	const live = [{ cycle: "3.1", eol: false, latest: "3.1.4" }, { cycle: "2.0", eol: "2020-01-01", latest: "2.0.9" }];
	assert.strictEqual(latestSupportedCycle(live, NOW).latest, "3.1.4");
});

test("newest is decided by version order, not by array order", () => {
	const shuffled = [CYCLES[3], CYCLES[1], CYCLES[0], CYCLES[2]];
	assert.strictEqual(latestSupportedCycle(shuffled, NOW).latest, "7.0.9");
});

test("no cycles, no target — and no throw", () => {
	assert.strictEqual(latestSupportedCycle([], NOW), null);
	assert.strictEqual(latestSupportedCycle(null, NOW), null);
});

test("an 'unsupported' cycle keeps its own latest — patching in place is the advice there", async () => {
	// Active support ended but security fixes continue, so the last patch of the CURRENT branch
	// is actionable. Only a dead cycle needs a migration target.
	const { checkEolDeps } = require("../lib/maintenance/outdated");
	const CYC = [
		{ cycle: "7.0", eol: "2030-01-01", latest: "7.0.4" },
		{ cycle: "5.4", eol: "2029-02-28", support: "2024-11-30", latest: "5.4.53" },
	];
	const dep = { ecosystem: "composer", namespace: "symfony", name: "console", version: "5.4.47",
		coordKey: "composer:symfony/console", manifestPaths: [] };
	const r = await checkEolDeps(new Map([[dep.coordKey, dep]]),
		{ cycles: { symfony: CYC }, now: new Date("2026-09-18"), eolSupport: true });
	assert.strictEqual(r[0].status, "unsupported");
	assert.strictEqual(r[0].latest, "5.4.53");
});
