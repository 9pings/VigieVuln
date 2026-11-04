const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { parseMaxAge, declaredCollectedAt, assertFresh } = require("../lib/advisory-freshness");
const { indexFeed } = require("../lib/application-providers/wordfence-v3");
const drupal = require("../lib/application-plugins/drupal");
const { runApplicationPlugins } = require("../lib/application-plugins/runner");

const NOW = Date.parse("2026-09-23T12:00:00Z");

test("max age accepts a strict duration and rejects anything else", () => {
	assert.equal(parseMaxAge("30s"), 30 * 1000);
	assert.equal(parseMaxAge("15m"), 15 * 60 * 1000);
	assert.equal(parseMaxAge("72h"), 72 * 3600 * 1000);
	assert.equal(parseMaxAge("7d"), 7 * 24 * 3600 * 1000);
	for (const bad of ["", "72", "hours", "1.5d", "-1d", "0d"]) assert.throws(() => parseMaxAge(bad), /duration/i);
});

test("declared collection date is read from the reserved metadata or a top-level field", () => {
	const iso = "2026-09-20T08:00:00Z";
	assert.equal(declaredCollectedAt({ _fadSnapshot: { collectedAt: iso } }).getTime(), Date.parse(iso));
	assert.equal(declaredCollectedAt({ collectedAt: iso }).getTime(), Date.parse(iso));
	assert.equal(declaredCollectedAt({ generatedAt: iso }).getTime(), Date.parse(iso));
	assert.equal(declaredCollectedAt({ advisories: {} }), null, "nothing declared means no freshness proof");
	assert.throws(() => declaredCollectedAt({ _fadSnapshot: { collectedAt: "yesterday" } }), /ISO 8601/);
});

test("freshness verdicts: fresh passes, stale and undeclared fail closed", () => {
	assert.equal(assertFresh({ collectedAt: "2026-09-23T09:00:00Z" }, "Drupal advisories", 72 * 3600 * 1000, NOW).collectedAt,
		"2026-09-23T09:00:00.000Z");
	assert.throws(() => assertFresh({ collectedAt: "2026-09-01T00:00:00Z" }, "Drupal advisories", 72 * 3600 * 1000, NOW),
		/stale.*--max-advisory-age/i);
	assert.throws(() => assertFresh({ advisories: {} }, "Drupal advisories", 72 * 3600 * 1000, NOW),
		/does not declare.*collection date/i);
});

test("Wordfence indexFeed tolerates the reserved snapshot metadata and keeps matching strict", () => {
	const uuid = "123e4567-e89b-12d3-a456-426614174000";
	const record = { id: uuid, title: "Fixture", cve: null, software: [{ type: "plugin", slug: "acme",
		affected_versions: { a: { from_version: "1", from_inclusive: true, to_version: "2", to_inclusive: true } } }] };
	const index = indexFeed({ _fadSnapshot: { collectedAt: "2026-09-23T00:00:00Z" }, [uuid]: record });
	assert.equal(index.get("plugin:acme").length, 1);
	assert.throws(() => indexFeed({ _meta: {}, [uuid]: record }), /invalid Wordfence v3 record/);
	assert.throws(() => indexFeed({ _fadSnapshot: "not an object" }), /_fadSnapshot/);
});

test("runner enforces max advisory age before any inventory runs", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-freshness-"));
	try {
		const feed = path.join(temp, "advisories.json");
		fs.writeFileSync(feed, JSON.stringify({ collectedAt: "2026-09-01T00:00:00Z",
			queriedPackages: ["drupal/core"], advisories: { "drupal/core": [
				{ advisoryId: "SA-CORE-2099-001", packageName: "drupal/core", title: "Fixture",
					link: "https://www.drupal.org/sa-core-2099-001", cve: null, affectedVersions: ">=10.3.0 <10.3.2" }] } }));
		const src = path.join(__dirname, "fixtures", "drupal-custom");
		const opts = { plugins: [drupal], selection: "drupal", activeCodecIds: [],
			drupalAdvisoriesPath: feed, maxAdvisoryAgeMs: 72 * 3600 * 1000, now: NOW };
		await assert.rejects(runApplicationPlugins(src, opts), /stale.*--max-advisory-age/i);
		fs.writeFileSync(feed, JSON.stringify({ collectedAt: "2026-09-23T09:00:00Z",
			queriedPackages: ["drupal/core"], advisories: { "drupal/core": [
				{ advisoryId: "SA-CORE-2099-001", packageName: "drupal/core", title: "Fixture",
					link: "https://www.drupal.org/sa-core-2099-001", cve: null, affectedVersions: ">=10.3.0 <10.3.2" }] } }));
		const result = await runApplicationPlugins(src, { ...opts, resolvedDeps: (await require("../lib/codecs/composer.codec").collect(src)).deps, activeCodecIds: ["composer"] });
		assert.equal(result.findings.length, 1);
		assert.equal(result.coverage.find(c => c.capability === "advisories").sourceSnapshot.collectedAt,
			"2026-09-23T09:00:00.000Z", "the declared collection date travels with the coverage provenance");
		const undeclared = path.join(temp, "undeclared.json");
		fs.writeFileSync(undeclared, JSON.stringify({ queriedPackages: [], advisories: {} }));
		await assert.rejects(runApplicationPlugins(src, { ...opts, drupalAdvisoriesPath: undeclared }),
			/does not declare.*collection date/i);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test('future collection dates fail closed beyond the five-minute clock-skew allowance', () => {
 for(const date of [NOW+300001,Date.parse('2099-01-01T00:00:00Z')])
  for(const snapshot of [{collectedAt:new Date(date).toISOString()},{generatedAt:new Date(date).toISOString()},{_fadSnapshot:{collectedAt:new Date(date).toISOString()}}])
   assert.throws(()=>assertFresh(snapshot,'fixture',86400000,NOW),/in the future/);
 for(const delta of [0,300000])assert.equal(assertFresh({collectedAt:new Date(NOW+delta).toISOString()},'fixture',86400000,NOW).collectedAt,new Date(NOW+delta).toISOString());
});
