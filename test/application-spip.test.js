const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const spip = require("../lib/application-plugins/spip");
const { runApplicationPlugins } = require("../lib/application-plugins/runner");
const { assessSpipAdvisories, validateSnapshot, fetchSpipAdvisories, SPIP_ADVISORIES_URL } = require("../lib/application-providers/spip-advisories");

const FIXTURE = path.join(__dirname, "fixtures", "spip-custom");
const NOW = Date.parse("2026-09-24T12:00:00Z");
const jsonResponse = body => ({ ok: true, status: 200, text: async () => JSON.stringify(body), json: async () => body });

/** A minimal NVD-shaped product CVE set: one range-bound CVE, one pin, one non-SPIP CPE. */
const nvdSnapshot = () => ({
	cpe: "cpe:2.3:a:spip:spip",
	vulnerabilities: [
		{ cve: { id: "CVE-2023-27330", published: "2023-05-10T00:00:00.000",
			descriptions: [{ lang: "en", value: "SPIP remote code execution." }],
			metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] },
			configurations: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:spip:spip:-:*:*:*:*:*:*:*", versionStartIncluding: "1.0.0",
				versionEndExcluding: "4.1.10" }] }] }] } },
		{ cve: { id: "CVE-2006-0625", published: "2006-02-09T00:00:00.000",
			descriptions: [{ lang: "en", value: "Historic injection in 1.8.2d." }],
			metrics: { cvssMetricV2: [{ cvssData: { baseScore: 7.5 } }] },
			configurations: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:spip:spip:1.8.2d:*:*:*:*:*:*:*" }] }] }] } },
		{ cve: { id: "CVE-2024-99999", published: "2024-01-01T00:00:00.000",
			descriptions: [{ lang: "en", value: "Another product entirely." }],
			metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.0 } }] },
			configurations: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:somevendor:other:1.0:*:*:*:*:*:*:*" }] }] }] } },
	],
	_fadSnapshot: { collectedAt: "2026-09-24T08:00:00.000Z", completeness: "tool-fetched", sourceUrl: SPIP_ADVISORIES_URL },
});

function tempDir() { return fs.mkdtempSync(path.join(os.tmpdir(), "fad-spip-")); }

test("detection is conjunctive: the markers AND a readable version constant, never a bare file name", async () => {
	const result = await runApplicationPlugins(FIXTURE, { plugins: [spip], selection: "spip" });
	assert.equal(result.applications.length, 1, "the fixture site is a SPIP instance");
	assert.equal(result.applications[0].id, "spip:site");
	assert.equal(result.applications[0].layout, "classic");
	const core = result.inventory.find(c => c.kind === "core");
	assert.equal(core.version, "4.1.2", "the observed version constant is the version evidence");
	assert.equal(core.coord, "spip/spip");
	// A bare PHP tree is never a phantom SPIP instance.
	const temp = tempDir();
	try {
		fs.mkdirSync(path.join(temp, "lib"), { recursive: true });
		fs.writeFileSync(path.join(temp, "composer.json"), JSON.stringify({ name: "acme/plain-lib", require: { "spip/spip": "4.1.2" } }));
		const plain = await runApplicationPlugins(temp, { plugins: [spip], selection: "spip" });
		assert.equal(plain.applications.length, 0, "a composer.json requiring spip/spip is not a SPIP instance");
	} finally { require("../lib/cache-db").closeCacheDbs(); fs.rmSync(temp, { recursive: true, force: true }); }
});

test("inventory: official dist plugins read paquet.xml, user plugins legacy plugin.xml, private paths stay private", async () => {
	const result = await runApplicationPlugins(FIXTURE, { plugins: [spip], selection: "spip",
		privateComponentPaths: ["site/plugins/acme-checkout"] });
	const plugins = result.inventory.filter(c => c.kind === "plugin");
	assert.equal(plugins.length, 2);
	const dist = plugins.find(c => c.machineName === "safehtml");
	assert.equal(dist.version, "3.0.2");
	assert.equal(dist.name, "SafeHTML");
	assert.equal(dist.visibility, "public", "plugins-dist is the official distribution set");
	assert.equal(dist.identityStatus, "verified");
	const custom = plugins.find(c => c.machineName === "acmecheckout");
	assert.equal(custom.version, "1.2.0", "legacy plugin.xml carries the same identity fields");
	assert.equal(custom.name, "Acme Checkout");
	assert.equal(custom.visibility, "private", "a declared private path is never sent anywhere");
	assert.equal(custom.coord, null, "SPIP plugins have no catalogue coordinate");
	const inventory = result.coverage.find(c => c.capability === "inventory");
	assert.equal(inventory.execution, "completed");
});

test("the NVD lane assesses the OBSERVED core version and leaves plugins honestly not-qualified", () => {
	const core = { id: "spip:site:core", applicationId: "spip:site", kind: "core", version: "4.1.2",
		visibility: "public", evidence: [{ path: "site/ecrire/inc_version.php", field: "spip_version_branche" }] };
	const plugin = { id: "spip:site:plugin:plugins-dist/safehtml", applicationId: "spip:site", kind: "plugin",
		version: "3.0.2", visibility: "public" };
	const privatePlugin = { id: "spip:site:plugin:plugins/acme-checkout", applicationId: "spip:site", kind: "plugin",
		version: "1.2.0", visibility: "private" };
	const assessed = assessSpipAdvisories(nvdSnapshot(), [core, plugin, privatePlugin]);
	assert.equal(assessed.matches.length, 1, "only the range-bound CVE matches 4.1.2");
	assert.equal(assessed.matches[0].cve.id, "CVE-2023-27330");
	assert.equal(assessed.matches[0].cve.severity, "CRITICAL");
	assert.equal(assessed.matches[0].cve.score, 9.8);
	assert.equal(assessed.matches[0].cve.fixVersion, "4.1.10", "NVD's versionEndExcluding is the fix version");
	assert.equal(assessed.matches[0].dep.coordKey, "composer:spip/spip");
	assert.equal(assessed.matches[0].dep.version, "4.1.2");
	const coreRow = assessed.coverage.find(c => c.occurrenceId === core.id);
	assert.equal(coreRow.execution, "completed");
	assert.equal(coreRow.result, "affected");
	const pluginRow = assessed.coverage.find(c => c.occurrenceId === plugin.id);
	assert.equal(pluginRow.execution, "not-run", "no advisory source exists for SPIP plugins — never a clean verdict");
	assert.equal(pluginRow.diagnostic, "CMS_ADVISORY_NOT_QUALIFIED");
	const privateRow = assessed.coverage.find(c => c.occurrenceId === privatePlugin.id);
	assert.equal(privateRow.sourceId, "internal-advisories");
	assert.equal(privateRow.diagnostic, "CMS_PRIVATE_COMPONENT");
	// A current core is a stated result, not a gap.
	const clean = assessSpipAdvisories(nvdSnapshot(), [{ ...core, version: "4.4.24" }]);
	assert.equal(clean.matches.length, 0);
	assert.equal(clean.coverage[0].result, "no-match");
});

test("the live NVD fetch validates, stamps and paginates loudly", async () => {
	const calls = [];
	const fetched = await fetchSpipAdvisories({
		fetchImpl: async url => { calls.push(String(url)); return jsonResponse({ totalResults: 1, vulnerabilities: nvdSnapshot().vulnerabilities.slice(0, 1) }); },
		now: NOW });
	assert.equal(fetched.snapshot.vulnerabilities.length, 1);
	assert.equal(fetched.snapshot._fadSnapshot.completeness, "tool-fetched");
	assert.equal(fetched.snapshot._fadSnapshot.collectedAt, new Date(NOW).toISOString());
	assert.match(calls[0], /virtualMatchString=cpe:2\.3:a:spip:spip/);
	// A partial page is refused, never cached.
	await assert.rejects(fetchSpipAdvisories({
		fetchImpl: async () => jsonResponse({ totalResults: 5000, vulnerabilities: nvdSnapshot().vulnerabilities }) }),
	/exceed the single-page limit/);
	await assert.rejects(fetchSpipAdvisories({
		fetchImpl: async () => jsonResponse({ message: "Unauthorized" }) }), /Unauthorized/);
	assert.throws(() => validateSnapshot({ vulnerabilities: [{ cve: { id: "CVE-1" } }] }), /configurations/);
});

test("the lane runs from a local snapshot, a live fetch, and a warmed cache without any flag", async () => {
	const temp = tempDir();
	try {
		// Local snapshot file → operator-declared provenance, assessment identical.
		const snapshotFile = path.join(temp, "spip-advisories.json");
		fs.writeFileSync(snapshotFile, JSON.stringify(nvdSnapshot()));
		const local = await runApplicationPlugins(FIXTURE, { plugins: [spip], selection: "spip",
			spipAdvisoriesPath: snapshotFile });
		assert.equal(local.findings.length, 1);
		assert.equal(local.findings[0].cve.id, "CVE-2023-27330");
		const coreRow = local.coverage.find(c => c.capability === "advisories" && c.occurrenceId?.endsWith(":core"));
		assert.equal(coreRow.execution, "completed");
		assert.equal(coreRow.sourceSnapshot.completeness, "operator-declared");

		// Live fetch → the snapshot is cached for offline reuse, tool-fetched provenance.
		const cacheDir = path.join(temp, "advisory-snapshots");
		const live = await runApplicationPlugins(FIXTURE, { plugins: [spip], selection: "spip",
			liveSpipAdvisoriesUrl: SPIP_ADVISORIES_URL, advisoryCacheDir: cacheDir, now: NOW,
			fetchImpl: async () => jsonResponse({ totalResults: 3, vulnerabilities: nvdSnapshot().vulnerabilities }) });
		assert.equal(live.findings.length, 1);
		const cachedFile = path.join(cacheDir, "spip-security-advisories.json");
		assert.ok(require('../lib/application-providers/snapshot-cache').exists(cachedFile), "the live fetch writes the snapshot for offline reuse");
		assert.equal(JSON.parse(require('../lib/application-providers/snapshot-cache').read(cachedFile).bytes)._fadSnapshot.completeness, "tool-fetched");
		assert.equal(live.coverage.find(c => c.capability === "advisories" && c.occurrenceId?.endsWith(":core")).sourceSnapshot.completeness, "tool-fetched");

		// The warmed cache is consumed with NO flag and NO key — the air-gap phase 3.
		const reuse = await runApplicationPlugins(FIXTURE, { plugins: [spip], selection: "spip",
			advisoryCacheDir: cacheDir });
		assert.equal(reuse.findings.length, 1, "same command, same options — identical results online and offline");
		const reuseRow = reuse.coverage.find(c => c.capability === "advisories" && c.occurrenceId?.endsWith(":core"));
		assert.equal(reuseRow.execution, "completed");
		assert.equal(reuseRow.sourceSnapshot.completeness, "tool-fetched");
	} finally { require("../lib/cache-db").closeCacheDbs(); fs.rmSync(temp, { recursive: true, force: true }); }
});

test("an unconfigured lane is an honest not-run, and the lifecycle row says not-qualified", async () => {
	const result = await runApplicationPlugins(FIXTURE, { plugins: [spip], selection: "spip" });
	const advisories = result.coverage.filter(c => c.capability === "advisories");
	assert.equal(advisories.length, 3, "one row per inventoried component");
	assert.ok(advisories.every(c => c.execution === "not-run" && c.diagnostic === "CMS_PROVIDER_UNCONFIGURED"));
	const lifecycle = result.coverage.find(c => c.capability === "lifecycle");
	assert.equal(lifecycle.execution, "not-run");
	assert.equal(lifecycle.diagnostic, "CMS_LIFECYCLE_NOT_QUALIFIED");
});

test("SPIP excludes non-vulnerable context CPEs and other products, and keeps missing severity unknown", () => {
	const core = { id: "spip:site:core", applicationId: "spip:site", kind: "core", version: "4.1.2", visibility: "public" };
	for (const change of [
		m => { m.vulnerable = false; },
		m => { m.criteria = "cpe:2.3:a:spip:spip_extra:*:*:*:*:*:*:*:*"; },
	]) {
		const snapshot = nvdSnapshot();
		change(snapshot.vulnerabilities[0].cve.configurations[0].nodes[0].cpeMatch[0]);
		assert.equal(assessSpipAdvisories(snapshot, [core]).matches.length, 0);
	}
	const snapshot = nvdSnapshot();
	delete snapshot.vulnerabilities[0].cve.metrics;
	assert.equal(assessSpipAdvisories(snapshot, [core]).matches[0].cve.severity, "UNKNOWN");
});

test("a required live SPIP source fails on an old proxy response with max-advisory-age", async () => {
	await assert.rejects(runApplicationPlugins(FIXTURE, { plugins: [spip], selection: "spip",
		liveSpipAdvisoriesUrl: SPIP_ADVISORIES_URL, now: NOW, maxAdvisoryAgeMs: 3600000,
		fetchImpl: async () => new Response(JSON.stringify(nvdSnapshot()), {
			headers: { "x-fad-proxy-fetched-at": "2020-01-01T00:00:00Z" },
		}),
	}), /snapshot collected .* is stale/);
});
