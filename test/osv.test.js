const isolatedTestCache = require('./helpers/isolated-cache')('osv');
const test = require("node:test");
const assert = require("node:assert");
const { osvEcosystemFor, osvPkgName, severityFromOsv, vulnToMatch, fixVersionFromOsv } = require("../lib/osv");

// Regression: a multi-branch advisory (Tomcat fixed in 9.0.118, 10.1.55 AND 11.0.22) must
// recommend the fix ABOVE the current version (the dep's own branch), never the lowest one
// — suggesting 9.0.118 for an 11.0.21 dep is a downgrade.
const TOMCAT_MULTIBRANCH = {
	affected: [{
		package: { name: "org.apache.tomcat.embed:tomcat-embed-core", ecosystem: "Maven" },
		ranges: [{ type: "ECOSYSTEM", events: [
			{ introduced: "0" }, { fixed: "9.0.118" },
			{ introduced: "10.1.0-M1" }, { fixed: "10.1.55" },
			{ introduced: "11.0.0-M1" }, { fixed: "11.0.22" },
		] }],
	}],
};

test("fixVersionFromOsv picks the next fix ABOVE the current version, not a lower branch", () => {
	const pkg = "org.apache.tomcat.embed:tomcat-embed-core";
	assert.strictEqual(fixVersionFromOsv(TOMCAT_MULTIBRANCH, pkg, "11.0.21"), "11.0.22");
	assert.strictEqual(fixVersionFromOsv(TOMCAT_MULTIBRANCH, pkg, "10.1.50"), "10.1.55");
	assert.strictEqual(fixVersionFromOsv(TOMCAT_MULTIBRANCH, pkg, "9.0.100"), "9.0.118");
});

test("fixVersionFromOsv returns null rather than a downgrade when no fix is above current", () => {
	const v = { affected: [{ package: { name: "g:a" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "9.0.118" }] }] }] };
	assert.strictEqual(fixVersionFromOsv(v, "g:a", "11.0.21"), null);
});

test("osvEcosystemFor maps codec ids to OSV ecosystem names", () => {
	assert.strictEqual(osvEcosystemFor({ ecosystem: "maven" }), "Maven");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "npm" }), "npm");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "yarn" }), "npm");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "nuget" }), "NuGet");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "composer" }), "Packagist");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "pypi" }), "PyPI");
});

test("osvPkgName delegates to codec for maven (g:a) and npm (bare name)", () => {
	assert.strictEqual(osvPkgName({ ecosystem: "maven", namespace: "org.apache", name: "log4j", groupId: "org.apache", artifactId: "log4j" }), "org.apache:log4j");
	assert.strictEqual(osvPkgName({ ecosystem: "npm", namespace: "", name: "lodash", artifactId: "lodash" }), "lodash");
});

const { queryOsvForDeps } = require("../lib/osv");
const { makeDepRecord } = require("../lib/dep-record");

// Regression: queryOsvForDeps must send the codec's package name + ecosystem to
// OSV for EVERY ecosystem. A prior bug cherry-picked only groupId/artifactId when
// rebuilding per-version deps, so composer/pypi/nuget queried name=undefined.
test("queryOsvForDeps sends correct package name + ecosystem per codec (mock fetcher)", async () => {
	const captured = [];
	const fetcher = async (url, opts) => {
		if (url.includes("/querybatch")) {
			const body = JSON.parse(opts.body);
			captured.push(...body.queries);
			return { ok: true, json: async () => ({ results: body.queries.map(() => ({ vulns: [] })) }) };
		}
		return { ok: true, json: async () => ({}) };
	};
	const deps = new Map();
	for (const [eco, ns, name, ver, expName, expEco] of [
		["pypi", "", "django", "9.9.9-fadtest", "django", "PyPI"],
		["composer", "guzzlehttp", "guzzle", "9.9.9-fadtest", "guzzlehttp/guzzle", "Packagist"],
		["nuget", "", "Newtonsoft.Json", "9.9.9-fadtest", "Newtonsoft.Json", "NuGet"],
		["maven", "org.apache", "log4j-core", "9.9.9-fadtest", "org.apache:log4j-core", "Maven"],
		["npm", "", "lodash", "9.9.9-fadtest", "lodash", "npm"],
	]) {
		const r = makeDepRecord({ ecosystem: eco, namespace: ns, name, version: ver, manifestPath: "x" });
		r._exp = { name: expName, eco: expEco };
		deps.set(r.coordKey, r);
	}
	await queryOsvForDeps(deps, { fetcher, cacheDir: require('path').join(isolatedTestCache, 'codecs') });
	for (const d of deps.values()) {
		const q = captured.find(c => c.package.name === d._exp.name);
		assert.ok(q, `expected an OSV query with package.name="${d._exp.name}" (${d.ecosystem})`);
		assert.strictEqual(q.package.ecosystem, d._exp.eco, `ecosystem for ${d._exp.name}`);
		assert.strictEqual(q.version, d.version);
	}
});

// Regression: OSV stores the CVSS *vector* in severity[].score — we must compute
// the base score, not extract the version "3.1" as the score. (audit fix #A)
test("severityFromOsv computes the v3 base score from the vector, not the version", () => {
	const mk = v => ({ severity: [{ type: "CVSS_V3", score: v }] });
	assert.deepEqual(severityFromOsv(mk("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")), { severity: "CRITICAL", score: 9.8 });
	// reflected-XSS reference vector → 6.1
	assert.deepEqual(severityFromOsv(mk("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")), { severity: "MEDIUM", score: 6.1 });
	// a CVSS v4 vector can't be scored here → null (lets NVD fill it in), never 4.0
	assert.equal(severityFromOsv(mk("CVSS:4.0/AV:N/AC:L")).score, null);
	// a bare numeric score is taken as-is
	assert.equal(severityFromOsv(mk("7.5")).score, 7.5);
});

test("vulnToMatch carries the CVSS vector + version from OSV severity", () => {
	const m = vulnToMatch({ ecosystem: "npm", name: "x", version: "1.0.0", coordKey: "npm:x" },
		{ id: "GHSA-aaaa", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] });
	assert.equal(m.cve.score, 9.8);
	assert.equal(m.cve.cvssVersion, "CVSS:3.1");
	assert.ok(m.cve.cvssVector.startsWith("CVSS:3.1/"));
});

// Regression (air-gapped principle): a warmed OSV cache older than the 12h TTL
// must STILL be served under --offline — it is the only source there. Expiring
// it silently reported "0 OSV vulns" for every ecosystem on an air-gapped box.
test("offline serves the warmed OSV cache even past the 12h TTL (no network)", async t => {
	const staleAt = Date.now() - 48 * 3600 * 1000; // 2 days old
	const dep = makeDepRecord({ ecosystem: "pypi", namespace: "", name: "fadtest-stale-pkg", version: "1.0.0-fadtest", manifestPath: "x" });
	const cacheDir = require('path').join(isolatedTestCache, 'stale');
	const store = require('../lib/advisory-store').openAdvisoryStore({ cacheDir });
	t.after(() => store.close());
	store.commit({ records: [{ source: 'osv', fetchedAt: staleAt, document:
		{ id: 'FADTEST-2026-0001', summary: 'stale-cache sentinel', aliases: ['CVE-2026-99999'], database_specific: { severity: 'HIGH' } } }],
		queries: [{ source: 'osv', ecosystem: 'PyPI', name: dep.name, version: dep.version,
			ids: ['FADTEST-2026-0001'], fetchedAt: staleAt, complete: true }] });
	const tripwire = async () => { throw new Error("offline mode must not touch the network"); };
		const matches = await queryOsvForDeps(new Map([[dep.coordKey, dep]]), { offline: true, fetcher: tripwire, cacheDir });
		assert.strictEqual(matches.length, 1, "stale-but-warmed cache entry still matched offline");
		assert.strictEqual(matches[0].cve.id, "CVE-2026-99999");
		assert.strictEqual(matches[0].cve.severity, "HIGH");
});
