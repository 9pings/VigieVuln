const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { buildScanProvenance, collectDataSources } = require("../lib/provenance");

function tmpCacheDir() {
	return fs.mkdtempSync(path.join(os.tmpdir(), "fad-prov-"));
}

test("buildScanProvenance records tool, mode and the run configuration", () => {
	const dir = tmpCacheDir();
	try {
		const p = buildScanProvenance({
			toolVersion: "2.3.2",
			generatedAt: "2026-06-18T00:00:00.000Z",
			options: { offline: true, transitive: false, transitiveDepth: "6", osv: false, failOn: "high", ecosystem: "maven,npm" },
			cacheDir: dir,
			runtime: { node: "v20.0.0", platform: "linux", arch: "x64" },
		});
		assert.strictEqual(p.tool.name, "VigieVuln");
		assert.strictEqual(p.tool.version, "2.3.2");
		assert.strictEqual(p.generatedAt, "2026-06-18T00:00:00.000Z");
		assert.strictEqual(p.mode, "offline");
		assert.strictEqual(p.runtime.node, "v20.0.0");
		assert.strictEqual(p.configuration.transitive, false);
		assert.strictEqual(p.configuration.failOn, "high");
		assert.ok(Array.isArray(p.dataSources));
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("collectDataSources reads each source's freshness marker", () => {
	const dir = tmpCacheDir();
	try {
		fs.mkdirSync(path.join(dir, "cve-data"), { recursive: true });
		fs.writeFileSync(path.join(dir, "cve-data", "meta.json"), JSON.stringify({ builtAt: "2026-06-01T10:00:00.000Z", cveCount: 1234 }));
		fs.writeFileSync(path.join(dir, "epss-cache.json"), JSON.stringify({ meta: { fetchedAt: Date.parse("2026-06-10T00:00:00.000Z") }, entries: { a: 1, b: 2 } }));
		fs.writeFileSync(path.join(dir, "kev-cache.json"), JSON.stringify({ _fetchedAt: Date.parse("2026-06-12T00:00:00.000Z"), body: { catalogVersion: "2026.06.12", dateReleased: "2026-06-12", vulnerabilities: [] } }));

		const sources = collectDataSources({ cacheDir: dir, options: {} });
		const by = Object.fromEntries(sources.map(s => [s.id, s]));

		assert.strictEqual(by.cve.status, "cached");
		assert.strictEqual(by.cve.asOf, "2026-06-01T10:00:00.000Z");
		assert.match(by.cve.detail, /1234/);

		assert.strictEqual(by.epss.status, "cached");
		assert.strictEqual(by.epss.asOf, "2026-06-10T00:00:00.000Z");

		assert.strictEqual(by.kev.status, "cached");
		assert.match(by.kev.detail || "", /2026\.06\.12/);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("collectDataSources marks a source disabled by its flag and missing when uncached", () => {
	const dir = tmpCacheDir();
	try {
		const sources = collectDataSources({ cacheDir: dir, options: { osv: false } });
		const by = Object.fromEntries(sources.map(s => [s.id, s]));
		assert.strictEqual(by.osv.status, "disabled");
		assert.strictEqual(by.nvd.status, "missing"); // nvd not disabled, but no cache present
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("collectDataSources counts OSV cache files and reports a newest date", () => {
	const dir = tmpCacheDir();
	try {
		fs.mkdirSync(path.join(dir, "osv-cache"), { recursive: true });
		fs.writeFileSync(path.join(dir, "osv-cache", "maven__g__a__1.0.json"), "{}");
		fs.writeFileSync(path.join(dir, "osv-cache", "vuln_GHSA-x.json"), "{}");
		const sources = collectDataSources({ cacheDir: dir, options: {} });
		const osv = sources.find(s => s.id === "osv");
		assert.strictEqual(osv.status, "cached");
		assert.match(osv.detail, /2/); // 2 cached files
		assert.ok(osv.asOf, "has a newest-entry date");
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
