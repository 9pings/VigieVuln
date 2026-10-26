/**
 * lib/provenance.js — scan-provenance / reproducibility manifest.
 *
 * A professional audit must be defensible and reproducible: a finding has to be
 * explainable from the exact inputs that produced it, and a second auditor should be
 * able to reproduce it. This module builds a manifest of WHAT vigievuln ran with —
 * tool version, runtime, run mode (offline/online), the run configuration (only the
 * flags that change WHAT is found), and the freshness of every data source (read from
 * its own cache under ~/.fad-checker/).
 *
 * The manifest reports the CACHE STATE of each source, not "online vs offline this
 * run" — the cache state is the reproducible truth and is what an --offline re-run
 * reads from. Pure given a cacheDir (injected for tests).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const DEFAULT_CACHE_DIR = path.join(os.homedir(), ".fad-checker");

function readJson(file) {
	try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return null; }
}

function iso(ms) {
	if (!ms || !Number.isFinite(Number(ms))) return null;
	try { return new Date(Number(ms)).toISOString(); } catch { return null; }
}

// Each data source declares how to read its freshness from its cache file/dir.
// kind:
//   "cve-meta"   cve-data/meta.json  → { builtAt, cveCount }
//   "meta"       <file>.json         → { meta: { fetchedAt }, entries }
//   "kev"        kev-cache.json       → { _fetchedAt, body: { catalogVersion, dateReleased } }
//   "snapshot"   euvd-cache.json      → { _fetchedAt, body: { count } }
//   "dir"        <dir>/               → file count + newest mtime
const SOURCE_DEFS = [
	{ id: "cve", label: "CVEProject (Maven index)", rel: "cve-data/meta.json", kind: "cve-meta" },
	{ id: "osv", label: "OSV.dev", rel: "osv-cache", kind: "dir", flag: "osv" },
	{ id: "packagistAudit", label: "Packagist security advisories", rel: "packagist-advisories", kind: "dir", flag: "packagistAudit" },
	{ id: "osvDb", label: "OSV local DB (Maven)", rel: "osv-db/maven-index.json", kind: "mtime" },
	{ id: "nvd", label: "NIST NVD", rel: "nvd-cache", kind: "dir", flag: "nvd" },
	{ id: "epss", label: "EPSS (FIRST.org)", rel: "epss-cache.json", kind: "meta", flag: "epss" },
	{ id: "kev", label: "CISA KEV", rel: "kev-cache.json", kind: "kev", flag: "kev" },
	{ id: "euvd", label: "ENISA EUVD", rel: "euvd-cache.json", kind: "snapshot", flag: "euvd" },
	{ id: "certfr", label: "CERT-FR (ANSSI)", rel: "certfr-cache.json", kind: "meta", flag: "certfr" },
	{ id: "eol", label: "endoflife.date", rel: "eol-cache.json", kind: "meta" },
	{ id: "mavenCentral", label: "Maven Central (latest)", rel: "version-cache.json", kind: "meta" },
	{ id: "npm", label: "npm registry", rel: "npm-registry-cache.json", kind: "meta" },
	{ id: "nuget", label: "NuGet registry", rel: "nuget-cache.json", kind: "meta" },
	{ id: "packagist", label: "Packagist", rel: "packagist-cache.json", kind: "meta" },
	{ id: "go", label: "Go module proxy", rel: "go-proxy-cache.json", kind: "meta" },
	{ id: "rubygems", label: "RubyGems", rel: "rubygems-cache.json", kind: "meta" },
];

// Read one source's freshness → { status, asOf, detail }.
function readSource(def, cacheDir) {
	const target = path.join(cacheDir, def.rel);
	if (def.kind === "dir") {
		let files; try { files = fs.readdirSync(target).filter(f => f.endsWith(".json")); } catch { return { status: "missing", asOf: null, detail: null }; }
		if (!files.length) return { status: "missing", asOf: null, detail: null };
		let newest = 0;
		for (const f of files) { try { const m = fs.statSync(path.join(target, f)).mtimeMs; if (m > newest) newest = m; } catch { /* skip */ } }
		return { status: "cached", asOf: iso(newest), detail: `${files.length} cached` };
	}
	if (def.kind === "mtime") {
		let st; try { st = fs.statSync(target); } catch { return { status: "missing", asOf: null, detail: null }; }
		return { status: "cached", asOf: iso(st.mtimeMs), detail: null };
	}
	const data = readJson(target);
	if (!data) return { status: "missing", asOf: null, detail: null };
	if (def.kind === "cve-meta") {
		return { status: "cached", asOf: data.builtAt || null, detail: data.cveCount != null ? `${data.cveCount} CVEs` : null };
	}
	if (def.kind === "snapshot") {
		const n = data.body && data.body.count;
		return { status: "cached", asOf: iso(data._fetchedAt), detail: n != null ? `${n} entries` : null };
	}
	if (def.kind === "kev") {
		const body = data.body || {};
		const ver = body.catalogVersion || body.dateReleased || null;
		return { status: "cached", asOf: iso(data._fetchedAt), detail: ver ? `catalog ${ver}` : null };
	}
	// "meta": { meta: { fetchedAt }, entries }
	const n = data.entries && typeof data.entries === "object" ? Object.keys(data.entries).length : null;
	return { status: "cached", asOf: iso(data.meta && data.meta.fetchedAt), detail: n != null ? `${n} entries` : null };
}

/**
 * Inspect the cache directory → an array of data-source descriptors:
 *   { id, label, status: "disabled"|"missing"|"cached", asOf, detail }
 * A source whose feature flag is turned off this run is "disabled".
 */
function collectDataSources({ cacheDir = DEFAULT_CACHE_DIR, options = {} } = {}) {
	return SOURCE_DEFS.map(def => {
		if (def.flag && options[def.flag] === false) {
			return { id: def.id, label: def.label, status: "disabled", asOf: null, detail: null };
		}
		const r = readSource(def, cacheDir);
		return { id: def.id, label: def.label, ...r };
	});
}

// Only the options that change WHAT is found belong in the reproducibility record.
function runConfiguration(options = {}) {
	return {
		ecosystems: options.ecosystem || "auto",
		transitive: options.transitive !== false,
		transitiveDepth: options.transitiveDepth != null ? String(options.transitiveDepth) : null,
		osv: options.osv !== false,
		packagistAudit: options.packagistAudit !== false,
		nvd: options.nvd !== false,
		epss: options.epss !== false,
		kev: options.kev !== false,
		euvd: options.euvd !== false,
		certfr: options.certfr !== false,
		allLibs: options.allLibs !== false,
		licenses: !!options.licenses,
		typosquat: !!options.typosquat,
		certs: options.certs !== false,
		certExpiryDays: options.certExpiryDays != null ? String(options.certExpiryDays) : null,
		failOn: options.failOn || "none",
		ignoreFile: options.ignore || null,
		vexFile: options.vex || null,
		excludePath: options.excludePath || [],
		defaultExcludes: options.defaultExcludes !== false,
	};
}

/**
 * Assemble the full scan-provenance manifest. Pure given cacheDir + runtime.
 */
function buildScanProvenance({ toolVersion, generatedAt, options = {}, cacheDir = DEFAULT_CACHE_DIR, runtime } = {}) {
	const rt = runtime || { node: process.version, platform: process.platform, arch: process.arch };
	return {
		tool: { name: "VigieVuln", version: String(toolVersion || "0") },
		generatedAt: generatedAt || null,
		mode: options.offline ? "offline" : "online",
		runtime: { node: rt.node, platform: rt.platform, arch: rt.arch },
		configuration: runConfiguration(options),
		dataSources: collectDataSources({ cacheDir, options }),
	};
}

module.exports = { buildScanProvenance, collectDataSources, runConfiguration, DEFAULT_CACHE_DIR };
