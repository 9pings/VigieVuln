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

const DEFAULT_CACHE_DIR = path.join(require("./cache-directory").getCacheDir());

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
	...[["maven", "Maven"], ["npm", "npm"], ["pypi", "PyPI"], ["composer", "Packagist"], ["nuget", "NuGet"], ["go", "Go"], ["ruby", "RubyGems"]].map(([eco, label]) => ({ id: `osvDb-${eco}`, label: `OSV local DB (${label})`, rel: `osv-db/${eco}-index.json`, kind: "osv-db", eco })),
	{ id: "nvd", label: "NIST NVD", rel: "nvd-cache", kind: "dir", flag: "nvd" },
	{ id: "epss", label: "EPSS (FIRST.org)", rel: "epss-cache.json", kind: "meta", flag: "epss" },
	{ id: "kev", label: "CISA KEV", rel: "kev-cache.json", kind: "kev", flag: "kev" },
	{ id: "euvd", label: "ENISA EUVD", rel: "euvd-cache.json", kind: "snapshot", flag: "euvd" },
	{ id: "gcve", label: "GCVE advisory index", rel: "gcve-data/index.json", kind: "gcve" },
	{ id: "gcveDerived", label: "GCVE identifiers (derived from CVE)", kind: "derived" },
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
	if (def.kind === "derived") return { status: "derived", asOf: null, detail: "Derived locally from CVE identifiers" };
	if(!fs.existsSync(path.join(cacheDir,'cache.sqlite')))return {status:'missing',asOf:null,detail:null};
	const db=require('./cache-db').getCacheDb(cacheDir),repo=require('./cache-repository').createCacheRepository(cacheDir);
	if(def.id==='nvd'){
		const row=db.prepare('SELECT COUNT(*) count,MIN(fetched_at) oldest FROM nvd_records').get();
		return row.count?{status:'cached',asOf:iso(row.oldest),detail:`${row.count} cached records`}:{status:'missing',asOf:null,detail:null};
	}
	if(def.id==='cve'){
		const snap=repo.getSnapshot('cve_lookup');
		return snap?{status:'cached',asOf:iso(snap.fetchedAt),detail:`${snap.recordCount} CVEs`}:{status:'missing',asOf:null,detail:null};
	}
	if(def.id==='packagistAudit'){
		const row=db.prepare("SELECT COUNT(*) count,MAX(fetched_at) newest FROM cache_entries WHERE namespace='packagist-audit'").get();
		return row.count?{status:'cached',asOf:iso(row.newest),detail:`${row.count} cached packages`}:{status:'missing',asOf:null,detail:null};
	}
	if(def.id==='osv'||def.kind==='osv-db')return {status:'missing',asOf:null,detail:null};
	const catalogue={kev:'kev',epss:'epss',euvd:'euvd',certfr:'certfr',gcve:'gcve'}[def.id];
	const auxiliary={npm:'npm-registry',nuget:'nuget',packagist:'packagist',go:'go-proxy',rubygems:'rubygems'}[def.id]||path.basename(def.rel);
	const data=catalogue?repo.get('catalogue',catalogue)?.value:repo.get('auxiliary',auxiliary)?.value;
	if (!data) return { status: "missing", asOf: null, detail: null };
	if (def.kind === "gcve") {
		const coverage = Array.isArray(data.coverage) ? data.coverage : [];
		return { status: "cached", asOf: data._fadSnapshot?.collectedAt || data.builtAt || null, detail: `${coverage.length} GNA sources; ${coverage.filter(c => c.complete).length} complete` };
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
function collectDataSources({ cacheDir = DEFAULT_CACHE_DIR, options = {}, ecosystems = null } = {}) {
	let store = null;
	if (fs.existsSync(path.join(cacheDir,'cache.sqlite'))) store = require('./advisory-store').openAdvisoryStore({cacheDir});
	try {
	const ttlMs = options.advisoryQueryTtlMs != null ? Number(options.advisoryQueryTtlMs) : (options.advisoryQueryTtl != null ? Number(options.advisoryQueryTtl) * 3600000 : 4 * 3600000);
	const osvEcosystems = {maven:'Maven',npm:'npm',pypi:'PyPI',composer:'Packagist',nuget:'NuGet',go:'Go',ruby:'RubyGems'};
	const active = ecosystems == null ? null : new Set(ecosystems);
	const uses = id => !active || active.has(id);
	const applies = def => {
		if (def.id.startsWith('osvDb-')) {
			if (!uses(def.id.slice(6))) return false;
			// The local catalogue is optional when exact OSV consultations cover
			// this run. Do not label that optional cache as "not warmed".
			return !active || options.osvDb === true || !!store?.getSourceCoverage('osv',osvEcosystems[def.id.slice(6)],{ttlMs});
		}
		if (['cve','mavenCentral'].includes(def.id)) return uses('maven') || uses('gradle');
		if (['packagistAudit','packagist'].includes(def.id)) return uses('composer');
		if (def.id === 'npm') return uses('npm') || uses('yarn');
		if (['nuget','go','rubygems'].includes(def.id)) return uses(def.id === 'rubygems' ? 'ruby' : def.id);
		return true;
	};
	return SOURCE_DEFS.filter(applies).map(def => {
		if ((def.flag && options[def.flag] === false) || (def.id === "cve" && options.disableCveProject) || (def.id.startsWith("osvDb-") && options.osvDb === false) || (def.id === "gcve" && (options.gcve === false || options.disableGcve))) {
			return { id: def.id, label: def.label, status: "disabled", asOf: null, detail: null };
		}
		let coverage = null;
		if (store && def.id === 'osv') {
			const summary=store.getQuerySummary('osv',{ttlMs});
			if (summary.count) return {id:def.id,label:def.label,status:'cached',asOf:iso(summary.oldestFetchedAt),detail:`shared store: ${summary.count} queried versions; ${summary.staleCount} stale`};
			const coverage=store.db.prepare("SELECT COUNT(*) count,MIN(fetched_at) oldest FROM advisory_coverage WHERE source='osv' AND slot='current'").get();
			if(coverage.count)return {id:def.id,label:def.label,status:'cached',asOf:iso(coverage.oldest),detail:`shared store: ${coverage.count} ecosystems`};
		}
		if (store) {
			if (def.id === 'cve') coverage = store.getSourceCoverage('cveproject','*',{ttlMs}) || store.getSourceCoverage('cveproject-legacy','*',{ttlMs});
			else if (def.id === 'gcve') coverage = store.getSourceCoverage('gcve','*',{ttlMs});
			else if (def.id.startsWith('osvDb-')) coverage = store.getSourceCoverage('osv',osvEcosystems[def.id.slice(6)], {ttlMs});
		}
		if (coverage) return { id:def.id, label:def.label, status:'cached', asOf:iso(coverage.fetchedAt), detail:`shared store: ${coverage.complete ? 'complete' : 'partial'}${coverage.fresh === false ? '; stale' : ''}` };
		const r = readSource(def, cacheDir);
		return { id: def.id, label: def.label, ...r };
	});
	} finally { store?.close(); }
}

// Only the options that change WHAT is found belong in the reproducibility record.
function runConfiguration(options = {}) {
	let proxyOrigin = null;
	if (options.proxyCache) {
		try { proxyOrigin = require("./proxy-scope").proxyOrigin(options.proxyCache); } catch { /* do not record credentials or malformed URLs */ }
	}
	return {
		ecosystems: options.ecosystem || "auto",
		sourceProfile: options.sourceProfile || "all",
		proxyOrigin,
		cveProject: !options.disableCveProject,
		cveOffline: !!options.cveOffline,
		osvDb: options.osvDb === true ? "enabled" : options.osvDb === false ? "disabled" : "auto",
		gcve: options.gcve !== false && !options.disableGcve,
		transitive: options.transitive !== false,
		transitiveDepth: options.transitiveDepth != null ? String(options.transitiveDepth) : null,
		osv: options.osv !== false,
		advisoryQueryTtlHours: options.advisoryQueryTtlMs != null ? Number(options.advisoryQueryTtlMs) / 3600000 : (options.advisoryQueryTtl != null ? Number(options.advisoryQueryTtl) : 4),
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
function buildScanProvenance({ toolVersion, generatedAt, options = {}, cacheDir = DEFAULT_CACHE_DIR, runtime, ecosystems = null } = {}) {
	const rt = runtime || { node: process.version, platform: process.platform, arch: process.arch };
	return {
		tool: { name: "VigieVuln", version: String(toolVersion || "0") },
		generatedAt: generatedAt || null,
		mode: options.offline ? "offline" : "online",
		runtime: { node: rt.node, platform: rt.platform, arch: rt.arch },
		configuration: runConfiguration(options),
		dataSources: collectDataSources({ cacheDir, options, ecosystems }),
	};
}

module.exports = { buildScanProvenance, collectDataSources, runConfiguration, DEFAULT_CACHE_DIR };
