/**
 * lib/composer/registry.js — query Packagist for a package's latest stable
 * version and its `abandoned` flag (≈ npm `deprecated`).
 *
 * API: https://packagist.org/packages/{vendor}/{pkg}.json
 *   → { package: { abandoned: bool|string, versions: { "<v>": {...} } } }
 *
 * Cached in ~/.fad-checker/packagist-cache.json for 24h.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { foldAbsent } = require("../../private-deps");
const path = require("path");
const os = require("os");
let pLimit; try { pLimit = require("p-limit"); } catch { pLimit = () => (fn) => fn(); }
const { authHeaderFor, normalise } = require("../../registries");
const { belongsToOtherComposerRegistry } = require("../../packagist-audit");

const CACHE_DIR = path.join(require("../../cache-directory").getCacheDir());
const CACHE_PATH = path.join(CACHE_DIR, "packagist-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000;
const API = "https://packagist.org/packages";

function loadCache() { try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); } catch { return { entries: {}, meta: {} }; } }
function saveCache(d) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify(d)); } catch { /* ignore */ } }

function isStable(v) { return /^\d+(\.\d+)*$/.test(String(v || "").replace(/^v/, "")); }
function cmp(a, b) {
	const pa = String(a).replace(/^v/, "").split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	const pb = String(b).replace(/^v/, "").split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
	return 0;
}

// Extract {abandoned, outdated} from a Packagist `package` object.
function packagistToFindings(pkg, { version }) {
	const out = { abandoned: null, outdated: null, license: null };
	if (pkg.abandoned === true) out.abandoned = { replacement: null };
	else if (typeof pkg.abandoned === "string") out.abandoned = { replacement: pkg.abandoned };
	const versions = pkg.versions || {};
	const stable = Object.keys(versions).map(v => v.replace(/^v/, "")).filter(isStable);
	if (stable.length) {
		const latest = stable.sort(cmp).at(-1);
		if (latest && cmp(latest, String(version).replace(/^v/, "")) > 0) out.outdated = { latest };
	}
	// Packagist version objects carry a `license` array (e.g. ["MIT"]).
	const vEntry = versions[version] || versions[`v${version}`] || versions[Object.keys(versions)[0]];
	if (vEntry?.license && vEntry.license.length) out.license = vEntry.license;
	return out;
}

// Convert a Composer v2 metadata document (`/p2/<name>.json`) into the packagist-like
// `package` shape packagistToFindings() consumes: { versions: { "<v>": {license} },
// abandoned }. The v2 format is { packages: { "<name>": [ {version, license, …}, … ] } }.
// Private feeds (Artifactory, Private Packagist) sometimes tag an abandoned package on
// its version objects; surface that if present.
function composerV2ToPackageObject(json, name) {
	const arr = (json && json.packages && (json.packages[name] || json.packages[name.toLowerCase()])) || [];
	const versions = {};
	let abandoned = null;
	for (const v of arr) {
		if (!v || !v.version) continue;
		versions[v.version] = { license: v.license || [] };
		if (abandoned == null && v.abandoned != null && v.abandoned !== false) {
			abandoned = (typeof v.abandoned === "string") ? v.abandoned : true;
		}
	}
	return { versions, abandoned };
}

// Custom registries first (Composer v2 metadata: <base>/p2/<name>.json), then the
// public Packagist rich API (packages/<name>.json). Per-registry Basic/Bearer auth.
async function fetchPackage(name, { offline, registries = [], fetcher = globalThis.fetch } = {}) {
	if (offline) return null;
	if (typeof name !== 'string' || name.length > 200 || !/^[a-z0-9]+(?:[_.-][a-z0-9]+)*\/[a-z0-9]+(?:(?:[_.]|-{1,2})[a-z0-9]+)*$/i.test(name)) return { error: 'invalid package name', absent: false };
	let lastErr = null;
	const statuses = [];   // one per base: HTTP status, or null for a non-answer
	for (const base of registries || []) {
		const headers = { "User-Agent": "vigievuln-packagist", Accept: "application/json" };
		const ah = authHeaderFor(base); if (ah) headers.Authorization = ah;
		try {
			const res = await require("../../providers").getResource("packagist", "p2", { name },
				{ fetcher, headers, urlOverride: `${normalise(base.url)}p2/${String(name).split('/').map(encodeURIComponent).join('/')}.json`, direct: true });
			if (res.ok) return composerV2ToPackageObject(await res.json(), name);
			lastErr = `HTTP ${res.status}`;
			statuses.push(res.status);
		} catch (e) { lastErr = e.message; statuses.push(null); }
	}
	try {
		const res = await require("../../providers").getResource("packagist", "package", { name },
			{ fetcher, headers: { "User-Agent": "vigievuln-packagist", Accept: "application/json" } });
		if (!res.ok) {
			statuses.push(res.status);
			return { error: `HTTP ${res.status}`, absent: foldAbsent(statuses) };
		}
		const json = await res.json();
		return json.package || { error: "no package field" };
	} catch (e) {
		statuses.push(null);
		return { error: lastErr || e.message, absent: foldAbsent(statuses) };
	}
}

// Mirror of checkNpmRegistryDeps: returns { deprecated:[], outdated:[] }.
async function checkComposerRegistryDeps(deps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8, registries = [], fetcher } = opts;
	// Adobe's Composer packages come from repo.magento.com. Packagist's package
	// endpoint cannot establish their latest version, deprecation or license.
	const targets = [...deps.values()].filter(d => d.ecosystem === "composer" && d.version &&
		!belongsToOtherComposerRegistry(d));
	const result = { deprecated: [], outdated: [], licensed: [], private: [] };
	if (!targets.length) return result;
	const cache = loadCache();
	const fresh = (offline || !require("../../providers").hasHostedProxy()) && cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const name = `${t.namespace}/${t.name}`.toLowerCase();
		const key = `${name}@${t.version}`;
		let ex = cache.entries[key];
		if (!ex) {
			const pkg = await fetchPackage(name, { offline, registries, ...(fetcher ? { fetcher } : {}) });
			if (pkg && !pkg.error) {
				const f = packagistToFindings(pkg, { version: t.version });
				ex = { abandoned: f.abandoned, latest: f.outdated?.latest || null, license: f.license || null };
				cache.entries[key] = ex;
			} else {
				ex = { abandoned: null, latest: null, license: null, absent: pkg?.absent === true };
			}
		}
		// Absent from EVERY configured registry: an internal package. Only a definitive
		// 404/410 from all of them gets here — a timeout leaves it unknown and silent.
		if (ex.absent) result.private.push({ dep: t, ecosystem: "composer" });
		if (ex.license) result.licensed.push({ dep: t, licenses: ex.license, source: "packagist" });
		if (ex.abandoned) {
			result.deprecated.push({ dep: t, severity: "MEDIUM", replacement: ex.abandoned.replacement, reason: "Package marked abandoned on Packagist", source: "packagist" });
			if (verbose) process.stdout.write(`  abandoned: ${name}@${t.version}\n`);
		}
		if (allLibs && ex.latest) {
			result.outdated.push({ dep: t, latest: ex.latest, releaseDate: null });
			if (verbose) process.stdout.write(`  outdated: ${name} ${t.version} → ${ex.latest}\n`);
		}
	})));
	if (!offline) {
		if (!fresh) cache.meta = { fetchedAt: Date.now() };
		if (!require("../../providers").hasHostedProxy()) saveCache(cache);
	}
	return result;
}

module.exports = { packagistToFindings, checkComposerRegistryDeps, fetchPackage, composerV2ToPackageObject };
