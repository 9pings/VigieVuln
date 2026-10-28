/**
 * lib/python/registry.js — query PyPI JSON for a package's latest version,
 * whether the resolved version is yanked, and the "Inactive" dev-status classifier.
 *
 * API: https://pypi.org/pypi/{name}/json
 *   → { info: { version, classifiers[] }, releases: { "<v>": [{ yanked, yanked_reason }] } }
 *
 * Cached in ~/.fad-checker/pypi-cache.json for 24h.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { foldAbsent } = require("../../private-deps");
const path = require("path");
const os = require("os");
let pLimit; try { pLimit = require("p-limit"); } catch { pLimit = () => (fn) => fn(); }
const { withPublic, authHeaderFor, normalise } = require("../../registries");

const CACHE_DIR = path.join(require("../../cache-directory").getCacheDir());
const CACHE_PATH = path.join(CACHE_DIR, "pypi-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000;

function loadCache() { try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); } catch { return { entries: {}, meta: {} }; } }
function saveCache(d) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify(d)); } catch { /* ignore */ } }
function cmp(a, b) {
	const pa = String(a).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	const pb = String(b).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
	return 0;
}

// PyPI's info.license is notoriously free-form (sometimes the full license text),
// so prefer the structured "License :: …" trove classifiers; fall back to a short
// info.license string only.
function pypiLicense(info) {
	const fromClassifiers = (info?.classifiers || [])
		.filter(c => /^License ::/.test(c) && !/OSI Approved$/.test(c))
		.map(c => c.split("::").pop().trim())
		.filter(Boolean);
	if (fromClassifiers.length) return fromClassifiers;
	const raw = (info?.license || "").trim();
	if (raw && raw.length <= 50 && !raw.includes("\n")) return raw;
	return null;
}

function pypiToFindings(data, { version }) {
	const out = { outdated: null, yanked: null, inactive: false, license: null };
	const latest = data.info?.version;
	if (latest && cmp(latest, version) > 0) out.outdated = { latest };
	const rel = data.releases?.[version];
	if (Array.isArray(rel) && rel.length && rel.every(f => f.yanked)) {
		out.yanked = { reason: rel.find(f => f.yanked_reason)?.yanked_reason || null };
	}
	if ((data.info?.classifiers || []).some(c => /Development Status :: 7 - Inactive/i.test(c))) out.inactive = true;
	out.license = pypiLicense(data.info);
	return out;
}

// Custom registries first (same JSON API: <base>/<name>/json), then pypi.org.
async function fetchProject(name, { offline, registries = [], fetcher = globalThis.fetch } = {}) {
	if (offline) return null;
	if (typeof name !== 'string' || !/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/i.test(name)) return { error: 'invalid package name', absent: false };
	const bases = withPublic("pypi", registries);
	let lastErr = null;
	const statuses = [];   // one per base: HTTP status, or null for a non-answer
	for (const base of bases) {
		const url = normalise(base.url) + `${encodeURIComponent(name)}/json`;
		const headers = { "User-Agent": "vigievuln-pypi", Accept: "application/json" };
		const ah = authHeaderFor(base); if (ah) headers.Authorization = ah;
		try { const res = await require("../../providers").getResource("pypi", "package", { name },
			{ fetcher, headers, ...(base.name === "public" ? {} : { urlOverride: url, direct: true }) });
			if (res.ok) return await res.json(); lastErr = `HTTP ${res.status}`; statuses.push(res.status); }
		catch (e) { lastErr = e.message; statuses.push(null); }
	}
	return { error: lastErr || "no data", absent: foldAbsent(statuses) };
}

// Mirror of checkNpmRegistryDeps: returns { deprecated:[], outdated:[] }.
async function checkPypiRegistryDeps(deps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8, registries = [] } = opts;
	const targets = [...deps.values()].filter(d => d.ecosystem === "pypi" && d.version);
	const result = { deprecated: [], outdated: [], licensed: [], private: [] };
	if (!targets.length) return result;
	const cache = loadCache();
	const fresh = (offline || !require("../../providers").hasHostedProxy()) && cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const key = `${t.name}@${t.version}`;
		let ex = cache.entries[key];
		if (!ex) {
			const data = await fetchProject(t.name, { offline, registries });
			if (data && !data.error) {
				const f = pypiToFindings(data, { version: t.version });
				ex = { yanked: f.yanked, inactive: f.inactive, latest: f.outdated?.latest || null, license: f.license || null };
				cache.entries[key] = ex;
			} else {
				ex = { yanked: null, inactive: false, latest: null, license: null, absent: data?.absent === true };
			}
		}
		// Absent from EVERY configured registry: an internal package. Only a definitive
		// 404/410 from all of them gets here — a timeout leaves it unknown and silent.
		if (ex.absent) result.private.push({ dep: t, ecosystem: "pypi" });
		if (ex.license) result.licensed.push({ dep: t, licenses: ex.license, source: "pypi" });
		if (ex.yanked) {
			result.deprecated.push({ dep: t, severity: "HIGH", replacement: null, reason: `Version yanked on PyPI${ex.yanked.reason ? `: ${ex.yanked.reason}` : ""}`, source: "pypi" });
			if (verbose) process.stdout.write(`  yanked: ${t.name}@${t.version}\n`);
		} else if (ex.inactive) {
			result.deprecated.push({ dep: t, severity: "LOW", replacement: null, reason: "Marked 'Development Status :: 7 - Inactive' on PyPI", source: "pypi" });
		}
		if (allLibs && ex.latest) {
			result.outdated.push({ dep: t, latest: ex.latest, releaseDate: null });
			if (verbose) process.stdout.write(`  outdated: ${t.name} ${t.version} → ${ex.latest}\n`);
		}
	})));
	// Offline reads must not re-stamp freshness — a stale cache would then look
	// fresh to the next ONLINE run and skip its refetch.
	if (!offline) {
		if (!fresh) cache.meta = { fetchedAt: Date.now() };
		if (!require("../../providers").hasHostedProxy()) saveCache(cache);
	}
	return result;
}

module.exports = { pypiToFindings, pypiLicense, checkPypiRegistryDeps, fetchProject };
