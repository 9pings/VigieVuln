/**
 * lib/codecs/ruby/registry.js — query RubyGems for latest version + licenses.
 *
 * API: https://rubygems.org/api/v1/gems/<gem>.json → { version, licenses[] }
 * One call yields both outdated (latest stable) and the SPDX-ish license list.
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

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
const CACHE_PATH = path.join(CACHE_DIR, "rubygems-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000;

function loadCache() { try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); } catch { return { entries: {}, meta: {} }; } }
function saveCache(d) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify(d)); } catch { /* ignore */ } }
function isStable(v) { return /^\d+(\.\d+)*$/.test(String(v || "")); }
function cmp(a, b) {
	const pa = String(a).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	const pb = String(b).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
	return 0;
}

// Pure extractor: RubyGems gem JSON → { latest, license }.
function gemToFindings(data) {
	const out = { latest: null, license: null };
	if (data?.version && isStable(data.version)) out.latest = data.version;
	const lic = data?.licenses;
	if (Array.isArray(lic) && lic.length) out.license = lic;
	return out;
}

// Custom gem servers first (same JSON API: <base>/<gem>.json), then rubygems.org.
async function fetchGem(name, { offline, registries = [], fetcher = globalThis.fetch } = {}) {
	if (offline) return null;
	const bases = withPublic("ruby", registries);
	let lastErr = null;
	const statuses = [];   // one per base: HTTP status, or null for a non-answer
	for (const base of bases) {
		const url = normalise(base.url) + `${encodeURIComponent(name)}.json`;
		const headers = { "User-Agent": "vigievuln-rubygems", Accept: "application/json" };
		const ah = authHeaderFor(base); if (ah) headers.Authorization = ah;
		try { const res = await require("../../providers").getResource("ruby", "gem", { name },
			{ fetcher, headers, ...(base.name === "public" ? {} : { urlOverride: url, direct: true }) });
			if (res.ok) return await res.json(); lastErr = `HTTP ${res.status}`; statuses.push(res.status); }
		catch (e) { lastErr = e.message; statuses.push(null); }
	}
	return { error: lastErr || "no data", absent: foldAbsent(statuses) };
}

async function checkRubyRegistryDeps(deps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8, registries = [] } = opts;
	const targets = [...deps.values()].filter(d => d.ecosystem === "ruby" && d.version);
	const result = { deprecated: [], outdated: [], licensed: [], private: [] };
	if (!targets.length) return result;
	const cache = loadCache();
	const fresh = cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const key = `${t.name}@${t.version}`;
		let ex = cache.entries[key];
		if (!ex) {
			const data = await fetchGem(t.name, { offline, registries });
			ex = (data && !data.error) ? gemToFindings(data) : { latest: null, license: null, absent: data?.absent === true };
			if (data && !data.error) cache.entries[key] = ex;
		}
		// Absent from EVERY configured registry: an internal package. Only a definitive
		// 404/410 from all of them gets here — a timeout leaves it unknown and silent.
		if (ex.absent) result.private.push({ dep: t, ecosystem: "ruby" });
		if (ex.license) result.licensed.push({ dep: t, licenses: ex.license, source: "rubygems" });
		if (allLibs && ex.latest && cmp(ex.latest, t.version) > 0) {
			result.outdated.push({ dep: t, latest: ex.latest, releaseDate: null });
			if (verbose) process.stdout.write(`  outdated: ${t.name} ${t.version} → ${ex.latest}\n`);
		}
	})));
	if (!offline) {
		if (!fresh) cache.meta = { fetchedAt: Date.now() };
		saveCache(cache);
	}
	return result;
}

module.exports = { gemToFindings, checkRubyRegistryDeps, fetchGem };
