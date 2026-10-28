/**
 * lib/codecs/go/registry.js — query the Go module proxy for the latest version.
 *
 * API: https://proxy.golang.org/<escaped-module>/@latest → { Version }
 * Module paths are case-encoded (uppercase → !lower) per the proxy protocol.
 * Deprecation/license aren't exposed by the proxy without fetching the module's
 * go.mod, so this only contributes "outdated".
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
const CACHE_PATH = path.join(CACHE_DIR, "go-proxy-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000;

function loadCache() { try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); } catch { return { entries: {}, meta: {} }; } }
function saveCache(d) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify(d)); } catch { /* ignore */ } }

// proxy.golang.org case-encoding: uppercase letters → "!" + lowercase.
function escapeModule(mod) {
	return String(mod).replace(/[A-Z]/g, c => "!" + c.toLowerCase());
}

function cmp(a, b) {
	const pa = String(a).replace(/^v/, "").split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	const pb = String(b).replace(/^v/, "").split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
	return 0;
}

// Custom GOPROXY first (same protocol: <base>/<escaped-module>/@latest), then proxy.golang.org.
async function fetchLatest(mod, { offline, registries = [], fetcher = globalThis.fetch } = {}) {
	if (offline) return null;
	const bases = withPublic("go", registries);
	let lastErr = null;
	const statuses = [];   // one per base: HTTP status, or null for a non-answer
	for (const base of bases) {
		const url = normalise(base.url) + `${escapeModule(mod)}/@latest`;
		const headers = { "User-Agent": "vigievuln-go", Accept: "application/json" };
		const ah = authHeaderFor(base); if (ah) headers.Authorization = ah;
		try {
			const res = await require("../../providers").getResource("go", "module-latest", { module: escapeModule(mod) },
				{ fetcher, headers, ...(base.name === "public" ? {} : { urlOverride: url, direct: true }) });
			if (res.ok) { const j = await res.json(); return { latest: (j.Version || "").replace(/^v/, "") || null }; }
			lastErr = `HTTP ${res.status}`;
			statuses.push(res.status);
		} catch (e) { lastErr = e.message; statuses.push(null); }
	}
	return { error: lastErr || "no data", absent: foldAbsent(statuses) };
}

async function checkGoRegistryDeps(deps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8, registries = [] } = opts;
	const targets = [...deps.values()].filter(d => d.ecosystem === "go" && d.version);
	const result = { deprecated: [], outdated: [], licensed: [], private: [] };
	if (!targets.length || !allLibs) return result;
	const cache = loadCache();
	const fresh = (offline || !require("../../providers").hasHostedProxy()) && cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const key = `${t.name}@${t.version}`;
		let ex = cache.entries[key];
		if (!ex) {
			const r = await fetchLatest(t.name, { offline, registries });
			ex = (r && !r.error) ? { latest: r.latest } : { latest: null, absent: r?.absent === true };
			if (r && !r.error) cache.entries[key] = ex;
		}
		// Absent from EVERY configured registry: an internal package. Only a definitive
		// 404/410 from all of them gets here — a timeout leaves it unknown and silent.
		if (ex.absent) result.private.push({ dep: t, ecosystem: "go" });
		if (ex.latest && cmp(ex.latest, t.version) > 0) {
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

module.exports = { checkGoRegistryDeps, escapeModule, fetchLatest };
