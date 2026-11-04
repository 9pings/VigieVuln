/**
 * lib/epss.js — enrich matches with EPSS (Exploit Prediction Scoring System).
 *
 * EPSS gives the probability (0-1) a CVE will be exploited in the next 30 days,
 * plus a percentile rank against all scored CVEs. FIRST.org recomputes it daily.
 *
 * API: https://api.first.org/data/v1/epss?cve=CVE-a,CVE-b,…  (batch ≤ ~100)
 * Cache: ~/.fad-checker/epss-cache.json, 4h TTL (aligned with the daily refresh).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const CACHE_DIR = path.join(require("./cache-directory").getCacheDir());
const CACHE_PATH = path.join(CACHE_DIR, "epss-cache.json");
const CACHE_TTL_MS = 4 * 3600 * 1000;
const EPSS_BASE = "https://api.first.org/data/v1/epss";
const BATCH = 100;

function loadCache() {
	try { return require('./cache-repository').createCacheRepository(CACHE_DIR).get('catalogue','epss')?.value || { meta: { fetchedAt: 0 }, entries: {} }; }
	catch { return { meta: { fetchedAt: 0 }, entries: {} }; }
}

function saveCache(data) {
	try {
		require('./cache-repository').createCacheRepository(CACHE_DIR).put('catalogue','epss',data,{fetchedAt:data.meta?.fetchedAt||Date.now()});
	} catch { /* ignore */ }
}

/** Pure: FIRST.org JSON → Map<cveId, {score, percentile}>. */
function parseEpssResponse(json) {
	const out = new Map();
	for (const row of json?.data || []) {
		if (!row?.cve) continue;
		const score = parseFloat(row.epss);
		const percentile = parseFloat(row.percentile);
		out.set(row.cve, {
			score: Number.isFinite(score) ? score : null,
			percentile: Number.isFinite(percentile) ? percentile : null,
		});
	}
	return out;
}

function chunk(arr, n) {
	const out = [];
	for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
	return out;
}

/**
 * Enrich matches in place with cve.epssScore / cve.epssPercentile.
 * opts: { offline, verbose, fetcher, onProgress }
 */
async function enrichEpss(matches, opts = {}) {
	const { offline, verbose, fetcher = globalThis.fetch, onProgress } = opts;
	const ids = new Set();
	for (const m of matches || []) if (m.cve?.id?.startsWith("CVE-")) ids.add(m.cve.id);
	if (!ids.size) return matches;

	const cache = loadCache();
	const strictHosted = !offline && require("./providers").hasHostedProxy();
	const fresh = !strictHosted && cache.meta?.fetchedAt && require('./cache-policy').fresh(cache.meta.fetchedAt, CACHE_TTL_MS);
	const previous = !fresh && !offline ? {entries:cache.entries, fetchedAt:cache.meta?.fetchedAt} : null;
	if (!fresh && !offline) cache.entries = {};

	const byId = new Map();
	const liveIds = [];
	for (const id of ids) {
		if (cache.entries[id]) byId.set(id, cache.entries[id]);
		else if (offline) byId.set(id, null);
		else liveIds.push(id);
	}

	let done = 0;
	let oldestFetchedAt = Date.now();
	const total = liveIds.length;
	const report = () => { if (onProgress) onProgress(done, total); };
	for (const group of chunk(liveIds, BATCH)) {
		try {
			const url = `${EPSS_BASE}?cve=${encodeURIComponent(group.join(","))}`;
			const r = await require("./providers").getResource("epss", "scores", { ids: group },
				{ fetcher, headers: { "User-Agent": "vigievuln-epss" } });
			if (r.ok) {
				oldestFetchedAt = Math.min(oldestFetchedAt,require('./providers/common').responseFetchedAt(r));
				const parsed = parseEpssResponse(await r.json());
				for (const id of group) {
					// Not every CVE has an EPSS score; cache the null so we don't refetch.
					const v = parsed.get(id) || { score: null, percentile: null };
					cache.entries[id] = v;
					byId.set(id, v);
				}
			} else if (strictHosted) {
				throw new Error(`EPSS HTTP ${r.status}`);
			} else if (verbose) {
				console.warn(`   EPSS HTTP ${r.status}`);
			}
		} catch (err) {
			if (strictHosted) throw err;
			if (verbose) console.warn(`   EPSS fetch failed: ${err.message}`);
		}
		done += group.length;
		report();
	}

	cache.meta = { fetchedAt: fresh ? cache.meta.fetchedAt : oldestFetchedAt };
	// Hosted responses must still be persisted for an air-gapped scan. The
	// strict hosted path above revalidates online and never trusts this cache
	// as a substitute for contacting the selected proxy.
	if (!offline) { require('./cache-policy').preserveEntries(cache, previous); saveCache(cache); }

	for (const m of matches || []) {
		const v = byId.get(m.cve?.id);
		if (!v) continue;
		if (v.score != null) m.cve.epssScore = v.score;
		if (v.percentile != null) m.cve.epssPercentile = v.percentile;
	}
	return matches;
}

module.exports = { enrichEpss, parseEpssResponse, CACHE_PATH };
