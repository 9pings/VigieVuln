/**
 * lib/kev.js — enrich matches with CISA KEV (Known Exploited Vulnerabilities).
 *
 * KEV is a single authoritative catalogue of CVEs CISA has observed being
 * exploited in the wild. Membership is the strongest "patch this now" signal.
 *
 * Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 * Cache: ~/.fad-checker/kev-cache.json, 4h TTL.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const CACHE_DIR = path.join(require("./cache-directory").getCacheDir());
const CACHE_PATH = path.join(CACHE_DIR, "kev-cache.json");
const CACHE_TTL_MS = 4 * 3600 * 1000;
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

function readCache({ offline = false } = {}) {
	try {
		const data = require('./cache-repository').createCacheRepository(CACHE_DIR).get('catalogue','kev')?.value;
		if (offline || require('./cache-policy').fresh(data._fetchedAt, CACHE_TTL_MS)) return data.body;
	} catch { /* ignore */ }
	return null;
}

function writeCache(body, fetchedAt = Date.now()) {
	try {
		require('./cache-repository').createCacheRepository(CACHE_DIR).put('catalogue','kev',{ _fetchedAt: fetchedAt, body });
	} catch { /* ignore */ }
}

/** Pure: KEV catalogue JSON → { byId: { cveID: {dateAdded, dueDate, ransomware} } }. */
function indexKevCatalog(json) {
	const byId = {};
	for (const v of json?.vulnerabilities || []) {
		if (!v?.cveID) continue;
		byId[v.cveID] = {
			dateAdded: v.dateAdded || null,
			dueDate: v.dueDate || null,
			ransomware: /^known$/i.test(v.knownRansomwareCampaignUse || ""),
		};
	}
	return { byId };
}

/**
 * Enrich matches in place: sets cve.kev / cve.kevDateAdded / cve.kevDueDate /
 * cve.kevRansomware for CVEs present in the catalogue.
 * opts: { offline, verbose, fetcher }
 */
async function enrichKev(matches, opts = {}) {
	const { offline, verbose, fetcher = globalThis.fetch, hostedProxy } = opts;
	const hasCve = (matches || []).some(m => m.cve?.id?.startsWith("CVE-"));
	if (!hasCve) return matches;
	if (hostedProxy && !offline) {
		const ids = [...new Set(matches.map(m => m.cve?.id).filter(id => /^CVE-\d{4}-\d{4,7}$/.test(id || "")))];
		const byId = new Map();
		for (let i = 0; i < ids.length; i += 100) {
			const r = await require("./providers").getResource("kev", "cves", { ids: ids.slice(i, i + 100) }, { fetcher, noStore: true, streaming: true });
			if (!r.ok) throw new Error(`hosted KEV unavailable (HTTP ${r.status})`);
			const data = await r.json();
			if (!Array.isArray(data.items)) throw new Error("invalid hosted KEV response");
			for (const item of data.items) byId.set(item.cve, item.kev);
		}
		for (const m of matches) { const hit = byId.get(m.cve?.id); if (hit) {
			m.cve.kev = true; m.cve.kevDateAdded = hit.dateAdded; m.cve.kevDueDate = hit.dueDate; m.cve.kevRansomware = hit.ransomware;
		} }
		return matches;
	}


	let index = readCache({ offline });
	if (!index && !offline) {
		try {
			const r = await require("./providers").getResource("kev", "catalog", {},
				{ fetcher, headers: { "User-Agent": "vigievuln-kev" } });
			if (r.ok) {
				index = indexKevCatalog(await r.json());
				writeCache(index, require('./providers/common').responseFetchedAt(r));
			} else if (verbose) {
				console.warn(`   KEV HTTP ${r.status}`);
			}
		} catch (err) {
			if (verbose) console.warn(`   KEV fetch failed: ${err.message}`);
		}
	}
	if (!index) {
		if (!offline) throw new Error('CISA KEV catalog unavailable; exploitation status is unknown');
		return matches;
	}

	for (const m of matches || []) {
		const hit = index.byId[m.cve?.id];
		if (!hit) continue;
		m.cve.kev = true;
		m.cve.kevDateAdded = hit.dateAdded;
		m.cve.kevDueDate = hit.dueDate;
		m.cve.kevRansomware = hit.ransomware;
	}
	return matches;
}

module.exports = { enrichKev, indexKevCatalog, CACHE_PATH };
