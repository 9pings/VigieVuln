/**
 * lib/euvd.js — enrich matches with the ENISA European Vulnerability Database (EUVD).
 *
 * The EUVD is the EU's own vulnerability database, run by ENISA under NIS2 and
 * operated with CIRCL. For a CVE it gives two things a European audit cites:
 *   - its EUVD identifier (EUVD-2021-34768 for Log4Shell), from the mapping dump;
 *   - whether ENISA lists it as exploited, and since when, from the exploited catalogue.
 *
 * Both are BULK reads — one CSV and ~20 pages — so the lookup is local and works
 * offline once warmed. Hosted proxy mode sends matched CVE identifiers to the proxy
 * and receives only their stored EUVD references.
 * ENISA's exploited flag is REPORTED (detail panel, exports), it does not move the
 * priority band or the `--fail-on kev` gate: those stay on CISA KEV, whose semantics
 * users already script against.
 *
 * Cache: ~/.fad-checker/euvd-cache.json, 24h TTL. A failed refresh keeps serving the
 * stale snapshot; offline serves it whatever its age.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const DEFAULT_CACHE_DIR = path.join(require("./cache-directory").getCacheDir());
const CACHE_FILE = "euvd-cache.json";
const CACHE_TTL_MS = 24 * 3600 * 1000;
const MAX_PAGES = 200;
const MONTHS = { Jan: 1, Feb: 2, Mar: 3, Apr: 4, May: 5, Jun: 6, Jul: 7, Aug: 8, Sep: 9, Oct: 10, Nov: 11, Dec: 12 };

const cachePath = dir => path.join(dir || DEFAULT_CACHE_DIR, CACHE_FILE);

function readCache(dir) {
	try { return JSON.parse(fs.readFileSync(cachePath(dir), "utf8")); } catch { return null; }
}

function writeCache(dir, body) {
	try {
		fs.mkdirSync(dir || DEFAULT_CACHE_DIR, { recursive: true });
		fs.writeFileSync(cachePath(dir), JSON.stringify({ _fetchedAt: Date.now(), body }));
	} catch { /* a cache is an optimisation */ }
}

/** Pure: the `euvd_id,cve_id` dump → { "CVE-…": "EUVD-…" }. First mapping wins. */
function parseMappingCsv(text) {
	const byCve = {};
	for (const line of String(text || "").split(/\r?\n/)) {
		const [euvd, cve] = line.split(",").map(s => (s || "").trim().replace(/^"|"$/g, ""));
		if (!/^EUVD-\d{4}-\d+$/.test(euvd) || !/^CVE-\d{4}-\d{4,}$/.test(cve)) continue;
		if (!byCve[cve]) byCve[cve] = euvd;
	}
	return byCve;
}

/** Pure: ENISA's "Oct 2, 2026, 12:00:00 AM" → "2026-10-02". Unparsable → null. */
function euvdDate(raw) {
	const m = /^([A-Z][a-z]{2}) (\d{1,2}), (\d{4})/.exec(String(raw || "").trim());
	if (!m || !MONTHS[m[1]]) return null;
	return `${m[3]}-${String(MONTHS[m[1]]).padStart(2, "0")}-${m[2].padStart(2, "0")}`;
}

/** Pure: one exploited-search page → { "CVE-…": "YYYY-MM-DD" | "" } (every CVE alias). */
function parseExploitedPage(json) {
	const out = {};
	for (const item of Array.isArray(json?.items) ? json.items : []) {
		const since = euvdDate(item?.exploitedSince) || "";
		for (const alias of String(item?.aliases || "").split(/\s+/)) {
			if (/^CVE-\d{4}-\d{4,}$/.test(alias) && !out[alias]) out[alias] = since;
		}
	}
	return out;
}

async function fetchSnapshot({ fetcher, verbose }) {
	const { getResource } = require("./providers");
	const headers = { "User-Agent": "vigievuln-euvd" };
	const mapping = await getResource("euvd", "cve-mapping", {}, { fetcher, headers });
	if (!mapping.ok) throw new Error(`EUVD mapping HTTP ${mapping.status}`);
	const byCve = parseMappingCsv(await mapping.text());
	const exploited = {};
	for (let page = 0; page < MAX_PAGES; page++) {
		const r = await getResource("euvd", "exploited", { page }, { fetcher, headers });
		if (!r.ok) throw new Error(`EUVD exploited catalogue HTTP ${r.status}`);
		const json = await r.json();
		Object.assign(exploited, parseExploitedPage(json));
		const n = Array.isArray(json?.items) ? json.items.length : 0;
		if (!n || (Number.isFinite(json?.total) && (page + 1) * 100 >= json.total)) break;
	}
	if (verbose) console.log(`   EUVD: ${Object.keys(byCve).length} ids, ${Object.keys(exploited).length} exploited`);
	return { byCve, exploited, count: Object.keys(byCve).length };
}

/**
 * Enrich matches in place: cve.euvd = { id, exploitedSince } for CVEs ENISA knows
 * (exploitedSince = "YYYY-MM-DD", "" when ENISA gives no date, null when not exploited).
 * opts: { offline, verbose, fetcher, cacheDir }
 */
async function enrichEuvd(matches, opts = {}) {
	const { offline, verbose, fetcher = globalThis.fetch, cacheDir, hostedProxy } = opts;
	if (!(matches || []).some(m => m.cve?.id?.startsWith("CVE-"))) return matches;
	if (hostedProxy && !offline) {
		const ids = [...new Set(matches.map(m => m.cve?.id).filter(id => /^CVE-\d{4}-\d{4,7}$/.test(id || "")))];
		const byId = new Map();
		for (let i = 0; i < ids.length; i += 100) {
			const res = await require("./providers").getResource("euvd", "cves", { ids: ids.slice(i, i + 100) }, { fetcher, noStore: true, streaming: true });
			if (!res.ok) throw new Error(`hosted EUVD unavailable (HTTP ${res.status})`);
			const data = await res.json();
			if (!Array.isArray(data.items)) throw new Error("invalid hosted EUVD response");
			for (const item of data.items) byId.set(item.cve, item);
		}
		for (const m of matches) {
			const item = byId.get(m.cve?.id);
			if (item && (item.id || item.exploitedSince != null)) m.cve.euvd = { id: item.id || null, exploitedSince: item.exploitedSince ?? null };
		}
		return matches;
	}


	const cached = readCache(cacheDir);
	let body = cached?.body || null;
	const fresh = cached && Date.now() - cached._fetchedAt < CACHE_TTL_MS;
	if (!fresh && !offline) {
		try {
			body = await fetchSnapshot({ fetcher, verbose });
			writeCache(cacheDir, body);
		} catch (err) {
			if (verbose) console.warn(`   EUVD fetch failed: ${err.message}${body ? " — serving the cached snapshot" : ""}`);
		}
	}
	if (!body?.byCve) return matches;

	for (const m of matches || []) {
		const id = m.cve?.id;
		const euvd = id && body.byCve[id];
		const exploited = id && Object.prototype.hasOwnProperty.call(body.exploited || {}, id) ? body.exploited[id] : null;
		if (!euvd && exploited == null) continue;
		m.cve.euvd = { id: euvd || null, exploitedSince: exploited };
	}
	return matches;
}

module.exports = { enrichEuvd, fetchSnapshot, parseMappingCsv, parseExploitedPage, euvdDate, CACHE_FILE };
