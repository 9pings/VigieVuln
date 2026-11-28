/**
 * lib/providers/euvd/enrich.js — enrich matches with the ENISA European Vulnerability Database (EUVD).
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
 * Cache: ~/.fad-checker/euvd-cache.json, 4h TTL. A failed refresh keeps serving the
 * stale snapshot; offline serves it whatever its age.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const DEFAULT_CACHE_DIR = path.join(require("../../cache/directory").getCacheDir());
const CACHE_FILE = "euvd-cache.json";
const CACHE_TTL_MS = 4 * 3600 * 1000;
const MAX_PAGES = 200;
const MONTHS = { Jan: 1, Feb: 2, Mar: 3, Apr: 4, May: 5, Jun: 6, Jul: 7, Aug: 8, Sep: 9, Oct: 10, Nov: 11, Dec: 12 };

const cachePath = dir => path.join(dir || DEFAULT_CACHE_DIR, CACHE_FILE);

function readCache(dir) {
	try { return require('../../cache/repository').createCacheRepository(dir || DEFAULT_CACHE_DIR).get('catalogue','euvd')?.value || null; } catch { return null; }
}

function writeCache(dir, body) {
	try {
		require('../../cache/repository').createCacheRepository(dir || DEFAULT_CACHE_DIR).put('catalogue','euvd',{ _fetchedAt: Date.now(), body });
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

/** Convert ENISA dates to an unzoned calendar day without inventing UTC. */
function normalizeEuvdCalendarDate(raw) {
 const value=typeof raw==='string'?raw.trim():'';
 const iso=/^(\d{4}-\d{2}-\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?)?$/.exec(value);
 const day=iso?.[1] || euvdDate(value);if(!day)return null;
 const parsed=new Date(day+'T00:00:00Z');
 if(!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0,10)!==day)return null;
 if(iso){if(iso[2] && (+iso[2]>23 || +iso[3]>59 || +(iso[4]||0)>59))return null;return value;}
 const clock=/^[A-Z][a-z]{2} \d{1,2}, \d{4}, (\d{1,2}):(\d{2}):(\d{2}) (AM|PM)$/i.exec(value);
 if(!clock)return /^[A-Z][a-z]{2} \d{1,2}, \d{4}$/.test(value) ? day : null;
 const h=Number(clock[1]),m=Number(clock[2]),sec=Number(clock[3]);if(h<1||h>12||m>59||sec>59)return null;
 const hour=(h%12)+(clock[4].toUpperCase()==='PM'?12:0);
 return `${day}T${String(hour).padStart(2,'0')}:${clock[2]}:${clock[3]}`;
}
function normalizeEuvdDetailDates(detail) {
 if(!detail || typeof detail!=='object')return detail;
 const out={...detail};
 for(const key of ['published','modified']){
  const raw=detail[key] ?? detail[key+'Original'];
  if(raw!=null){out[key]=normalizeEuvdCalendarDate(raw) || raw;if(out[key+'Original']==null && out[key]!==raw)out[key+'Original']=raw;}
 }
 return out;
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

async function fetchSnapshot({ fetcher, verbose, onEuvdRequest }) {
	const { getResource } = require("..");
	const headers = { "User-Agent": "vigievuln-euvd" };
	onEuvdRequest?.(require("../common").failureKey("euvd", "cve-mapping", {}));
	const mapping = await getResource("euvd", "cve-mapping", {}, { fetcher, headers });
	if (!mapping.ok) throw new Error(`EUVD mapping HTTP ${mapping.status}`);
	const byCve = parseMappingCsv(await mapping.text());
	const exploited = {};
	for (let page = 0; page < MAX_PAGES; page++) {
		onEuvdRequest?.(require("../common").failureKey("euvd", "exploited", { page }));
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
	const { offline, verbose, fetcher = globalThis.fetch, cacheDir, hostedProxy, onStale } = opts;
	if (!(matches || []).some(m => m.cve?.id?.startsWith("CVE-"))) return matches;
	const repository = require('../../cache/repository').createCacheRepository(cacheDir || DEFAULT_CACHE_DIR);
	const targeted = repository.get('catalogue','euvd-targeted')?.value || { entries: {} };
	if (hostedProxy && !offline) {
		const ids = [...new Set(matches.map(m => m.cve?.id).filter(id => /^CVE-\d{4}-\d{4,7}$/.test(id || "")))];
		const byId = new Map();
		opts.onEnrichmentProgress?.({source:'euvd',completed:0,total:ids.length});
		for (let i = 0; i < ids.length; i += 100) {
			opts.onEuvdRequest?.(require("../common").failureKey("euvd", "cves", { ids: ids.slice(i, i + 100) }));
			const res = await require("..").getResource("euvd", "cves", { ids: ids.slice(i, i + 100) }, { fetcher, noStore: true, streaming: true });
			if (!res.ok) throw require('../request-failure').responseError('EUVD mapping',res,{viaProxy:true});
			const data = await res.json();
			if (!Array.isArray(data.items)) throw new Error("invalid hosted EUVD response");
			const requested=ids.slice(i,i+100), requestedSet=new Set(requested);
			const received=new Map();
			for (const item of data.items) {
				if (!item || !requestedSet.has(item.cve) || received.has(item.cve)) throw new Error('invalid hosted EUVD record');
				received.set(item.cve,item);byId.set(item.cve,item);
			}
			const rawDate=res.headers?.get?.('x-fad-proxy-fetched-at'),parsed=Date.parse(rawDate||'');
			const fetchedAt=Number.isFinite(parsed)&&parsed>0&&parsed<=Date.now()+300000 ? parsed : null;
			const stale=res.headers?.get?.('x-fad-proxy')==='stale' || fetchedAt===null;
			for (const id of requested) {
                const item=received.get(id)||null, old=targeted.entries[id];
                const preserve=old?.details && item?.id && old.details.id===item.id;
                targeted.entries[id]={item,fetchedAt,stale,...(preserve?{details:old.details,detailsFetchedAt:old.detailsFetchedAt,detailsStale:old.detailsStale,detailsOrigin:old.detailsOrigin,detailsFailure:old.detailsFailure}:{})};
            }
			opts.onEnrichmentProgress?.({source:'euvd',completed:Math.min(i+100,ids.length),total:ids.length});
		}
		repository.put('catalogue','euvd-targeted',targeted);
		for (const m of matches) {
			const item = byId.get(m.cve?.id);
			if (item && (item.id || item.exploitedSince != null)) m.cve.euvd = { id: item.id || null, exploitedSince: item.exploitedSince ?? null };
		}
		return matches;
	}


	const savedIds=new Set();
	if (offline) {
		let oldest=null,stale=false;
		for (const m of matches) {
			const entry=targeted.entries[m.cve?.id];if(!entry)continue;
			savedIds.add(m.cve.id);
			if(entry.stale || !entry.fetchedAt || Date.now()-entry.fetchedAt>=CACHE_TTL_MS){stale=true;if(entry.fetchedAt && (!oldest || entry.fetchedAt<oldest))oldest=entry.fetchedAt;}
			const item=entry.item;
			if(item && (item.id || item.exploitedSince != null))m.cve.euvd={id:item.id||null,exploitedSince:item.exploitedSince??null};
		}
		if(stale)onStale?.(oldest ? new Date(oldest).toISOString() : null);
	}
	const cached = readCache(cacheDir);
	let body = cached?.body || null;
	const fresh = cached && require('../../cache/policy').fresh(cached._fetchedAt, CACHE_TTL_MS);
	if (!fresh && !offline) {
		try {
			body = await fetchSnapshot({ fetcher, verbose, onEuvdRequest:opts.onEuvdRequest });
			writeCache(cacheDir, body);
		} catch (err) {
			opts.onEuvdFailure?.(err);
			if (verbose) require('../../ui').networkNotice(`   EUVD fetch failed: ${err.message}${body ? " — serving the cached snapshot" : ""}`);
		}
	}
	if (!body?.byCve) return matches;

	for (const m of matches || []) {
		const id = m.cve?.id;
		if (savedIds.has(id)) continue;
		const euvd = id && body.byCve[id];
		const exploited = id && Object.prototype.hasOwnProperty.call(body.exploited || {}, id) ? body.exploited[id] : null;
		if (!euvd && exploited == null) continue;
		m.cve.euvd = { id: euvd || null, exploitedSince: exploited };
	}
	return matches;
}

module.exports = { enrichEuvd, fetchSnapshot, parseMappingCsv, parseExploitedPage, euvdDate, normalizeEuvdCalendarDate, normalizeEuvdDetailDates, CACHE_FILE };
