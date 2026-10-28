/**
 * lib/certfr.js — link matched CVEs to the CERT-FR (ANSSI) advisories that cite them.
 *
 * CERT-FR publishes every "avis" (advisory) and "alerte" (alert) as JSON, each listing
 * the CVEs it covers — but offers no CVE → advisory lookup. So fad keeps a LOCAL index:
 * the two listings (one request each) give every advisory with its last revision date,
 * and only an advisory that is new or revised since the last run is fetched. The first
 * run reads them all (~18 000 small JSON files, a few minutes, once); later runs fetch
 * the handful published since. Hosted proxy mode instead sends matched CVE identifiers
 * to the proxy and receives only their stored advisory references.
 *
 * Cache: ~/.fad-checker/certfr-cache.json = { meta: { fetchedAt }, entries: { ref:
 * { kind, rev, title, cves } } } — the accumulating entry-map shape, so --import-cache
 * merges it key by key. The listings are re-read after 24h; offline uses what is there.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const DEFAULT_CACHE_DIR = path.join(require("./cache-directory").getCacheDir());
const CACHE_FILE = "certfr-cache.json";
const CACHE_TTL_MS = 24 * 3600 * 1000;
const KINDS = ["avis", "alerte"];
const SAVE_EVERY = 500;

const cachePath = dir => path.join(dir || DEFAULT_CACHE_DIR, CACHE_FILE);

function readCache(dir) {
	try {
		const data = JSON.parse(fs.readFileSync(cachePath(dir), "utf8"));
		if (data?.entries && typeof data.entries === "object") return data;
	} catch { /* none yet */ }
	return { meta: { fetchedAt: 0 }, entries: {} };
}

function writeCache(dir, data) {
	if (dir === false) return;   // a caller that persists the index itself (vigievuln)
	try {
		fs.mkdirSync(dir || DEFAULT_CACHE_DIR, { recursive: true });
		const tmp = cachePath(dir) + ".tmp";
		fs.writeFileSync(tmp, JSON.stringify(data));
		fs.renameSync(tmp, cachePath(dir));
	} catch { /* a cache is an optimisation */ }
}

/** Public page of an advisory. */
function certfrUrl(kind, ref) {
	return `https://www.cert.ssi.gouv.fr/${kind}/${ref}/`;
}

/** Pure: the advisory JSON → the CVE ids it cites, upper-cased and de-duplicated. */
function advisoryCves(json) {
	const out = new Set();
	for (const c of Array.isArray(json?.cves) ? json.cves : []) {
		const id = String(c?.name || "").trim().toUpperCase();
		if (/^CVE-\d{4}-\d{4,}$/.test(id)) out.add(id);
	}
	return [...out];
}

/** Pure: listing rows that are new or revised against the cached entries. */
function staleAdvisories(listing, entries, kind) {
	return (Array.isArray(listing) ? listing : [])
		.filter(row => row?.reference && entries[row.reference]?.rev !== (row.last_revision_date || ""))
		.map(row => ({ kind, ref: row.reference, rev: row.last_revision_date || "", title: row.title || "" }));
}

/** Pure: entries → { "CVE-…": [{ ref, kind, title }] }, newest advisory first. */
function indexByCve(entries) {
	const byCve = {};
	for (const [ref, e] of Object.entries(entries || {})) {
		for (const cve of e?.cves || []) (byCve[cve] ||= []).push({ ref, kind: e.kind, title: e.title || "" });
	}
	for (const list of Object.values(byCve)) list.sort((a, b) => b.ref.localeCompare(a.ref));
	return byCve;
}

async function refresh(data, { fetcher, verbose, cacheDir, concurrency, onProgress }) {
	const { getResource } = require("./providers");
	const headers = { "User-Agent": "vigievuln-certfr" };
	const todo = [];
	for (const kind of KINDS) {
		const r = await getResource("certfr", "index", { kind }, { fetcher, headers });
		if (!r.ok) throw new Error(`CERT-FR ${kind} listing HTTP ${r.status}`);
		todo.push(...staleAdvisories(await r.json(), data.entries, kind));
	}
	let done = 0, failed = 0, next = 0;
	const worker = async () => {
		while (next < todo.length) {
			const a = todo[next++];
			try {
				const r = await getResource("certfr", "advisory", { kind: a.kind, ref: a.ref, rev: a.rev }, { fetcher, headers });
				// A 404/410 is an answer (a listed advisory without JSON): record it empty so it
				// is not re-requested every run. Anything else is retried next time.
				if (r.ok) data.entries[a.ref] = { kind: a.kind, rev: a.rev, title: a.title, cves: advisoryCves(await r.json()) };
				else if (r.status === 404 || r.status === 410) data.entries[a.ref] = { kind: a.kind, rev: a.rev, title: a.title, cves: [] };
				else failed++;
			} catch { failed++; }
			done++;
			if (onProgress) onProgress(done, todo.length);
			if (done % SAVE_EVERY === 0) writeCache(cacheDir, data);
		}
	};
	await Promise.all(Array.from({ length: Math.max(1, concurrency) }, worker));
	// A run that could not read some advisories leaves the listing stamp unchanged, so the
	// next run retries them instead of waiting a day.
	if (!failed) data.meta = { fetchedAt: Date.now() };
	writeCache(cacheDir, data);
	if (verbose) console.log(`   CERT-FR: ${todo.length - failed} advisories indexed${failed ? `, ${failed} failed` : ""}`);
	return { changed: todo.filter(a => data.entries[a.ref]?.rev === a.rev).map(a => a.ref), failed };
}

/**
 * Enrich matches in place: cve.certfr = [{ ref, kind, title }] for CVEs cited by a
 * CERT-FR advisory or alert. opts: { offline, verbose, fetcher, cacheDir, concurrency, onProgress }
 */
async function enrichCertFr(matches, opts = {}) {
	const { offline, verbose, fetcher = globalThis.fetch, cacheDir, concurrency = 8, onProgress, hostedProxy } = opts;
	if (!(matches || []).some(m => m.cve?.id?.startsWith("CVE-"))) return matches;
	if (hostedProxy && !offline) {
		const ids = [...new Set(matches.map(m => m.cve?.id).filter(id => /^CVE-\d{4}-\d{4,7}$/.test(id || "")))];
		const byId = new Map();
		for (let i = 0; i < ids.length; i += 100) {
			const res = await require("./providers").getResource("certfr", "cves", { ids: ids.slice(i, i + 100) }, { fetcher, noStore: true, streaming: true });
			if (!res.ok) throw new Error(`hosted CERT-FR unavailable (HTTP ${res.status})`);
			const data = await res.json();
			if (!Array.isArray(data.items)) throw new Error("invalid hosted CERT-FR response");
			for (const item of data.items) byId.set(item.cve, item.advisories);
		}
		for (const m of matches) { const hits = byId.get(m.cve?.id); if (hits?.length) m.cve.certfr = hits; }
		return matches;
	}


	const data = readCache(cacheDir);
	if (!offline && Date.now() - (data.meta?.fetchedAt || 0) >= CACHE_TTL_MS) {
		try { await refresh(data, { fetcher, verbose, cacheDir, concurrency, onProgress }); }
		catch (err) { if (verbose) console.warn(`   CERT-FR refresh failed: ${err.message} — using the cached index`); }
	}
	const byCve = indexByCve(data.entries);
	for (const m of matches || []) {
		const hits = m.cve?.id && byCve[m.cve.id];
		if (hits?.length) m.cve.certfr = hits;
	}
	return matches;
}

/**
 * Bring an index { meta, entries } up to date in place (listings + new/revised advisories).
 * cacheDir: false = do not write the fad cache file (the caller persists the entries).
 */
const refreshCertFrIndex = (data, opts = {}) => refresh(data, { concurrency: 8, ...opts });

module.exports = { enrichCertFr, refreshCertFrIndex, advisoryCves, staleAdvisories, indexByCve, certfrUrl, CACHE_FILE };
