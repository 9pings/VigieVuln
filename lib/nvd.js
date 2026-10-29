/**
 * lib/nvd.js — enrich already-found CVEs with the NIST NVD record.
 *
 * NVD's API doesn't expose a Maven-coord index, so we don't use it for
 * recall. Instead we look up each known CVE ID to get the canonical
 * description, full CVSS metrics (v2 / v3.1 / v4.0), CPE configurations,
 * and reference URLs.
 *
 * API: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN
 * Rate limit: 5 req / 30s unauthenticated, 50 req / 30s with NVD_API_KEY env var.
 *
 * Cache: ~/.fad-checker/nvd-cache/<cve-id>.json, 7-day TTL.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { getNvdApiKey } = require("./config");

const NVD_CACHE_DIR = path.join(require("./cache-directory").getCacheDir(), "nvd-cache");
const NVD_CACHE_TTL_MS = 7 * 24 * 3600 * 1000;
// Bump whenever `extractFromNvdRecord` adds a new field — pre-bump cache
// entries are treated as cache-miss so we re-fetch and pick up the new field.
// 2: added `cwes` (Common Weakness Enumeration list).
const NVD_CACHE_SCHEMA = 2;
const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

function getRateDelay() {
	// 50 req / 30s with API key, 5 req / 30s without
	return getNvdApiKey() ? 600 : 6000;
}

// NIST rate-limit policy is a rolling 30s window. Burst up to N at once then
// wait until the oldest send is older than 30s. Without a key the burst size
// stays at 5; with a key it's 50 — which lets latency overlap and avoids
// blocking on a `setTimeout` between every request.
function getBurstSize() {
	return getNvdApiKey() ? 50 : 5;
}
const NVD_WINDOW_MS = 30_000;

function cachePath(cveId) {
	return path.join(NVD_CACHE_DIR, `${cveId}.json`);
}

function readCache(cveId, offline = false) {
	const p = cachePath(cveId);
	if (!fs.existsSync(p)) return null;
	try {
		const data = JSON.parse(fs.readFileSync(p, "utf8"));
		// Offline (air-gapped): the warmed cache is the ONLY source — never reject it
		// for age or an older schema. Dropping it would silently lose ALL NVD
		// enrichment (CWEs, CVSS vector, references, CPE configs) for that CVE, which
		// is exactly the "offline missed some CWE titles" regression. A stale/older
		// body just means a field may be missing — strictly better than nothing.
		// (Online still enforces schema + TTL so we re-fetch and upgrade.)
		if (offline) return data.body ?? null;
		// Schema mismatch → force re-fetch so newly-added fields (e.g. cwes) get populated.
		if ((data._schema || 1) < NVD_CACHE_SCHEMA) return null;
		if (Date.now() - data._fetchedAt < NVD_CACHE_TTL_MS) return data.body;
	} catch { /* ignore */ }
	return null;
}

function writeCache(cveId, body) {
	fs.mkdirSync(NVD_CACHE_DIR, { recursive: true });
	fs.writeFileSync(cachePath(cveId), JSON.stringify({ _schema: NVD_CACHE_SCHEMA, _fetchedAt: Date.now(), body }));
}

function bestMetric(metrics) {
	// NVD 2.0 returns metrics organised by version: cvssMetricV40, V31, V30, V2
	const order = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"];
	// Proper CVSS version label — NOT "cvssMetricV31".replace(...) which yielded the
	// malformed "CVSS:V31" that downstream consumers (csaf cvssV3Version, sbom
	// cvssMethod, the report) test with .includes("3.1") and so always missed.
	const VER = { cvssMetricV40: "CVSS:4.0", cvssMetricV31: "CVSS:3.1", cvssMetricV30: "CVSS:3.0", cvssMetricV2: "CVSS:2.0" };
	for (const k of order) {
		if (Array.isArray(metrics?.[k]) && metrics[k].length) {
			const cv = metrics[k][0].cvssData;
			return {
				version: VER[k],
				score: cv.baseScore,
				severity: (cv.baseSeverity || severityFromScore(cv.baseScore) || "UNKNOWN").toUpperCase(),
				vector: cv.vectorString,
			};
		}
	}
	return null;
}

function severityFromScore(s) {
	if (s == null) return null;
	if (s >= 9) return "CRITICAL";
	if (s >= 7) return "HIGH";
	if (s >= 4) return "MEDIUM";
	if (s > 0) return "LOW";
	return "NONE";
}

function extractFromNvdRecord(record) {
	if (!record) return null;
	const desc = (record.descriptions || []).find(d => d.lang === "en")?.value || "";
	const metric = bestMetric(record.metrics);
	// Keep each reference together with its NVD tags (Patch, Exploit, Vendor Advisory, Third Party Advisory, Mailing List, ...)
	const refs = (record.references || []).map(r => ({
		url: r.url,
		source: r.source || null,
		tags: r.tags || [],
	}));
	const cpes = [];
	for (const c of record.configurations || []) {
		for (const n of c.nodes || []) {
			for (const m of n.cpeMatch || []) cpes.push(m.criteria);
		}
	}
	// Preserve the full configurations tree so cve-match / cpe.js can evaluate
	// AND/OR nodes and version ranges (versionStartIncluding, etc.). We strip
	// `matchCriteriaId` and other UUID-only fields to keep the cache compact.
	const configurations = (record.configurations || []).map(c => ({
		operator: c.operator || "OR",
		negate: c.negate || false,
		nodes: (c.nodes || []).map(slimNode),
	}));
	// CWE identifiers (Common Weakness Enumeration). NVD shape:
	//   weaknesses: [{ source, type, description: [{ lang, value: "CWE-79" }] }]
	const cwes = [];
	const seenCwe = new Set();
	for (const w of record.weaknesses || []) {
		for (const d of w.description || []) {
			const v = (d.value || "").trim();
			if (/^CWE-\d+$/i.test(v) && !seenCwe.has(v.toUpperCase())) {
				seenCwe.add(v.toUpperCase());
				cwes.push(v.toUpperCase());
			}
		}
	}
	return {
		id: record.id,
		description: desc,
		severity: metric?.severity || "UNKNOWN",
		score: metric?.score ?? null,
		cvssVector: metric?.vector || null,
		cvssVersion: metric?.version || null,
		published: record.published || null,
		modified: record.lastModified || null,
		references: refs,
		cpes,
		cwes,
		configurations,
	};
}

function slimNode(n) {
	return {
		operator: n.operator || "OR",
		negate: n.negate || false,
		cpeMatch: (n.cpeMatch || []).map(m => ({
			vulnerable: m.vulnerable !== false,
			criteria: m.criteria,
			versionStartIncluding: m.versionStartIncluding,
			versionStartExcluding: m.versionStartExcluding,
			versionEndIncluding: m.versionEndIncluding,
			versionEndExcluding: m.versionEndExcluding,
		})),
		children: Array.isArray(n.children) ? n.children.map(slimNode) : undefined,
	};
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const MIRROR_TIMEOUT_MS = 30000;
const MIRROR_NAME = "fkie-cad/nvd-json-data-feeds";
const MIRROR_CONCURRENCY = 16;

/**
 * Read one CVE from the fkie-cad mirror. → { record } (already extracted + cached),
 * { absent: true } (404: not mirrored yet — a brand-new CVE), or { failed: true }.
 * Carries its own deadline, so the source-health guard hands the outcome straight back:
 * the caller decides what a miss means (NVD must then answer).
 */
async function fetchFromMirror(cveId, opts = {}) {
	const { fetcher = globalThis.fetch } = opts;
	try {
		const providers = require("./providers");
		const m = await providers.getResource("nvd", "cve-mirror", { id: cveId },
			{ fetcher, headers: { "User-Agent": "vigievuln-nvd-enrich" }, ...(providers.hasHostedProxy() ? {requestTimeoutMs:MIRROR_TIMEOUT_MS, retryProxyDenied:false, noSourceRetry:true} : {signal:AbortSignal.timeout(MIRROR_TIMEOUT_MS)}) });
		if (m.status === 404) return { absent: true };
		if (!m.ok) return { failed: true };
		const raw = await m.json();
		const extracted = extractFromNvdRecord(raw && raw.id ? raw : raw?.vulnerabilities?.[0]?.cve);
		if (!extracted) return { failed: true };
		extracted.via = MIRROR_NAME;
		writeCache(cveId, extracted);
		return { record: extracted };
	} catch { return { failed: true }; }
}

/**
 * One CVE's NVD record. NVD first; when NVD does not ANSWER (throttled 403/429, 5xx, no
 * transport) the same record is read from the fkie-cad git mirror, and only when both fail
 * is the hole reported (lib/source-health.js#noteFanoutExhausted → the run stops before
 * writing anything). A definitive NVD 404 is an answer — the CVE is not in NVD — and is
 * never sent to the mirror.
 *
 * With the mirror on (default), the NVD request carries its own deadline, which makes the
 * source-health guard hand it straight back instead of running its 5-retry schedule: a
 * throttled NVD then costs one request, not ~40 s of backoff, because a host that has the
 * same data with no rate limit is right there. `--no-nvd-mirror` restores NVD-only with
 * the full retry schedule.
 *
 * Last resort, online: a cached record past its TTL is served rather than dropped (stale
 * enrichment beats no CWE/CVSS at all — the offline path already does exactly this).
 */
async function fetchOne(cveId, opts = {}) {
	const { fetcher = globalThis.fetch, verbose, offline, mirror = true } = opts;
	const cached = !offline && require("./providers").hasHostedProxy() ? null : readCache(cveId, offline);
	if (cached !== null && cached !== undefined) return cached;
	if (offline) return null;
	const headers = { "User-Agent": "vigievuln-nvd-enrich" };
	const key = getNvdApiKey();
	if (key) headers["apiKey"] = key;
	const url = `${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`;
	const providers = require("./providers");
	const health = require("./source-health");
	const deadline = () => providers.hasHostedProxy() ? {requestTimeoutMs:MIRROR_TIMEOUT_MS} : (mirror ? { signal: AbortSignal.timeout(MIRROR_TIMEOUT_MS) } : {});

	let nvdReason;
	try {
		const r = await providers.getResource("nvd", "cve", { id: cveId }, { fetcher, headers, ...deadline(), ...(providers.hasHostedProxy() && mirror ? {retryProxyDenied:false,noSourceRetry:true} : {}) });
		if (r.status === 404) { writeCache(cveId, null); return null; }
		if (r.ok) {
			const data = await r.json();
			const extracted = extractFromNvdRecord(data.vulnerabilities?.[0]?.cve);
			writeCache(cveId, extracted);
			return extracted;
		}
		nvdReason = `HTTP ${r.status}`;
	} catch (err) {
		nvdReason = `network: ${err.message}`;
	}
	if (verbose) console.warn(`   NVD ${nvdReason} for ${cveId}`);
	// A 4xx we caused (bad request…) is an answer, not an outage: nothing to fall back for.
	if (health.classifyMissReason(nvdReason) === "answered") return null;

	if (mirror) {
		const got = await fetchFromMirror(cveId, { fetcher });
		if (got.record) {
			if (verbose) console.warn(`   ${cveId} served by the NVD mirror (${MIRROR_NAME})`);
			return got.record;
		}
	}
	const stale = require("./providers").hasHostedProxy() ? null : readCache(cveId, true);
	if (stale) return stale;
	// Neither NVD nor its mirror produced this record: a coverage hole, reported under NVD.
	health.noteFanoutExhausted(url, [nvdReason]);
	return null;
}

/**
 * Enrich an array of vigievuln matches in place by fetching their NVD records.
 * Adds: cve.description (replaced by NVD's), cve.cvssVector, cve.cvssVersion,
 * cve.references, cve.cpes. Severity/score are only overwritten if currently UNKNOWN/null.
 *
 * Rate limited per the NIST policy (use NVD_API_KEY for faster access).
 */
async function enrichMatches(matches, opts = {}) {
	const { offline, onProgress } = opts;
	const uniqueCves = new Set();
	for (const m of matches) if (m.cve?.id?.startsWith("CVE-")) uniqueCves.add(m.cve.id);
	// `opts.hasKey` lets a test pin the key/no-key branch whatever ~/.fad-checker holds.
	const hasKey = opts.hasKey ?? !!getNvdApiKey();
	const hosted = !offline && require("./providers").hasHostedProxy();
	const burst = hosted ? 10 : getBurstSize();

	// Partition cached vs live up-front so the progress display reflects the
	// actual work to do (the user's "stuck at OSV" complaint was caused by
	// silent serial fetching with no progress output).
	const byId = new Map();
	const liveIds = [];
	for (const cveId of uniqueCves) {
		const cached = !offline && require("./providers").hasHostedProxy() ? null : readCache(cveId, offline);
		if (cached !== null && cached !== undefined) {
			byId.set(cveId, cached);
			continue;
		}
		if (offline) { byId.set(cveId, null); continue; }
		liveIds.push(cveId);
	}

	// No NVD key: the mirror goes FIRST. NVD without a key allows 5 requests per 30 s, the
	// mirror has the same JSON and no limit, so every CVE it holds is read from it in
	// parallel. What it does not hold (404 — a CVE published since its last sync) or cannot
	// serve is left in `liveIds` for NVD, which must then answer: those requests go
	// through the normal paced loop below with NVD's full retry schedule, and a source
	// that still does not answer stops the run (reliability over speed). With a key NVD
	// stays first and the mirror is its fallback (fetchOne).
	const mirrorFirst = !offline && !require("./providers").hasHostedProxy() && opts.mirror !== false && !hasKey && liveIds.length > 0;
	if (mirrorFirst) {
		const pending = [...liveIds];
		const notMirrored = [];
		let mirrored = 0;
		const workers = Array.from({ length: Math.min(MIRROR_CONCURRENCY, pending.length) }, async () => {
			while (pending.length) {
				const id = pending.shift();
				const got = await fetchFromMirror(id, opts);
				if (got.record) { byId.set(id, got.record); mirrored++; }
				else notMirrored.push(id);
				if (onProgress) onProgress(mirrored, liveIds.length);
			}
		});
		await Promise.all(workers);
		if (!onProgress) console.log(`🔍 NVD: ${mirrored} CVE record(s) from the ${MIRROR_NAME} mirror${notMirrored.length ? `, ${notMirrored.length} not mirrored → NVD` : ""}.`);
		liveIds.length = 0;
		liveIds.push(...notMirrored);
	}
	// NVD for whatever is left. When the mirror was already asked, NVD-only with the guard's
	// retry schedule — it is the last source, it has to answer.
	const nvdOpts = mirrorFirst ? { ...opts, mirror: false } : opts;

	if (liveIds.length && !onProgress) {
		const etaSec = Math.ceil((liveIds.length / burst) * (NVD_WINDOW_MS / 1000));
		const keyHint = hosted ? "via hosted proxy" : hasKey ? "with API key (50/30s)" : "no API key — throttled to 5/30s, run `vigievuln --set-nvd-key <KEY>` (free, instant) to be 10× faster";
		const cachedCount = byId.size;
		const cachedHint = cachedCount ? `, ${cachedCount} cached` : "";
		console.log(`🔍 NVD: enriching ${liveIds.length} CVEs${cachedHint} — ${keyHint}.${hosted ? '' : ` ETA ~${etaSec}s.`}`);
	} else if (uniqueCves.size && !onProgress) {
		console.log(`🔍 NVD: ${uniqueCves.size} CVEs (all cached).`);
	}

	// Token-bucket burst: fire `burst` requests in parallel, wait until the
	// oldest send is older than NVD_WINDOW_MS, repeat. Better progress UX than
	// the previous serial sleep loop — same effective throughput.
	let done = 0;
	const startedAt = [];
	const startProgress = Date.now();
	const printProgress = (final = false) => {
		if (onProgress) { onProgress(done, liveIds.length); return; }
		const elapsed = Math.round((Date.now() - startProgress) / 1000);
		const pct = liveIds.length ? Math.round((done / liveIds.length) * 100) : 100;
		const line = `   NVD: ${done}/${liveIds.length} (${pct}%) — ${elapsed}s elapsed`;
		if (process.stdout.isTTY) process.stdout.write(`\r${line}${final ? "\n" : "                    "}`);
		else if (final) console.log(line);
	};

	for (let i = 0; i < liveIds.length; i += burst) {
		const slice = liveIds.slice(i, i + burst);
		const windowStart = Date.now();
		startedAt.push(windowStart);
		const results = await Promise.all(slice.map(id => fetchOne(id, nvdOpts)));
		for (let j = 0; j < slice.length; j++) byId.set(slice[j], results[j]);
		done += slice.length;
		printProgress();

		// Respect the rolling 30s window before starting the next burst.
		if (!hosted && i + burst < liveIds.length) {
			const since = Date.now() - windowStart;
			if (since < NVD_WINDOW_MS) await sleep(NVD_WINDOW_MS - since);
		}
	}
	if (liveIds.length) printProgress(true);

	for (const m of matches) {
		const data = byId.get(m.cve?.id);
		if (!data) continue;
		// Merge: prefer NVD's official text + CVSS but keep what vigievuln/OSV already has
		// NVD's description is the official long form — prefer it when available.
		if (data.description) {
			m.cve.description = data.description.length > 2000
				? data.description.slice(0, 2000) + "…"
				: data.description;
		}
		if (data.severity && (m.cve.severity === "UNKNOWN" || !m.cve.severity || m.cve.severityScheme === "drupal-rating")) {
			m.cve.severity = data.severity;
			if (m.cve.severityScheme === "drupal-rating") m.cve.severityScheme = "cvss";
		}
		if (m.cve.score == null) m.cve.score = data.score;
		// Only overwrite the vector/version when NVD actually has one — an NVD record
		// without CVSS metrics must not clobber an OSV-derived vector/version (which is
		// what feeds CSAF cvssV3Version + SBOM cvssMethod).
		if (data.cvssVector) m.cve.cvssVector = data.cvssVector;
		if (data.cvssVersion) m.cve.cvssVersion = data.cvssVersion;
		m.cve.nvdRefs = data.references || [];   // [{url, tags, source}]
		m.cve.cpes = data.cpes || [];
		m.cve.cwes = data.cwes || [];
		m.cve.configurations = data.configurations || [];
		if (!m.cve.published && data.published) m.cve.published = data.published;
		if (!m.cve.modified  && data.modified)  m.cve.modified  = data.modified;
		// Tag NVD as a contributing source so the report shows fad+nvd / osv+nvd.
		const sources = new Set((m.source || "").split("+").filter(Boolean));
		sources.add("nvd");
		m.source = [...sources].sort().join("+");
	}
	return matches;
}

module.exports = {
	enrichMatches,
	fetchOne,
	extractFromNvdRecord,
	readCache,
	writeCache,
	NVD_CACHE_DIR,
	NVD_CACHE_SCHEMA,
	NVD_CACHE_TTL_MS,
	getNvdApiKey,
};
