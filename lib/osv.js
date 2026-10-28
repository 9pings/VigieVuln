/**
 * lib/osv.js — query OSV.dev for Maven-ecosystem vulnerabilities.
 *
 * OSV.dev (Google + GitHub Security Lab) aggregates CVE + GHSA data and
 * maintains a curated Maven-coordinate mapping. For Maven recall this is
 * vastly better than the raw CVEProject feed (which lacks packageName
 * fields on pre-2024 CVEs).
 *
 * API: https://google.github.io/osv.dev/post-v1-querybatch/
 *   POST /v1/querybatch  with up to 1000 queries
 *   POST /v1/query       for a single dep
 *   GET  /v1/vulns/{id}  to fetch full details
 *
 * Cached responses live in ~/.fad-checker/osv-cache/ for 12h.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const OSV_CACHE_DIR = path.join(require("./cache-directory").getCacheDir(), "osv-cache");
const OSV_CACHE_TTL_MS = 12 * 3600 * 1000;
const OSV_BASE = "https://api.osv.dev";
const BATCH_SIZE = 800;          // OSV limit is 1000; stay under for safety

/**
 * A cache FILENAME, never a path. The version was interpolated raw until a package-lock v1
 * entry for a URL-installed dep ("version": "https://registry.npmjs.org/x/-/x-0.12.5.tgz")
 * turned it into a nested path and killed the scan on ENOENT mid-step. Anything that is not
 * safe in a single segment is collapsed — which also means a version can never walk out of
 * the cache directory. `_` is not used as the replacement for `v` because a version legally
 * contains `_`; `%` keeps distinct versions distinct.
 */
function cacheKey(g, a, v, ecosystem = "maven") {
	const safeG = (g || "").replace(/[/\\]/g, "_");
	const safeA = (a || "").replace(/[/\\@]/g, "_");
	const safeV = String(v == null ? "none" : v).replace(/[^A-Za-z0-9._+-]/g, "%");
	return `${ecosystem}__${safeG}__${safeA}__${safeV}.json`;
}

// OFFLINE bypasses the TTL (same rule as lib/nvd.js): the warmed cache is the
// ONLY source on an air-gapped box, so a >12h-old entry must still be served —
// expiring it there silently reported "0 OSV vulns" for every ecosystem.
// Online keeps enforcing the TTL so entries refresh normally.
function readCache(name, { ignoreTtl = false, cacheDir = OSV_CACHE_DIR } = {}) {
	const p = path.join(cacheDir, name);
	if (!fs.existsSync(p)) return null;
	try {
		const data = JSON.parse(fs.readFileSync(p, "utf8"));
		// Before schema 2 an empty list could be a failed HTTP request. It is
		// unknown, not proof of a clean package. Keep legacy positive findings.
		if (Array.isArray(data.body) && !data.body.length && data._schema !== 2) return null;
		if (ignoreTtl || Date.now() - data._fetchedAt < OSV_CACHE_TTL_MS) return data.body;
	} catch { /* ignore */ }
	return null;
}

function writeCache(name, body, { cacheDir = OSV_CACHE_DIR } = {}) {
	fs.mkdirSync(cacheDir, { recursive: true });
	fs.writeFileSync(path.join(cacheDir, name), JSON.stringify({ _schema: 2, _fetchedAt: Date.now(), body }));
}

const SEVERITY_ALIASES = { MODERATE: "MEDIUM", IMPORTANT: "HIGH", SEVERE: "HIGH", INFO: "LOW" };

function normalizeSeverity(s) {
	const up = String(s || "").toUpperCase();
	return SEVERITY_ALIASES[up] || up;
}

function severityFromScore(n) {
	if (!Number.isFinite(n)) return "UNKNOWN";
	if (n >= 9) return "CRITICAL";
	if (n >= 7) return "HIGH";
	if (n >= 4) return "MEDIUM";
	if (n > 0) return "LOW";
	return "NONE";
}

// Compute a CVSS v3.0/3.1 base score from its vector string. Returns null for
// non-v3 vectors (v2/v4) or anything unparseable. OSV stores the *vector* in
// `severity[].score` for CVSS_V3 — there is NO bare base number to read, so the
// old "first number in the string" approach extracted the VERSION ("3.1") as the
// score, mislabelling HIGH findings as ~low everywhere downstream (SARIF
// security-severity, priority banding, SBOM/CSAF ratings).
function cvss3BaseScore(vector) {
	const v = String(vector || "");
	if (!/^CVSS:3\.[01]\//.test(v)) return null;
	const p = {};
	for (const kv of v.split("/").slice(1)) {
		const [k, val] = kv.split(":");
		if (k && val) p[k] = val;
	}
	const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[p.AV];
	const AC = { L: 0.77, H: 0.44 }[p.AC];
	const UI = { N: 0.85, R: 0.62 }[p.UI];
	const scopeChanged = p.S === "C";
	const PR = scopeChanged
		? { N: 0.85, L: 0.68, H: 0.5 }[p.PR]
		: { N: 0.85, L: 0.62, H: 0.27 }[p.PR];
	const imp = { H: 0.56, L: 0.22, N: 0 };
	const C = imp[p.C], I = imp[p.I], A = imp[p.A];
	if ([AV, AC, UI, PR, C, I, A].some(x => x == null)) return null;
	const iss = 1 - (1 - C) * (1 - I) * (1 - A);
	const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
	if (impact <= 0) return 0;
	const exploit = 8.22 * AV * AC * PR * UI;
	const base = Math.min(scopeChanged ? 1.08 * (impact + exploit) : impact + exploit, 10);
	return Math.ceil(base * 10) / 10; // CVSS roundup to one decimal
}

/** Best CVSS info from an OSV vuln: { score, vector, version } (version like "3.1"). */
function cvssInfoFromVuln(vuln) {
	for (const s of vuln.severity || []) {
		const str = String(s.score || "");
		const mver = str.match(/^CVSS:(\d\.\d)\//);
		if (mver) {
			const version = mver[1];
			const score = (version === "3.0" || version === "3.1") ? cvss3BaseScore(str) : null;
			return { score, vector: str, version };
		}
		const mnum = str.match(/^\s*(\d+(\.\d+)?)\s*$/); // a bare numeric score ("9.8")
		if (mnum) return { score: parseFloat(mnum[1]), vector: null, version: null };
	}
	return { score: null, vector: null, version: null };
}

/** Map an OSV vuln to { severity, score }. */
function severityFromOsv(vuln) {
	const direct = vuln.database_specific?.severity;
	const { score } = cvssInfoFromVuln(vuln);
	if (direct) return { severity: normalizeSeverity(direct), score };
	if (score != null) return { severity: severityFromScore(score), score };
	return { severity: "UNKNOWN", score: null };
}

function scoreFromVuln(vuln) { return cvssInfoFromVuln(vuln).score; }

/**
 * Pick the fix version to recommend from OSV's affected ranges. A multi-branch advisory
 * (e.g. Tomcat fixed in 9.0.118, 10.1.55 AND 11.0.22) lists one `fixed` per branch — the
 * old code returned the FIRST, which for an 11.0.21 dep meant "upgrade to 9.0.118", i.e. a
 * DOWNGRADE. Instead pick the smallest fix strictly ABOVE the current version: that's the
 * next patched release on the dep's own branch. If none is greater (the branch has no
 * published fix, or the dep is already patched), return null rather than suggest a downgrade.
 */
function fixVersionFromOsv(vuln, depKey, depVersion) {
	const { compareMavenVersions } = require("./maven-version");
	const fixes = [];
	for (const a of vuln.affected || []) {
		const name = a.package?.name?.toLowerCase();
		if (name && name !== depKey.toLowerCase()) continue;
		for (const r of a.ranges || []) {
			for (const ev of r.events || []) {
				if (ev.fixed) fixes.push(String(ev.fixed));
			}
		}
	}
	if (!fixes.length) return null;
	const cmp = (x, y) => { try { return compareMavenVersions(x, y); } catch { return String(x).localeCompare(String(y)); } };
	const sorted = [...fixes].sort(cmp);
	if (!depVersion) return sorted[0]; // no current version to compare against → lowest published fix
	const upgrades = sorted.filter(f => cmp(f, depVersion) > 0);
	return upgrades.length ? upgrades[0] : null;
}

/** The fix on the dep's OWN branch (see maven-version#branchFixFromOsvEvents). → { branchFix } | {} */
function branchFixFromOsv(vuln, depKey, depVersion) {
	if (!depVersion) return {};
	const { branchFixFromOsvEvents } = require("./maven-version");
	for (const a of vuln.affected || []) {
		const name = a.package?.name?.toLowerCase();
		if (name && name !== String(depKey).toLowerCase()) continue;
		for (const r of a.ranges || []) {
			if (r.type && r.type !== "ECOSYSTEM" && r.type !== "SEMVER") continue;
			const f = branchFixFromOsvEvents(String(depVersion), r.events);
			if (f) return { branchFix: f };
		}
	}
	return {};
}

/** Pick the best CVE id from an OSV vuln (prefer CVE-* aliases over GHSA-*). */
function pickPrimaryId(vuln) {
	if (vuln.id?.startsWith("CVE-")) return vuln.id;
	const cveAlias = (vuln.aliases || []).find(a => a.startsWith("CVE-"));
	return cveAlias || vuln.id;
}

// OSV ecosystem name per codec id. OSV.dev natively supports all of these.
const OSV_ECO = { maven: "Maven", npm: "npm", yarn: "npm", nuget: "NuGet", composer: "Packagist", pypi: "PyPI", go: "Go", ruby: "RubyGems" };

/** OSV ecosystem string for a dep, derived from its codec id. */
function osvEcosystemFor(dep) { return OSV_ECO[dep.ecosystem] || "Maven"; }

/** Build the OSV package-name key for a dep — delegated to the dep's codec. */
function osvPkgName(dep) {
	const { getCodec } = require("./codecs");
	const c = getCodec(dep.ecosystem);
	if (c) return c.osvPackageName(dep);
	// Fallback historique si le codec est introuvable.
	return dep.ecosystem === "npm" ? dep.artifactId : `${dep.groupId}:${dep.artifactId}`;
}

/** Convert one OSV vuln to vigievuln match shape. */
function vulnToMatch(dep, vuln) {
	const id = pickPrimaryId(vuln);
	const { severity, score } = severityFromOsv(vuln);
	const cvss = cvssInfoFromVuln(vuln);
	// `details` (long markdown) is the substantive description; `summary` is just the title.
	// We keep them both: summary as headline, details as body.
	const summary = (vuln.summary || "").trim();
	const details = (vuln.details || "").trim();
	let description = "";
	if (summary && details && !details.toLowerCase().startsWith(summary.toLowerCase())) {
		description = `${summary}\n\n${details}`;
	} else if (details) {
		description = details;
	} else {
		description = summary;
	}
	// Keep up to 2000 chars — enough for full advisory text without bloating the report.
	if (description.length > 2000) description = description.slice(0, 2000) + "…";
	// Categorise OSV references: ADVISORY / FIX / REPORT / WEB / PACKAGE / ARTICLE / EVIDENCE
	const refs = (vuln.references || []).map(r => ({ type: String(r.type || "WEB").toUpperCase(), url: r.url }));
	return {
		dep,
		cve: {
			id,
			severity,
			score,
			...(cvss.vector ? { cvssVector: cvss.vector } : {}),
			...(cvss.version ? { cvssVersion: `CVSS:${cvss.version}` } : {}),
			description,
			summary,
			fixVersion: fixVersionFromOsv(vuln, osvPkgName(dep), dep.version),
			...branchFixFromOsv(vuln, osvPkgName(dep), dep.version),
			ghsa: (vuln.aliases || []).find(a => a.startsWith("GHSA-")) || (vuln.id?.startsWith("GHSA-") ? vuln.id : null),
			published: vuln.published || null,
			modified: vuln.modified || null,
			osvRefs: refs,
			aliases: vuln.aliases || [],
		},
		source: "osv",
		confidence: "exact",
	};
}

const validVulnId = id => typeof id === "string" && /^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$/.test(id);
function incompleteOsv(message) {
	const error = new Error(`OSV coverage incomplete: ${message}`);
	error.code = "OSV_INCOMPLETE";
	return error;
}

// querybatch can paginate EACH query independently. An empty object is a valid
// no-findings result; a missing result, an error or an unfinished page is not.
async function fetchBatchPages(batch, fetcher) {
	const results = batch.map(() => ({ vulns: [] }));
	let pending = batch.map((query, index) => ({ query, index, seen: new Set() }));
	while (pending.length) {
		const res = await require("./providers").getResource("osv", "packages", {
			queries: pending.map(({ query }) => ({
				ecosystem: query.package.ecosystem, name: query.package.name, version: query.version,
				...(query.page_token ? { page_token: query.page_token } : {}),
			})),
		}, { fetcher, headers: { "User-Agent": "vigievuln-osv" } });
		if (!res.ok) throw incompleteOsv(`querybatch HTTP ${res.status}`);
		const data = await res.json();
		if (!Array.isArray(data?.results) || data.results.length !== pending.length)
			throw incompleteOsv("querybatch returned a missing or truncated result list");
		const next = [];
		for (let i = 0; i < pending.length; i++) {
			const item = data.results[i], slot = pending[i];
			if (!item || typeof item !== "object" || Array.isArray(item) || item.error
				|| (item.vulns !== undefined && (!Array.isArray(item.vulns) || !item.vulns.every(v => validVulnId(v?.id)))))
				throw incompleteOsv("querybatch returned an invalid result");
			results[slot.index].vulns.push(...(item.vulns || []));
			if (item.next_page_token) {
				const token = item.next_page_token;
				if (typeof token !== "string" || slot.seen.has(token) || slot.seen.size >= 1000)
					throw incompleteOsv("invalid or repeated pagination token");
				slot.seen.add(token);
				next.push({ ...slot, query: { ...slot.query, page_token: token } });
			}
		}
		pending = next;
	}
	return results;
}

async function queryBatch(deps, opts = {}) {
	const { verbose, offline, fetcher = globalThis.fetch, onProgress, cacheDir = OSV_CACHE_DIR, onWarning } = opts;
	const cacheOpts = { ignoreTtl: !!offline, cacheDir };
	const hostedFresh = !offline && require("./providers").hasHostedProxy();
	const pendingWrites = [];
	let missingPackages = 0, missingDetails = 0;
	// Build query list + parallel cached/uncached split
	const queries = [];
	const indexMap = []; // index in `deps` → either { cached: vulns } or { queryIdx: N }

	for (let i = 0; i < deps.length; i++) {
		const d = deps[i];
		const ck = cacheKey(d.groupId, d.artifactId, d.version, d.ecosystem || "maven");
		const hit = hostedFresh ? null : readCache(ck, cacheOpts);
		if (Array.isArray(hit) && hit.every(validVulnId)) {
			indexMap[i] = { cached: hit };
		} else {
			if (offline) missingPackages++;
			indexMap[i] = { queryIdx: queries.length, cacheKey: ck };
			// Ecosystem + package name are both derived from the dep's codec, so
			// adding a new ecosystem (NuGet/Packagist/PyPI) needs no change here.
			const ecosystem = osvEcosystemFor(d);
			const pkgName = osvPkgName(d);
			queries.push({
				package: { name: pkgName, ecosystem },
				version: d.version,
			});
		}
	}

	// Run batch queries for uncached deps (if any). In offline mode we skip
	// the network and rely entirely on cached per-dep ID lists.
	const allResults = new Array(queries.length);
	if (queries.length && !offline) {
		const batches = [];
		for (let i = 0; i < queries.length; i += BATCH_SIZE) {
			batches.push(queries.slice(i, i + BATCH_SIZE));
		}
		let batchIdx = 0;
		for (const batch of batches) {
			batchIdx++;
			if (onProgress) onProgress(batchIdx, batches.length);
			else if (process.stdout.isTTY) process.stdout.write(`\r   OSV batch ${batchIdx}/${batches.length} (${batch.length} deps)…                  `);
			else if (batches.length > 1) console.log(`   OSV batch ${batchIdx}/${batches.length} (${batch.length} deps)…`);
			let results;
			try { results = await fetchBatchPages(batch, fetcher); }
			catch (error) { throw error.code === "OSV_INCOMPLETE" ? error : incompleteOsv(error.message); }
			for (let j = 0; j < batch.length; j++) {
				allResults[(batchIdx - 1) * BATCH_SIZE + j] = results[j];
			}
		}
		if (onProgress) { /* finalized by caller */ }
		else if (process.stdout.isTTY) process.stdout.write(`\r   OSV batches complete (${batches.length})                          \n`);

		// Stage per-dependency lists. Do not replace the previous snapshot until
		// every page AND every referenced advisory detail has been obtained.
		for (let i = 0; i < deps.length; i++) {
			const slot = indexMap[i];
			if (slot.queryIdx != null) {
				const queryGlobalIdx = slot.queryIdx;
				const result = allResults[queryGlobalIdx];
				const ids = [...new Set((result.vulns || []).map(v => v.id))];
				pendingWrites.push([slot.cacheKey, ids]);
				slot.cached = ids;
			}
		}
	}

	// Collect every unique vuln id we need to enrich — whether it came from
	// the cached per-dep list or from a fresh batch result.
	const allIds = new Set();
	for (const slot of indexMap) for (const id of (slot.cached || [])) allIds.add(id);

	// Split cached vs live so the progress display reflects actual work and
	// detail fetches run in parallel (was silent serial — caused the
	// "stuck after OSV" symptom on large dep trees).
	const detailById = new Map();
	const liveIds = [];
	for (const id of allIds) {
		const detailCacheKey = `vuln_${id}.json`;
		const hit = hostedFresh ? null : readCache(detailCacheKey, cacheOpts);
		if (hit?.id === id) { detailById.set(id, hit); continue; }
		if (offline) { missingDetails++; continue; }
		liveIds.push(id);
	}

	if (liveIds.length) {
		if (!onProgress) console.log(`   OSV details: ${liveIds.length} to fetch${allIds.size - liveIds.length ? `, ${allIds.size - liveIds.length} cached` : ""}…`);
		const concurrency = 10;
		let cursor = 0;
		let fetched = 0;
		const failures = [];
		const startedAt = Date.now();
		const printOsvProgress = (final = false) => {
			if (onProgress) { onProgress(fetched, liveIds.length); return; }
			const elapsed = Math.round((Date.now() - startedAt) / 1000);
			const pct = Math.round((fetched / liveIds.length) * 100);
			const line = `   OSV details: ${fetched}/${liveIds.length} (${pct}%) — ${elapsed}s`;
			if (process.stdout.isTTY) process.stdout.write(`\r${line}${final ? "\n" : "          "}`);
			else if (final) console.log(line);
		};
		const workers = Array.from({ length: concurrency }, async () => {
			while (cursor < liveIds.length) {
				const id = liveIds[cursor++];
				const detailCacheKey = `vuln_${id}.json`;
				try {
					const r = await require("./providers").getResource("osv", "vuln", { id },
						{ fetcher, headers: { "User-Agent": "vigievuln-osv" } });
					if (!r.ok) throw new Error(`HTTP ${r.status}`);
					const body = await r.json();
					if (body?.id !== id) throw new Error("invalid advisory detail");
					detailById.set(id, body);
					writeCache(detailCacheKey, body, { cacheDir });
				} catch (error) { failures.push(`${id}: ${error.message}`); }
				fetched++;
				if (fetched % 5 === 0 || fetched === liveIds.length) printOsvProgress();
			}
		});
		await Promise.all(workers);
		printOsvProgress(true);
		if (failures.length) throw incompleteOsv(`${failures.length} advisory detail(s) unavailable (${failures[0]})`);
	}

	for (const [key, ids] of pendingWrites) writeCache(key, ids, { cacheDir });
	if (missingPackages || missingDetails) onWarning?.({
		type: "osv-coverage",
		message: `Offline OSV cache incomplete: ${missingPackages} package/version lookup(s) and ${missingDetails} advisory detail(s) unavailable. Missing data is not evidence of no vulnerabilities; warm the cache online.`,
	});
	return runMatches(deps, indexMap, detailById);
}

function runMatches(deps, indexMap, detailById) {
	const matches = [];
	for (let i = 0; i < deps.length; i++) {
		const slot = indexMap[i];
		const ids = slot.cached || [];
		const dep = deps[i];
		for (const id of ids) {
			const vuln = detailById instanceof Map ? detailById.get(id) : null;
			if (!vuln) {
				// Stub-only (id known but no details fetched yet). Skip rather
				// than emit a descriptionless UNKNOWN-severity placeholder:
				// such stubs were FP-prone because the local cache key is
				// (g, a, v) but the underlying advisory may no longer apply
				// to a version upgraded since cache build. M2 in CRITICAL-REVIEW.md.
				continue;
			}
			matches.push(vulnToMatch(dep, vuln));
		}
	}
	return matches;
}

/**
 * Public: query OSV for every dep in `resolvedDeps` Map, return vigievuln-shape matches.
 */
async function queryOsvForDeps(resolvedDeps, opts = {}) {
	const deps = [];
	for (const d of resolvedDeps.values()) {
		if (d.scope === "parent") continue; // parents don't have OSV entries typically
		// Query every distinct concrete version (e.g. two profiles pinning the
		// same g:a), not just the representative highest — otherwise a vuln that
		// only affects a lower-versioned variant would be missed.
		const versions = (d.versions && d.versions.length) ? d.versions : [d.version];
		for (const ver of versions) {
			if (!ver || /\$\{|SNAPSHOT/i.test(ver)) continue;
			// npm version specifiers like "^1.0.0" can't be queried against OSV —
			// need a concrete version. Lockfiles always provide one; package.json-
			// only deps are skipped here.
			if (d.ecosystem === "npm" && /^[\^~>=<*]|^(latest|next|workspace:|git\+|file:|link:)/.test(ver)) continue;
			// Spread the whole depRecord (carries namespace/name/coordKey, which the
			// codec's osvPackageName + the report's dedup rely on) and override only
			// the version for this per-version query. Cherry-picking fields here used
			// to drop name/namespace → OSV queried `undefined` for composer/pypi/nuget.
			deps.push({ ...d, version: ver });
		}
	}
	return queryBatch(deps, opts);
}

module.exports = {
	cacheKey,
	queryOsvForDeps,
	queryBatch,
	vulnToMatch,
	severityFromOsv,
	fixVersionFromOsv,
	osvEcosystemFor,
	osvPkgName,
	OSV_CACHE_DIR,
};
