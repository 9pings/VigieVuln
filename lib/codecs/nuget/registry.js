/**
 * lib/nuget/registry.js — query the NuGet registration index for a package's
 * latest stable version and per-version deprecation.
 *
 * API: https://api.nuget.org/v3/registration5-gz-semver2/{lowerid}/index.json
 *   → { items: [ { items: [ { catalogEntry: { version, deprecation } } ] } ] }
 *
 * Cached in ~/.fad-checker/nuget-cache.json for 24h.
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
const CACHE_PATH = path.join(CACHE_DIR, "nuget-cache.json");
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

// Walk a registration index (inline items) → { outdated, deprecated }.
function nugetRegistrationToFindings(reg, { version }) {
	const entries = [];
	for (const page of reg.items || []) for (const leaf of page.items || []) if (leaf.catalogEntry) entries.push(leaf.catalogEntry);
	const out = { outdated: null, deprecated: null, license: null };
	const stable = entries.map(e => e.version).filter(isStable);
	if (stable.length) { const latest = stable.sort(cmp).at(-1); if (latest && cmp(latest, version) > 0) out.outdated = { latest }; }
	const mine = entries.find(e => String(e.version) === String(version));
	if (mine?.deprecation) out.deprecated = { reason: (mine.deprecation.reasons || []).join(", ") || "deprecated", replacement: mine.deprecation.alternatePackage?.id || null };
	// Modern packages expose an SPDX licenseExpression; older ones only a licenseUrl (→ unknown).
	const licEntry = mine || entries.at(-1);
	if (licEntry?.licenseExpression) out.license = licEntry.licenseExpression;
	return out;
}

// A NuGet v3 service index (…/index.json) lists resources; the registration base is
// the resource whose @type starts with "RegistrationsBaseUrl" (prefer a gz/semver2
// variant). A configured base that is NOT a service index is treated as a
// registration base directly. Resolved bases are memoised for the process lifetime.
const _regBaseMemo = new Map();
async function resolveRegistrationBase(base, fetcher, headers) {
	const raw = String(base.url || "");
	if (!/index\.json\/?$/i.test(raw)) return normalise(raw);
	const url = raw.replace(/\/$/, "");
	if (_regBaseMemo.has(url)) return _regBaseMemo.get(url);
	let resolved = null;
	try {
		const res = await require("../../providers").getResource("nuget", "service-index", {},
			{ fetcher, headers, ...(url === "https://api.nuget.org/v3/index.json" ? {} : { urlOverride: url, direct: true }) });
		if (res.ok) {
			const idx = await res.json();
			const resources = idx.resources || [];
			const pick = resources.find(r => /^RegistrationsBaseUrl\/.*(gz|semver2)/i.test(r["@type"]))
				|| resources.find(r => String(r["@type"] || "").startsWith("RegistrationsBaseUrl"));
			if (pick && pick["@id"]) resolved = normalise(pick["@id"]);
		}
	} catch { /* fall through → null */ }
	_regBaseMemo.set(url, resolved);
	return resolved;
}

// Packages with many versions ship a PAGED registration index: pages carry an
// "@id" URL + [lower, upper] range instead of inline items. Without fetching
// them, deprecation/outdated came back silently empty for exactly the popular
// packages (Newtonsoft.Json, Serilog, …). Fetch only what the findings need:
// the LAST page (latest version) and the page whose range covers `version`.
async function inlineNeededPages(reg, version, fetcher, headers) {
	const pages = reg.items || [];
	const need = new Set();
	const last = pages[pages.length - 1];
	if (last && !Array.isArray(last.items) && last["@id"]) need.add(last);
	for (const p of pages) {
		if (Array.isArray(p.items) || !p["@id"]) continue;
		if (version && p.lower != null && p.upper != null && cmp(version, p.lower) >= 0 && cmp(version, p.upper) <= 0) need.add(p);
	}
	await Promise.all([...need].map(async p => {
		try { const parsed = new URL(p["@id"]); const r = await require("../../providers").getResource("nuget", "registration-page",
			{ path: parsed.pathname }, { fetcher, headers,
				...(parsed.hostname === "api.nuget.org" ? {} : { urlOverride: p["@id"], direct: true }) });
			if (r.ok) { const j = await r.json(); if (Array.isArray(j.items)) p.items = j.items; } }
		catch { /* page stays un-inlined — findings degrade, don't fail */ }
	}));
}

// Custom registries first (NuGet v3 registration API: <regBase>/<lowerid>/index.json),
// then api.nuget.org. A service-index base is resolved to its RegistrationsBaseUrl.
async function fetchRegistration(name, { offline, version = null, registries = [], fetcher = globalThis.fetch } = {}) {
	if (offline) return null;
	const id = name.toLowerCase();
	const bases = withPublic("nuget", registries);
	let lastErr = null;
	const statuses = [];   // one per base: HTTP status, or null for a non-answer
	for (const base of bases) {
		const headers = { "User-Agent": "vigievuln-nuget", Accept: "application/json" };
		const ah = authHeaderFor(base); if (ah) headers.Authorization = ah;
		let regBase;
		try { regBase = await resolveRegistrationBase(base, fetcher, headers); }
		catch (e) { lastErr = e.message; statuses.push(null); continue; }
		if (!regBase) { lastErr = "no registration base"; statuses.push(null); continue; }
		try {
			const url = `${regBase}${id}/index.json`;
			const res = await require("../../providers").getResource("nuget", "registration", { name: id },
				{ fetcher, headers, ...(url === `https://api.nuget.org/v3/registration5-gz-semver2/${id}/index.json`
					? {} : { urlOverride: url, direct: true }) });
			if (res.ok) {
				const reg = await res.json();
				await inlineNeededPages(reg, version, fetcher, headers);
				return reg;
			}
			lastErr = `HTTP ${res.status}`;
			statuses.push(res.status);
		} catch (e) { lastErr = e.message; }
	}
	return { error: lastErr || "no data", absent: foldAbsent(statuses) };
}

// Mirror of checkNpmRegistryDeps: returns { deprecated:[], outdated:[] }.
async function checkNugetRegistryDeps(deps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8, registries = [], fetcher } = opts;
	const targets = [...deps.values()].filter(d => d.ecosystem === "nuget" && d.version);
	const result = { deprecated: [], outdated: [], licensed: [], private: [] };
	if (!targets.length) return result;
	const cache = loadCache();
	const fresh = (offline || !require("../../providers").hasHostedProxy()) && cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const key = `${t.name.toLowerCase()}@${t.version}`;
		let ex = cache.entries[key];
		if (!ex) {
			const reg = await fetchRegistration(t.name, { offline, version: t.version, registries, ...(fetcher ? { fetcher } : {}) });
			if (reg && !reg.error) {
				const f = nugetRegistrationToFindings(reg, { version: t.version });
				ex = { deprecated: f.deprecated, latest: f.outdated?.latest || null, license: f.license || null };
				cache.entries[key] = ex;
			} else {
				ex = { deprecated: null, latest: null, license: null, absent: reg?.absent === true };
			}
		}
		// Absent from EVERY configured registry: an internal package. Only a definitive
		// 404/410 from all of them gets here — a timeout leaves it unknown and silent.
		if (ex.absent) result.private.push({ dep: t, ecosystem: "nuget" });
		if (ex.license) result.licensed.push({ dep: t, licenses: ex.license, source: "nuget" });
		if (ex.deprecated) {
			result.deprecated.push({ dep: t, severity: "MEDIUM", replacement: ex.deprecated.replacement, reason: ex.deprecated.reason, source: "nuget" });
			if (verbose) process.stdout.write(`  deprecated: ${t.name}@${t.version}\n`);
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

module.exports = { nugetRegistrationToFindings, checkNugetRegistryDeps, fetchRegistration, resolveRegistrationBase };
