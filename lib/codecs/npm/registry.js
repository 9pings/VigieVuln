/**
 * lib/npm/registry.js — npm registry queries for the npm half of the
 * EOL/obsolete/outdated story.
 *
 * Two authoritative, online signals come from one packument fetch:
 *   - deprecated: the maintainer's `deprecated` string on the *resolved*
 *     version (the same data behind `npm WARN deprecated …`).
 *   - outdated:   `dist-tags.latest` vs. the resolved version.
 *
 * The point of querying the registry rather than a curated list is to skip
 * nothing: every npm dep is checked against the source of truth.
 *
 * `packumentToFindings` is the pure extractor (unit-tested without network);
 * `checkNpmRegistryDeps` is the cached, concurrent driver.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { foldAbsent } = require("../../private-deps");
const path = require("path");
const os = require("os");
const pLimit = require("p-limit");
const { semverCompare, webjarToNpm } = require("./collect");
const { withPublic, authHeaderFor, normalise } = require("../../registries");

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
const CACHE_PATH = path.join(CACHE_DIR, "npm-registry-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000; // 1 day, aligned with Maven Central

function loadCache() {
	try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); }
	catch { return { meta: { fetchedAt: 0 }, entries: {} }; }
}

function saveCache(data) {
	try {
		fs.mkdirSync(CACHE_DIR, { recursive: true });
		fs.writeFileSync(CACHE_PATH, JSON.stringify(data));
	} catch { /* ignore */ }
}

/** Pull a recommended replacement out of a free-form deprecation message. */
function replacementFromMessage(msg) {
	if (!msg) return null;
	const url = msg.match(/https?:\/\/\S+/);
	if (url) return url[0].replace(/[).,]+$/, "");
	return "see deprecation notice";
}

/**
 * Extract { deprecated, outdated } findings for one dep from its packument.
 * Pure — no network, no cache. Either field is null when not applicable.
 */
function packumentToFindings(packument, dep) {
	const out = { deprecated: null, outdated: null, license: null };
	if (!packument || typeof packument !== "object") return out;

	const versionEntry = packument.versions?.[dep.version];
	// License: prefer the resolved version's field, fall back to the packument root.
	const lic = versionEntry?.license ?? versionEntry?.licenses ?? packument.license ?? packument.licenses;
	if (lic) out.license = lic;
	const depMsg = versionEntry && typeof versionEntry.deprecated === "string"
		? versionEntry.deprecated.trim()
		: "";
	if (depMsg) {
		out.deprecated = {
			dep,
			severity: "MEDIUM",
			replacement: replacementFromMessage(depMsg),
			reason: depMsg,
			source: "npm",
		};
	}

	const latest = packument["dist-tags"]?.latest;
	if (latest && dep.version) {
		let behind = false;
		try { behind = semverCompare(dep.version, latest) < 0; }
		catch { behind = false; }
		if (behind) {
			const t = packument.time?.[latest];
			out.outdated = {
				dep,
				latest,
				releaseDate: typeof t === "string" ? t.slice(0, 10) : null,
			};
		}
	}
	return out;
}

/** registry path-encodes a scoped name's slash. */
function encodeName(name) {
	return name.startsWith("@") ? name.replace("/", "%2F") : encodeURIComponent(name);
}

/**
 * Fetch a packument, trying each custom registry first (with per-registry auth),
 * then the public registry.npmjs.org as the final fallback. Returns the parsed
 * packument, or { error } if every base failed.
 */
async function fetchPackument(name, opts = {}) {
	if (opts.offline) return null;
	const timeoutMs = opts.timeoutMs || 15000;
	const fetcher = opts.fetcher || globalThis.fetch;
	const bases = withPublic("npm", opts.registries || []);
	const enc = encodeName(name);
	let lastErr = null;
	const statuses = [];   // one per base: HTTP status, or null for a non-answer
	for (const base of bases) {
		// Per-request timeout: a single stalled connection must never hang the
		// whole run (one slow package would otherwise occupy a concurrency slot
		// forever and starve the pool).
		const url = normalise(base.url) + enc;
		const headers = { "User-Agent": "fad-checker-npm-registry", Accept: "application/json" };
		const ah = authHeaderFor(base);
		if (ah) headers.Authorization = ah;
		try {
			const res = await require("../../providers").getResource("npm", "package", { name },
				{ fetcher, headers, signal: AbortSignal.timeout(timeoutMs),
					...(base.name === "public" ? {} : { urlOverride: url, direct: true }) });
			if (res.ok) return await res.json();
			lastErr = `HTTP ${res.status}`;
			statuses.push(res.status);
		} catch (err) {
			lastErr = err.name === "TimeoutError" ? `timeout after ${timeoutMs}ms` : err.message;
			statuses.push(null);
		}
	}
	return { error: lastErr || "no data", absent: foldAbsent(statuses) };
}

/**
 * Check every npm dep against the registry.
 *
 * Returns { deprecated: [obsolete-shaped], outdated: [outdated-shaped] }.
 * Deprecation always runs (online); outdated is only collected when allLibs
 * is set, mirroring the Maven Central outdated gate (--no-all-libs).
 *
 * opts: { verbose, offline, allLibs, concurrency = 8 }
 */
async function checkNpmRegistryDeps(resolvedDeps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8, onProgress, registries = [] } = opts;
	// Targets = npm deps (queried by their own name) + WebJars (queried by their
	// derived npm-equivalent name; version matches upstream). The original dep
	// is kept for display/results so the report shows e.g. org.webjars:angularjs.
	const targets = [];
	for (const d of resolvedDeps.values()) {
		if (!d.version) continue;
		if (d.ecosystem === "npm") { targets.push({ dep: d, npmName: d.artifactId, version: d.version }); continue; }
		const wj = webjarToNpm(d);
		if (wj?.name) targets.push({ dep: d, npmName: wj.name, version: d.version });
	}
	const result = { deprecated: [], outdated: [], licensed: [], private: [] };
	if (!targets.length) return result;

	const cache = loadCache();
	const fresh = cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};

	const cacheKey = t => `${t.npmName}@${t.version}`;
	const liveCount = offline ? 0 : targets.filter(t => !cache.entries[cacheKey(t)]).length;
	if (liveCount && !offline && !onProgress) {
		console.log(`📦 npm registry: checking ${targets.length} packages for deprecation${allLibs ? " + outdated" : ""} (${liveCount} live, ${targets.length - liveCount} cached)…`);
	}

	// Incremental progress — fetching ~hundreds/thousands of packuments at
	// concurrency N would otherwise be total silence for a minute or more.
	let processed = 0;
	const startedAt = Date.now();
	const printProgress = (final = false) => {
		if (onProgress) { onProgress(processed, targets.length); return; }
		if (!liveCount) return;
		const elapsed = Math.round((Date.now() - startedAt) / 1000);
		const pct = Math.round((processed / targets.length) * 100);
		const line = `   npm registry: ${processed}/${targets.length} (${pct}%) — ${elapsed}s`;
		if (process.stdout.isTTY) process.stdout.write(`\r${line}${final ? "\n" : "          "}`);
		else if (final) console.log(line);
	};

	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const { dep, npmName, version } = t;
		const key = cacheKey(t);
		let extracted = cache.entries[key];
		if (!extracted) {
			const packument = await fetchPackument(npmName, { offline, registries });
			if (packument && !packument.error) {
				const f = packumentToFindings(packument, { version });
				extracted = {
					deprecated: f.deprecated ? { reason: f.deprecated.reason, replacement: f.deprecated.replacement } : null,
					latest: f.outdated ? f.outdated.latest : null,
					latestDate: f.outdated ? f.outdated.releaseDate : null,
					license: f.license || null,
				};
				cache.entries[key] = extracted;
			} else {
				extracted = { deprecated: null, latest: null, latestDate: null, error: packument?.error || "no data", absent: packument?.absent === true };
				if (!offline) cache.entries[key] = extracted;
			}
		}
		processed++;
		printProgress();
		// Absent from EVERY configured registry: an internal package. Only a definitive
		// 404/410 from all of them gets here — a timeout leaves it unknown and silent.
		if (extracted.absent) result.private.push({ dep: dep, ecosystem: "npm" });
		if (extracted.deprecated) {
			result.deprecated.push({
				dep,
				severity: "MEDIUM",
				replacement: extracted.deprecated.replacement,
				reason: extracted.deprecated.reason,
				source: "npm",
			});
			if (verbose) process.stdout.write(`  deprecated: ${npmName}@${version}\n`);
		}
		if (allLibs && extracted.latest) {
			result.outdated.push({ dep, latest: extracted.latest, releaseDate: extracted.latestDate || null });
			if (verbose) process.stdout.write(`  outdated: ${npmName} ${version} → ${extracted.latest}\n`);
		}
		if (extracted.license) result.licensed.push({ dep, licenses: extracted.license, source: "npm" });
	})));
	if (liveCount) printProgress(true);

	if (!offline) {
		if (!fresh) cache.meta = { fetchedAt: Date.now() };
		saveCache(cache);
	}

	result.deprecated.sort((a, b) => a.dep.artifactId.localeCompare(b.dep.artifactId));
	result.outdated.sort((a, b) => a.dep.artifactId.localeCompare(b.dep.artifactId));
	if (liveCount && !offline && !onProgress) console.log(`   npm registry: ${result.deprecated.length} deprecated, ${result.outdated.length} outdated`);
	return result;
}

module.exports = { packumentToFindings, checkNpmRegistryDeps, replacementFromMessage, fetchPackument };
