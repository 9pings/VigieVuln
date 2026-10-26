/**
 * lib/maven-repo.js — fan-out HTTP fetcher across the user's configured
 * Maven repositories with Maven Central as a final fallback.
 *
 * Use cases:
 *   - Fetching a transitive POM (lib/transitive.js)
 *   - Checking whether an artifact exists at all (HEAD)
 *   - Reading <maven-metadata.xml> for latest-version discovery
 *     (lib/outdated.js)
 *
 * Repository entry shape (from ~/.fad-checker/config.json or CLI):
 *   { name?, url, auth? }   auth = "user:pass" (we wrap as Basic <base64>)
 *
 * URL convention: each repo URL must end at the directory under which Maven
 * artifacts are laid out the standard way:
 *   <repo-url>/<groupId-with-/>/<artifactId>/<version>/<artifactId>-<version>.pom
 *
 * The first 2xx wins. Misses are silently aggregated; the caller decides
 * what to do with "not found anywhere".
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const MAVEN_CENTRAL = { name: "central", url: "https://repo1.maven.org/maven2/", central: true };

/**
 * The mirrors Maven itself lists, and only those:
 * https://repo.maven.apache.org/maven2/.meta/repository-metadata.xml — every other entry in
 * that file (ibiblio, uk.maven.org, cica.es, netcologne) is commented out, i.e. retired.
 *
 * They are used to spread metadata lookups, which run once per dependency and otherwise all
 * land on the same host. They are NOT an authority: Maven's own guide says "these mirrors may
 * not have the same contents and we don't support them in any way", and Google syncs 12×/day
 * (Americas) and 4×/day (EU, Asia) without claiming completeness. A few hours of lag cannot
 * change whether a dependency is outdated in any way that matters, and Central stays in the
 * list behind them, so a coordinate a mirror lacks still resolves.
 */
const DEFAULT_CENTRAL_MIRRORS = [
	{ name: "google-maven-central", url: "https://maven-central.storage-download.googleapis.com/maven2/", central: true, mirror: true },
	{ name: "google-maven-central-eu", url: "https://maven-central-eu.storage-download.googleapis.com/maven2/", central: true, mirror: true },
	{ name: "google-maven-central-ap", url: "https://maven-central-asia.storage-download.googleapis.com/maven2/", central: true, mirror: true },
];

/**
 * Per-run health of the repository list. A mirror that stops answering must not be retried on
 * every remaining coordinate — on a 400-dependency reactor that is 400 timeouts.
 *
 * Only MIRRORS are eligible. A mirror is redundant by construction (Central sits behind it in
 * the same list), so dropping one loses nothing. Dropping Central, or a private repository,
 * would silently turn a transient blip into a coverage hole for the rest of the scan — and a
 * missing private artifact is exactly the finding an audit is there to produce.
 */
function createRepoHealth() {
	const down = new Map();
	return {
		isDown: url => down.has(url),
		markDown(repo, reason) {
			if (!repo || !repo.mirror || down.has(repo.url)) return false;
			down.set(repo.url, { name: repo.name, url: repo.url, reason });
			return true;
		},
		downList: () => [...down.values()],
	};
}

const defaultRepoHealth = createRepoHealth();

/** 32-bit FNV-1a. Deterministic across runs and platforms — a re-scan must query the same host. */
function hashKey(str) {
	let h = 0x811c9dc5;
	for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
	return h >>> 0;
}

/**
 * Private repositories keep their configured order and stay in front — that contract is what
 * makes an internal artifact resolve internally. The Central block behind them is rotated by a
 * hash of the lookup key so consecutive coordinates land on different hosts, while the same
 * coordinate always lands on the same one (an audit re-run has to be reproducible).
 */
function orderRepos(repos, key) {
	const list = repos || [];
	if (!key) return list.slice();
	const head = list.filter(r => !r.central);
	const block = list.filter(r => r.central);
	if (block.length < 2) return [...head, ...block];
	const off = hashKey(String(key)) % block.length;
    return [...head, ...block.slice(off), ...block.slice(0, off)];
}

function normalise(url) {
	if (!url) return url;
	return url.endsWith("/") ? url : url + "/";
}

/**
 * Parse user:pass embedded in a URL (e.g. https://alice:s3cr3t@nexus.acme/...)
 * Returns { url, auth } where auth is "user:pass" stripped of the URL part.
 */
function splitUrlAuth(url) {
	if (!url) return { url, auth: null };
	try {
		const u = new URL(url);
		if (u.username || u.password) {
			const auth = decodeURIComponent(u.username) + ":" + decodeURIComponent(u.password);
			u.username = ""; u.password = "";
			return { url: u.toString(), auth };
		}
	} catch { /* not a URL — return as-is */ }
	return { url, auth: null };
}

/**
 * Build the effective repository list: user-configured + extras (from --repo
 * CLI) + Maven Central as final fallback. Dedupes by URL.
 */
function buildRepoList(userRepos, extraRepos = [], { mirrors = true } = {}) {
	const out = [];
	const seen = new Set();
	const push = r => {
		if (!r?.url) return;
		const { url, auth } = splitUrlAuth(normalise(r.url));
		if (seen.has(url)) return;
		seen.add(url);
		out.push({ name: r.name || url, url, auth: r.auth || auth || null, token: r.token || null,
			central: !!r.central, mirror: !!r.mirror });
	};
	for (const r of userRepos || []) push(r);
	for (const r of extraRepos || []) push(r);
	push(MAVEN_CENTRAL);
	if (mirrors) for (const m of DEFAULT_CENTRAL_MIRRORS) push(m);
	return out;
}

function authHeader(auth) {
	if (!auth) return null;
	return "Basic " + Buffer.from(auth).toString("base64");
}

function repoAuthHeader(repo) {
	return repo.token ? `Bearer ${repo.token}` : authHeader(repo.auth);
}

/**
 * Try fetching `pathSuffix` (relative to each repo URL) from every repo
 * in order. Returns the first 2xx response as { repo, response, body? }.
 *
 * opts:
 *   method     "GET" (default) | "HEAD"
 *   fetcher    custom fetch (for tests)
 *   readBody   read response.text() into body (default false to save mem
 *              on HEAD calls; transitive.js sets true for POMs)
 *   userAgent  default "vigievuln-maven-repo"
 *   onMiss     callback(repo, status) for telemetry (verbose mode)
 *   timeoutMs  per-request abort deadline (default DEFAULT_TIMEOUT_MS). A request
 *              against a blackholed route (offline VM, firewalled proxy) otherwise
 *              hangs for the OS TCP timeout — minutes of silence per repo.
 */
const DEFAULT_TIMEOUT_MS = 20000;

/**
 * Run `fn(signal)` under an abort deadline. An explicit AbortController + a
 * setTimeout cleared on settle — NOT AbortSignal.timeout(), whose timer is
 * unref'd: with nothing else keeping the loop alive (a test's fake fetcher,
 * a bun build) the process could exit before the deadline ever fires.
 */
async function withDeadline(timeoutMs, fn) {
	if (!timeoutMs) return fn(undefined);
	const ac = new AbortController();
	const timer = setTimeout(() => ac.abort(new Error(`timeout after ${timeoutMs} ms`)), timeoutMs);
	try { return await fn(ac.signal); }
	finally { clearTimeout(timer); }
}

async function tryRepos(repos, pathSuffix, opts = {}) {
	const { method = "GET", fetcher = globalThis.fetch, readBody = false, userAgent = "vigievuln-maven-repo", onMiss, timeoutMs = DEFAULT_TIMEOUT_MS, health = defaultRepoHealth, key = null } = opts;
	// Why tracked here and not by lib/source-health.js's fetch guard: these requests carry
	// our own AbortSignal, so the guard passes them straight through (it must not retry
	// inside our deadline, nor in front of this failover). Exhausting the rotation without
	// one host answering is the coverage hole, and only this loop knows it happened.
	const misses = [];
	let firstUrl = null;
	for (const repo of orderRepos(repos, key)) {
		if (health && health.isDown(repo.url)) continue;
		const url = repo.url + pathSuffix.replace(/^\//, "");
		if (!firstUrl) firstUrl = url;
		const headers = { "User-Agent": userAgent };
		const ah = repoAuthHeader(repo);
		if (ah) headers.Authorization = ah;
		let r;
		try {
			r = await withDeadline(timeoutMs, signal => require("./providers").getResource("maven", "artifact",
				{ path: pathSuffix.replace(/^\/+/, ""), method },
				{ fetcher, headers, signal, ...(url === `https://repo1.maven.org/maven2/${pathSuffix.replace(/^\/+/, "")}`
					? {} : { urlOverride: url, direct: true }) }));
		} catch (err) {
			// Unreachable or timed out: a mirror that does this once will do it for every
			// remaining coordinate, so take it out of the rotation for the run.
			if (health) health.markDown(repo, err.message);
			misses.push(`network: ${err.message}`);
			if (onMiss) onMiss(repo, `network: ${err.message}`);
			continue;
		}
		if (r.ok) {
			let body = null;
			if (readBody && method !== "HEAD") {
				try { body = await r.text(); } catch { /* ignore body read fail */ }
			}
			return { repo, response: r, body, url };
		}
		// 404 means "this repo does not hold that artifact", which is normal and says nothing
		// about its health. Rate limiting and server errors do: stop asking this mirror.
		if (r.status === 429 || r.status >= 500) { if (health) health.markDown(repo, `HTTP ${r.status}`); }
		misses.push(`HTTP ${r.status}`);
		if (onMiss) onMiss(repo, `HTTP ${r.status}`);
	}
	if (firstUrl) require("./source-health").noteFanoutExhausted(firstUrl, misses);
	return null;
}

/**
 * Keep only the repositories that ANSWER at all. One HEAD on each repo root, in
 * parallel, bounded by timeoutMs: any HTTP status (200, 401, 404, …) proves the
 * host is reachable; a network error or a timeout drops the repo. Used as a
 * preflight before fanning out 100+ existence probes on a box that turned out to
 * be offline (no --offline flag) — one bounded wait instead of one per coord.
 *
 * opts: fetcher (tests), timeoutMs (default 5000), userAgent
 */
async function reachableRepos(repos, opts = {}) {
	const { fetcher = globalThis.fetch, timeoutMs = 5000, userAgent = "vigievuln-preflight" } = opts;
	const checks = (repos || []).map(async repo => {
		const headers = { "User-Agent": userAgent };
		const ah = repoAuthHeader(repo);
		if (ah) headers.Authorization = ah;
		try {
			await withDeadline(timeoutMs, signal => require("./providers").getResource("maven", "preflight", {},
				{ fetcher, headers, signal, urlOverride: repo.url, direct: true }));
			return repo;
		} catch {
			return null;
		}
	});
	return (await Promise.all(checks)).filter(Boolean);
}

/** Convenience: HEAD an artifact (any of the listed repos) to check existence. */
function existsInAny(repos, pathSuffix, opts = {}) {
	return tryRepos(repos, pathSuffix, { ...opts, method: "HEAD" });
}

/** Convenience: GET a POM (text/xml) — sets readBody=true. */
function fetchPomFromRepos(repos, groupId, artifactId, version, opts = {}) {
	const p = `${groupId.replace(/\./g, "/")}/${artifactId}/${version}/${artifactId}-${version}.pom`;
	return tryRepos(repos, p, { ...opts, method: "GET", readBody: true });
}

/** Convenience: GET maven-metadata.xml (for latest-version discovery). */
function fetchMavenMetadata(repos, groupId, artifactId, opts = {}) {
	if (opts.key === undefined) opts = { ...opts, key: `${groupId}:${artifactId}` };
	const p = `${groupId.replace(/\./g, "/")}/${artifactId}/maven-metadata.xml`;
	return tryRepos(repos, p, { ...opts, method: "GET", readBody: true });
}

module.exports = {
	MAVEN_CENTRAL,
	DEFAULT_CENTRAL_MIRRORS,
	orderRepos,
	createRepoHealth,
	defaultRepoHealth,
	DEFAULT_TIMEOUT_MS,
	buildRepoList,
	tryRepos,
	reachableRepos,
	existsInAny,
	fetchPomFromRepos,
	fetchMavenMetadata,
	splitUrlAuth,
	authHeader,
};
