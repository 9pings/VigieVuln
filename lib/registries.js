/**
 * lib/registries.js — per-ecosystem registry list assembly + auth + fan-out.
 *
 * Generalizes lib/maven-repo.js's list-building to npm/pypi/ruby/go. Custom
 * registries are tried first (declared order); callers append the public base
 * last via withPublic(). Lists are unioned across config layers, deduped by URL.
 *
 * Entry shape: { name?, url, auth?, token? }
 *   auth  "user:pass" → Authorization: Basic <base64>
 *   token "…"         → Authorization: Bearer <token>
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const SUPPORTED = ["maven", "npm", "pypi", "ruby", "go", "nuget", "composer"];

const PUBLIC_BASES = {
	maven: "https://repo1.maven.org/maven2/",
	npm: "https://registry.npmjs.org/",
	pypi: "https://pypi.org/pypi/",
	ruby: "https://rubygems.org/api/v1/gems/",
	go: "https://proxy.golang.org/",
	// NuGet: the public v3 registration base (each fetch appends "<lowerid>/index.json").
	nuget: "https://api.nuget.org/v3/registration5-gz-semver2/",
	// Composer: the Packagist root (the public path is "packages/<name>.json"; custom
	// feeds are queried via the v2 "p2/<name>.json" metadata API — see composer/registry.js).
	composer: "https://packagist.org/",
};

function normalise(url) {
	if (!url) return url;
	return url.endsWith("/") ? url : url + "/";
}

function splitUrlAuth(url) {
	if (!url) return { url, auth: null };
	try {
		const u = new URL(url);
		if (u.username || u.password) {
			const auth = decodeURIComponent(u.username) + ":" + decodeURIComponent(u.password);
			u.username = ""; u.password = "";
			return { url: u.toString(), auth };
		}
	} catch { /* not a URL */ }
	return { url, auth: null };
}

function authHeaderFor(entry) {
	if (!entry) return null;
	if (entry.token) return "Bearer " + entry.token;
	if (entry.auth) return "Basic " + Buffer.from(entry.auth).toString("base64");
	return null;
}

/** Union of registry entries from several layers (arrays). Dedup by URL, first wins. */
function buildRegistryList(_ecosystem, layers = []) {
	const out = [];
	const seen = new Set();
	for (const layer of layers) {
		for (const r of layer || []) {
			if (!r?.url) continue;
			const { url, auth } = splitUrlAuth(normalise(r.url));
			if (seen.has(url)) continue;
			seen.add(url);
			out.push({ name: r.name || url, url, auth: r.auth || auth || null, token: r.token || null });
		}
	}
	return out;
}

/** Append the ecosystem's public base (no auth) as the final fallback. */
function withPublic(ecosystem, list) {
	const pub = PUBLIC_BASES[ecosystem];
	const out = [...(list || [])];
	if (pub && !out.some(r => normalise(r.url) === pub)) out.push({ name: "public", url: pub, auth: null, token: null });
	return out;
}

/** Merge two registry maps (eco → entries[]) into one (concat per eco). */
function mergeRegistryMaps(...maps) {
	const out = {};
	for (const m of maps) {
		if (!m || typeof m !== "object") continue;
		for (const eco of Object.keys(m)) {
			if (!Array.isArray(m[eco])) continue;
			out[eco] = (out[eco] || []).concat(m[eco]);
		}
	}
	return out;
}

/**
 * Try each base in order; return the first response whose `res.ok` is true,
 * as { res, base, url }. Applies per-base auth. opts.fetcher for tests.
 */
async function fetchFirstOk(bases, buildUrl, opts = {}) {
	const { fetcher = globalThis.fetch, userAgent = "vigievuln", timeoutMs, onMiss } = opts;
	// See lib/maven-repo.js#tryRepos: these carry our own AbortSignal, so the fetch guard
	// leaves them alone and this loop reports its own exhaustion. A 404 from every base is
	// an ANSWER (that is how an internal package is detected), not an outage.
	const misses = [];
	let firstUrl = null;
	for (const base of bases) {
		const url = buildUrl(normalise(base.url));
		if (!firstUrl) firstUrl = url;
		const headers = { "User-Agent": userAgent, Accept: "application/json" };
		const ah = authHeaderFor(base);
		if (ah) headers.Authorization = ah;
		let res;
		try {
			res = await fetcher(url, { headers, ...(timeoutMs ? { signal: AbortSignal.timeout(timeoutMs) } : {}) });
		} catch (err) { misses.push(`network: ${err.message}`); if (onMiss) onMiss(base, `network: ${err.message}`); continue; }
		if (res.ok) return { res, base, url };
		misses.push(`HTTP ${res.status}`);
		if (onMiss) onMiss(base, `HTTP ${res.status}`);
	}
	if (firstUrl) require("./source-health").noteFanoutExhausted(firstUrl, misses);
	return null;
}

module.exports = {
	SUPPORTED, PUBLIC_BASES,
	normalise, splitUrlAuth, authHeaderFor,
	buildRegistryList, withPublic, mergeRegistryMaps, fetchFirstOk,
};
