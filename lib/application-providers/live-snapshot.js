/**
 * Live advisory-source clients and the atomic snapshot cache.
 * The Drupal endpoint is the one announced by the official packages.drupal.org
 * Composer descriptor; the Wordfence v3 production-feed URL and bearer
 * authentication follow the vendor's published API documentation.
 */
const { responseFetchedAt } = require("../providers/common");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { indexFeed } = require("./wordfence-v3");
const { validateSnapshot: validateGithubAdvisories } = require("./github-advisories");
const { validateChecksums } = require("./wp-checksums");

const DRUPAL_ADVISORIES_URL = "https://packages.drupal.org/8/security-advisories";
const WORDFENCE_PRODUCTION_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production";
const GITHUB_ADVISORIES_URL = "https://api.github.com/repos/";
const PRESTASHOP_GITHUB_ADVISORIES_URL = `${GITHUB_ADVISORIES_URL}PrestaShop/PrestaShop/security-advisories`;
const TYPO3_GITHUB_ADVISORIES_URL = `${GITHUB_ADVISORIES_URL}TYPO3/typo3/security-advisories`;
const MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024;

async function responseJson(response, label) {
	if (!response || !response.ok) throw new Error(`${label} request failed with HTTP ${response?.status ?? "unknown"}`);
	const text = await response.text();
	if (Buffer.byteLength(text) > MAX_SNAPSHOT_BYTES) throw new Error(`${label} response exceeds ${MAX_SNAPSHOT_BYTES} bytes`);
	let body;
	try { body = JSON.parse(text); }
	catch { throw new Error(`${label} response is not valid JSON`); }
	if (body && typeof body === "object" && body.status === "error" && typeof body.message === "string")
		throw new Error(`${label} API error: ${body.message}`);
	return { body, fetchedAt: responseFetchedAt(response), sha256: crypto.createHash("sha256").update(text).digest("hex") };
}

async function fetchDrupalAdvisories(packages = [], { fetchImpl = globalThis.fetch, apiUrl = DRUPAL_ADVISORIES_URL, now = Date.now() } = {}) {
	const queried = [...new Set((packages || []).map(p => String(p).trim().toLowerCase()).filter(p => p.startsWith("drupal/")))];
	const collectedAt = new Date(now).toISOString();
	const meta = { collectedAt, completeness: "tool-fetched", sourceUrl: apiUrl };
	if (!queried.length) return { snapshot: { queriedPackages: [], advisories: {}, _fadSnapshot: { ...meta } }, sourceSnapshot: { ...meta } };
	const url = new URL(apiUrl);
	for (const pkg of queried) url.searchParams.append("packages[]", pkg);
	const { body, sha256, fetchedAt } = await responseJson(await require("../providers").getResource("drupal", "advisories", { packages: queried },
		{ fetcher: fetchImpl, signal: AbortSignal.timeout(60000),
			...(apiUrl === DRUPAL_ADVISORIES_URL ? {} : { urlOverride: url.toString(), direct: true }) }),
		"Drupal security-advisories");
	meta.collectedAt = new Date(Math.min(fetchedAt, now)).toISOString();
	if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.advisories !== "object" || Array.isArray(body.advisories))
		throw new Error("Drupal security-advisories response is missing its advisories object");
	for (const [name, entries] of Object.entries(body.advisories))
		if (!Array.isArray(entries)) throw new Error(`Drupal security-advisories response is invalid for ${name}`);
	return { snapshot: { queriedPackages: queried, advisories: body.advisories, _fadSnapshot: { ...meta } },
		sourceSnapshot: { sha256, ...meta } };
}

/**
 * Merges a newly fetched Drupal response into a previously cached live snapshot, so a
 * second instance whose packages were not part of the first query is still evaluated.
 * Only responses actually obtained are merged: the result carries the exact union of the
 * packages really queried, and its provenance fingerprints that union.
 */
function mergeDrupalSnapshots(cached, fetched) {
	const snapshot = {
		queriedPackages: [...new Set([...(cached.snapshot.queriedPackages || []),
			...(fetched.snapshot.queriedPackages || [])].map(p => String(p).toLowerCase()))],
		advisories: { ...(cached.snapshot.advisories || {}), ...(fetched.snapshot.advisories || {}) },
		_fadSnapshot: { ...(fetched.snapshot._fadSnapshot || fetched.sourceSnapshot) },
	};
	const dates = [cached.sourceSnapshot?.collectedAt, fetched.sourceSnapshot?.collectedAt].map(Date.parse);
	if (dates.every(Number.isFinite)) snapshot._fadSnapshot.collectedAt = new Date(Math.min(...dates)).toISOString();
	return { snapshot, sourceSnapshot: { ...fetched.sourceSnapshot, ...snapshot._fadSnapshot,
		sha256: crypto.createHash("sha256").update(JSON.stringify(snapshot)).digest("hex") } };
}

async function fetchWordfenceFeed(url, { fetchImpl = globalThis.fetch, now = Date.now(), apiKey } = {}) {
	const sourceUrl = String(url);
	const key = typeof apiKey === "string" ? apiKey.trim() : "";
	const proxyCredentials = sourceUrl === WORDFENCE_PRODUCTION_URL && require("../providers").hasProxyRoute();
	if (!key && !proxyCredentials)
		throw new Error("Wordfence live scan requires an API key (--wordfence-api-key or WORDFENCE_API_KEY), or the official feed via --proxy-cache with a server key");
	const response = await require("../providers").getResource("wordfence", "production-feed", {}, {
		fetcher: fetchImpl, signal: AbortSignal.timeout(120000), headers: key ? { Authorization: `Bearer ${key}` } : {},
		...(sourceUrl === WORDFENCE_PRODUCTION_URL ? {} : { urlOverride: sourceUrl, direct: true }),
	});
	if (!response?.ok && !key && proxyCredentials)
		throw new Error(`Wordfence proxy request failed with HTTP ${response?.status ?? "unknown"}; configure a valid --wordfence-key on the cache server`);
	const { body, sha256, fetchedAt } = await responseJson(response, "Wordfence v3 feed");
	const collectedAt = new Date(Math.min(fetchedAt, now)).toISOString();
	const meta = { collectedAt, completeness: "tool-fetched", sourceUrl };
	const snapshot = { ...body, _fadSnapshot: { ...meta } };
	indexFeed(snapshot); // validate before anything is cached or matched; the reserved metadata key is tolerated
	return { snapshot, sourceSnapshot: { sha256, ...meta } };
}

/**
 * Pages a publisher's GitHub repository security-advisory feed (the machine channel the
 * publisher themselves maintains; unauthenticated, subject to GitHub's rate limits) and
 * validates every page before anything is cached or matched. A next-link that never
 * ends fails loudly instead of yielding a silently partial feed.
 */
async function fetchGithubAdvisories(repo, { fetchImpl = globalThis.fetch, apiUrl = GITHUB_ADVISORIES_URL,
	endpoint = null, now = Date.now(), maxPages = 10 } = {}) {
	const collectedAt = new Date(now).toISOString();
	const meta = { collectedAt, completeness: "tool-fetched" };
	const advisories = [];
	let url;
	if (endpoint) {
		if (!/^https?:\/\/\S+$/i.test(String(endpoint))) throw new Error("Github advisories endpoint must be an absolute http(s) URL");
		url = `${String(endpoint)}${String(endpoint).includes("?") ? "&" : "?"}per_page=100`;
	} else {
		if (!/^[^/\s]+\/[^/\s]+$/.test(String(repo || ""))) throw new Error("Github advisories repo must be owner/repo");
		url = `${apiUrl}${repo}/security-advisories?per_page=100`;
	}
	meta.sourceUrl = url;
	for (let page = 1; page <= maxPages; page++) {
		const requestParams = { repo, page, perPage: 100 };
		const canonicalUrl = require("../providers").getProvider("github").build("publisher-advisories", requestParams).url;
		const response = await require("../providers").getResource("github", "publisher-advisories", requestParams,
			{ fetcher: fetchImpl, signal: AbortSignal.timeout(60000),
				headers: { Accept: "application/vnd.github+json", "User-Agent": "vigievuln-github-advisories" },
				...(url === canonicalUrl ? {} : { urlOverride: url, direct: true }) });
		const { body, fetchedAt } = await responseJson(response, "Github security-advisories");
		meta.collectedAt = new Date(Math.min(Date.parse(meta.collectedAt), fetchedAt)).toISOString();
		if (!Array.isArray(body)) throw new Error("Github security-advisories must return a JSON array");
		validateGithubAdvisories({ advisories: [...advisories, ...body] });
		advisories.push(...body);
		const link = response.headers?.get?.("link") || null;
		const nextUrl = String(link || "").split(",").map(part => part.trim())
			.find(part => /rel="next"/.test(part))?.match(/<([^>]+)>/)?.[1] || null;
		if (!nextUrl) return { snapshot: { advisories, _fadSnapshot: { ...meta } },
			sourceSnapshot: { sha256: crypto.createHash("sha256").update(JSON.stringify(advisories)).digest("hex"), ...meta } };
		url = nextUrl;
	}
	throw new Error(`Github security-advisories pagination exceeds more than ${maxPages} pages`);
}

/**
 * Fetches the official WordPress core checksums reference, pinned by version and locale.
 * The response is validated before anything is cached: a shape change fails loudly
 * instead of producing a bogus comparison against an unusable reference.
 */
async function fetchWordpressChecksums(version, locale = "en_US", { fetchImpl = globalThis.fetch,
	apiUrl = require("./wp-checksums").WP_CHECKSUMS_API, now = Date.now() } = {}) {
	const cleanVersion = String(version || "").trim();
	if (!cleanVersion) throw new Error("WordPress checksums require a core version");
	const url = `${apiUrl}?version=${encodeURIComponent(cleanVersion)}&locale=${encodeURIComponent(String(locale || "en_US"))}`;
	const { body, sha256, fetchedAt } = await responseJson(await require("../providers").getResource("wordpress", "checksums",
		{ version: cleanVersion, locale: String(locale || "en_US") },
		{ fetcher: fetchImpl, signal: AbortSignal.timeout(60000),
			...(apiUrl === require("./wp-checksums").WP_CHECKSUMS_API ? {} : { urlOverride: url, direct: true }) }),
		"WordPress checksums");
	const collectedAt = new Date(Math.min(fetchedAt, now)).toISOString();
	const meta = { collectedAt, completeness: "tool-fetched", sourceUrl: url };
	const snapshot = { ...body, version: typeof body?.version === "string" ? body.version : cleanVersion,
		locale: typeof body?.locale === "string" ? body.locale : String(locale || "en_US"), _fadSnapshot: { ...meta } };
	validateChecksums(snapshot);
	return { snapshot, sourceSnapshot: { sha256, ...meta } };
}

function writeSnapshotAtomically(filePath, snapshot) {
	const dir = path.dirname(filePath);
	fs.mkdirSync(dir, { recursive: true });
	const temp = path.join(dir, `.${path.basename(filePath)}.tmp-${process.pid}`);
	try {
		fs.writeFileSync(temp, `${JSON.stringify(snapshot, null, "\t")}\n`);
		fs.renameSync(temp, filePath);
	} catch (error) {
		try { fs.unlinkSync(temp); } catch { /* best-effort cleanup of the staged temp file */ }
		throw error;
	}
}

module.exports = { DRUPAL_ADVISORIES_URL, WORDFENCE_PRODUCTION_URL, GITHUB_ADVISORIES_URL, PRESTASHOP_GITHUB_ADVISORIES_URL, TYPO3_GITHUB_ADVISORIES_URL, fetchDrupalAdvisories, fetchWordfenceFeed, fetchGithubAdvisories, fetchWordpressChecksums, mergeDrupalSnapshots, writeSnapshotAtomically };
