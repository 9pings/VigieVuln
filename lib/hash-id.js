/**
 * lib/hash-id.js — identity-by-checksum for unmanaged artifacts.
 *
 * Two known-good sources, tried in order:
 *  1. deps.dev query-by-hash → exact package coordinate (whole published archive).
 *  2. CIRCL hashlookup → known OS/distro/CDN/NSRL file + free KnownMalicious flag.
 *
 * Cache-backed (~/.fad-checker/hash-id-cache.json, 24h) and --offline-aware: offline
 * reads cache only and never touches the network (project air-gapped principle).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const CACHE_DIR = path.join(require("./cache-directory").getCacheDir());
const CACHE_PATH = path.join(CACHE_DIR, "hash-id-cache.json");
const CACHE_TTL_MS = 24 * 3600 * 1000;
const DEPSDEV = "https://api.deps.dev/v3/query";
const CIRCL = "https://hashlookup.circl.lu/lookup/sha256";

const SYSTEM_TO_ECO = { MAVEN: "maven", NPM: "npm", NUGET: "nuget", PYPI: "pypi", RUBYGEMS: "ruby", CARGO: "cargo", GO: "go" };

function sha1ToBase64(hex) { return Buffer.from(hex, "hex").toString("base64"); }

function parseDepsDev(body) {
	const vk = body?.results?.[0]?.version?.versionKey;
	if (!vk?.name) return null;
	return { ecosystem: SYSTEM_TO_ECO[vk.system] || (vk.system || "").toLowerCase() || null, name: vk.name, version: vk.version || null, source: "deps.dev" };
}

function parseCircl(body) {
	if (!body || body.message || !(body.FileName || body.ProductCode)) return null;
	const malicious = Array.isArray(body.KnownMalicious) ? body.KnownMalicious.length > 0 : !!body.KnownMalicious;
	return {
		ecosystem: null,
		name: body.ProductCode?.ProductName || body.FileName || null,
		version: body.ProductCode?.ProductVersion || null,
		source: `circl:${body.db || "hashlookup"}`,
		trust: body["hashlookup:trust"] != null ? body["hashlookup:trust"] : null,
		knownMalicious: malicious,
	};
}

function loadCache({ offline = false } = {}) {
	try {
		const d = JSON.parse(fs.readFileSync(CACHE_PATH, "utf8"));
		if (offline || Date.now() - (d._fetchedAt || 0) < CACHE_TTL_MS) return d.entries || {};
	} catch { /* ignore */ }
	return {};
}
function saveCache(entries) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify({ _fetchedAt: Date.now(), entries })); } catch { /* ignore */ } }

async function lookupHash(hashes, opts = {}) {
	const { fetcher = globalThis.fetch, offline = false, cache } = opts;
	const entries = cache || loadCache({ offline });
	const key = hashes.sha256 || hashes.sha1;
	if (!key) return null;
	if (Object.prototype.hasOwnProperty.call(entries, key)) return entries[key];
	if (offline) return null;

	let identity = null;
	// 1) deps.dev (SHA1 base64)
	if (hashes.sha1) {
		try {
			const r = await require("./providers").getResource("hashid", "depsdev-sha1",
				{ base64: sha1ToBase64(hashes.sha1) }, { fetcher, headers: { "User-Agent": "vigievuln-hashid" } });
			if (r.ok) identity = parseDepsDev(await r.json());
		} catch { /* ignore, try CIRCL */ }
	}
	// 2) CIRCL (SHA-256)
	if (!identity && hashes.sha256) {
		try {
			const r = await require("./providers").getResource("hashid", "circl-sha256", { sha256: hashes.sha256 },
				{ fetcher, headers: { "User-Agent": "vigievuln-hashid", Accept: "application/json" } });
			if (r.ok) identity = parseCircl(await r.json());
		} catch { /* ignore */ }
	}
	entries[key] = identity;
	if (!cache) saveCache(entries);
	return identity;
}

module.exports = { sha1ToBase64, parseDepsDev, parseCircl, lookupHash, loadCache, saveCache, CACHE_PATH };
