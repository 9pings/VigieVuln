/**
 * lib/osv-db.js — offline-COMPLETE OSV matching from a locally imported OSV database
 * (the per-ecosystem `all.zip` exports OSV.dev publishes on its public GCS bucket).
 *
 * Why this exists alongside lib/osv.js: the latter queries the OSV.dev API *per
 * dependency* and caches each response (12 h TTL). Offline, that only covers the deps
 * that happened to be queried online before — a cold dep has NO OSV data. This module
 * imports the FULL OSV database once while online (Maven = 9 MB zip, ~6.6 k advisories)
 * and matches EVERY dep against it offline, deterministically, regardless of the per-dep
 * cache. That is exactly the model OSV-Scanner uses for air-gapped scans
 * (`--download-offline-databases`), and it makes fad's offline Maven recall complete and
 * cache-independent for an air-gapped engagement.
 *
 * Maven only for now: range matching needs the ecosystem's version ordering, and fad has
 * a robust Maven comparator (lib/maven-version). npm/PyPI/etc. are a documented follow-up
 * (they need semver/PEP-440 ordering). The OSV records are full OSV-schema vuln objects —
 * identical to the API — so lib/osv.js#vulnToMatch is reused verbatim.
 *
 * Online (download+index) + cached (~/.fad-checker/osv-db, 24 h) + offline-aware (loads a
 * present index, never blocks). The index travels in the cache archive automatically.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { unzipSync } = require("fflate");
const { compareMavenVersions } = require("./maven-version");
const { vulnToMatch } = require("./osv");

const OSV_DB_DIR = path.join(require("./cache-directory").getCacheDir(), "osv-db");
const BUCKET = "https://osv-vulnerabilities.storage.googleapis.com";
const TTL_MS = 24 * 3600 * 1000;
// OSV ecosystem export name per fad codec id. Maven only for now (version ordering).
const ECO = { maven: "Maven" };
const indexPath = eco => path.join(OSV_DB_DIR, `${eco}-index.json`);

/** Keep only what vulnToMatch + matching need, so the cached index stays compact. */
function trimVuln(vuln, affForPkg) {
	return {
		id: vuln.id,
		aliases: vuln.aliases || [],
		summary: vuln.summary || "",
		details: (vuln.details || "").slice(0, 2000),
		severity: vuln.severity || [],
		...(vuln.database_specific?.severity ? { database_specific: { severity: vuln.database_specific.severity } } : {}),
		references: (vuln.references || []).slice(0, 20),
		published: vuln.published || null,
		modified: vuln.modified || null,
		affected: affForPkg.map(a => ({ package: a.package, ranges: a.ranges || [], versions: a.versions || [] })),
	};
}

/** Build { byPackage: { "g:a"(lower): [trimmedVuln] }, … } from an all.zip buffer. */
function buildIndexFromZip(buf, ecosystemName) {
	const files = unzipSync(new Uint8Array(buf));
	const dec = new TextDecoder();
	const byPackage = {};
	let count = 0;
	for (const name of Object.keys(files)) {
		let vuln;
		try { vuln = JSON.parse(dec.decode(files[name])); } catch { continue; }
		if (!vuln || vuln.withdrawn) continue;
		// A vuln can list several packages; index it under each (with that package's affected slice).
		const byPkg = new Map();
		for (const a of (vuln.affected || [])) {
			if (a.package?.ecosystem !== ecosystemName) continue;
			const nm = a.package?.name;
			if (!nm) continue;
			if (!byPkg.has(nm)) byPkg.set(nm, []);
			byPkg.get(nm).push(a);
		}
		for (const [nm, affs] of byPkg) {
			const key = nm.toLowerCase();
			(byPackage[key] = byPackage[key] || []).push(trimVuln(vuln, affs));
			count++;
		}
	}
	return { _builtAt: Date.now(), ecosystem: ecosystemName, count, packages: Object.keys(byPackage).length, byPackage };
}

/**
 * Ensure the local OSV DB index for an ecosystem. Downloads + (re)builds when online and
 * stale/missing; offline (or on any network failure) loads whatever is present, else null.
 */
async function ensureOsvDb(opts = {}) {
	const { offline, refresh, verbose, fetcher = globalThis.fetch, ecosystem = "maven" } = opts;
	const ecoName = ECO[ecosystem];
	if (!ecoName) return null;
	const ip = indexPath(ecosystem);
	const loadAny = () => { try { return JSON.parse(fs.readFileSync(ip, "utf8")); } catch { return null; } };
	const loadFresh = () => { const j = loadAny(); return j && (Date.now() - (j._builtAt || 0) < TTL_MS) ? j : null; };

	if (offline) return loadAny();
	if (!refresh) { const f = loadFresh(); if (f) return f; }
	try {
		const res = await require("./providers").getResource("osvdb", "ecosystem-archive", { ecosystem: ecoName },
			{ fetcher, headers: { "User-Agent": "vigievuln-osv-db" } });
		if (!res || !res.ok) { if (verbose) console.warn(`osv-db: HTTP ${res?.status}`); return loadAny(); }
		const buf = Buffer.from(await res.arrayBuffer());
		const index = buildIndexFromZip(buf, ecoName);
		fs.mkdirSync(OSV_DB_DIR, { recursive: true });
		fs.writeFileSync(ip, JSON.stringify(index));
		return index;
	} catch (e) { if (verbose) console.warn(`osv-db: ${e.message}`); return loadAny(); }
}

// ---- OSV range evaluation over Maven version ordering ----
// Follows the schema's reference algorithm (https://ossf.github.io/osv-schema/#evaluation).
// `events` are NOT required to be sorted, so they are sorted by version first ("0" =
// lowest) and walked as a state machine; walking them in ARRAY order mis-evaluated a valid
// unsorted record in both directions (test/osv-events-order.test.js).
const cmpV = (a, b) => {
	// "0" is OSV's "since the beginning", below every real version — including Maven
	// qualifiers such as "0-alpha" that ComparableVersion orders BELOW "0".
	if (a === "0" || b === "0") return a === b ? 0 : (a === "0" ? -1 : 1);
	return compareMavenVersions(a, b);
};
// At an equal version, introduced is applied before fixed/last_affected, so a degenerate
// [X introduced, X fixed] pair yields "not affected" whatever order it was written in.
const EVENT_RANK = { introduced: 0, last_affected: 1, fixed: 2 };
function rangeAffects(version, range) {
	if (!range || range.type === "GIT") return false;
	const v = String(version);
	const events = [];
	const limits = [];
	for (const e of (range.events || [])) {
		if (e.limit !== undefined) { limits.push(String(e.limit)); continue; }
		const kind = ["introduced", "fixed", "last_affected"].find(k => e[k] !== undefined);
		if (kind) events.push({ kind, at: String(e[kind]) });
	}
	// limit: the range only applies BELOW some limit ("*" = unbounded). No limit = no bound.
	if (limits.length && !limits.some(l => l === "*" || cmpV(v, l) < 0)) return false;
	events.sort((a, b) => cmpV(a.at, b.at) || (EVENT_RANK[a.kind] - EVENT_RANK[b.kind]));
	let affected = false;
	for (const e of events) {
		const c = cmpV(v, e.at);
		if (e.kind === "introduced") { if (c >= 0) affected = true; }
		else if (e.kind === "fixed") { if (c >= 0) affected = false; }
		else if (c > 0) affected = false; // last_affected is inclusive
	}
	return affected;
}
function vulnAffectsVersion(version, trimmedVuln) {
	for (const a of (trimmedVuln.affected || [])) {
		if ((a.versions || []).includes(version)) return true;
		for (const r of (a.ranges || [])) if (rangeAffects(version, r)) return true;
	}
	return false;
}

/**
 * Match resolved Maven deps against a local OSV DB index. Returns vulnToMatch-shaped
 * matches (source 'osv'), one per (coord, version, vuln). Scans every distinct version.
 */
function matchOsvDbDeps(resolvedDeps, index) {
	if (!index || !index.byPackage) return [];
	const out = [];
	const seen = new Set();
	for (const dep of resolvedDeps.values()) {
		if (dep.ecosystem !== "maven") continue;
		if (dep.provenance === "embedded" || dep.provenance === "binary") continue;
		const recs = index.byPackage[`${dep.groupId}:${dep.artifactId}`.toLowerCase()];
		if (!recs || !recs.length) continue;
		const versions = (dep.versions && dep.versions.length) ? dep.versions : [dep.version];
		for (const ver of versions) {
			if (!ver || /\$\{/.test(String(ver))) continue;
			for (const rec of recs) {
				if (!vulnAffectsVersion(ver, rec)) continue;
				const key = `${dep.groupId}:${dep.artifactId}:${ver}|${rec.id}`;
				if (seen.has(key)) continue;
				seen.add(key);
				out.push(vulnToMatch(ver === dep.version ? dep : { ...dep, version: ver }, rec));
			}
		}
	}
	return out;
}

/**
 * Decide whether this run uses the local OSV database.
 *
 * It is NEVER downloaded implicitly. The import is ~9 MB and buys offline completeness, not
 * speed: the per-dependency OSV.dev queries still run (this step merges on top of them), and
 * they are not what makes a large Maven scan slow anyway — `search.maven.org` and NVD are.
 * Paying that download on someone's first Java scan would be a cost with no visible return.
 *
 * So: use the index when it is already on disk — warmed by an earlier `--osv-db`, or carried
 * in by `--import-cache` — because matching against it then costs nothing and is exactly what
 * an air-gapped run wants. Otherwise it takes `--osv-db` to ask for it.
 *
 * Tri-state, courtesy of commander: `undefined` = decide here, `true` = the user asked for it
 * by name (download included), `false` = `--no-osv-db`.
 *
 * @param {{osvDb?: boolean, osv?: boolean}} options
 * @param {{runMaven?: boolean, runGradle?: boolean, hasIndex?: boolean}} eco
 */
function autoEnableOsvDb(options = {}, eco = {}) {
	if (options.osvDb === true) return true;     // asked for by name, honour it anywhere
	if (options.osvDb === false) return false;   // --no-osv-db
	if (options.vigievulnProxy && !options.offline) return false; // do not silently merge an old local snapshot
	if (options.osv === false) return false;     // --no-osv means no OSV data at all
	if (!(eco.runMaven || eco.runGradle)) return false;
	return !!eco.hasIndex;   // present = free to use; absent = do not download behind their back
}

/** Cheap "is the index already on disk" probe, so the decision above stays pure. */
function hasOsvDbIndex(ecosystem = "maven") {
	try { return fs.existsSync(indexPath(ecosystem)); } catch { return false; }
}

module.exports = { ensureOsvDb, buildIndexFromZip, matchOsvDbDeps, rangeAffects, vulnAffectsVersion, autoEnableOsvDb, hasOsvDbIndex, OSV_DB_DIR };
