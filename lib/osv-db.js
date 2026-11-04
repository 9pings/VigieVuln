/**
 * Offline OSV matching from imported ecosystem snapshots. Unlike per-version API
 * caches, these retain advisory ranges and can evaluate previously unseen versions.
 * Unsupported range semantics remain indeterminate and are reported to callers.
 * Maven's legacy index may also be downloaded explicitly; multi-ecosystem JSONL
 * snapshots are streamed from a cache bundle and checked for corruption before use.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { unzipSync } = require("fflate");
const { compareMavenVersions } = require("./maven-version");
const { vulnToMatch } = require("./osv");

const OSV_DB_DIR = path.join(require("./cache-directory").getCacheDir(), "osv-db");
const BUCKET = "https://osv-vulnerabilities.storage.googleapis.com";
const TTL_MS = 4 * 3600 * 1000;
// OSV ecosystem export name per fad codec id. Maven only for now (version ordering).
const ECO = { maven: "Maven", npm: "npm", pypi: "PyPI", composer: "Packagist", nuget: "NuGet", go: "Go", ruby: "RubyGems" };
const indexPath = eco => path.join(OSV_DB_DIR, `${eco}-index.json`);
const recordsPath = eco => path.join(OSV_DB_DIR, 'records', eco);

// OSV identities have ecosystem-specific casing rules. Go module paths and
// Ruby names must never be folded into another package's identity.
function packageKey(name, eco) {
	const n = String(name || "");
	if (eco === "PyPI") return n.toLowerCase().replace(/[-_.]+/g, "-");
	return ["Maven", "npm", "NuGet", "Packagist"].includes(eco) ? n.toLowerCase() : n;
}

function newOsvIndex(ecosystemName, builtAt = Date.now()) {
	return { _schema: 2, _builtAt: builtAt, ecosystem: ecosystemName, count: 0, packages: 0, byPackage: Object.create(null) };
}

function addOsvRecord(index, vuln) {
	if (!vuln || typeof vuln.id !== 'string' || !vuln.id) throw new Error('invalid OSV advisory');
	if (vuln.withdrawn) return;
	const byPkg = new Map();
	for (const a of (Array.isArray(vuln.affected) ? vuln.affected : [])) {
		if (a.package?.ecosystem !== index.ecosystem || typeof a.package?.name !== 'string' || !a.package.name) continue;
		const key = packageKey(a.package.name, index.ecosystem);
		if (!byPkg.has(key)) byPkg.set(key, []);
		byPkg.get(key).push(a);
	}
	for (const [key, affs] of byPkg) {
		if (!Object.hasOwn(index.byPackage, key)) { index.byPackage[key] = []; index.packages++; }
		index.byPackage[key].push(trimVuln(vuln, affs));
		index.count++;
	}
}

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
	const dec = new TextDecoder('utf-8', { fatal: true });
	const index = newOsvIndex(ecosystemName);
	for (const name of Object.keys(files)) {
		if (!name.endsWith('.json')) continue;
		addOsvRecord(index, JSON.parse(dec.decode(files[name])));
	}
	return index;
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
	const loadRecords = () => { try {
		const dir = recordsPath(ecosystem), meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));
		if (meta._schema !== 1 || meta.ecosystem !== ecoName || typeof meta.complete !== 'boolean' || !Number.isSafeInteger(meta._builtAt) || meta._builtAt <= 0 || meta._builtAt > Date.now() + 300000 ||
			!Number.isSafeInteger(meta.recordCount) || meta.recordCount < 0 || !/^[a-f0-9]{64}$/.test(meta.sha256) || !fs.statSync(path.join(dir, 'records.jsonl')).isFile()) return null;
		return {...meta, recordsFile:path.join(dir, 'records.jsonl')};
	} catch { return null; } };
	const loadAny = () => { try {
		const index = JSON.parse(fs.readFileSync(ip, "utf8"));
		return index && index.ecosystem === ecoName && index.byPackage && typeof index.byPackage === 'object' && !Array.isArray(index.byPackage) && Number.isFinite(index._builtAt) && index._builtAt > 0 && index._builtAt <= Date.now() + 300000 ? index : null;
	} catch { return null; } };
	const loadBest = () => { const a = loadRecords(), b = loadAny(); return a && (!b || a._builtAt >= b._builtAt) ? a : b; };
	const loadFresh = () => { const j = loadBest(); return j && require('./cache-policy').fresh(j._builtAt || 0, TTL_MS) ? j : null; };

	if (offline) return loadBest();
	if (!refresh) { const f = loadFresh(); if (f) return f; }
	try {
		// Large ZIP64 upstream exports need the server's streaming validator.
		if (ecosystem !== 'maven') throw new Error(`direct OSV ${ecoName} import is not supported; import a verified seed`);
		const res = await require("./providers").getResource("osvdb", "ecosystem-archive", { ecosystem: ecoName },
			{ fetcher, headers: { "User-Agent": "vigievuln-osv-db" } });
		if (!res || !res.ok) { if (verbose) console.warn(`osv-db: HTTP ${res?.status}`); return loadBest(); }
		const buf = Buffer.from(await res.arrayBuffer());
		// The in-process ZIP decoder does not support large ZIP64 archives. Never
		// silently use a truncated database: prebuilt indexes come from the server.
		const index = buildIndexFromZip(buf, ecoName);
		if (!index.count) throw new Error('empty OSV index');
		fs.mkdirSync(OSV_DB_DIR, { recursive: true });
		const tmp = `${ip}.${process.pid}.${require('crypto').randomBytes(6).toString('hex')}.tmp`;
		try { fs.writeFileSync(tmp, JSON.stringify(index), { flag: 'wx' }); fs.renameSync(tmp, ip); }
		finally { try { fs.unlinkSync(tmp); } catch {} }
		return index;
	} catch (e) { if (verbose) console.warn(`osv-db: ${e.message}`); return loadBest(); }
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

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;
// The Maven comparator uses JavaScript Numbers internally. Avoid precision loss.
function safeMavenCompare(a,b) {
	if (/\d{16}/.test(String(a)) || /\d{16}/.test(String(b))) return null;
	return compareMavenVersions(a,b);
}
function compareSemver(a, b) {
	const x = SEMVER.exec(String(a)), y = SEMVER.exec(String(b));
	const valid = m => m && m.slice(1, 4).every(n => n === '0' || !n.startsWith('0')) &&
		(!m[4] || m[4].split('.').every(n => n && (!/^\d+$/.test(n) || n === '0' || !n.startsWith('0')))) &&
		(!m[5] || m[5].split('.').every(Boolean));
	if (!valid(x) || !valid(y)) return null;
	for (let i = 1; i <= 3; i++) { const l = BigInt(x[i]), r = BigInt(y[i]); if (l !== r) return l < r ? -1 : 1; }
	if (!x[4] || !y[4]) return x[4] === y[4] ? 0 : x[4] ? -1 : 1;
	const p = x[4].split('.'), q = y[4].split('.');
	for (let i = 0; i < Math.max(p.length, q.length); i++) {
		if (p[i] === undefined) return -1;
		if (q[i] === undefined) return 1;
		const pn = /^\d+$/.test(p[i]), qn = /^\d+$/.test(q[i]);
		if (pn && qn) { const l = BigInt(p[i]), r = BigInt(q[i]); if (l !== r) return l < r ? -1 : 1; }
		else if (pn !== qn) return pn ? -1 : 1;
		else if (p[i] !== q[i]) return p[i] < q[i] ? -1 : 1;
	}
	return 0;
}

// Three-valued evaluator: unsupported semantics and malformed versions are
// unknown, not clean. GIT ranges need a commit graph and are never guessed.
function rangeVerdict(version, range, ecosystem) {
	if (!range || !['SEMVER', 'ECOSYSTEM'].includes(range.type) || !Array.isArray(range.events) || !range.events.length) return null;
	let cmp;
	if (range.type === 'SEMVER' || ['npm', 'Go'].includes(ecosystem)) cmp = compareSemver;
	else if (ecosystem === 'Maven') cmp = safeMavenCompare;
	else if (ecosystem === 'RubyGems') cmp = require('./ruby-version').compareRubyVersions;
	else return null;
	const v = String(version);
	// Validate version itself even for an open range introduced at 0.
	try { if (cmp(v, v) !== 0) return null; } catch { return null; }
	const compare = (a, b) => a === '0' || b === '0' ? (a === b ? 0 : a === '0' ? -1 : 1) : cmp(a, b);
	const events = [], limits = [];
	for (const item of range.events) {
		if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).length !== 1) return null;
		const [kind, at] = Object.entries(item)[0];
		if (!['introduced', 'fixed', 'last_affected', 'limit'].includes(kind) || typeof at !== 'string' || !at) return null;
		if (kind === 'limit') limits.push(at); else events.push({ kind, at });
	}
	if (!events.some(e => e.kind === 'introduced')) return null;
	try {
		for (const e of events) if (compare(v, e.at) == null) return null;
		for (const l of limits) if (l !== '*' && compare(v, l) == null) return null;
		if (limits.length && !limits.some(l => l === '*' || compare(v, l) < 0)) return false;
		events.sort((a, b) => compare(a.at, b.at) || (EVENT_RANK[a.kind] - EVENT_RANK[b.kind]));
		let affected = false;
		for (const e of events) {
			const c = compare(v, e.at);
			if (e.kind === 'introduced' && c >= 0) affected = true;
			else if (e.kind === 'fixed' && c >= 0) affected = false;
			else if (e.kind === 'last_affected' && c > 0) affected = false;
		}
		return affected;
	} catch { return null; }
}

function vulnVerdict(version, vuln, ecosystem, opts = {}) {
	let unknown = false;
	for (const a of (vuln.affected || [])) {
		const versions = Array.isArray(a.versions) ? a.versions : [];
		// Our reviewed evidence can establish individual positive and negative
		// releases without establishing the complete affected history. Interpret
		// this extension only when the caller identifies our own advisory store;
		// external OSV documents cannot change OSV's version-list semantics.
		const partial = opts.source === 'vigievuln' && a.database_specific?.vigievuln_partial_versions === true;
		if (partial) {
			const tested = vulnVerdict(version, {affected:[{versions, ranges:a.ranges || []}]}, ecosystem);
			const knownSafe = Array.isArray(a.database_specific.unaffected_versions)
				? vulnVerdict(version, {affected:[{versions:a.database_specific.unaffected_versions}]}, ecosystem)
				: false;
			if (tested === true && knownSafe === true) { unknown = true; continue; }
			if (tested === true) return true;
			if (knownSafe !== true || tested === null) unknown = true;
			continue;
		}
		if (versions.includes(String(version))) return true;
		// Composer removes the VCS tag's optional v prefix. Match only identical
		// numeric release spellings here; this does not infer range ordering, pad
		// components, or interpret development branches and prerelease suffixes.
		// https://getcomposer.org/doc/articles/versions.md#tags
		if (ecosystem === 'Packagist' && /^[vV]?\d{1,5}(?:\.\d+){0,3}$/.test(String(version)) &&
			versions.some(candidate => typeof candidate === 'string' && /^[vV]?\d{1,5}(?:\.\d+){0,3}$/.test(candidate) &&
				candidate.replace(/^[vV]/, '') === String(version).replace(/^[vV]/, ''))) return true;
		for (const candidate of versions) {
			let comparison = null;
			try {
				if (ecosystem === 'Maven') comparison = safeMavenCompare(String(version), String(candidate));
				else if (['npm', 'Go'].includes(ecosystem)) comparison = compareSemver(version, candidate);
				else if (ecosystem === 'RubyGems') comparison = require('./ruby-version').compareRubyVersions(version, candidate);
			} catch { /* unknown */ }
			if (comparison === 0) return true;
			if (comparison == null) unknown = true;
		}
		for (const r of (Array.isArray(a.ranges) ? a.ranges : [])) {
			const verdict = rangeVerdict(version, r, ecosystem);
			if (verdict === true) return true;
			if (verdict === null) unknown = true;
		}
		// Version spellings outside understood ecosystems can be equivalent even
		// when the literal strings differ (e.g. PEP 440 1.0 and 1.0.0).
		if (!(a.ranges || []).length && versions.length && !['Maven', 'npm', 'Go', 'RubyGems'].includes(ecosystem)) unknown = true;
		if (!(a.ranges || []).length && !versions.length) unknown = true;
	}
	return unknown ? null : false;
}

/**
 * Match resolved Maven deps against a local OSV DB index. Returns vulnToMatch-shaped
 * matches (source 'osv'), one per (coord, version, vuln). Scans every distinct version.
 */
function matchOsvDbDeps(resolvedDeps, index, { onUnknown } = {}) {
	if (!index || !index.byPackage) return [];
	const out = [];
	const seen = new Set();
	const ecoName = index.ecosystem || 'Maven'; // legacy Maven index has no schema
	const { osvEcosystemFor, osvPkgName } = require('./osv');
	for (const dep of resolvedDeps.values()) {
		if (!Object.hasOwn(ECO, dep.ecosystem === 'yarn' ? 'npm' : dep.ecosystem) || osvEcosystemFor(dep) !== ecoName) continue;
		if (dep.provenance === "binary") continue;
		const name = osvPkgName(dep), pkgKey = packageKey(name, ecoName);
		const recs = Object.hasOwn(index.byPackage, pkgKey) ? index.byPackage[pkgKey] : null;
		if (!recs || !recs.length) continue;
		const versions = (dep.versions && dep.versions.length) ? dep.versions : [dep.version];
		for (const ver of versions) {
			if (!ver || /\$\{/.test(String(ver))) continue;
			for (const rec of recs) {
				// The legacy lookup key folds case. Confirm the original Maven
				// coordinate before using its affected versions or ranges.
				const affected = ecoName === 'Maven' ? (rec.affected || []).filter(a => a?.package?.ecosystem === 'Maven' && a.package.name === name) : rec.affected;
				if (ecoName === 'Maven' && !affected.length) {
					if ((rec.affected || []).some(a => !a?.package?.name)) onUnknown?.({ecosystem:ecoName,name,version:ver,advisory:rec.id});
					continue;
				}
				const verdict = vulnVerdict(ver, { ...rec, affected }, ecoName);
				if (verdict === null) { if (onUnknown) onUnknown({ecosystem:ecoName, name, version:ver, advisory:rec.id}); continue; }
				if (!verdict) continue;
				const key = `${dep.coordKey || pkgKey}:${ver}|${rec.id}`;
				if (seen.has(key)) continue;
				seen.add(key);
				const match = vulnToMatch(ver === dep.version ? dep : { ...dep, version: ver }, rec);
				out.push(match);
			}
		}
	}
	return out;
}

/** Stream seed records; do not publish partial matches if integrity fails. */
async function matchOsvDbRecords(resolvedDeps, index, { onUnknown } = {}) {
	if (!index?.recordsFile || !ECO || !Object.values(ECO).includes(index.ecosystem)) throw new Error('invalid OSV seed');
	const { osvEcosystemFor, osvPkgName } = require('./osv');
	const targets = new Map();
	for (const dep of resolvedDeps.values()) {
		if (!dep || !Object.hasOwn(ECO, dep.ecosystem === 'yarn' ? 'npm' : dep.ecosystem) || osvEcosystemFor(dep) !== index.ecosystem || dep.provenance === 'binary') continue;
		const name = osvPkgName(dep); if (!name) continue;
		const key = packageKey(name, index.ecosystem);
		if (!targets.has(key)) targets.set(key, []);
		targets.get(key).push(dep);
	}
	const stream = fs.createReadStream(index.recordsFile), hash = require('crypto').createHash('sha256');
	stream.on('data', chunk => hash.update(chunk));
	const lines = require('./line-stream').readTextLines(stream);
	const out = [], seen = new Set(), unknown = [], unknownKeys = new Set(); let count = 0;
	try {
		for await (const line of lines) {
			if (!line) throw new Error('empty OSV seed record');
			const vuln = JSON.parse(line); count++;
			if (!vuln || typeof vuln.id !== 'string' || !Array.isArray(vuln.affected)) throw new Error('invalid OSV seed record');
			if (vuln.withdrawn) continue;
			const relevant = new Map();
			for (const a of vuln.affected) {
				if (a?.package?.ecosystem !== index.ecosystem || typeof a.package.name !== 'string') continue;
				const key = packageKey(a.package.name, index.ecosystem);
				if (!targets.has(key)) continue;
				if (!relevant.has(key)) relevant.set(key, []);
				relevant.get(key).push(a);
			}
			for (const [key, affected] of relevant) for (const dep of targets.get(key)) {
				const exactAffected = index.ecosystem === 'Maven' ? affected.filter(a => a.package.name === osvPkgName(dep)) : affected;
				if (!exactAffected.length) continue;
				const record = { ...vuln, affected: exactAffected };
				for (const ver of (dep.versions?.length ? dep.versions : [dep.version])) {
					if (!ver || /\$\{/.test(String(ver))) continue;
					const id = `${dep.coordKey || key}:${ver}|${vuln.id}`;
					const verdict = vulnVerdict(ver, record, index.ecosystem);
					if (verdict === null && !unknownKeys.has(id)) { unknownKeys.add(id); unknown.push({ecosystem:index.ecosystem,name:osvPkgName(dep),version:ver,advisory:vuln.id}); }
					if (verdict !== true || seen.has(id)) continue;
					seen.add(id); const match = vulnToMatch(ver === dep.version ? dep : {...dep,version:ver}, record);
					out.push(match);
				}
			}
		}
	} finally { stream.destroy(); }
	if (count !== index.recordCount || hash.digest('hex') !== index.sha256) throw new Error('OSV seed checksum or count mismatch');
	if (onUnknown) for (const item of unknown) onUnknown(item);
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
	if (!(eco.runMaven || eco.runGradle || eco.hasOtherIndex)) return false;
	return !!(eco.hasIndex || eco.hasOtherIndex); // do not download behind their back
}

/** Cheap "is the index already on disk" probe, so the decision above stays pure. */
function hasOsvDbIndex(ecosystem = "maven") {
	try { return fs.existsSync(indexPath(ecosystem)) || (fs.existsSync(path.join(recordsPath(ecosystem), 'meta.json')) && fs.existsSync(path.join(recordsPath(ecosystem), 'records.jsonl'))); } catch { return false; }
}

module.exports = { ensureOsvDb, buildIndexFromZip, newOsvIndex, addOsvRecord, packageKey, ECO, matchOsvDbDeps, matchOsvDbRecords, rangeAffects, rangeVerdict, vulnVerdict, compareSemver, vulnAffectsVersion, autoEnableOsvDb, hasOsvDbIndex, OSV_DB_DIR };
