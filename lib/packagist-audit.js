/**
 * lib/packagist-audit.js — the Packagist security-advisories lane for Composer deps.
 *
 * `composer audit` (Composer ≥ 2.4) queries `https://packagist.org/api/security-advisories/`
 * — the advisory database Packagist builds from GitHub advisories and FriendsOfPHP, keyed
 * by composer package and version constraint. fad's OSV lane misses advisories that OSV
 * carries only as CVEProject entries without Packagist coordinates (GIT/CPE ranges only):
 * measured on the real-instance corpus (2026-09-23), twig/twig CVE-2026-46636 and
 * CVE-2026-46627 (drupal 8.5.0 @1.35.0, symfony-demo @3.10.3) and knplabs/knp-snappy
 * CVE-2026-46643 (BookStack @1.4.2) were found by `composer audit` and not by OSV — this
 * lane closes that class with the official source's own data.
 *
 * Only package NAMES travel to packagist.org (never versions), exactly like the existing
 * Packagist registry pass in lib/codecs/composer/registry.js. Under `--offline` this lane
 * reads the warm cache and makes zero network calls. An unavailable packagist.org is
 * reported as incomplete coverage; only an explicit completeness gate fails the CLI.
 *
 * Advisories are cached per package in ~/.fad-checker/packagist-advisories/ (24 h TTL;
 * offline ignores the TTL, same rule as OSV/NVD: the warmed cache is the only source on
 * an air-gapped box).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const PACKAGIST_AUDIT_API = "https://packagist.org/api/security-advisories/";
const DEFAULT_CACHE_DIR = path.join(require("./cache-directory").getCacheDir(), "packagist-advisories");
const CACHE_TTL_MS = 24 * 3600 * 1000;
const BATCH_SIZE = 100;      // composer audit sends 100 packages per request; stay aligned

// ── Composer version + constraint semantics ─────────────────────────────────────────
// Mirrors composer/semver (VersionParser::normalize / parseConstraints, Comparator =
// PHP version_compare on the normalized form), because an advisory's `affectedVersions`
// means what COMPOSER says it means — a home-grown semver reading got three things
// wrong: a range-derived upper bound let the bound's own pre-releases in (`^1.0`
// matched 2.0.0-alpha), `-pN` patch releases sorted BELOW their base (Composer ranks
// them above), and `< 3.4.6` (operator, space, version) was rejected as unparsable.
//
// Stability order: dev < alpha < beta < RC < stable < patch. Composer aliases a/b/pl/p.
const STABILITY_RANK = { dev: 0, alpha: 1, beta: 2, rc: 3, stable: 4, patch: 5 };
const STABILITY_ALIAS = { a: "alpha", alpha: "alpha", b: "beta", beta: "beta", rc: "rc", stable: "stable", p: "patch", pl: "patch", patch: "patch" };
// VersionParser's classical version + modifier regex (any number of numeric parts —
// Composer stops at 4, but a longer one was accepted before and is still ordered sanely),
// optional build metadata ignored like Composer does.
const VERSION_RE = /^v?(\d+(?:\.\d+)*)(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)(\d*(?:[.-]\d+)*))?([.-]?dev)?(?:\+\S+)?$/i;

// "1.35.0" → { nums:[1,35,0], stab:"stable", stabNums:[], dev:false, hasStab:false };
// "v1.7.0-beta2" → stab "beta", stabNums [2]; "1.0.0-dev" → stab "dev". Unparsable
// (branch "dev-main", "1.0.x-dev", an unknown suffix "1.0.0-foo") → null.
function parseComposerVersion(value) {
	const input = String(value ?? "").trim();
	if (input.length > 256) return null;
	const m = VERSION_RE.exec(input);
	if (!m) return null;
	const word = m[2] ? STABILITY_ALIAS[m[2].toLowerCase()] : null;
	const dev = !!m[4];
	return {
		nums: m[1].split(".").map(Number),
		stab: word || (dev ? "dev" : "stable"),
		stabNums: m[3] ? m[3].split(/[.-]/).filter(Boolean).map(Number) : [],
		// a trailing -dev on a stability-suffixed version ("1.0.0-beta1-dev") ranks it
		// just below that pre-release, exactly as version_compare does
		dev: dev && !!word,
		hasStab: !!word || dev,
	};
}

function cmpParsed(left, right) {
	for (let i = 0; i < Math.max(left.nums.length, right.nums.length, 4); i++) {
		const d = (left.nums[i] || 0) - (right.nums[i] || 0);
		if (d) return Math.sign(d);
	}
	const r = STABILITY_RANK[left.stab] - STABILITY_RANK[right.stab];
	if (r) return Math.sign(r);
	// Numeric, not lexical (beta2 < beta10); a missing number sorts first (beta < beta1).
	for (let i = 0; i < Math.max(left.stabNums.length, right.stabNums.length); i++) {
		if (left.stabNums[i] == null) return -1;
		if (right.stabNums[i] == null) return 1;
		const d = left.stabNums[i] - right.stabNums[i];
		if (d) return Math.sign(d);
	}
	if (left.dev !== right.dev) return left.dev ? -1 : 1;
	return 0;
}

function cmpComposerVersions(a, b) {
	const left = parseComposerVersion(a), right = parseComposerVersion(b);
	if (!left || !right) return null;
	return cmpParsed(left, right);
}

// manipulateVersionString(): bump the 1-based `position` part, zero everything after,
// and make it a "-dev" bound — the exclusive upper limit every range operator derives,
// so `<2.0.0.0-dev` keeps 2.0.0-alpha/beta/RC out of `^1.0` as Composer does.
function devBound(nums, position, increment) {
	const out = [0, 1, 2, 3].map(i => nums[i] || 0);
	out[position - 1] += increment;
	for (let i = position; i < 4; i++) out[i] = 0;
	return { nums: out, stab: "dev", stabNums: [], dev: false, hasStab: true };
}
const asDev = v => ({ ...v, stab: "dev", stabNums: [], dev: false, hasStab: true });

// One AND token → [{ op, v }] (all must hold), [] (matches anything), or null
// (unparsable — the caller turns that into an undecidable verdict, never a guess).
function parseConstraintToken(raw) {
	let tok = String(raw || "").trim();
	let flag = null;
	const fm = /@(stable|rc|beta|alpha|dev)$/i.exec(tok);
	if (fm) { flag = fm[1].toLowerCase(); tok = tok.slice(0, fm.index).trim(); }
	if (!tok) return [];
	if (/^v?[xX*](?:\.[xX*])*$/.test(tok)) return [];
	let m;
	// "1.0 - 2.0" (re-joined by the tokenizer). Lower gets -dev unless it names a
	// stability; a partial upper becomes "<next-dev", a full or suffixed one "<=".
	if ((m = /^(\S+)\u0001(\S+)$/.exec(tok))) {
		const lo = parseComposerVersion(m[1]), hi = parseComposerVersion(m[2]);
		if (!lo || !hi) return null;
		const hiParts = /^v?(\d+(?:\.\d+)*)/.exec(m[2].trim())[1].split(".").length;
		const upper = (hiParts >= 3 || hi.hasStab) ? { op: "<=", v: hi } : { op: "<", v: devBound(hi.nums, hiParts === 1 ? 1 : 2, 1) };
		return [{ op: ">=", v: lo.hasStab ? lo : asDev(lo) }, upper];
	}
	// Wildcards 1.2.* / 1.* / 1.2.x → >=1.2.0.0-dev <1.3.0.0-dev.
	if ((m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.[xX*])+$/.exec(tok))) {
		const nums = [m[1], m[2], m[3]].filter(x => x != null).map(Number);
		return [{ op: ">=", v: devBound(nums, nums.length, 0) }, { op: "<", v: devBound(nums, nums.length, 1) }];
	}
	if ((m = /^([\^~])(.+)$/.exec(tok))) {
		if (m[2].startsWith(">")) return null;               // "~>" is Ruby, Composer rejects it
		const v = parseComposerVersion(m[2]);
		if (!v) return null;
		const given = /^v?(\d+(?:\.\d+)*)/.exec(m[2].trim())[1].split(".").length;
		let position;
		if (m[1] === "^") {
			// The first non-zero SPECIFIED part moves: ^1.2 → <2, ^0.3 → <0.4, ^0.0.3 → <0.0.4.
			if (v.nums[0] !== 0 || given < 2) position = 1;
			else if (v.nums[1] !== 0 || given < 3) position = 2;
			else position = 3;
		} else {
			// One significance above the last specified part: ~1.2 → <2, ~1.2.3 → <1.3.
			position = Math.max(1, Math.min(given, 4) - 1);
		}
		return [{ op: ">=", v: v.hasStab ? v : asDev(v) }, { op: "<", v: devBound(v.nums, position, 1) }];
	}
	if ((m = /^(<>|!=|>=|<=|==|>|<|=)?\s*(.+)$/.exec(tok))) {
		const v = parseComposerVersion(m[2]);
		if (!v) return null;
		const op = m[1] === "<>" ? "!=" : m[1] === "==" ? "=" : m[1] || null;
		if (!op) {
			// A bare FULL version is equality. A bare PARTIAL ("7.4") is read as its
			// branch (>=7.4 <7.5) — a deliberate fad reading kept from the first version
			// of this lane (Composer itself would read "==7.4.0.0").
			// A bare SUFFIXED token ("1.0.0-beta1") stays undecidable: publisher feeds
			// reuse this evaluator (lib/application-providers/github-advisories.js) and
			// write malformed intervals in that shape, so equality would be a guess there.
			if (v.hasStab) return null;
			const parts = /^v?(\d+(?:\.\d+)*)/.exec(m[2].trim())[1].split(".").length;
			if (parts >= 3) return [{ op: "=", v }];
			return [{ op: ">=", v: devBound(v.nums, parts, 0) }, { op: "<", v: devBound(v.nums, parts, 1) }];
		}
		let bound = v;
		if (op !== "=" && flag && !v.hasStab) bound = flag === "stable" ? v : { ...v, stab: flag, hasStab: true };
		// VersionParser appends "-dev" to `<` and `>=` operands that name no stability.
		else if ((op === "<" || op === ">=") && !v.hasStab) bound = asDev(v);
		return [{ op, v: bound }];
	}
	return null;
}

// Split one OR branch into its AND tokens. Composer separates them by "," or
// whitespace, but never between an operator and its version ("< 3.4.6") nor around
// the " - " of a hyphen range — so those are glued first.
function andTokens(branch) {
	return String(branch)
		.replace(/(<>|!=|>=|<=|==|>|<|=)\s+/g, "$1")
		.replace(/\s+-\s+/g, "\u0001")
		.split(/\s*,\s*|\s+/)
		.filter(Boolean);
}

function orBranches(constraint) {
	return String(constraint ?? "").split(/\s*\|\|?\s*/).map(b => b.trim()).filter(Boolean);
}

function holds(version, { op, v }) {
	const c = cmpParsed(version, v);
	return op === ">=" ? c >= 0 : op === ">" ? c > 0 : op === "<=" ? c <= 0 : op === "<" ? c < 0
		: op === "!=" ? c !== 0 : c === 0;
}

// Evaluate ONE AND-group. Returns true | false | null (undecidable — never a verdict
// built on an unparsable token).
function satisfiesGroup(version, tokens) {
	let satisfied = true;
	for (const tok of tokens) {
		const parts = parseConstraintToken(tok);
		if (parts == null) return null;
		if (!parts.every(part => holds(version, part))) satisfied = false;
	}
	return satisfied;
}

/**
 * Does a concrete composer version satisfy a Packagist `affectedVersions` constraint
 * (OR of `|`/`||` branches, AND of `,`/space tokens)? → true | false | null.
 */
function satisfiesComposerConstraint(version, constraint) {
	const s = String(constraint ?? "").trim();
	if (!s) return null;
	const v = parseComposerVersion(version);
	if (!v) return null;
	let sawUndecidable = false;
	for (const branch of orBranches(s)) {
		const verdict = satisfiesGroup(v, andTokens(branch));
		if (verdict === true) return true;
		if (verdict === null) sawUndecidable = true;
	}
	return sawUndecidable ? null : false;
}

/**
 * The fix version implied for `version` by the constraint: the smallest STRICT `<`
 * bound of the satisfied branch that lies above the version. `<=` and wildcards name no
 * next release — null, not a fabricated version.
 */
function fixVersionFromConstraint(version, constraint) {
	const s = String(constraint ?? "").trim();
	if (!s) return null;
	const fixes = [];
	for (const branch of orBranches(s)) {
		if (satisfiesComposerConstraint(version, branch) !== true) continue;
		for (const tok of andTokens(branch)) {
			const m = /^<(?![>=])(.+)$/.exec(tok.replace(/@\w+$/i, "").trim());
			if (!m) continue;
			const c = cmpComposerVersions(version, m[1]);
			if (c != null && c < 0) fixes.push(m[1].trim());
		}
	}
	if (!fixes.length) return null;
	return fixes.sort((x, y) => cmpComposerVersions(x, y))[0];
}

const SEVERITY_ALIASES = { moderate: "MEDIUM", important: "HIGH", severe: "HIGH", info: "LOW" };
function normalizeSeverity(raw) {
	const up = String(raw || "").trim().toUpperCase();
	return SEVERITY_ALIASES[up.toLowerCase()] || (["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(up) ? up : "UNKNOWN");
}

function cacheFileName(name) {
	const safe = String(name).toLowerCase().replace(/\/+/g, "__").replace(/[^a-z0-9._-]+/g, "%");
	return `${safe}.json`;
}

function readCache(cacheDir, name, { ignoreTtl = false } = {}) {
	const p = path.join(cacheDir, cacheFileName(name));
	try {
		const data = JSON.parse(fs.readFileSync(p, "utf8"));
		// Legacy empty entries may have come from omitted packages or malformed
		// responses, so they cannot establish a clean answer after the schema fix.
		if (Array.isArray(data.body) && (data._schema === 2 || data.body.length) &&
			(ignoreTtl || Date.now() - data._fetchedAt < CACHE_TTL_MS)) return data.body;
	} catch { /* miss */ }
	return null;
}

function writeCache(cacheDir, name, body) {
	try {
		fs.mkdirSync(cacheDir, { recursive: true });
		fs.writeFileSync(path.join(cacheDir, cacheFileName(name)), JSON.stringify({ _schema: 2, _fetchedAt: Date.now(), body }));
	} catch { /* a cache write failure must never kill the scan */ }
}

// Concrete = a resolvable version, never a range ("1.2.*", "^1.2", "dev-main", ">=5").
// A TAGGED pre-release or patch release ("2.0.0-beta1", "2.4.3-p1") is concrete too —
// composer.lock records it as installed, and dropping it silently lost every advisory
// for it; the evaluator above orders those exactly as Composer does. A "-dev" build is
// not: it names a moving branch tip, not a release an advisory range was written for.
function isConcreteVersion(v) {
	const parsed = parseComposerVersion(v);
	return !!parsed && parsed.stab !== "dev" && !parsed.dev;
}

function belongsToOtherComposerRegistry(depRecord) {
	const name = `${depRecord.namespace || ""}/${depRecord.name}`.toLowerCase();
	// Adobe distributes its product and bundled Magento packages through
	// repo.magento.com, which requires credentials. An absent Packagist record for
	// them is expected and must not be interpreted as an empty advisory list.
	return name.startsWith("magento/") || (depRecord.occurrences || [])
		.some(occurrence => occurrence.distHost === "repo.magento.com");
}

/** The best finding id: CVE over remote GHSA over the Packagist advisoryId. */
function advisoryPrimaryId(adv) {
	if (/^CVE-\d{4}-\d{4,}$/i.test(String(adv.cve || ""))) return adv.cve;
	const ghsa = advisoryAliases(adv).find(id => /^GHSA-[a-z0-9-]+$/i.test(id));
	if (ghsa) return ghsa;
	return adv.advisoryId || null;
}

function advisoryAliases(adv) {
	return [...new Set([adv.advisoryId, adv.remoteId, adv.cve,
		...(Array.isArray(adv.sources) ? adv.sources.map(source => source?.remoteId) : [])]
		.filter(value => typeof value === "string" && value.trim()))];
}

/** One advisory → a vigievuln match (the shape mergeBySource consumes). */
function advisoryToMatch(depRecord, adv) {
	const id = advisoryPrimaryId(adv);
	if (!id) return null;
	const aliases = advisoryAliases(adv);
	const ghsa = aliases.find(alias => /^GHSA-[a-z0-9-]+$/i.test(alias)) || null;
	const refs = [];
	if (/^https?:\/\//i.test(String(adv.link || ""))) refs.push({ type: "ADVISORY", url: adv.link });
	return {
		dep: depRecord,
		cve: {
			id,
			severity: normalizeSeverity(adv.severity),
			score: null,
			description: String(adv.title || "").trim(),
			summary: String(adv.title || "").trim(),
			fixVersion: fixVersionFromConstraint(depRecord.version, adv.affectedVersions),
			ghsa,
			published: adv.reportedAt || null,
			osvRefs: refs,
			aliases,
		},
		source: "packagist",
		confidence: "exact",
	};
}

/**
 * Pure: evaluate a per-package advisory map against the resolved composer deps.
 * `advisoriesByPkg` is keyed by lowercase `vendor/name` (the API response's advisories map).
 */
function collectPackagistMatches(resolvedDeps, advisoriesByPkg) {
	const matches = [];
	if (!resolvedDeps || !advisoriesByPkg) return matches;
	const byPkg = new Map();
	for (const [name, list] of Object.entries(advisoriesByPkg)) {
		if (Array.isArray(list)) byPkg.set(String(name).toLowerCase(), list);
	}
	for (const depRecord of resolvedDeps.values()) {
		if (depRecord.ecosystem !== "composer") continue;
		const pkgName = `${depRecord.namespace || ""}/${depRecord.name}`.toLowerCase();
		const advisories = byPkg.get(pkgName);
		if (!advisories || !advisories.length) continue;
		const versions = (depRecord.versions && depRecord.versions.length ? depRecord.versions : [depRecord.version])
			.filter(isConcreteVersion);
		for (const ver of versions) {
			const perVersion = { ...depRecord, version: ver };
			for (const adv of advisories) {
				if (!adv || typeof adv.affectedVersions !== "string") continue;
				if (satisfiesComposerConstraint(ver, adv.affectedVersions) !== true) continue;
				const match = advisoryToMatch(perVersion, adv);
				if (match) matches.push(match);
			}
		}
	}
	return matches;
}

/**
 * Query the Packagist security-advisories endpoint for every resolved composer dep's
 * package names, then evaluate the returned constraints per concrete version.
 * Returns vigievuln-shape matches (source: "packagist").
 */
async function queryPackagistAudit(resolvedDeps, opts = {}) {
	const { verbose, offline, fetcher = globalThis.fetch, cacheDir = DEFAULT_CACHE_DIR, onProgress, onSkipped, onUnknown } = opts;
	const advisoriesByPkg = {};
	const names = new Set();
	const skipped = new Set();
	const unknown = new Set();
	for (const depRecord of (resolvedDeps ? resolvedDeps.values() : [])) {
		if (depRecord.ecosystem !== "composer") continue;
		if (belongsToOtherComposerRegistry(depRecord)) {
			skipped.add(`${depRecord.namespace || ""}/${depRecord.name}`.toLowerCase());
			continue;
		}
		const versions = (depRecord.versions && depRecord.versions.length ? depRecord.versions : [depRecord.version]);
		if (!versions.some(isConcreteVersion)) continue;
		names.add(`${depRecord.namespace || ""}/${depRecord.name}`.toLowerCase());
	}
	if (skipped.size && onSkipped) onSkipped([...skipped].sort());
	if (!names.size) return [];

	const missing = [];
	for (const name of names) {
		const hit = !offline && require("./providers").hasHostedProxy() ? null : readCache(cacheDir, name, { ignoreTtl: !!offline });
		if (hit !== null) advisoriesByPkg[name] = hit;
		else missing.push(name);
	}

	if (missing.length && !offline) {
		const batches = [];
		for (let i = 0; i < missing.length; i += BATCH_SIZE) batches.push(missing.slice(i, i + BATCH_SIZE));
		for (let i = 0; i < batches.length; i++) {
			if (onProgress) onProgress(i + 1, batches.length);
			else if (verbose && batches.length > 1) console.log(`   Packagist audit batch ${i + 1}/${batches.length} (${batches[i].length} packages)…`);
			const url = `${PACKAGIST_AUDIT_API}?${batches[i].map(n => `packages[]=${encodeURIComponent(n)}`).join("&")}`;
			try {
				const res = await require("./providers").getResource("packagist", "advisories", { packages: batches[i] },
					{ fetcher, headers: { "User-Agent": "vigievuln-packagist-audit", Accept: "application/json" } });
				if (!res.ok) throw new Error(`Packagist audit HTTP ${res.status}`);
				const data = await res.json();
				const got = data?.advisories;
				// PHP serializes an empty advisory map as [] when no queried package is
				// known. A non-empty list remains an invalid response.
				if (!got || typeof got !== "object" || (Array.isArray(got) && got.length))
					throw new Error("Packagist audit response is missing its advisories object");
				const byName = new Map(Object.entries(got).map(([name, list]) => [name.toLowerCase(), list]));
				// Packagist documents an omitted package as "no data". Preserve that
				// coverage gap in the report; never cache it as a clean result.
				for (const name of batches[i]) {
					if (!byName.has(name)) { unknown.add(name); continue; }
					if (!Array.isArray(byName.get(name)))
						throw new Error(`Packagist audit has invalid advisory list for ${name}`);
					if (byName.get(name).some(adv => !adv || typeof adv.advisoryId !== "string" ||
						typeof adv.affectedVersions !== "string"))
						throw new Error(`Packagist audit has invalid advisory records for ${name}`);
				}
				for (const name of batches[i]) {
					if (!byName.has(name)) continue;
					advisoriesByPkg[name] = byName.get(name);
					writeCache(cacheDir, name, advisoriesByPkg[name]);
				}
			} catch (err) {
				throw new Error(`Packagist audit batch ${i + 1}/${batches.length} failed: ${err.message}`, { cause: err });
			}
		}
	}
	if (unknown.size && onUnknown) onUnknown([...unknown].sort());

	return collectPackagistMatches(resolvedDeps, advisoriesByPkg);
}

module.exports = {
	satisfiesComposerConstraint,
	cmpComposerVersions,
	fixVersionFromConstraint,
	collectPackagistMatches,
	queryPackagistAudit,
	belongsToOtherComposerRegistry,
	PACKAGIST_AUDIT_API,
	DEFAULT_CACHE_DIR,
};
