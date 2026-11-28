/**
 * lib/codecs/maven/version.js — Maven-flavoured version parsing and comparison.
 *
 * Maven version ordering rules (approximation of Apache Maven's
 * ComparableVersion):
 *   - Versions are split on `.` and `-` into segments.
 *   - Numeric segments compare numerically.
 *   - String segments compare via a qualifier ordering:
 *       alpha < beta < milestone < rc < snapshot < "" (release) < sp
 *   - Trailing zeros are insignificant: 1.0 == 1.0.0 == 1.
 *   - Known release qualifiers (final, release, ga) are treated as "".
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

// Lower number == lower precedence
const QUALIFIER_ORDER = {
	"alpha": 1, "a": 1,
	"beta": 2, "b": 2,
	"milestone": 3, "m": 3,
	"rc": 4, "cr": 4,
	"snapshot": 5,
	"": 6, "ga": 6, "final": 6, "release": 6,
	"sp": 7,
};

function parseMavenVersion(versionStr) {
	if (versionStr == null) return { original: "", segments: [] };
	const original = String(versionStr).trim();
	if (!original) return { original: "", segments: [] };

	// Split on `.` and `-`, lowercase string segments. The separator BEFORE each segment is
	// kept: Maven opens a sub-list at `-`, so 1.0.1 (after `.`) is newer than 1.0-1.
	const lower = original.toLowerCase();
	const raw = lower.split(/[.\-]/);
	const seps = [".", ...(lower.match(/[.\-]/g) || [])];
	// A digit→letter transition is a separator too (Maven: 1.0a1 = 1.0-a1, alpha 1).
	const split = raw.flatMap((s, i) => {
		const m = /^(\d+)([a-z].*)$/.exec(s);
		return m ? [[m[1], seps[i]], [m[2], "-"]] : [[s, seps[i]]];
	});
	const segments = split.map(([s, sep]) => {
		if (/^\d+$/.test(s)) return { kind: "num", value: parseInt(s, 10), sep };
		// Embedded numbers (e.g. "rc1" → ["rc", 1])
		const m = s.match(/^([a-z]+)(\d+)$/);
		if (m) return { kind: "qual+num", qual: m[1], num: parseInt(m[2], 10), sep };
		return { kind: "str", value: s, sep };
	});
	return { original, segments };
}

// Maven's ComparableVersion: "unknown qualifiers are considered after known qualifiers,
// with lexical order". So 32.0.0-jre / -android / Jetty's .v20230217 / -redhat-1 are all
// NEWER than the bare release. Ranking them just below it made guava 32.0.0-jre "affected"
// by every CVE fixed in 32.0.0 — the very release it is.
const UNKNOWN_QUALIFIER_RANK = 8;
function qualifierRank(q) {
	if (q == null) return QUALIFIER_ORDER[""];
	const r = QUALIFIER_ORDER[q.toLowerCase()];
	return r != null ? r : UNKNOWN_QUALIFIER_RANK;
}
/** Two qualifiers: by rank, and lexically when both are unknown. */
function compareQualifiers(a, b) {
	const d = qualifierRank(a) - qualifierRank(b);
	if (d !== 0) return d;
	if (qualifierRank(a) === UNKNOWN_QUALIFIER_RANK) return String(a).localeCompare(String(b));
	return 0;
}

function qualOf(seg) {
	if (!seg) return null;
	if (seg.kind === "str") return seg.value;
	if (seg.kind === "qual+num") return seg.qual;
	return null;
}

function cmpSegments(a, b) {
	// a or b may be missing — treat as numeric 0 (trailing zeros are insignificant)
	if (!a) {
		if (b.kind === "num") return b.value === 0 ? 0 : -1;
		// b is a qualifier (str or qual+num) — pre-release < release
		return qualifierRank("") - qualifierRank(qualOf(b));
	}
	if (!b) {
		if (a.kind === "num") return a.value === 0 ? 0 : 1;
		return qualifierRank(qualOf(a)) - qualifierRank("");
	}
	if (a.kind === "num" && b.kind === "num") {
		// Same position, different separators (1.0.1 vs 1.0-1): the `.` item is newer —
		// Maven compares an IntItem against a ListItem. Only for significant (non-zero) items,
		// since a trailing .0 is normalised away (1.0-1 > 1.0.0).
		if (a.sep !== b.sep && a.value !== 0 && b.value !== 0) return a.sep === "." ? 1 : -1;
		return a.value - b.value;
	}
	// A number against any qualifier — pre-release, sp or unknown alike: the number is
	// newer (Maven: IntItem > StringItem). 1.0.1 > 1.0-sp, 1.0.1 > 1.0-jre, 1.0.1 > 1.0-rc1.
	// A ZERO with no non-zero number after it is the normalised-away trailing item, so it compares like a missing one: the
	// qualifier against the release (5.0.0.sp1 > 5.0.0.0, 1.0.jre > 1.0.0, 1.0.rc1 < 1.0.0).
	if (a.kind === "num") return a.zeroTail ? QUALIFIER_ORDER[""] - qualifierRank(qualOf(b)) : 1;
	if (b.kind === "num") return b.zeroTail ? qualifierRank(qualOf(a)) - QUALIFIER_ORDER[""] : -1;
	if (a.kind === "qual+num" && b.kind === "qual+num") {
		const d = compareQualifiers(a.qual, b.qual);
		return d !== 0 ? d : a.num - b.num;
	}
	// rc vs rc1: same qualifier, the bare one counts as number 0 (Maven: 1-rc < 1-rc1).
	if (a.kind === "qual+num") return compareQualifiers(a.qual, b.value) || a.num;
	if (b.kind === "qual+num") return compareQualifiers(a.value, b.qual) || -b.num;
	return compareQualifiers(a.value, b.value);
}

// Mark each 0 that no non-zero number follows: Maven normalises it away (1.0.0 == 1,
// 1.0-rc1 == 1-rc1), whereas the leading 0 of 0.1.2 is significant.
function markZeroTail(segs) {
	let nonZeroAfter = false;
	for (let i = segs.length - 1; i >= 0; i--) {
		const s = segs[i];
		if (s.kind === "num") {
			s.zeroTail = s.value === 0 && !nonZeroAfter;
			if (s.value !== 0) nonZeroAfter = true;
		}
	}
	return segs;
}

function compareMavenVersions(aStr, bStr) {
	const a = markZeroTail(parseMavenVersion(aStr).segments);
	const b = markZeroTail(parseMavenVersion(bStr).segments);
	const n = Math.max(a.length, b.length);
	for (let i = 0; i < n; i++) {
		const c = cmpSegments(a[i], b[i]);
		if (c !== 0) return c < 0 ? -1 : 1;
	}
	return 0;
}

/**
 * Check whether a dependency version falls within a CVE-specified range.
 * spec shape: { version, status, lessThan, lessThanOrEqual, versionType }
 * Returns true if depVersion is affected.
 */
// A bound participates in comparisons only if it looks like a version. CVE 5.x
// records carry placeholders in these fields ("log4j-core*", "*", "unspecified")
// — comparing those as Maven versions is garbage (alpha sorts below numeric), so
// CVE-2021-44228's `lessThan: "log4j-core*"` used to unmatch every real version.
function versionLikeBound(s) {
	return s != null && /^[0-9]/.test(String(s).trim()) && String(s).trim() !== "0";
}

function isVersionAffected(depVersion, spec) {
	if (!spec) return false;
	if (spec.status && spec.status !== "affected") return false;

	const dep = parseMavenVersion(depVersion);
	if (!dep.segments.length) return false;

	const lower = versionLikeBound(spec.version) && spec.version !== "*" ? spec.version : null;
	const upperExcl = versionLikeBound(spec.lessThan) ? spec.lessThan : null;
	const upperIncl = versionLikeBound(spec.lessThanOrEqual) ? spec.lessThanOrEqual : null;

	// Fail-closed: a spec with no usable version constraint carries no information.
	// Without this guard the function falls through to `return true` for every input,
	// which was the H1 cascade described in CRITICAL-REVIEW.md. A wildcard/placeholder
	// upper on its own does not count ({version:"*", lessThan:"*"} must stay inert).
	if (!lower && !upperExcl && !upperIncl) return false;

	// Lower bound (inclusive)
	if (lower && compareMavenVersions(depVersion, lower) < 0) return false;
	// Upper bound exclusive
	if (upperExcl && compareMavenVersions(depVersion, upperExcl) >= 0) return false;
	// Upper bound inclusive
	if (upperIncl && compareMavenVersions(depVersion, upperIncl) > 0) return false;
	// Exact match with no upper of ANY kind (not even a wildcard) — only affected if
	// equal. A wildcard upper ({version:"2.0", lessThan:"log4j-core*"}) instead means
	// "from 2.0 onward, unbounded", so it must NOT collapse to an exact match.
	if (lower && spec.lessThan == null && spec.lessThanOrEqual == null) {
		if (compareMavenVersions(depVersion, lower) !== 0) return false;
	}
	return true;
}

/**
 * Parse a Maven version range expression like "[1.0,2.0)", "(,1.5]", "1.2.3".
 * Returns { lower, lowerInclusive, upper, upperInclusive, exact } or null.
 */
function parseRange(rangeStr) {
	if (rangeStr == null) return null;
	const s = String(rangeStr).trim();
	if (!s) return null;
	if (!/^[\[\(]/.test(s)) return { exact: s };
	const open = s[0];
	const close = s[s.length - 1];
	const inner = s.slice(1, -1);
	const [lo, hi] = inner.split(",").map(p => p.trim());
	return {
		lower: lo || null,
		lowerInclusive: open === "[",
		upper: hi || null,
		upperInclusive: close === "]",
	};
}

/**
 * Maven's hard-pin syntax: "[1.2.3]" means EXACTLY 1.2.3. It is a concrete version wearing
 * range brackets, and upstream POMs on Maven Central do use it (e.g. netty declares
 * "[4.1.35.Final]"). Unwrap it to the bare version.
 *
 * Keeping the brackets corrupts the coordinate for every consumer downstream — the report,
 * the purl, and the SBOM/CSAF/SARIF/JSON exports — and makes the finding un-joinable with any
 * other tool's output for the same dependency.
 *
 * A comma means a genuine range ("[1.0,2.0)", "(,1.5]") and is returned unchanged: choosing a
 * version out of a range is resolution, not normalisation, and an unresolved range should keep
 * surfacing as unresolved rather than silently becoming a concrete version.
 */
function normalizeHardPin(versionStr) {
	if (versionStr == null) return versionStr;
	const s = String(versionStr).trim();
	const pin = /^\[\s*([^,\[\]]+?)\s*\]$/.exec(s);
	return pin ? pin[1] : versionStr;
}


// Qualifiers that mean "not ready yet". Deliberately an explicit list and NOT "ranks below
// release": QUALIFIER_ORDER puts UNKNOWN qualifiers just under release, so a rank test would
// classify guava's `31.1-jre`, JBoss's `4.2.18.Final` and `1.0.0.RELEASE` as pre-releases and
// leave those coordinates with no version to recommend at all.
const PRERELEASE_QUALIFIERS = new Set(["alpha", "a", "beta", "b", "milestone", "m", "rc", "cr", "snapshot"]);

/** Does any segment of this version carry a pre-release qualifier? */
function isPrereleaseVersion(versionStr) {
	if (!versionStr) return false;
	for (const seg of parseMavenVersion(versionStr).segments) {
		const q = qualOf(seg);
		if (q && PRERELEASE_QUALIFIERS.has(String(q).toLowerCase())) return true;
	}
	return false;
}

/**
 * The version to recommend out of a maven-metadata.xml version list.
 *
 * Maven's own `<release>` is "latest non-SNAPSHOT" and therefore happily points at a beta —
 * on a real 165-coordinate reactor it does so 22 times. An audit report that tells a client
 * to move to `3.3.0-BETA` is worse than one that names a slightly stale stable version, so
 * the highest STABLE version wins.
 *
 * Exception: a dependency already sitting on a pre-release. Recommending the newest stable
 * would then be a downgrade, so pre-releases stay eligible for it.
 *
 * @param {string[]} versions
 * @param {{current?: string}} [opts] current version of the dependency, when known
 */
function latestStableVersion(versions, opts = {}) {
	const list = (versions || []).filter(Boolean);
	if (!list.length) return null;
	const sorted = [...list].sort(compareMavenVersions);
	const pool = (opts.current && isPrereleaseVersion(opts.current))
		? sorted
		: sorted.filter(v => !isPrereleaseVersion(v));
	// Nothing stable was ever published — name the newest rather than nothing.
	return (pool.length ? pool : sorted)[(pool.length ? pool : sorted).length - 1];
}

/**
 * Where THIS version's own branch gets the fix — not the lowest fix anywhere.
 *
 * An advisory carries one range per maintained branch: for CVE-2024-38820, 6.1.x is fixed in
 * 6.1.14 (open source) while 5.3.x is affected up to 5.3.40 and fixed in a commercial build.
 * A 5.3.39 user is told "6.1.14" by the lowest-fix rule — a major migration — when the answer
 * on their branch is "a build above 5.3.40". → { fixed: "x" } (first fixed version) or
 * { after: "x" } (last affected; the fix is any later build), or null when no range that
 * contains the version states its upper bound.
 *
 * `ranges` in CVE-record shape ({ version, lessThan, lessThanOrEqual }).
 */
function branchFixFromRanges(version, ranges) {
	for (const r of ranges || []) {
		if (!isVersionAffected(version, r)) continue;
		if (versionLikeBound(r.lessThan)) return { fixed: String(r.lessThan) };
		if (versionLikeBound(r.lessThanOrEqual)) return { after: String(r.lessThanOrEqual) };
	}
	return null;
}

/**
 * Same, from OSV `events` (any order — sorted here, "0" lowest, per the OSV schema).
 */
function branchFixFromOsvEvents(version, events) {
	const cmp = (a, b) => (a === "0" ? (b === "0" ? 0 : -1) : b === "0" ? 1 : compareMavenVersions(a, b));
	const ev = (events || []).map(e => ({ kind: Object.keys(e)[0], v: String(Object.values(e)[0]) }))
		.filter(e => ["introduced", "fixed", "last_affected"].includes(e.kind))
		.sort((x, y) => cmp(x.v, y.v));
	let start = null;
	for (const e of ev) {
		if (e.kind === "introduced") { start = e.v; continue; }
		if (start == null) continue;
		const inside = cmp(version, start) >= 0 && (e.kind === "fixed" ? cmp(version, e.v) < 0 : cmp(version, e.v) <= 0);
		if (inside) return e.kind === "fixed" ? { fixed: e.v } : { after: e.v };
		start = null;
	}
	return null;
}

/** The stricter of two branch fixes (the one a single upgrade must satisfy). */
function stricterBranchFix(a, b) {
	if (!a) return b; if (!b) return a;
	const va = a.fixed || a.after, vb = b.fixed || b.after;
	const c = compareMavenVersions(va, vb);
	if (c !== 0) return c > 0 ? a : b;
	return a.after ? a : b;             // same bound: "after x" (> x) is stricter than "fixed x" (≥ x)
}

/**
 * Maven version RANGES (`[1.0,2.0)`, `[1.0,)`, `(,1.0]`, `[1.0]`, unions `(,1.0],[1.2,)`).
 * A range is not a version: comparing "[1.0,2.0)" as one made it sort below everything, so
 * it matched every upper-bounded CVE. Maven resolves a range to the HIGHEST published
 * version inside it (maven-metadata.xml); a range nobody resolved is an unknown version.
 */
function isVersionRange(v) {
	return typeof v === "string" && /^\s*[\[(].*[\])]\s*$/.test(v);
}
function parseVersionRange(str) {
	if (!isVersionRange(str)) return null;
	const out = [];
	const re = /([\[(])([^\[\]()]*)([\])])/g;
	let m;
	while ((m = re.exec(str))) {
		const [lo, hi, ...rest] = m[2].split(",").map(x => x.trim());
		if (rest.length) return null;
		if (hi === undefined) {                       // [1.0] — exactly that version
			if (m[1] !== "[" || m[3] !== "]" || !lo) return null;
			out.push({ lower: lo, lowerInc: true, upper: lo, upperInc: true });
		} else {
			out.push({ lower: lo || null, lowerInc: m[1] === "[", upper: hi || null, upperInc: m[3] === "]" });
		}
	}
	return out.length ? out : null;
}
function versionInRange(v, intervals) {
	return (intervals || []).some(r => {
		if (r.lower) { const c = compareMavenVersions(v, r.lower); if (c < 0 || (c === 0 && !r.lowerInc)) return false; }
		if (r.upper) { const c = compareMavenVersions(v, r.upper); if (c > 0 || (c === 0 && !r.upperInc)) return false; }
		return true;
	});
}
/** Highest of `available` inside `range` (SNAPSHOTs excluded, like a release build). */
function resolveVersionRange(range, available) {
	const intervals = parseVersionRange(range);
	if (!intervals) return null;
	const hits = (available || []).filter(v => !/-SNAPSHOT$/i.test(v) && versionInRange(v, intervals));
	if (!hits.length) return null;
	return hits.sort(compareMavenVersions).at(-1);
}

module.exports = {
	branchFixFromRanges,
	branchFixFromOsvEvents,
	stricterBranchFix,
	isVersionRange,
	parseVersionRange,
	versionInRange,
	resolveVersionRange,
	parseMavenVersion,
	isPrereleaseVersion,
	latestStableVersion,
	compareMavenVersions,
	isVersionAffected,
	versionLikeBound,
	parseRange,
	normalizeHardPin,
};
