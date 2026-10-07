/**
 * Is a version affected by an OSV record? Same evaluation as fad (lib/osv-db.js, the OSV
 * schema's reference algorithm), with the ordering of the package's ecosystem.
 *
 * Zero false positive: a verdict is given only where the ordering is exact — Maven
 * (fad's ComparableVersion, checked against Maven itself), npm and Go (SemVer 2.0
 * precedence, prereleases below their release). Elsewhere only the record's explicit
 * `versions` list counts; a range is shown as text, never turned into a verdict.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { fad } = require("../fad");

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** SemVer 2.0 precedence; null when either side is not a semver. */
function compareSemver(a, b) {
	const x = SEMVER.exec(String(a)), y = SEMVER.exec(String(b));
	if (!x || !y) return null;
	for (let i = 1; i <= 3; i++) { const d = Number(x[i]) - Number(y[i]); if (d) return Math.sign(d); }
	if (!x[4] && !y[4]) return 0;
	if (!x[4]) return 1;                    // a release is above its prereleases
	if (!y[4]) return -1;
	const p = x[4].split("."), q = y[4].split(".");
	for (let i = 0; i < Math.max(p.length, q.length); i++) {
		if (p[i] === undefined) return -1;
		if (q[i] === undefined) return 1;
		const pn = /^\d+$/.test(p[i]), qn = /^\d+$/.test(q[i]);
		if (pn && qn) { const d = Number(p[i]) - Number(q[i]); if (d) return Math.sign(d); }
		else if (pn !== qn) return pn ? -1 : 1;
		else if (p[i] !== q[i]) return p[i] < q[i] ? -1 : 1;
	}
	return 0;
}

/** The comparator of a purl type, or null (no verdict from ranges there). */
function comparatorFor(type) {
	if (type === "maven") return fad("maven-version").compareMavenVersions;
	if (type === "npm" || type === "golang") return compareSemver;
	return null;
}

const RANK = { introduced: 0, last_affected: 1, fixed: 2 };

/** One OSV range → affected?, null when it cannot be decided with this comparator. */
function rangeAffects(version, range, cmp) {
	if (!range || range.type === "GIT" || !cmp) return null;
	const c = (a, b) => (a === "0" || b === "0") ? (a === b ? 0 : (a === "0" ? -1 : 1)) : cmp(a, b);
	const events = [], limits = [];
	for (const e of range.events || []) {
		if (e.limit !== undefined) { limits.push(String(e.limit)); continue; }
		const kind = ["introduced", "fixed", "last_affected"].find(k => e[k] !== undefined);
		if (kind) events.push({ kind, at: String(e[kind]) });
	}
	for (const e of events) if (c(version, e.at) === null) return null;
	if (limits.length && !limits.some(l => l === "*" || c(version, l) < 0)) return false;
	events.sort((a, b) => c(a.at, b.at) || (RANK[a.kind] - RANK[b.kind]));
	let affected = false;
	for (const e of events) {
		const d = c(version, e.at);
		if (e.kind === "introduced") { if (d >= 0) affected = true; }
		else if (e.kind === "fixed") { if (d >= 0) affected = false; }
		else if (d > 0) affected = false;
	}
	return affected;
}

/**
 * → true (affected), false (proven not affected) or null (no verdict) for one version of
 * one package, given the record's `affected` entries for that package.
 */
function versionAffected(type, version, affectedEntries) {
	const cmp = comparatorFor(type);
	let undecided = false;
	for (const a of affectedEntries || []) {
		if ((a.versions || []).includes(version)) return true;
		for (const r of a.ranges || []) {
			const v = rangeAffects(version, r, cmp);
			if (v === true) return true;
			if (v === null) undecided = true;
		}
		if (!(a.ranges || []).length && !(a.versions || []).length) undecided = true;
	}
	return undecided ? null : false;
}

module.exports = { compareSemver, comparatorFor, rangeAffects, versionAffected };
