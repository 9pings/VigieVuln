/**
 * lib/gap-adjudicate.js — adjudicate a claimed false negative against the public record.
 *
 * Context. A comparative benchmark produces pairs another scanner found and vigievuln
 * did not. It is tempting to treat that list as a recall backlog and start widening the
 * matcher until it shrinks. That is how a scanner acquires mass false positives, because
 * a claimed miss is only a real miss when the public record actually binds that
 * vulnerability to that coordinate AND that version.
 *
 * This module answers, per pair, which of those it is — using the SAME range evaluation
 * the scanner itself uses (`lib/osv-db`.vulnAffectsVersion), so a verdict of
 * CONFIRMED_MISS means "fad had the data and still didn't report it", never "the two
 * implementations disagree".
 *
 * It is pure: callers fetch the OSV record (see `scripts/adjudicate-gap.js`) and pass it
 * in. No fixture database ships with it — the authority is OSV at the time you ask.
 *
 * A note on OSV semantics, because misreading it is the specific error this guards:
 * `affected[].versions` is the list of **affected** versions, NOT the versions that carry
 * the fix. `{introduced: 1.2.12, fixed: 1.2.13}` means 1.2.12 is vulnerable and anything
 * below it is not. Reading that list as "fixed in" inverts every verdict.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { vulnAffectsVersion } = require("./osv-db");

const VERDICT = {
	// OSV has no such advisory. Usually a vendor-proprietary id, but NOT a claim that no
	// public database has it: NVD carries entries OSV does not. Named for what is actually
	// checked, because "in no public database" would be an overclaim.
	NOT_IN_OSV: "NOT_IN_OSV",
	// The advisory exists but binds no Maven package (typically a GIT commit range only),
	// so no ecosystem query can return it. Unreachable without curation.
	NO_MAVEN_BINDING: "NO_MAVEN_BINDING",
	// The advisory binds Maven coordinates, but not the one claimed.
	WRONG_ARTIFACT: "WRONG_ARTIFACT",
	// Right coordinate, but the claimed version sits outside every declared range.
	OUT_OF_RANGE: "OUT_OF_RANGE",
	// Coordinate and version both match the public record: fad had the data to find it.
	CONFIRMED_MISS: "CONFIRMED_MISS",
	// Already in the scanner's output under one of the vulnerability's other identifiers.
	// A vulnerability routinely carries a CVE and several GHSA ids that alias each other,
	// so comparing raw ids invents misses that do not exist.
	ALREADY_REPORTED: "ALREADY_REPORTED",
};

// Only the last one is a recall bug. WRONG_ARTIFACT and OUT_OF_RANGE are the other tool
// disagreeing with the public record — chasing them is how you manufacture noise.
const REAL_GAP = new Set([VERDICT.CONFIRMED_MISS]);

/**
 * OSV stores the same vulnerability more than once: the record converted from the CVE
 * (often a GIT commit range and nothing else) and the GHSA alias that actually binds it
 * to ecosystem packages. Adjudicating against whichever one you happened to fetch first
 * gives the wrong verdict — the CVE record alone looks like "no ecosystem binding". Union
 * their `affected` sets and judge against the whole public record.
 */
function mergeRecords(records) {
	const recs = (records || []).filter(Boolean);
	if (!recs.length) return null;
	const withBinding = recs.find(r => (r.affected || []).some(a => a.package));
	return {
		id: (withBinding || recs[0]).id,
		aliases: [...new Set(recs.flatMap(r => [r.id, ...(r.aliases || [])]).filter(Boolean))],
		affected: recs.flatMap(r => r.affected || []),
	};
}

const mavenAffected = rec => (rec.affected || []).filter(a => a.package && a.package.ecosystem === "Maven");

/**
 * @param {{coord: string, version: string}} pair  Maven "groupId:artifactId" + version.
 * @param {object|null} osvRecord  The OSV vuln object, or null when OSV has no such id.
 * @returns {{verdict: string, coord: string, version: string, id: string|null, boundCoords: string[]}}
 */
function classifyPair(pair, osvRecord) {
	const base = { coord: pair.coord, version: pair.version, id: osvRecord ? osvRecord.id : (pair.id || null),
		aliases: osvRecord ? (osvRecord.aliases || [osvRecord.id]) : (pair.ids || []), boundCoords: [] };
	if (!osvRecord) return { ...base, verdict: VERDICT.NOT_IN_OSV };

	const affected = mavenAffected(osvRecord);
	if (!affected.length) return { ...base, verdict: VERDICT.NO_MAVEN_BINDING };

	const boundCoords = [...new Set(affected.map(a => a.package.name))];
	const mine = affected.filter(a => a.package.name === pair.coord);
	if (!mine.length) return { ...base, boundCoords, verdict: VERDICT.WRONG_ARTIFACT };

	// Reuse the scanner's own evaluator so a CONFIRMED_MISS is actionable by definition.
	const hit = vulnAffectsVersion(pair.version, { affected: mine });
	return { ...base, boundCoords, verdict: hit ? VERDICT.CONFIRMED_MISS : VERDICT.OUT_OF_RANGE };
}

/** `coord@version|id` — the key a scanner's own output is indexed by. */
const foundKey = (coord, version, id) => `${coord}@${version}|${id}`;

/**
 * Downgrade the misses the scanner in fact already reports under another identifier.
 * Without this the count is inflated by pure id bookkeeping: OSV links a CVE and its
 * GHSA twins as aliases, and each side of a comparison may have picked a different one.
 */
function reconcileFound(rows, foundSet) {
	if (!foundSet || !foundSet.size) return rows;
	return rows.map(r => {
		if (r.verdict !== VERDICT.CONFIRMED_MISS) return r;
		const ids = r.aliases && r.aliases.length ? r.aliases : [r.id].filter(Boolean);
		const seen = ids.some(i => foundSet.has(foundKey(r.coord, r.version, i)));
		return seen ? { ...r, verdict: VERDICT.ALREADY_REPORTED } : r;
	});
}

/** Roll a list of classified rows into counts + the one number that matters. */
function summarize(rows) {
	const counts = Object.fromEntries(Object.values(VERDICT).map(v => [v, 0]));
	for (const r of rows) counts[r.verdict] = (counts[r.verdict] || 0) + 1;
	return {
		total: rows.length,
		counts,
		realGap: rows.filter(r => REAL_GAP.has(r.verdict)).length,
	};
}

module.exports = { classifyPair, summarize, mergeRecords, reconcileFound, foundKey, VERDICT, REAL_GAP };
