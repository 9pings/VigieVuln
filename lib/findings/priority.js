/**
 * lib/findings/priority.js — composite prioritisation of a CVE match.
 *
 * Blends three independent signals the report already carries:
 *   - CVSS base score (severity of the flaw if exploited)
 *   - EPSS percentile (likelihood it WILL be exploited — lib/providers/epss/enrich.js)
 *   - CISA KEV membership (it IS being exploited in the wild — lib/providers/kev/enrich.js)
 *
 * KEV always wins (band "exploited", score floored at 90). Otherwise the score
 * is an 80/20 blend of CVSS and EPSS percentile. Pure — no I/O.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const SEV_SCORE = { CRITICAL: 9.5, HIGH: 7.5, MEDIUM: 5, LOW: 2, NONE: 0, UNKNOWN: 0 };

function severityToScore(sev) {
	return SEV_SCORE[(sev || "UNKNOWN").toUpperCase()] ?? 0;
}

function clamp(n, lo, hi) {
	return Math.max(lo, Math.min(hi, n));
}

/**
 * Compute a priority object for a cve sub-record.
 * Returns { score (0-100), band, cvss, epssPercentile, kev, sortKey }.
 */
function computePriority(cve = {}) {
	const hasCvss = typeof cve.score === "number" && cve.score > 0;
	const hasSeverity = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].includes(String(cve.severity || "").toUpperCase());
	const epssKnown = typeof cve.epssPercentile === "number";
	const epssPercentile = epssKnown ? clamp(cve.epssPercentile, 0, 1) : 0;
	const kev = !!cve.kev;
	if (!hasCvss && !hasSeverity && !kev) {
		return { score: null, band: "unknown", cvss: null, epssPercentile, kev: false, sortKey: [0, -1] };
	}
	// A literal 0 is treated as "no CVSS" and we fall back to the severity label:
	// enrichers emit null for scoreless CVEs, so a 0 here is a placeholder, and a
	// CRITICAL-labelled finding must not band as "low" just because score===0.
	const cvss = hasCvss ? cve.score : severityToScore(cve.severity);

	// When EPSS is known, blend 80% CVSS + 20% exploit-likelihood (so a known-low
	// EPSS slightly deprioritises a high-CVSS flaw). When EPSS is absent we don't
	// dilute — a CVSS 9.8 with no EPSS data must still read as critical.
	let score = epssKnown
		? clamp(cvss * 10 * 0.8 + epssPercentile * 100 * 0.2, 0, 100)
		: clamp(cvss * 10, 0, 100);
	let band;
	if (kev) {
		score = Math.max(score, 90);
		band = "exploited";
	} else if (score >= 90) band = "critical";
	else if (score >= 70) band = "high";
	else if (score >= 40) band = "medium";
	else band = "low";

	const rounded = Math.round(score * 10) / 10;
	return {
		score: rounded,
		band,
		cvss: cve.severityScheme === "drupal-rating" && !hasCvss ? null : cvss,
		epssPercentile,
		kev,
		// Descending-sort tuple, aligned with the displayed score: exploited
		// first, then the blended score (which already folds in CVSS + EPSS).
		sortKey: [kev ? 1 : 0, rounded],
	};
}

/** Attach m.cve.priority to every match in place. */
function attachPriority(matches) {
	for (const m of matches || []) {
		if (m && m.cve) m.cve.priority = computePriority(m.cve);
	}
	return matches;
}

/** Compare two matches descending by priority sortKey, then CVE id ascending. */
function comparePriority(a, b) {
	const pa = a.cve?.priority || computePriority(a.cve);
	const pb = b.cve?.priority || computePriority(b.cve);
	for (let i = 0; i < pa.sortKey.length; i++) {
		if (pb.sortKey[i] !== pa.sortKey[i]) return pb.sortKey[i] - pa.sortKey[i];
	}
	return (a.cve?.id || "").localeCompare(b.cve?.id || "");
}

/** Return a new array sorted descending by priority. */
function sortByPriority(matches) {
	return [...(matches || [])].sort(comparePriority);
}

module.exports = { computePriority, attachPriority, comparePriority, sortByPriority, severityToScore };
