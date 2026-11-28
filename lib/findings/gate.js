/**
 * lib/findings/gate.js — CI gating: decide whether a finding set should fail the build.
 *
 * Levels: none | low | medium | high | critical | kev. A severity level fails
 * when any (non-suppressed) match is at or above it; `kev` fails only on a CISA
 * known-exploited finding — the modern "patch what's actually attacked" gate.
 * Pure — the caller sets process.exitCode.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const SEV_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * evaluateGate(matches, level) → { failed, reason, count, level }.
 * `matches` should already exclude cpe-filtered/dev — typically the prodActive set.
 */
function evaluateGate(matches, level) {
	const lvl = String(level || "none").toLowerCase();
	const active = (matches || []).filter(m => !m.suppressed);
	if (lvl === "none") return { failed: false, reason: "gating disabled", count: 0, level: lvl };

	if (lvl === "kev") {
		const hits = active.filter(m => m.cve?.kev);
		return {
			failed: hits.length > 0,
			count: hits.length,
			level: lvl,
			reason: hits.length ? `${hits.length} known-exploited (CISA KEV) finding(s)` : "no known-exploited finding",
		};
	}

	const threshold = SEV_RANK[lvl];
	if (threshold == null) return { failed: false, reason: `unknown level "${lvl}"`, count: 0, level: lvl };
	const hits = active.filter(m => (SEV_RANK[(m.cve?.severity || "none").toLowerCase()] ?? 0) >= threshold);
	return {
		failed: hits.length > 0,
		count: hits.length,
		level: lvl,
		reason: hits.length ? `${hits.length} finding(s) at or above ${lvl}` : `no finding at or above ${lvl}`,
	};
}

module.exports = { evaluateGate, SEV_RANK };
