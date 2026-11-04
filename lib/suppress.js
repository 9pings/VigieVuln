/**
 * lib/suppress.js — triage: suppress accepted-risk / false-positive findings so
 * re-audits of the same codebase stay signal-rich.
 *
 * Two inputs:
 *   --ignore <file> : plain text rules, one per line:
 *        CVE-2021-44228                  # suppress this CVE everywhere
 *        CVE-2021-44228 org.apache.*     # …only for matching coord/purl (glob)
 *        * com.acme.internal:*           # any CVE for these coords
 *        anything after '#' is a reason
 *   --vex <file>    : a CSAF VEX document — CVEs whose product_status is
 *        known_not_affected / fixed are suppressed (round-trips fad's own
 *        --report-csaf output; products mapped back to coords via their purl).
 *
 * Pure parsing + matching; the caller reads the files and mutates matches.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { purlFor } = require("./purl");

function coordOf(dep) {
	const ns = dep.namespace || dep.groupId || "";
	const name = dep.name || dep.artifactId;
	if (dep.ecosystem === "maven" && ns) return `${ns}:${name}`;
	if (dep.ecosystem === "composer" && ns) return `${ns}/${name}`;
	return name;
}

// Glob → anchored RegExp ('*' = any run). Everything else is literal.
function globToRe(glob) {
	const esc = String(glob).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
	return new RegExp(`^${esc}$`);
}

/** Parse an --ignore file body into rules [{ cve, coordRe, coord, reason }]. */
function parseIgnoreFile(text) {
	const rules = [];
	for (const raw of String(text || "").split(/\r?\n/)) {
		const hash = raw.indexOf("#");
		const reason = hash >= 0 ? raw.slice(hash + 1).trim() : null;
		const line = (hash >= 0 ? raw.slice(0, hash) : raw).trim();
		if (!line) continue;
		const parts = line.split(/\s+/);
		const cve = parts[0];
		const coord = parts[1] || null;
		rules.push({ cve, coord, coordRe: coord ? globToRe(coord) : null, reason: reason || "ignored" });
	}
	return rules;
}

/** Parse a CSAF VEX document into suppression rules for not_affected/fixed CVEs. */
function parseVex(csaf) {
	const rules = [];
	if (!csaf || typeof csaf !== "object") return rules;
	// product_id → purl, to map suppressed products back to coordinates.
	const purlByPid = new Map();
	for (const p of csaf.product_tree?.full_product_names || []) {
		const purl = p.product_identification_helper?.purl;
		if (p.product_id && typeof purl === "string") purlByPid.set(p.product_id, purl);
	}
	for (const v of csaf.vulnerabilities || []) {
		const cve = v.cve;
		if (!cve) continue;
		const cleared = [
			...(v.product_status?.known_not_affected || []),
			...(v.product_status?.fixed || []),
		];
		// No clearance means no exemption, including known_affected and
		// under_investigation. Empty lists must never become global rules.
		if (!cleared.length) continue;
		for (const pid of cleared) {
			if ((v.product_status?.known_affected || []).includes(pid) ||
				(v.product_status?.under_investigation || []).includes(pid)) continue;
			const purl = purlByPid.get(pid);
			// A product we can't map back to a coord must NOT become a coordRe:null
			// rule — that would suppress this CVE for EVERY dependency (a security
			// false-negative). Skip it: a product-scoped clearance only ever narrows.
			if (!purl) continue;
			const status = (v.product_status?.fixed || []).includes(pid) ? "fixed" : "known_not_affected";
			// PURLs do not distinguish physical occurrences. A clearance for one
			// product cannot clear an affected/unknown sibling with that same PURL.
			const siblings = [...purlByPid].filter(([, value]) => value === purl).map(([id]) => id);
			if (siblings.some(id => !(v.product_status?.[status] || []).includes(id))) continue;
			if ((csaf.vulnerabilities || []).some(other => other.cve === cve &&
				[...(other.product_status?.known_affected || []), ...(other.product_status?.under_investigation || [])]
					.some(id => purlByPid.get(id) === purl))) continue;
			// Imported identities are exact PURLs, never user-authored ignore globs.
			rules.push({ cve, coord: purl, purl, reason: `VEX: ${status}`, status });
		}
	}
	return rules;
}

/** Explicit ignore rules can use any identifier of the merged finding.
 * VEX remains primary-id exact: alias expansion would also need conflict analysis
 * across all VEX entries, not merely an alias lookup on a clearance. */
function ruleMatches(rule, m) {
	const ids = rule.purl ? [m.cve?.id] : [m.cve?.id, m.cve?.ghsa,
		...(Array.isArray(m.cve?.aliases) ? m.cve.aliases : [])].filter(id => typeof id === "string");
	if (rule.cve && rule.cve !== "*" && !ids.includes(rule.cve)) return false;
	if (rule.purl) return rule.purl === purlFor(m.dep);
	if (!rule.coordRe) return true;
	const coord = coordOf(m.dep);
	const purl = purlFor(m.dep) || "";
	return rule.coordRe.test(coord) || rule.coordRe.test(purl) || rule.coordRe.test(m.dep.name || "");
}

/** Signal an explicit global wildcard without rejecting the user's triage policy. */
function hasGlobalIgnoreRule(rules) {
	return (rules || []).some(rule => rule.cve === "*" && !rule.purl &&
		(!rule.coord || /^\*+$/.test(rule.coord)));
}

/** Build a matcher from a flat rule list. */
function buildSuppressor(rules) {
	return (m) => {
		for (const r of rules || []) if (ruleMatches(r, m)) return { suppressed: true, reason: r.reason, ...(r.status ? { status: r.status } : {}) };
		return null;
	};
}

/** Mark matches in place; returns the number suppressed. */
function applySuppressions(matches, rules) {
	const suppressor = buildSuppressor(rules);
	let n = 0;
	for (const m of matches || []) {
		const hit = suppressor(m);
		if (hit) { m.suppressed = true; m.suppressedReason = hit.reason; if (hit.status) m.suppressionStatus = hit.status; n++; }
	}
	return n;
}

module.exports = { parseIgnoreFile, parseVex, buildSuppressor, applySuppressions, globToRe, hasGlobalIgnoreRule };
