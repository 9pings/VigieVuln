/**
 * lib/inventory/license-policy.js — normalize free-form license strings to SPDX ids and
 * classify them into policy categories (permissive / copyleft / proprietary).
 *
 * Data-driven: data/license-policy.json holds the id→category table and an
 * alias map for the messy real-world strings registries and POMs emit
 * ("Apache 2.0", "The MIT License", "GNU GPLv3", …). Pure — no I/O at call time.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");

const POLICY = (() => {
	try {
		// require() (not fs.readFileSync) so bun --compile bundles the data file
		// into the standalone binary instead of reading it off disk at runtime.
		const raw = require("../../data/license-policy.json");
		return { categories: raw.categories || {}, aliases: raw.aliases || {} };
	} catch { return { categories: {}, aliases: {} }; }
})();

// Case-insensitive index of canonical SPDX ids for direct matches.
const CANON_BY_LOWER = new Map(Object.keys(POLICY.categories).map(id => [id.toLowerCase(), id]));

const FLAGGED_CATEGORIES = new Set(["strong-copyleft", "network-copyleft", "proprietary", "unknown"]);
// Most-restrictive-wins order when a dep has several licenses.
const CATEGORY_RANK = { permissive: 1, unknown: 2, "weak-copyleft": 3, proprietary: 4, "strong-copyleft": 5, "network-copyleft": 6 };

/** Normalize one license token to a canonical SPDX id, or null if unknown. */
function normalizeSpdx(raw) {
	if (raw == null) return null;
	// npm sometimes uses { type, url } objects.
	const s = (typeof raw === "object" ? (raw.type || raw.name || "") : String(raw)).trim();
	if (!s) return null;
	const lower = s.toLowerCase();
	if (CANON_BY_LOWER.has(lower)) return CANON_BY_LOWER.get(lower);
	if (POLICY.aliases[lower]) return POLICY.aliases[lower];
	// Tolerate a trailing "+" (or-later) and "-only" decorations.
	const stripped = lower.replace(/\+$/, "").trim();
	if (CANON_BY_LOWER.has(stripped)) return CANON_BY_LOWER.get(stripped);
	if (POLICY.aliases[stripped]) return POLICY.aliases[stripped];
	return null;
}

/** Split an SPDX expression / array / "A OR B" / "A/B" string into raw tokens. */
function splitExpression(raw) {
	if (Array.isArray(raw)) return raw.flatMap(splitExpression);
	if (raw == null) return [];
	if (typeof raw === "object") return [raw.type || raw.name || ""].filter(Boolean);
	return String(raw)
		.replace(/[()]/g, " ")
		.split(/\s+(?:OR|AND)\s+|\s+WITH\s+|[,/|]/i)
		.map(t => t.trim())
		.filter(Boolean);
}

/** Category for a canonical SPDX id (defaults to "unknown"). */
function classify(spdxId) {
	if (!spdxId) return "unknown";
	return POLICY.categories[spdxId] || "unknown";
}

/**
 * Resolve a dep's raw license value(s) into { ids, raw, category }.
 * `ids` are canonical SPDX (raw token kept when unmapped); `category` is the
 * most restrictive among them.
 */
function resolveDepLicense(rawValue) {
	const tokens = splitExpression(rawValue);
	if (!tokens.length) return { ids: [], raw: [], category: "unknown" };
	const ids = [];
	const rawKept = [];
	let best = "permissive";
	let bestRank = 0;
	let anyKnown = false;
	for (const tok of tokens) {
		const id = normalizeSpdx(tok);
		if (id) { ids.push(id); anyKnown = true; } else rawKept.push(tok);
		const cat = id ? classify(id) : "unknown";
		const rank = CATEGORY_RANK[cat] || CATEGORY_RANK.unknown;
		if (rank > bestRank) { bestRank = rank; best = cat; }
	}
	// All tokens unmapped → unknown overall.
	if (!anyKnown) best = "unknown";
	return { ids, raw: rawKept, category: best };
}

/**
 * Assess a flat list of license findings.
 * findings: [{ dep, licenses: <raw string|array|object>, source }]
 * Returns { assessed: [{dep, source, ids, raw, category}], byCategory, flagged }.
 */
function assessLicenses(findings) {
	const assessed = [];
	const byCategory = {};
	const flagged = [];
	for (const f of findings || []) {
		const r = resolveDepLicense(f.licenses);
		const entry = { dep: f.dep, source: f.source || null, ids: r.ids, raw: r.raw, category: r.category };
		assessed.push(entry);
		(byCategory[r.category] = byCategory[r.category] || []).push(entry);
		if (FLAGGED_CATEGORIES.has(r.category)) flagged.push(entry);
	}
	return { assessed, byCategory, flagged };
}

module.exports = {
	normalizeSpdx, splitExpression, classify, resolveDepLicense, assessLicenses,
	FLAGGED_CATEGORIES, CATEGORY_RANK,
};
