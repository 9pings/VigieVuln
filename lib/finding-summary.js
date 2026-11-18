/** Shared counts for physical findings and overlapping application exposures. */
const crypto = require("node:crypto");
const path = require("node:path");
const SEVERITIES = ["critical", "high", "medium", "low", "none", "unknown"];

function identity(m) {
	if (m.findingId) return JSON.stringify([m.dep?.artifactTargetId || "", m.findingId]);
	const dep = m.dep || {};
	return [m.cve?.id || "", dep.ecosystem || "", dep.artifactTargetId || "", dep.coordKey || `${dep.groupId || dep.namespace || ""}:${dep.artifactId || dep.name || ""}`,
		dep.version || "", dep.artifactPath || dep.manifestPaths?.[0] || dep.pomPaths?.[0] || ""].join("\0");
}

function uniqueFindings(matches = []) {
	const unique = new Map();
	for (const match of matches) {
		const key = identity(match);
		if (!unique.has(key)) { unique.set(key, match); continue; }
		const prior = unique.get(key);
		if (match.source) {
			const sources = new Set([...(prior.source || "").split("+"), ...String(match.source).split("+")].filter(Boolean));
			unique.set(key, { ...prior, source: [...sources].sort().join("+") });
		}
	}
	return [...unique.values()];
}

function coalescePhysicalFindings(matches = [], srcRoot = null) {
	const byKey = new Map();
	const union = (a, b) => [...new Set([...(a || []), ...(b || [])])];
	const refs = (a, b) => {
		const found = new Map();
		for (const ref of [...(a || []), ...(b || [])]) if (ref?.url) found.set(ref.url, ref);
		return [...found.values()];
	};
	for (const match of matches) {
		const dep = match.dep || {};
		const file = dep.occurrences?.[0]?.manifestPath || dep.manifestPaths?.[0];
		const location = file && srcRoot && path.isAbsolute(file) ? path.relative(srcRoot, file) : file;
		const rel = location ? String(location).split(path.sep).join("/") : null;
		const physical = dep.ecosystem === "composer" && rel && dep.coordKey && dep.version && match.cve?.id;
		const key = physical ? [match.cve.id, dep.coordKey, dep.version, rel, ...(dep.artifactTargetId ? [dep.artifactTargetId] : [])].join("\0") : identity(match);
		const findingId = physical ? `fad-cve-${crypto.createHash("sha256").update(key).digest("hex").slice(0, 24)}` : match.findingId;
		const previous = byKey.get(key);
		if (!previous) { byKey.set(key, { ...match, ...(findingId ? { findingId } : {}) }); continue; }
		const cve = { ...previous.cve, ...Object.fromEntries(Object.entries(match.cve || {}).filter(([, value]) => value != null)) };
		if (previous.cve?.score != null && match.cve?.severityScheme === "drupal-rating") {
			cve.severity = previous.cve.severity;
			cve.severityScheme = previous.cve.severityScheme || "cvss";
		}
		cve.aliases = union(previous.cve?.aliases, match.cve?.aliases);
		cve.upstream = union(previous.cve?.upstream, match.cve?.upstream);
		cve.osvRefs = refs(previous.cve?.osvRefs, match.cve?.osvRefs);
		cve.nvdRefs = refs(previous.cve?.nvdRefs, match.cve?.nvdRefs);
		byKey.set(key, { ...previous, cve, findingId: findingId || previous.findingId,
			source: union((previous.source || "").split("+").filter(Boolean), (match.source || "").split("+").filter(Boolean)).sort().join("+"),
			applicationIds: union(previous.applicationIds, match.applicationIds),
			ownerComponentIds: union(previous.ownerComponentIds, match.ownerComponentIds),
			applicationRelation: previous.applicationRelation === "direct" || match.applicationRelation === "direct" ? "direct" :
				previous.applicationRelation || match.applicationRelation || null,
			dependencyPaths: [...(previous.dependencyPaths || []), ...(match.dependencyPaths || [])],
			advisoryId: previous.advisoryId || match.advisoryId,
		});
	}
	return [...byKey.values()];
}

function summarizeFindings(matches = []) {
	const unique = uniqueFindings(matches);
	const bySeverity = Object.fromEntries(SEVERITIES.map(k => [k, 0]));
	const byApplication = {};
	const byApplicationRelation = { direct: 0, indirect: 0, unknown: 0 };
	const excluded = { suppressed: 0, cpeFiltered: 0 };
	let total = 0;
	let kev = 0;
	let applicationUnique = 0;
	let applicationExposureOverlaps = false;
	for (const m of unique) {
		if (m.suppressed) { excluded.suppressed++; continue; }
		if (m.cpeFiltered) { excluded.cpeFiltered++; continue; }
		total++;
		if (m.cve?.kev) kev++;
		const severity = String(m.cve?.severity || "unknown").toLowerCase();
		bySeverity[severity in bySeverity ? severity : "unknown"]++;
		const applications = [...new Set(m.applicationIds || [])];
		if (applications.length) applicationUnique++;
		if (applications.length > 1) applicationExposureOverlaps = true;
		for (const id of applications) byApplication[id] = (byApplication[id] || 0) + 1;
		if (applications.length) {
			const relation = m.applicationRelation;
			byApplicationRelation[relation in byApplicationRelation ? relation : "unknown"]++;
		}
	}
	return { total, kev, applicationUnique, bySeverity, byApplication, byApplicationRelation, applicationExposureOverlaps, excluded };
}

module.exports = { summarizeFindings, uniqueFindings, coalescePhysicalFindings };
