/** Matcher for an operator-supplied packages.drupal.org/8 security-advisories JSON snapshot. */
const crypto = require("node:crypto");
const { satisfiesComposerConstraint } = require("../packagist/audit");

function parseVersion(value) {
	const match = String(value || "").trim().match(/^v?(\d+(?:\.\d+)*)(?:-(alpha|beta|rc|dev)(\d*))?$/i);
	if (!match) return null;
	return { numbers: match[1].split(".").map(Number), prerelease: match[2] ?
		{ dev: 0, alpha: 1, beta: 2, rc: 3 }[match[2].toLowerCase()] : 4,
		preNumber: match[3] ? Number(match[3]) : 0 };
}

function compareVersion(a, b) {
	const left = parseVersion(a), right = parseVersion(b);
	if (!left || !right) return null;
	for (let i = 0; i < Math.max(left.numbers.length, right.numbers.length); i++) {
		const diff = (left.numbers[i] || 0) - (right.numbers[i] || 0);
		if (diff) return Math.sign(diff);
	}
	if (left.prerelease !== right.prerelease) return Math.sign(left.prerelease - right.prerelease);
	return Math.sign(left.preNumber - right.preNumber);
}

/**
 * SA constraints ARE Composer constraints: evaluated by the Composer evaluator of
 * lib/providers/packagist/audit.js so pre-releases follow Composer ("<10.3.0" is "<10.3.0.0-dev",
 * "10.2.*" is ">=10.2.0.0-dev <10.3.0.0-dev", ">=10.3.0" admits 10.3.0-rc1). The local
 * comparator got all three wrong. Its null (unparsable version or token) stays
 * "indeterminate", never "no-match"; so does an empty `||` alternative.
 */
function affectedComposerVersion(version, constraint) {
	if (!version || typeof constraint !== "string" || !constraint.trim()) return "indeterminate";
	const verdict = satisfiesComposerConstraint(version, constraint);
	if (verdict === true) return "affected";
	if (verdict === null || constraint.split(/\|\|?/).some(alternative => !alternative.trim())) return "indeterminate";
	return "no-match";
}

function validateSnapshot(snapshot) {
	if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot) ||
		!snapshot.advisories || typeof snapshot.advisories !== "object" ||
		Array.isArray(snapshot.advisories))
		throw new Error("Drupal advisory snapshot needs an advisories object");
	if (snapshot.queriedPackages && !Array.isArray(snapshot.queriedPackages)) throw new Error("queriedPackages must be an array");
	const queried = new Set((snapshot.queriedPackages || []).filter(name => typeof name === "string").map(name => name.toLowerCase()));
	for (const [name, entries] of Object.entries(snapshot.advisories)) {
		if (!Array.isArray(entries)) throw new Error(`Drupal advisory list is invalid for ${name}`);
		queried.add(name.toLowerCase());
		for (const entry of entries) if (!entry || typeof entry.advisoryId !== "string" ||
			entry.packageName?.toLowerCase() !== name.toLowerCase() || typeof entry.affectedVersions !== "string")
			throw new Error(`Drupal advisory record is invalid for ${name}`);
	}
	return queried;
}

/**
 * The publisher's "fixed in" for the observed version: the smallest EXCLUSIVE upper
 * bound among the affected ranges that sits above it — SA ranges are disjoint
 * branches ("X || Y"), so the first bound above the version is the patch release
 * that exits the matched branch. Wildcard-only branches publish no patch level:
 * null rather than an invented one.
 */
function fixVersionForConstraint(version, constraint) {
	if (!version || typeof constraint !== "string" || !constraint.trim()) return null;
	if (!parseVersion(version)) return null;
	let fix = null;
	for (const token of constraint.split(/[\s,]+/)) {
		const match = token.match(/^<v?(\d+(?:\.\d+)*)$/i);
		if (!match) continue;
		const compared = compareVersion(version, match[1]);
		if (compared == null || compared >= 0) continue; // at/below us → not this branch's fix
		if (fix == null || (compareVersion(match[1], fix) || 0) < 0) fix = match[1];
	}
	return fix;
}

function assessDrupalAdvisories(snapshot, components = []) {
	const queried = validateSnapshot(snapshot);
	const matches = [], coverage = [], diagnostics = [];
	for (const component of components) {
		const base = { applicationId: component.applicationId, occurrenceId: component.id, capability: "advisories",
			sourceId: component.visibility === "private" ? "internal-advisories" : "drupal-security-advisories",
			expected: 1, executed: 0 };
		let diagnostic = null;
		if (component.visibility === "private") diagnostic = "CMS_PRIVATE_COMPONENT";
		else if (component.kind === "core" && /^7(?:\.|$)/.test(component.version || "")) diagnostic = "CMS_UNSUPPORTED_BRANCH";
		else if (!component.version) diagnostic = "CMS_VERSION_UNKNOWN";
		else if (!component.coord || !component.coord.startsWith("drupal/")) diagnostic = "CMS_IDENTITY_UNVERIFIED";
		else if (!queried.has(component.coord.toLowerCase())) diagnostic = "CMS_PACKAGE_NOT_QUERIED";
		if (diagnostic) {
			coverage.push({ ...base, execution: "not-run", result: "indeterminate", diagnostic });
			continue;
		}
		const entries = Object.entries(snapshot.advisories).find(([name]) => name.toLowerCase() === component.coord.toLowerCase())?.[1] || [];
		let affected = false, uncertain = false;
		for (const entry of entries) {
			const verdict = affectedComposerVersion(component.version, entry.affectedVersions);
			if (verdict === "indeterminate") { uncertain = true; continue; }
			if (verdict !== "affected") continue;
			affected = true;
			const cveId = /^CVE-\d{4}-\d{4,}$/i.test(entry.cve || "") ? entry.cve : null;
			const rating = entry.title.match(/\b(Highly critical|Critical|Moderately critical|Less critical)\b/i)?.[1] || null;
			const severity = { "highly critical": "CRITICAL", critical: "HIGH", "moderately critical": "MEDIUM", "less critical": "LOW" }[rating?.toLowerCase()] || "UNKNOWN";
			const ref = /^https:\/\/www\.drupal\.org\/sa-[a-z0-9-]+$/i.test(entry.link || "") ? entry.link : null;
			const evidencePaths = (component.evidence || []).map(e => e.path).filter(Boolean);
			const lockPath = evidencePaths.find(file => file.endsWith("composer.lock"));
			const dep = { ecosystem: "composer", namespace: "drupal", name: component.coord.split("/")[1],
				coordKey: `composer:${component.coord}`, version: component.version, scope: "prod", isDev: false,
				provenance: "application", manifestPaths: [lockPath || evidencePaths[0]].filter(Boolean) };
			const findingId = `fad-advisory-${crypto.createHash("sha256").update(`${entry.advisoryId}\0${component.id}`).digest("hex").slice(0, 24)}`;
			matches.push({ findingId, applicationIds: [component.applicationId], ownerComponentIds: [component.id],
				applicationRelation: "direct", attributionStatus: "confirmed", dependencyPaths: [], dep,
				source: "drupal-security-advisories", confidence: "probable", advisoryId: entry.advisoryId,
				cve: { id: cveId || entry.advisoryId, aliases: cveId ? [entry.advisoryId, cveId] : [entry.advisoryId],
					severity, severityOriginal: rating, severityScheme: "drupal-rating", score: null,
					description: entry.title, published: entry.reportedAt || null,
					fixVersion: fixVersionForConstraint(component.version, entry.affectedVersions),
					osvRefs: ref ? [{ url: ref, type: "ADVISORY" }] : [] } });
		}
		coverage.push({ ...base, executed: 1, execution: uncertain ? "partial" : "completed",
			result: uncertain ? "indeterminate" : affected ? "affected" : "no-match",
			...(uncertain ? { diagnostic: "CMS_CONSTRAINT_UNSUPPORTED" } : {}) });
		if (uncertain) diagnostics.push({ code: "CMS_CONSTRAINT_UNSUPPORTED", applicationId: component.applicationId,
			componentId: component.id, message: `a Drupal advisory constraint could not be evaluated for ${component.coord}` });
	}
	return { matches, coverage, diagnostics };
}

module.exports = { compareVersion, affectedComposerVersion, fixVersionForConstraint, assessDrupalAdvisories, validateSnapshot };
