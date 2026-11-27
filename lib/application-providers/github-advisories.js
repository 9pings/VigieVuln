/**
 * Static matcher for a publisher's GitHub repository security-advisory snapshot
 * (api.github.com/repos/<owner>/<repo>/security-advisories — the machine-readable
 * channel the publisher themselves writes; observed live for PrestaShop/PrestaShop
 * and TYPO3/typo3, and empty for joomla/joomla-cms and magento/magento2, whose
 * bulletins stay HTML pages). Only advisories the publisher attributed to a
 * composer package can match; the 2020-era PrestaShop records whose package
 * identity is empty in the official feed are attributed to the configured core
 * coordinate, and that inference is documented per lane.
 */
const crypto = require("node:crypto");
const { satisfiesComposerConstraint, cmpComposerVersions } = require("../packagist-audit");

/**
 * Publisher range grammars observed in the live feeds (2026-09-23), applied BEFORE the
 * shared Composer evaluation, which the rest of the app (Packagist lane, Drupal lane)
 * keeps byte-identical. The published fields are not always Composer syntax:
 *  - the generic GitHub spellings: operators followed by a space (">= 9.0.0, < 9.1.5"),
 *    hyphen intervals written without spaces ("14.2.0-14.3.6"), and bare exact product
 *    versions with more than three numeric parts ("1.7.0.0"), which the shared
 *    evaluator would leave undecidable;
 *  - PrestaShop writes "and" for two different things: ">= 8.0.0 and < 8.1.1" is a
 *    proper interval (Composer AND), while "< 8.2.6 and < 9.1.1" pairs with two patched
 *    versions and means BOTH branches are affected (an OR of upper-bounded branches —
 *    a literal AND there would make the second fix meaningless);
 *  - TYPO3 writes "13.0.0-13.4.33, 14.0.0-14.3.5": comma-joined hyphen intervals are
 *    alternative affected branches (an OR); with Composer's AND they would describe an
 *    empty set and every real advisory would silently become a false negative.
 */
function githubRangeGrammar(range) {
	return String(range ?? "")
		.replace(/(>=|<=|!=|==|=|>|<)\s+/g, "$1")                       // ">= 9.0.0" → ">=9.0.0"
		.replace(/(\d+(?:\.\d+)+)-(\d+(?:\.\d+)+)/g, "$1 - $2");          // spaceless hyphen interval
}

function prestashopRangeGrammar(range) {
	const s = githubRangeGrammar(range);
	if (!/\band\b/i.test(s)) return s;
	const clauses = s.split(/\s+and\s+/i).map(clause => clause.trim()).filter(Boolean);
	if (clauses.length >= 2 && clauses.every(clause => /^</.test(clause))) return clauses.join(" || ");
	return s.replace(/\s+and\s+/gi, ",");
}

function typo3RangeGrammar(range) {
	const parts = githubRangeGrammar(range).split(",").map(part => part.trim()).filter(Boolean);
	if (parts.length < 2 || !parts.every(part =>
		/^v?\d+(?:\.\d+)*\s*-\s*v?\d+(?:\.\d+)*$/.test(part) || /^v?\d+(?:\.\d+){2,}$/.test(part))) return parts.join(",");
	return parts.join(" || ");
}

// The patched refinement keeps lossy unbounded ranges from flagging fixed versions:
// a version at or above the smallest parseable patched token carries the fix.
function smallestPatchedVersion(patched) {
	let smallest = null;
	for (const token of String(patched ?? "").split(/[\s|&,]+/).filter(Boolean)) {
		if (cmpComposerVersions(token, token) == null) continue;
		if (smallest == null || cmpComposerVersions(token, smallest) < 0) smallest = token;
	}
	return smallest;
}

/** The fix this version should move to: the smallest patched release strictly above it —
 *  in a multi-branch record ("8.2.6 & 9.1.1") that names each branch's own fix. */
function nextPatchedVersion(version, patched) {
	let next = null;
	for (const token of String(patched ?? "").split(/[\s|&,]+/).filter(Boolean)) {
		const compared = cmpComposerVersions(version, token);
		if (compared == null || compared >= 0) continue;
		if (next == null || cmpComposerVersions(token, next) < 0) next = token;
	}
	return next;
}

function validateSnapshot(input, { fallbackCoord = null, normalizeRange = null } = {}) {
	if (Array.isArray(input)) input = { advisories: input };
	if (!input || typeof input !== "object" || Array.isArray(input) || !Array.isArray(input.advisories))
		throw new Error("Github advisory snapshot needs an advisories array");
	const fallback = typeof fallbackCoord === "string" && fallbackCoord.trim() ? fallbackCoord.trim().toLowerCase() : null;
	const normalize = typeof normalizeRange === "function" ? normalizeRange : (range => range);	const index = new Map();
	let unattributable = 0;
	for (const advisory of input.advisories) {
		if (!advisory || typeof advisory !== "object" || typeof advisory.ghsa_id !== "string" || !advisory.ghsa_id.trim())
			throw new Error("Github advisory record needs a ghsa_id");
		if (!Array.isArray(advisory.vulnerabilities)) throw new Error(`Github advisory ${advisory.ghsa_id} needs a vulnerabilities array`);
		for (const vulnerability of advisory.vulnerabilities) {
			if (!vulnerability || typeof vulnerability !== "object" ||
				typeof vulnerability.vulnerable_version_range !== "string")
				throw new Error(`Github advisory ${advisory.ghsa_id} has an invalid vulnerability entry`);
			let name = typeof vulnerability.package?.name === "string" ? vulnerability.package.name.trim().toLowerCase() : "";
			if (!name) {
				if (!fallback) { unattributable++; continue; }
				name = fallback;
			}
			if (!index.has(name)) index.set(name, []);
			// The generic GitHub spellings (spaced operators, spaceless hyphen intervals)
			// apply to every lane; the per-publisher grammar then handles its own quirks.
			index.get(name).push({ ghsa: advisory.ghsa_id, advisory,
				vulnerability: { ...vulnerability,
					vulnerable_version_range: normalize(githubRangeGrammar(vulnerability.vulnerable_version_range)) },
				inferredCoord: name === fallback && !vulnerability.package?.name });
		}
	}
	return { index, unattributable };
}

// A matched branch is bounded above when its own grammar names an upper limit; only an
// unbounded branch ("> 1.7.0.0", "*") needs the patched refinement — a bounded branch
// already excludes its fix, and applying the smallest patched token across multi-branch
// records ("8.2.6 & 9.1.1") would wrongly fix the 9.x branch.
function boundedAbove(branch) {
	const b = String(branch ?? "").trim();
	if (/<\s*\d/.test(b)) return true;            // "< x" / "<= x" bounds
	if (/[\^~]/.test(b) || /\*/.test(b)) return true;   // caret/tilde/wildcard branches
	if (/^(\S+)\s+-\s+(\S+)$/.test(b) || /^v?\d+(?:\.\d+)+-v?\d+(?:\.\d+)+$/.test(b)) return true;   // hyphen interval
	if (/^\d+(?:\.\d+)+(?:[-.]\w+)?$/.test(b)) return true;   // an exact version (incl. prerelease)
	return false;
}

/** A branch with no lower bound ("< 9.1.1") spans every earlier line; a matched version
 *  is fixed by the smallest patched release of its own MAJOR line — the publisher's
 *  product lines (8.x, 9.x) each carry their own fix, so 9.0.5 stays affected (fix
 *  9.1.1) while 8.2.6 and a later 8.3.0 are fixed (fix 8.2.6). */
function fixedByLowerUnbounded(version, branch, patched) {
	const majorOf = value => {
		const match = String(value ?? "").match(/^v?(\d+)\b/i);
		return match ? Number(match[1]) : null;
	};
	const major = majorOf(version);
	if (major == null) return null;   // undecidable, never a verdict
	let smallest = null;
	for (const token of String(patched ?? "").split(/[\s|&,]+/).filter(Boolean)) {
		if (majorOf(token) !== major) continue;
		if (cmpComposerVersions(version, token) == null) return null;
		if (smallest == null || cmpComposerVersions(token, smallest) < 0) smallest = token;
	}
	if (smallest == null) return false;   // no fix named for this line: the branch's bound decides
	return cmpComposerVersions(version, smallest) >= 0;
}

function assessGithubAdvisories(input, components = [], { sourceId = "github-advisories", fallbackCoord = null, normalizeRange = null } = {}) {
	const { index, unattributable } = validateSnapshot(input, { fallbackCoord, normalizeRange });
	const matches = [], coverage = [], diagnostics = [];
	for (const component of components) {
		const base = { applicationId: component.applicationId, occurrenceId: component.id, capability: "advisories",
			sourceId: component.visibility === "private" ? "internal-advisories" : sourceId, expected: 1, executed: 0 };
		let diagnostic = null;
		if (component.visibility === "private") diagnostic = "CMS_PRIVATE_COMPONENT";
		else if (!component.version) diagnostic = "CMS_VERSION_UNKNOWN";
		else if (!component.coord || typeof component.coord !== "string") diagnostic = "CMS_IDENTITY_UNVERIFIED";
		if (diagnostic) {
			coverage.push({ ...base, execution: "not-run", result: "indeterminate", diagnostic });
			continue;
		}
		const entries = index.get(component.coord.toLowerCase()) || [];
		let affected = false, uncertain = false;
		for (const { ghsa, advisory, vulnerability } of entries) {
			const branches = String(vulnerability.vulnerable_version_range ?? "").split(/\s*(?:\|\||\|)\s*/).filter(Boolean);
			let entryAffected = false, entryUncertain = false;
			for (const branch of branches) {
				// A branch that is exactly a bare product version ("1.6.0.1") is an
				// equality; the shared evaluator only equality-matches three-part tokens,
				// so this is decided here rather than by changing it.
				const bareExact = /^v?(\d+(?:\.\d+){2,})$/.exec(branch.trim());
				const verdict = bareExact
					? (cmpComposerVersions(component.version, bareExact[1]) === 0 ? true
						: cmpComposerVersions(component.version, bareExact[1]) == null ? null : false)
					: satisfiesComposerConstraint(component.version, branch);
				if (verdict == null) { entryUncertain = true; continue; }
				if (verdict !== true) continue;
				if (!boundedAbove(branch)) {
					// unbounded above: only the publisher's patched bound can separate
					// the fixed releases from the affected ones (the lossy "> 1.7.0.0" records).
					const patched = smallestPatchedVersion(vulnerability.patched_versions);
					if (patched == null) { entryUncertain = true; continue; }
					const fixed = cmpComposerVersions(component.version, patched);
					if (fixed == null) { entryUncertain = true; continue; }
					if (fixed >= 0) continue;   // at or above the patched release: fixed
				} else if (!/>/.test(branch)) {
					// upper-bounded with no lower bound ("< 9.1.1"): fixed by a patched
					// release of the version's own major.minor line, never by another line's fix.
					const fixed = fixedByLowerUnbounded(component.version, branch, vulnerability.patched_versions);
					if (fixed == null) { entryUncertain = true; continue; }
					if (fixed) continue;
				}
				entryAffected = true;
			}
			if (entryUncertain) uncertain = true;
			if (!entryAffected) continue;
			affected = true;
			const cveId = /^CVE-\d{4}-\d{4,}$/i.test(String(advisory.cve_id || "")) ? advisory.cve_id : null;
			const severity = ["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"].includes(String(advisory.severity || "").toUpperCase())
				? String(advisory.severity).toUpperCase().replace("MODERATE", "MEDIUM") : "UNKNOWN";
			const evidencePaths = (component.evidence || []).map(e => e.path).filter(Boolean);
			const dep = { ecosystem: "composer", namespace: component.coord.split("/")[0], name: component.coord.split("/")[1],
				coordKey: `composer:${component.coord.toLowerCase()}`, version: component.version, scope: "prod", isDev: false,
				provenance: "application", manifestPaths: evidencePaths.slice(0, 1) };
			const findingId = `fad-advisory-${crypto.createHash("sha256").update(`${ghsa}\0${component.id}`).digest("hex").slice(0, 24)}`;
			matches.push({ findingId, applicationIds: [component.applicationId], ownerComponentIds: [component.id],
				applicationRelation: "direct", attributionStatus: "confirmed", dependencyPaths: [], dep,
				source: sourceId, confidence: "probable", advisoryId: ghsa,
				cve: { id: cveId || ghsa, aliases: [...new Set([ghsa, ...(cveId ? [cveId] : [])])],
					severity, severityOriginal: advisory.severity || null, severityScheme: "github-severity",
					score: Number.isFinite(advisory.cvss?.score) ? advisory.cvss.score : null,
					cvssVector: advisory.cvss?.vector_string || null,
					cvssVersion: advisory.cvss?.vector_string?.split("/")[0] || null,
					description: advisory.summary || "", title: advisory.summary || null,
					published: advisory.published_at || null, modified: advisory.updated_at || null,
					cwes: [...new Set([
						...(Array.isArray(advisory.cwe_ids) ? advisory.cwe_ids : []),
						...(Array.isArray(advisory.cwes) ? advisory.cwes.map(c => c?.cwe_id) : []),
					].filter(id => typeof id === "string" && /^CWE-[1-9]\d*$/i.test(id)).map(id => id.toUpperCase()))],
					fixVersion: nextPatchedVersion(component.version, vulnerability.patched_versions),
					osvRefs: /^https?:\/\//i.test(advisory.html_url || "") ? [{ url: advisory.html_url, type: "ADVISORY" }] : [] } });
		}
		coverage.push({ ...base, executed: 1, execution: uncertain ? "partial" : "completed",
			result: uncertain ? "indeterminate" : affected ? "affected" : "no-match",
			...(uncertain ? { diagnostic: "CMS_CONSTRAINT_UNSUPPORTED" } : {}) });
		if (uncertain) diagnostics.push({ code: "CMS_CONSTRAINT_UNSUPPORTED", applicationId: component.applicationId,
			componentId: component.id, message: `a Github advisory range could not be evaluated for ${component.coord}` });
	}
	if (unattributable) diagnostics.push({ code: "CMS_ADVISORY_UNATTRIBUTABLE",
		message: `${unattributable} advisory record(s) in the Github feed carry no package identity and cannot be attributed to any inventoried component` });
	return { matches, coverage, diagnostics };
}

module.exports = { validateSnapshot, assessGithubAdvisories, smallestPatchedVersion, nextPatchedVersion,
	githubRangeGrammar, prestashopRangeGrammar, typo3RangeGrammar };
