/**
 * lib/application-providers/spip-advisories.js — the SPIP core advisory lane.
 *
 * SPIP is the one CMS in the set with NO publisher API and NO package ecosystem:
 * not on Packagist (`spip/spip` 404s — SPIP ships from files.spip.net), not on GitHub
 * (hosted on git.spip.net, so no GHSA), blog.spip.net publishes prose release notes.
 * The one machine-readable source that exists is **NVD**, which carries the SPIP core
 * CPE (`cpe:2.3:a:spip:spip`, 69 CVEs at implementation time) with version ranges —
 * the same data that powers fad's CPE cross-check, queried per product instead of per
 * CVE. This lane fetches that product's CVE set once, evaluates the OBSERVED core
 * version against each range, and produces findings; SPIP *plugins* have no advisory
 * source anywhere, so the lane says so instead of pretending.
 *
 * Pure: fetch/validate/assess take plain data. No I/O, no cache writes (the plugin does
 * the snapshot caching, like every other advisory lane).
 */
const crypto = require("node:crypto");

/** NVD CVE query for the SPIP core product at ANY version (69 CVEs → one page). */
const SPIP_ADVISORIES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:spip:spip&resultsPerPage=2000&startIndex=0";
const SPIP_CPE_PREFIX = "cpe:2.3:a:spip:spip";

/** NVD severity band from a CVSS base score — the same thresholds NVD itself uses. */
function severityFromScore(score) {
	if (score == null) return "UNKNOWN";
	const s = Number(score);
	if (!Number.isFinite(s)) return "UNKNOWN";
	if (s >= 9) return "CRITICAL";
	if (s >= 7) return "HIGH";
	if (s >= 4) return "MEDIUM";
	return "LOW";
}

/** Worst CVSS base score across the metric versions NVD records for a CVE. */
function worstScore(metrics) {
	let worst = null;
	for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
		for (const metric of metrics?.[key] || []) {
			const score = metric?.cvssData?.baseScore ?? metric?.baseScore;
			if (Number.isFinite(Number(score)) && (worst == null || Number(score) > worst)) worst = Number(score);
		}
	}
	return worst;
}

/**
 * Fetch the SPIP product's CVE set from NVD. Returns { snapshot, sourceSnapshot };
 * the snapshot is a self-contained, schema-validated document that also assesses
 * offline and travels in ~/.fad-checker/advisory-snapshots/.
 */
async function fetchSpipAdvisories({ fetchImpl = globalThis.fetch, apiUrl = SPIP_ADVISORIES_URL,
	apiKey, now = Date.now() } = {}) {
	const collectedAt = new Date(now).toISOString();
	const meta = { collectedAt, completeness: "tool-fetched", sourceUrl: apiUrl };
	const headers = { "User-Agent": "vigievuln-nvd-spip" };
	if (apiKey) headers["apiKey"] = String(apiKey).trim();
	const response = await require("../providers").getResource("nvd", "spip-advisories", {}, {
		fetcher: fetchImpl, headers, signal: AbortSignal.timeout(60000),
		...(apiUrl === SPIP_ADVISORIES_URL ? {} : { urlOverride: apiUrl, direct: true }),
	});
	if (!response || !response.ok) throw new Error(`NVD SPIP advisories request failed with HTTP ${response?.status ?? "unknown"}`);
	meta.collectedAt = new Date(require("../providers/common").responseFetchedAt(response, now)).toISOString();
	const text = await response.text();
	let body;
	try { body = JSON.parse(text); }
	catch { throw new Error("NVD SPIP advisories response is not valid JSON"); }
	if (body && typeof body === "object" && body.message) throw new Error(`NVD SPIP advisories API error: ${body.message}`);
	const vulnerabilities = Array.isArray(body?.vulnerabilities) ? body.vulnerabilities : null;
	if (!vulnerabilities) throw new Error("NVD SPIP advisories response is missing its vulnerabilities array");
	const total = Number(body?.totalResults);
	if (Number.isFinite(total) && total > vulnerabilities.length)
		throw new Error(`NVD SPIP advisories pagination: ${total} CVEs exceed the single-page limit of ${vulnerabilities.length} — refusing to cache a partial set`);
	const snapshot = { cpe: SPIP_CPE_PREFIX, vulnerabilities, _fadSnapshot: { ...meta } };
	validateSnapshot(snapshot);
	return { snapshot, sourceSnapshot: { sha256: crypto.createHash("sha256").update(text).digest("hex"), ...meta } };
}

/** Schema: a snapshot is the NVD vulnerabilities array with an id and CPE configurations. */
function validateSnapshot(snapshot) {
	if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot) || !Array.isArray(snapshot.vulnerabilities))
		throw new Error("SPIP advisory snapshot needs a vulnerabilities array");
	for (const entry of snapshot.vulnerabilities) {
		const cve = entry?.cve || entry;
		if (!cve || typeof cve.id !== "string" || !cve.id)
			throw new Error("SPIP advisory snapshot record is missing its CVE id");
		if (!Array.isArray(cve.configurations)) throw new Error(`SPIP advisory record ${cve.id} has no CPE configurations`);
	}
	return snapshot;
}

/** The SPIP-core cpeMatch entries of a CVE — the product is queried as a virtual match. */
function spipCpeMatches(cve) {
	const out = [];
	for (const configuration of cve.configurations || [])
		for (const node of configuration.nodes || [])
			for (const cpeMatch of node.cpeMatch || []) {
				const criteria = String(cpeMatch?.criteria || "");
				if (cpeMatch.vulnerable !== false && criteria.toLowerCase().startsWith(SPIP_CPE_PREFIX + ":")) out.push(cpeMatch);
			}
	return out;
}

/**
 * Assess a validated snapshot against the inventoried components. The core's OBSERVED
 * version is evaluated against every CVE's CPE ranges (matchVersionRange — the same
 * primitive the report's own CPE cross-check uses); a plugin has no advisory source
 * anywhere, so its row stays honestly not-run instead of inheriting the core's verdict.
 */
function assessSpipAdvisories(snapshot, components = []) {
	const { matchVersionRange } = require("../cpe");
	const validated = validateSnapshot(snapshot);
	const core = (components || []).find(c => c.kind === "core");
	const matches = [], coverage = [], diagnostics = [];
	for (const component of components || []) {
		const base = { applicationId: component.applicationId, occurrenceId: component.id,
			capability: "advisories", sourceId: component.visibility === "private" ? "internal-advisories" : "spip-security-advisories",
			expected: 1, executed: 0 };
		if (component.visibility === "private") {
			coverage.push({ ...base, execution: "not-run", result: "indeterminate", diagnostic: "CMS_PRIVATE_COMPONENT" });
			continue;
		}
		if (component.kind !== "core") {
			// No machine-readable advisory source exists for SPIP plugins (NVD carries
			// the core product only; the depot has no advisory API) — never a clean verdict.
			coverage.push({ ...base, execution: "not-run", result: "indeterminate", diagnostic: "CMS_ADVISORY_NOT_QUALIFIED" });
			continue;
		}
		if (!core?.version) {
			coverage.push({ ...base, execution: "not-run", result: "indeterminate", diagnostic: "CMS_VERSION_UNKNOWN" });
			continue;
		}
		let affected = false;
		for (const entry of validated.vulnerabilities) {
			const cve = entry.cve || entry;
			let rangeMatch = null;
			for (const cpeMatch of spipCpeMatches(cve)) {
				if (matchVersionRange(core.version, cpeMatch)) { rangeMatch = cpeMatch; break; }
			}
			if (!rangeMatch) continue;
			affected = true;
			const score = worstScore(cve.metrics);
			const description = (cve.descriptions || []).find(d => d.lang === "en")?.value
				|| (cve.descriptions || [])[0]?.value || "";
			const evidencePaths = (component.evidence || []).map(e => e.path).filter(Boolean);
			matches.push({
				findingId: `fad-advisory-${crypto.createHash("sha256").update(`${cve.id}\0${component.id}`).digest("hex").slice(0, 24)}`,
				applicationIds: [component.applicationId], ownerComponentIds: [component.id],
				applicationRelation: "direct", attributionStatus: "confirmed", dependencyPaths: [],
				dep: { ecosystem: "composer", namespace: "spip", name: "spip", coordKey: "composer:spip/spip",
					version: core.version, scope: "prod", isDev: false, provenance: "application",
					manifestPaths: evidencePaths.slice(0, 1) },
				source: "spip-security-advisories", confidence: "probable", advisoryId: cve.id,
				// NVD's exclusive range end IS the fix ("affected < 4.1.10" → fixed in
				// 4.1.10); a hard pin that matched carries no fix version.
				cve: { id: cve.id, aliases: [], severity: severityFromScore(score), score,
					description, published: cve.published || null,
					fixVersion: rangeMatch.versionEndExcluding || null },
			});
		}
		coverage.push({ ...base, executed: 1, execution: "completed",
			result: affected ? "affected" : "no-match" });
	}
	return { matches, coverage, diagnostics };
}

module.exports = { SPIP_ADVISORIES_URL, SPIP_CPE_PREFIX, fetchSpipAdvisories, validateSnapshot, assessSpipAdvisories };
