/**
 * lib/inventory/private-deps.js — "this coordinate exists in no registry we asked", for every
 * ecosystem that has a registry.
 *
 * Maven has had this since the beginning: a coordinate absent from every configured
 * repository is an internal artifact, and chapter 0 names it so the hole in the coverage is
 * reported rather than silent. Nothing equivalent existed for npm, PyPI, NuGet, Composer,
 * Go or RubyGems — an in-house `@acme/*` package simply returned no findings and looked
 * clean, which is the exact failure mode the Maven warning exists to prevent.
 *
 * The signal was already on the wire: those codecs query their registry for deprecation and
 * outdated data, and a 404 came back every time. It was collapsed into an error string and
 * dropped. So this adds no requests — it reads what the existing pass already learned.
 *
 * The distinction that matters, and the reason this is a module rather than a regex at the
 * call site: only a DEFINITIVE answer counts. A 404 (or 410) from every base means absent.
 * A timeout, a 5xx, a refused connection or an auth failure means UNKNOWN — the registry
 * did not say the package is missing, it failed to answer. Reporting those as private would
 * accuse a client of shipping internal packages because their proxy was flaky, which is
 * worse than saying nothing.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

// Statuses that are a registry SAYING the package is not there, as opposed to failing to say.
// 404 is the universal answer; Go's proxy uses 410 Gone for modules it will not serve.
const ABSENT_STATUS = new Set([404, 410]);

/** Is this HTTP status a definitive "not here"? */
function isAbsentStatus(status) {
	return ABSENT_STATUS.has(Number(status));
}

/**
 * Classify one registry lookup.
 *
 * @param {{absent?: boolean, error?: string}|null} result what the codec's fetcher returned
 *        — a packument/metadata object on success, or `{ error, absent }` on failure.
 * @returns {"found"|"absent"|"unknown"}
 */
function classifyLookup(result) {
	if (!result) return "unknown";                 // offline, or never attempted
	if (!result.error) return "found";
	return result.absent === true ? "absent" : "unknown";
}

/**
 * Fold the per-base outcomes of one lookup into the `absent` flag the codecs report.
 * Absent only when at least one base was asked AND every one of them gave a definitive
 * "not here". Any inconclusive base poisons the verdict, on purpose.
 *
 * @param {Array<number|null>} statuses one entry per base: the HTTP status, or null for a
 *        network error / timeout (which is never conclusive).
 */
function foldAbsent(statuses) {
	const list = statuses || [];
	if (!list.length) return false;
	return list.every(s => s !== null && isAbsentStatus(s));
}

/**
 * Build the report warning's item list from per-ecosystem hits.
 * Sorted so a re-run produces the same order — an audit diff must not churn.
 *
 * @param {Array<{dep: object, ecosystem: string}>} hits
 */
function buildPrivateItems(hits, { relativise = p => p } = {}) {
	return (hits || [])
		.map(h => {
			const d = h.dep || {};
			const ns = d.namespace || d.groupId || "";
			const name = d.name || d.artifactId || "";
			const id = ns ? `${ns}${d.ecosystem === "maven" ? ":" : "/"}${name}` : name;
			return {
				id,
				ecosystem: h.ecosystem || d.ecosystem || "",
				manifestPaths: (d.manifestPaths || []).map(relativise),
			};
		})
		.sort((a, b) => a.ecosystem.localeCompare(b.ecosystem) || a.id.localeCompare(b.id));
}

module.exports = { isAbsentStatus, classifyLookup, foldAbsent, buildPrivateItems };
