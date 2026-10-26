/**
 * lib/scan-completeness.js — produce warnings telling the user when vigievuln
 * has gone as far as it can without running the real build tool.
 *
 * The two big "you need a real scan" cases:
 *   1. BOMs (Maven `<scope>import</scope>`): version pins live in another
 *      POM that may itself be transitive. We follow LOCAL BOMs in core.js,
 *      but external BOMs (Spring Boot, Quarkus, JBoss…) bring in a managed
 *      version table that we can't enumerate without resolving them. The
 *      resolved deps map will still list deps with unresolved `${prop}` or
 *      missing versions in this case.
 *   2. Unresolved versions: any dep whose `version` is null or still
 *      contains a `${…}` placeholder — we can't query OSV/Maven Central
 *      for these, so they silently fall out of the scan.
 *
 * For npm/yarn, lockfiles already pin everything, so we only flag the
 * already-handled "no lockfile" case from lib/npm/collect.js elsewhere.
 *
 * Output: an array of warning objects matching the same shape as
 * lib/npm/collect.js warnings ({ type, manifestPath?, message, ... }).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
/**
 * Scan the resolved deps map and return warnings.
 *
 * opts:
 *   ranSnyk   — true if --snyk was run (suppresses the "run snyk" hint)
 *   ranTransitive — true if --transitive was on (changes wording slightly)
 */
function detectScanCompletenessWarnings(resolvedDeps, opts = {}) {
	const warnings = [];
	if (!resolvedDeps || typeof resolvedDeps.values !== "function") return warnings;

	// Deps without a concrete version are the actionable signal — these
	// silently fall out of the CVE / OSV / outdated scans. Their root cause
	// is almost always an external BOM (spring-boot-dependencies, …) or a
	// property defined outside the source tree. We report the deps, not the
	// BOMs themselves: a present-and-correct BOM is not a problem.
	const unresolved = [];
	for (const d of resolvedDeps.values()) {
		// Maven-only: the unresolved-version case (external BOM / out-of-tree
		// property) is specific to Maven. Other ecosystems pin via lockfile, and
		// native binaries (provenance:"binary") are identified by checksum, not a
		// version — they belong to the Unmanaged/vendored-binaries chapter, NOT
		// here. Including them mislabelled e.g. libeay32.dll as a Maven dep.
		if (d.ecosystem !== "maven") continue;
		if (d.provenance === "binary") continue;
		if (d.scope === "import") continue;  // BOM-pointer entries themselves: not a dep
		if (!d.version) unresolved.push({ ...d, reason: "no-version" });
		else if (/\$\{[^}]+\}/.test(String(d.version))) unresolved.push({ ...d, reason: "unresolved-property" });
	}

	if (unresolved.length) {
		// Dedupe by g:a (same coord may appear in several modules), MERGING the
		// manifest paths so the report can show WHERE each unresolved dep is declared.
		// Items are objects ({ id, manifestPaths }) — renderWarningItems() renders the
		// "defined in: <pom.xml>" line for that shape (same as the private-libs warning).
		const byKey = new Map();
		for (const d of unresolved) {
			const k = `${d.groupId}:${d.artifactId}`;
			const paths = (d.manifestPaths && d.manifestPaths.length) ? d.manifestPaths
				: (d.pomPaths && d.pomPaths.length) ? d.pomPaths
				: [];
			let entry = byKey.get(k);
			if (!entry) {
				entry = { id: `${k}${d.version ? " (" + d.version + ")" : " (no version resolved)"}`, manifestPaths: [] };
				byKey.set(k, entry);
			}
			for (const p of paths) if (!entry.manifestPaths.includes(p)) entry.manifestPaths.push(p);
		}
		const items = [...byKey.values()];
		warnings.push({
			type: "unresolved-versions",
			count: items.length,
			items,
			message: `${items.length} Maven dep(s) without a concrete version — silently skipped from CVE/OSV/outdated scans. Their versions are likely pinned by an external BOM or a property defined outside the source tree. Run "mvn dependency:tree" against the source (or "snyk test --all-projects" against the cleaned POMs${opts.ranSnyk ? " — already done with --snyk" : ", or re-run vigievuln with --snyk"}) to resolve them and complete the scan.`,
		});
	}

	return warnings;
}

module.exports = { detectScanCompletenessWarnings };
