/**
 * lib/maintenance/commercial-support.js — paid support past the open-source end of life.
 *
 * endoflife.date's `extendedSupport` says a vendor sells fixes for a cycle whose open-source
 * life is over (Broadcom for Spring 5.3 until 2029…). Those fixes are not on Maven Central:
 * they ship as builds (5.3.41, 5.3.42…) from the vendor's private repository, to subscribers.
 * So an EOL finding stays an EOL finding — a project on the public artifacts does not have
 * them — and this module adds, per finding, what an auditor needs to put the paid option
 * next to "migrate":
 *
 *   - `branchFix`        — the build of THIS branch every CVE found on the component needs
 *                          (from the advisories' own per-branch bounds: CVE-2024-38820 is
 *                          affected up to 5.3.40 on 5.3.x → any build above 5.3.40), with how
 *                          many of the CVEs state such a bound;
 *   - `latestCommercial` — the newest build of the branch the configured vendor repository
 *                          publishes beyond Maven Central (only with that repository configured,
 *                          `--add-repo maven <name> <url> --token …`), and whether it meets
 *                          `branchFix`;
 *   - `commercialBuild`  — the project ALREADY runs a vendor build: its version is beyond the
 *                          last public release of the cycle AND absent from Maven Central.
 *                          Then the cycle is covered by the paid support it comes from, and
 *                          the finding leaves the EOL list (the caller turns it into a note).
 *
 * Maven only: the vendor builds this can prove are Maven coordinates; HeroDevs-style
 * replacements publish under other names that no public registry lists.
 */
const { fetchMetadataVersions } = require("../codecs/maven/transitive");
const { compareMavenVersions, stricterBranchFix } = require("../codecs/maven/version");

const fixVersion = f => (f ? f.fixed || f.after : null);
/** Does `version` satisfy the branch fix? */
function meets(version, f) {
	if (!f || !version) return false;
	const c = compareMavenVersions(version, fixVersion(f));
	return f.after ? c > 0 : c >= 0;
}

/** The coords (g:a) and versions an EOL finding covers: the anchor and every component. */
function findingCoords(e) {
	const out = new Map();
	const d = e.dep || {};
	if (d.ecosystem === "maven" && d.groupId && d.artifactId && d.version) out.set(`${d.groupId}:${d.artifactId}`, String(d.version));
	for (const c of e.components || []) if (String(c.name).includes(":") && c.version) out.set(c.name, String(c.version));
	return out;
}

/**
 * Annotate EOL findings in place. → { commercialBuilds: [finding…] } (also flagged
 * `status: "commercial"` on the finding, for the caller to move out of the EOL list).
 * opts: offline, repos (lib/providers/maven/repo list incl. configured ones), fetcher, cacheDir.
 */
async function annotateCommercialSupport(eolResults, matches, opts = {}) {
	const commercialBuilds = [];
	// Configured repositories only — Maven Central and its mirrors (`central: true`) list exactly Central.
	const vendorRepos = (opts.repos || []).filter(r => r && typeof r === "object" && !r.central && r.url!==require('../providers/maven/repo').GOOGLE_MAVEN.url && !/repo1\.maven\.org|repo\.maven\.apache\.org/i.test(String(r.url)));
	for (const e of eolResults || []) {
		if (!e.extendedSupport || e.status === "ok") continue;
		const coords = findingCoords(e);
		if (!coords.size) continue;

		// 1. The fix this branch needs, from the CVEs actually found on these coords/versions.
		let need = null, withBound = 0, total = 0;
		for (const m of matches || []) {
			if (m.suppressed || m.cpeFiltered || !m.dep) continue;
			const key = `${m.dep.groupId}:${m.dep.artifactId}`;
			if (coords.get(key) !== String(m.dep.version)) continue;
			total++;
			if (m.cve?.branchFix) { withBound++; need = stricterBranchFix(need, m.cve.branchFix); }
		}
		if (total) e.branchFix = { ...(need || {}), cves: total, withBound };

		const [anchorKey, anchorVersion] = coords.entries().next().value;
		const [g, a] = anchorKey.split(":");
		const central = await fetchMetadataVersions(g, a, { offline: opts.offline, fetcher: opts.fetcher, cacheDir: opts.cacheDir });
		const cyclePrefix = e.cycle ? `${e.cycle}.` : null;

		// 2. Already on a vendor build? Beyond the cycle's last public release AND not on Central.
		if (e.cycleLatest && central.length && compareMavenVersions(anchorVersion, e.cycleLatest) > 0 && !central.includes(anchorVersion)) {
			e.commercialBuild = { version: anchorVersion, lastPublic: e.cycleLatest };
			e.status = "commercial";
			commercialBuilds.push(e);
		}

		// 3. The newest vendor build of the branch, when a vendor repository is configured.
		if (vendorRepos.length && cyclePrefix && central.length) {
			const all = await fetchMetadataVersions(g, a, { offline: opts.offline, fetcher: opts.fetcher, cacheDir: opts.cacheDir, repos: vendorRepos });
			const vendorOnly = all.filter(v => v.startsWith(cyclePrefix) && !central.includes(v)).sort(compareMavenVersions);
			if (vendorOnly.length) {
				const latest = vendorOnly.at(-1);
				e.latestCommercial = { version: latest, meetsBranchFix: need ? meets(latest, need) : null };
			}
		}
	}
	return { commercialBuilds };
}

module.exports = { annotateCommercialSupport, meets, findingCoords };
