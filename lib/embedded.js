/**
 * lib/embedded.js — inventory of Maven coordinates discovered inside committed
 * .jar/.war/.ear archives (provenance:"embedded"), whether or not they carry a CVE.
 *
 * This is a governance / cyber-hygiene signal: the JAR twin of the native-binary
 * inventory (lib/unmanaged.js → chapter 1C) and the vendored-JS inventory
 * (lib/retire.js → chapter 1D). Code that ships inside a committed binary which no
 * pom.xml declares has unknown provenance and patch story even when not vulnerable.
 *
 * Pure: shared by the HTML report (chapter 1B) and the JSON export so both list the
 * SAME set. CVE counts/severity are cross-referenced from the embedded CVE matches
 * by coordKey.
 */

const EMB_SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0, UNKNOWN: 0 };

/**
 * @param resolvedDeps Map of all resolved deps (embedded ones carry provenance:"embedded").
 * @param embeddedMatches CVE matches whose dep is embedded (subset of the scan's matches).
 * @returns sorted array of { archive, groupId, artifactId, version, coordKey, manifestPath, vulnCount, maxSeverity }
 */
function buildEmbeddedInventory(resolvedDeps, embeddedMatches) {
	const cveByCoord = new Map(); // coordKey → { ids:Set, maxSeverity }
	for (const m of (embeddedMatches || [])) {
		const key = m.dep?.coordKey;
		if (!key) continue;
		let e = cveByCoord.get(key);
		if (!e) { e = { ids: new Set(), maxSeverity: null }; cveByCoord.set(key, e); }
		e.ids.add(m.cve?.id);
		const sev = m.cve?.severity || "UNKNOWN";
		if (!e.maxSeverity || (EMB_SEV_RANK[sev] || 0) > (EMB_SEV_RANK[e.maxSeverity] || 0)) e.maxSeverity = sev;
	}
	const out = [];
	for (const dep of (resolvedDeps?.values?.() || [])) {
		if (dep.provenance !== "embedded") continue;
		const manifestPath = (dep.manifestPaths || [])[0] || "(unknown archive)";
		const archive = String(manifestPath).split("!/")[0];
		const cve = cveByCoord.get(dep.coordKey);
		out.push({
			...(dep.artifactTargetId ? {artifactTargetId:dep.artifactTargetId} : {}),
			archive,
			groupId: dep.groupId || dep.namespace || "",
			artifactId: dep.artifactId || dep.name || "",
			version: dep.version || "",
			coordKey: dep.coordKey,
			manifestPath,
			vulnCount: cve ? cve.ids.size : 0,
			maxSeverity: cve ? cve.maxSeverity : null,
		});
	}
	out.sort((a, b) =>
		(EMB_SEV_RANK[b.maxSeverity] || 0) - (EMB_SEV_RANK[a.maxSeverity] || 0)
		|| String(a.archive).localeCompare(String(b.archive))
		|| `${a.groupId}:${a.artifactId}:${a.version}`.localeCompare(`${b.groupId}:${b.artifactId}:${b.version}`));
	return out;
}

module.exports = { buildEmbeddedInventory, EMB_SEV_RANK };
