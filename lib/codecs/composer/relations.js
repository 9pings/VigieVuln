/**
 * Per-version union of the collector's occurrence evidence. This does not resolve
 * Composer's graph or infer a relation from scope, isDev, or another version.
 * Unknown occurrences remain visible even alongside a proven relation.
 */
function versionRelationsFor(dep) {
	const byVersion = new Map((dep.versions || []).map(version => [version, new Set()]));
	for (const occurrence of dep.occurrences || []) {
		const relations = byVersion.get(occurrence.version);
		if (!relations) continue; // Never add a version to the scan from metadata.
		const relation = occurrence.managerRelation;
		relations.add(relation === "direct" || relation === "transitive" ? relation : "unknown");
	}
	return Object.fromEntries([...byVersion].map(([version, relations]) =>
		[version, relations.size ? [...relations] : ["unknown"]]));
}

module.exports = { versionRelationsFor };
