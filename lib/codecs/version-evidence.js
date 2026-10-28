// Merge collector occurrences without letting one project's version/scope classify another.
function mergeVersionEvidence(existing, record, relations = ['unknown']) {
	const evidence = Array.isArray(relations) && relations.length ? relations : ['unknown'];
	record.versionRelations = Object.fromEntries(record.versions.map(v => [v,
		[...new Set(evidence.map(r => ['direct', 'transitive'].includes(r) ? r : 'unknown'))].sort()]));
	if (!existing) return record;
	for (const p of record.manifestPaths) if (!existing.manifestPaths.includes(p)) existing.manifestPaths.push(p);
	for (const v of record.versions) {
		if (!existing.versions.includes(v)) existing.versions.push(v);
		existing.versionPaths[v] = [...new Set([...(existing.versionPaths[v] || []), ...(record.versionPaths[v] || [])])];
		existing.versionRelations[v] = [...new Set([...(existing.versionRelations[v] || []), ...record.versionRelations[v]])].sort();
	}
	if (!existing.version) existing.version = record.version;
	if (existing.isDev && !record.isDev) { existing.isDev = false; existing.scope = record.scope; }
	else if (existing.scope === 'transitive' && record.scope !== 'transitive' && existing.isDev === record.isDev) existing.scope = record.scope;
	return existing;
}
module.exports = { mergeVersionEvidence };
