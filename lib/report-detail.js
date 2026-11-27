'use strict';
// A report is read, not grepped. One component with thousands of advisories (a kernel
// package carries more than 9 000) would bury every other finding and weigh hundreds of
// megabytes in every format, and so would one advisory repeated for each of the forty
// packages built from the same source. Findings are therefore grouped:
//   - a system source package and every package built from it form one group, any other
//     component is its own group;
//   - within a source group each advisory is detailed once, on its highest-priority package;
//   - a group details its `limit` highest-priority advisories (occurrences, for a component).
// Every other finding stays listed in the machine exports with its identity, component,
// rating and fix, without the advisory texts.
const { sortByPriority } = require('./priority');
const PER_COMPONENT_DETAIL_LIMIT = 100;

function componentKey(dep = {}) {
	return dep.coordKey || [dep.artifactTargetId, dep.ecosystem, dep.groupId, dep.artifactId || dep.name, dep.version].join('\0');
}
function detailGroupKey(dep = {}) {
	return dep.ecosystem === 'system' && dep.sourceName
		? ['source', dep.artifactTargetId, dep.manager, dep.sourceName, dep.sourceVersion].join('\0')
		: componentKey(dep);
}

/**
 * Plan the detail of a list of matches.
 * → detailed: matches reported in full, highest priority first
 *   siblings: detailed match → the other occurrences of that advisory in its group
 *   compact:  every match that is not detailed
 *   groups:   { dep, source, packages, detailed, beyond: [first match of each advisory past the limit] }
 */
function planDetail(matches, limit = PER_COMPONENT_DETAIL_LIMIT) {
	const groups = new Map(), detailed = [], siblings = new Map(), compact = new Set();
	for (const m of sortByPriority(matches || [])) {
		const dep = m.dep || {}, key = detailGroupKey(dep);
		let group = groups.get(key);
		if (!group) groups.set(key, group = { dep, source: key !== componentKey(dep), packages: new Set(), primaries: new Map(), beyond: new Map() });
		group.packages.add(componentKey(dep));
		// Only the packages of one source share an advisory. Two matches on another component
		// are distinct occurrences (physical copies in two manifests) and each keeps its row.
		const id = group.source ? (m.cve?.id || m) : m;
		if (group.primaries.has(id)) { siblings.get(group.primaries.get(id)).push(m); compact.add(m); continue; }
		if (group.beyond.has(id)) { compact.add(m); continue; }
		if (group.primaries.size < limit) { group.primaries.set(id, m); siblings.set(m, []); detailed.push(m); continue; }
		group.beyond.set(id, m); compact.add(m);
	}
	return { detailed, siblings, compact,
		groups: [...groups.values()].map(g => ({ dep: g.dep, source: g.source, packages: g.packages.size, detailed: g.primaries.size, beyond: [...g.beyond.values()] })) };
}

/** The matches reported without their advisory texts. */
function beyondDetailLimit(matches, limit = PER_COMPONENT_DETAIL_LIMIT) {
	return planDetail(matches, limit).compact;
}

module.exports = { PER_COMPONENT_DETAIL_LIMIT, componentKey, detailGroupKey, planDetail, beyondDetailLimit };
