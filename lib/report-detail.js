'use strict';
// A report is read, not grepped. One component with thousands of advisories (a kernel
// package carries more than 9 000) would bury every other finding and weigh hundreds of
// megabytes in every format. Each component keeps full detail for its highest-priority
// findings; the others remain listed in the machine exports with their identity, rating
// and fix, without the advisory texts.
const { sortByPriority } = require('./priority');
const PER_COMPONENT_DETAIL_LIMIT = 100;

function componentKey(dep = {}) {
	return dep.coordKey || [dep.artifactTargetId, dep.ecosystem, dep.groupId, dep.artifactId || dep.name, dep.version].join('\0');
}

/** The matches ranked beyond the limit within their own component, highest priority first. */
function beyondDetailLimit(matches, limit = PER_COMPONENT_DETAIL_LIMIT) {
	const seen = new Map(), beyond = new Set();
	for (const m of sortByPriority(matches || [])) {
		const key = componentKey(m.dep), rank = (seen.get(key) || 0) + 1;
		seen.set(key, rank);
		if (rank > limit) beyond.add(m);
	}
	return beyond;
}

module.exports = { PER_COMPONENT_DETAIL_LIMIT, componentKey, beyondDetailLimit };
