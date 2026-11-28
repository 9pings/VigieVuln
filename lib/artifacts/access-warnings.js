'use strict';
// A live system collected without root meets hundreds of unreadable directories and files.
// One notice says what that means, instead of one warning per path.
const DENIED = new Set(['EACCES', 'EPERM']);
const denied = w => DENIED.has(w?.code) || /\b(?:EACCES|EPERM)\b/.test(String(w?.message || ''));
const pathOf = w => w.manifestPath || /(?:open|scandir|lstat|stat|readlink|opendir) '([^']+)'/.exec(String(w.message || ''))?.[1] || null;

function foldAccessWarnings(warnings = []) {
	const hits = warnings.filter(denied);
	// Folding again (a later collection step adds its own warnings) extends the same notice.
	const earlier = warnings.filter(w => w?.reason === 'permission-denied' && Array.isArray(w.items));
	if (hits.length + earlier.length < 2) return warnings;
	const known = new Set(earlier.flatMap(w => w.items.map(item => item.id)));
	const fresh = [...new Set(hits.map(pathOf).filter(Boolean))].filter(p => !known.has(p));
	const count = earlier.reduce((n, w) => n + (w.count || 0), 0) + fresh.length + hits.filter(w => !pathOf(w)).length;
	const paths = [...known, ...fresh].sort();
	return [...warnings.filter(w => !denied(w) && !earlier.includes(w)), {
		type: 'dependency-coverage', capability: 'inventory', reason: 'permission-denied', count,
		items: paths.slice(0, 200).map(id => ({ id })),
		message: `${count} path(s) could not be read (permission denied): their content is not in the inventory. Run the collection as root for a complete inventory.`,
	}];
}

module.exports = { foldAccessWarnings };
