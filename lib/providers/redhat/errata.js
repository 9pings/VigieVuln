'use strict';
/**
 * Red Hat errata, for the distributions rebuilt from Red Hat Enterprise Linux sources.
 *
 * AlmaLinux and Rocky Linux publish their own errata, but not for every update: packages
 * refreshed with a minor release, and some kernel updates, have none, or one that lists
 * fewer CVEs. Measured on a Rocky Linux 8.6 image: 795 (package, CVE) pairs fixed by a Red
 * Hat erratum that Rocky's feed does not mention. A rebuilt package keeps the version of the
 * Red Hat package it rebuilds, so the Red Hat erratum's fixed version compares with it.
 *
 * The distribution's own errata decide for every CVE they mention for a package: a Red Hat
 * erratum is reported only for the CVEs they do not mention.
 */
const { family } = require('./unfixed');

const SOURCE = 'redhat-errata', TTL_MS = 24 * 3600 * 1000;
const isCve = id => /^CVE-\d{4}-\d{4,}$/.test(id);
const empty = () => ({ matches: [], observations: [], coverage: [], warnings: [], assessments: [] });

async function assessRedHatErrata(inventory, opts = {}) {
	const result = empty(), scope = family(inventory?.distribution);
	if (!scope?.ownErrata || opts.osv === false) return result;
	const advisories = require('../../system-inventory/advisories');
	const rhel = { id: 'rhel', versionId: String(inventory.distribution.versionId), name: `Red Hat Enterprise Linux ${inventory.distribution.versionId}` };
	const options = { ...opts, advisoryConfig: undefined, adapters: undefined, records: undefined };
	const redhat = advisories.scope(rhel, options);
	const built = new RegExp(`[.+]el${scope.major}(?![0-9])`);
	const packages = (inventory.packages || []).filter(p => p.manager === 'rpm' && p.name && !['third-party', 'ambiguous'].includes(p.packageOrigin?.status) && built.test(`${p.version || ''} ${p.release || ''}`));
	if (!redhat || !packages.length) { result.coverage.push({ source: SOURCE, execution: 'not-applicable', result: 'not-applicable' }); return result; }

	const repository = opts.repository || require('../../cache/repository').createCacheRepository(opts.cacheDir || require('../../cache/directory').getCacheDir());
	const namespace = 'system-osv:' + redhat.ecosystem;
	let failure = null;
	const snapshot = () => repository.getSnapshot(namespace);
	const stale = s => !s?.complete || s.stale || !(Date.now() - (s.fetchedAt || 0) < TTL_MS);
	if (!opts.offline && (stale(snapshot()) || opts.refresh || opts.forceUpdate)) {
		try { await advisories.syncSystemAdvisories(rhel, options); }
		catch (error) { if (opts.signal?.aborted) throw error; failure = error; result.warnings.push({ type: 'source-unavailable', source: SOURCE, message: `Red Hat errata: ${error.message}${snapshot() ? '; saved data retained.' : ''}` }); }
	}
	if (!snapshot()) {
		result.coverage.push({ source: SOURCE, execution: failure ? 'failed' : 'not-run', result: 'indeterminate', reason: failure?.message || 'No Red Hat errata cached for this release.' });
		return result;
	}
	const assessed = await advisories.assessSystemInventory({ distribution: rhel, packages }, options);

	// What the distribution's own errata already say of each package.
	const own = advisories.scope(inventory.distribution, opts), ownNamespace = own ? 'system-osv:' + own.ecosystem : null, known = new Map();
	const mentioned = name => {
		if (!known.has(name)) {
			const ids = new Set();
			for (const record of (ownNamespace && repository.get(ownNamespace, name)?.value) || []) for (const id of [record.id, ...(record.aliases || []), ...(record.related || []), ...(record.upstream || [])]) ids.add(id);
			known.set(name, ids);
		}
		return known.get(name);
	};
	let superseded = 0;
	for (const match of assessed.matches) {
		const dep = match.dep, seen = new Set([...mentioned(dep.name), ...(dep.sourceName && dep.sourceName !== dep.name ? mentioned(dep.sourceName) : [])]);
		const cves = [...new Set([match.cve.id, ...match.cve.aliases, ...match.cve.upstream, ...match.cve.related].filter(isCve))];
		const missing = cves.filter(id => !seen.has(id));
		// Same erratum number under the rebuild's prefix (RLSA-2024:1234 for RHSA-2024:1234): its own record.
		const number = /:(\d+)$/.exec(match.cve.sourceAdvisoryId || '')?.[0];
		const rebuilt = number && [...seen].some(id => !isCve(id) && id.endsWith(number));
		if (cves.length ? !missing.length : rebuilt) { superseded++; continue; }
		const keep = list => list.filter(id => !isCve(id) || missing.includes(id));
		result.matches.push({ ...match, source: SOURCE, cve: { ...match.cve, aliases: keep(match.cve.aliases), upstream: keep(match.cve.upstream), related: keep(match.cve.related),
			distributionAdvisory: { source: 'Red Hat', release: redhat.ecosystem, appliedTo: scope.rebuild } } });
	}
	const partial = failure || assessed.coverage.some(c => c.status !== 'complete');
	result.coverage.push({ source: SOURCE, execution: partial ? 'partial' : 'completed', result: result.matches.length ? 'affected' : 'no-match', release: redhat.ecosystem, appliedTo: scope.rebuild,
		count: packages.length, superseded, fetchedAt: snapshot().fetchedAt || null, ...(failure ? { reason: failure.message } : {}) });
	return result;
}

module.exports = { assessRedHatErrata, SOURCE };
