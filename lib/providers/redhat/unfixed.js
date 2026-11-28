'use strict';
/**
 * Vulnerabilities Red Hat states are present without a fix. Errata only describe what was
 * fixed: on an up-to-date RHEL 8 image half of what Red Hat itself tracks has no erratum
 * ("Affected", "Fix deferred", "Will not fix", "Out of support scope").
 *
 * The statement is made for a package of one major release of Red Hat Enterprise Linux. It
 * holds for the distributions rebuilt from the same sources (AlmaLinux, Rocky Linux, CentOS
 * Linux, Oracle Linux) unless their own errata mention that CVE for the package: their own
 * record then decides. "Under investigation" is reported as an observation, not a finding.
 */
const { MAJORS } = require('./index');
const { STATES } = require('./oval');

const SOURCE = 'redhat-oval', FORMAT = 1, TTL_MS = 24 * 3600 * 1000, MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024;
const REBUILDS = new Map([['almalinux', 'AlmaLinux'], ['rocky', 'Rocky Linux'], ['centos', 'CentOS Linux'], ['ol', 'Oracle Linux']]);
// Rebuilds that publish errata of their own, which then decide for the CVEs they mention.
const OWN_ERRATA = new Set(['almalinux', 'rocky']);
const UNDER_INVESTIGATION = STATES.indexOf('Under investigation');

/** The Red Hat Enterprise Linux release whose statements describe this distribution, or null. */
function family(distribution) {
	const id = String(distribution?.id || '').toLowerCase(), major = String(distribution?.versionId || '').split('.')[0];
	if (!/^\d+$/.test(major)) return null;
	if (id === 'rhel') return { major, rebuild: null, ownErrata: false };
	// CentOS Stream is the upstream of the next minor release, not a rebuild of a released one.
	if (!REBUILDS.has(id) || (id === 'centos' && /stream/i.test(String(distribution.name || '')))) return null;
	return { major, rebuild: REBUILDS.get(id), ownErrata: OWN_ERRATA.has(id) };
}
const repositoryOf = opts => opts.repository || require('../../cache/repository').createCacheRepository(opts.cacheDir || require('../../cache/directory').getCacheDir());

async function refresh(major, opts) {
	const response = await require('..').getResource('redhat', 'oval-unpatched', { major }, { fetcher: opts.fetcher, noStore: true, streaming: true, signal: opts.signal });
	if (!response.ok) throw Error(`Red Hat OVAL HTTP ${response.status}`);
	const bytes = Buffer.from(await response.arrayBuffer());
	if (!bytes.length || bytes.length > MAX_DOWNLOAD_BYTES) throw Error('Red Hat OVAL file is empty or exceeds its size limit');
	const parsed = require('./oval').readUnpatched(bytes);
	return { format: FORMAT, fetchedAt: Date.now(), published: parsed.timestamp, count: parsed.count, advisories: parsed.advisories, components: parsed.components };
}

// CVEs the distribution's own errata mention for a package: its own record decides for those.
function ownErrata(inventory, opts) {
	const scope = require('../../system-inventory/advisories').scope(inventory.distribution, opts);
	if (!scope) return () => new Set();
	const cache = repositoryOf(opts), namespace = 'system-osv:' + scope.ecosystem, seen = new Map();
	return name => {
		if (!seen.has(name)) {
			const ids = new Set();
			for (const record of cache.get(namespace, name)?.value || []) for (const id of [record.id, ...(record.aliases || []), ...(record.related || []), ...(record.upstream || [])]) ids.add(id);
			seen.set(name, ids);
		}
		return seen.get(name);
	};
}

async function assessRedHatUnfixed(inventory, opts = {}) {
	const result = { matches: [], observations: [], coverage: [], warnings: [], assessments: [] };
	const scope = family(inventory?.distribution);
	if (!scope) return result;
	const release = `enterprise_linux:${scope.major}`;
	if (!MAJORS.has(scope.major)) {
		result.coverage.push({ source: SOURCE, execution: 'not-applicable', result: 'not-consulted', expected: false, reason: `Red Hat publishes no OVAL data for Enterprise Linux ${scope.major}.` });
		return result;
	}
	const packages = (inventory.packages || []).filter(p => p.manager === 'rpm' && p.name && !['third-party', 'ambiguous'].includes(p.packageOrigin?.status));
	if (!packages.length) { result.coverage.push({ source: SOURCE, execution: 'not-applicable', result: 'not-applicable' }); return result; }

	const repository = repositoryOf(opts), namespace = `${SOURCE}:${scope.major}`;
	let saved = repository.get(namespace, 'unfixed')?.value, failure = null;
	if (saved?.format !== FORMAT) saved = null;
	const stale = () => !saved || !(Date.now() - saved.fetchedAt < TTL_MS) || saved.fetchedAt > Date.now();
	if (!opts.offline && (stale() || opts.forceUpdate || opts.refresh)) {
		try { saved = await refresh(scope.major, opts); repository.put(namespace, 'unfixed', saved, { fetchedAt: saved.fetchedAt }); }
		catch (error) { if (opts.signal?.aborted) throw error; failure = error; result.warnings.push({ type: 'source-unavailable', source: SOURCE, message: `Red Hat OVAL: ${error.message}${saved ? '; saved data retained.' : ''}` }); }
	}
	if (!saved) {
		result.coverage.push({ source: SOURCE, execution: failure ? 'failed' : 'not-run', result: 'indeterminate', reason: failure?.message || 'No Red Hat OVAL data cached for this release.' });
		return result;
	}
	const mentionedByOwnErrata = scope.ownErrata ? ownErrata(inventory, opts) : () => new Set();
	const built = new RegExp(`[.+]el${scope.major}(?![0-9])`);
	// Red Hat lists every binary package of a source package (kernel, kernel-core, kernel-modules…)
	// for the same CVE. One finding per source package says it, naming the packages concerned,
	// instead of one per binary package: a kernel carries several thousand such CVEs.
	let examined = 0, skipped = 0;
	const groups = new Map();
	for (const dep of packages) {
		// A package of another origin carrying a Red Hat name is not the package Red Hat describes.
		if (!built.test(`${dep.version || ''} ${dep.release || ''}`)) { skipped++; continue; }
		examined++;
		const module = String(dep.modularityLabel || '').split(':').slice(0, 2).join(':');
		const listed = [...(dep.modularityLabel ? [] : saved.components[dep.name] || []), ...(module ? saved.components[`${module}/${dep.name}`] || [] : [])];
		if (!listed.length) continue;
		const own = new Set([...mentionedByOwnErrata(dep.name), ...(dep.sourceName && dep.sourceName !== dep.name ? mentionedByOwnErrata(dep.sourceName) : [])]);
		const key = `${dep.sourceName || dep.name}\0${dep.sourceVersion || dep.version}`;
		let group = groups.get(key);
		if (!group) groups.set(key, group = new Map());
		for (const [id, state] of listed) {
			if (!saved.advisories[id] || own.has(id)) continue;
			let entry = group.get(id);
			if (!entry) group.set(id, entry = { state, deps: [] });
			entry.deps.push(dep);
		}
	}
	for (const group of groups.values()) for (const [id, { state, deps }] of group) {
		const advisory = saved.advisories[id];
		// The package named after its source speaks for the group, else the first by name.
		const sorted = [...deps].sort((a, b) => a.name.localeCompare(b.name)), dep = sorted.find(d => d.name === d.sourceName) || sorted[0];
		const status = { source: 'Red Hat', release, state: STATES[state], ...(scope.rebuild ? { appliedTo: scope.rebuild } : {}),
			packages: sorted.map(d => d.name), observedAt: saved.fetchedAt };
		const url = `https://access.redhat.com/security/cve/${id}`;
		if (state === UNDER_INVESTIGATION) {
			result.observations.push({ dep, cveId: id, source: SOURCE, status: 'possible', sourceUrl: url, reason: 'Red Hat is investigating whether this package is affected.', evidence: status });
			continue;
		}
		result.matches.push({ dep, source: SOURCE, cve: { id, summary: advisory.title || '', description: advisory.title || '', severity: advisory.severity, score: advisory.score,
			...(advisory.vector ? { cvssVector: advisory.vector } : {}), fixVersion: null, published: advisory.published, modified: advisory.updated,
			distributionAdvisory: { source: 'Red Hat', release }, distributionStatus: status, osvRefs: [{ type: 'ADVISORY', url }] } });
	}
	const old = stale();
	if (old && !failure && !opts.offline) result.warnings.push({ type: 'source-stale', source: SOURCE, message: 'Red Hat OVAL data is older than a day.' });
	result.coverage.push({ source: SOURCE, execution: failure ? 'partial' : 'completed', result: result.matches.length ? 'affected' : 'no-match', release, count: examined,
		...(skipped ? { skipped } : {}), advisories: saved.count, fetchedAt: saved.fetchedAt, published: saved.published, ...(scope.rebuild ? { appliedTo: scope.rebuild } : {}), ...(failure ? { reason: failure.message } : {}) });
	return result;
}

module.exports = { assessRedHatUnfixed, family, SOURCE };
