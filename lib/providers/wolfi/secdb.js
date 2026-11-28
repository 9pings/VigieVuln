'use strict';
// Turns a Wolfi or Chainguard security database into advisory records the distribution lane
// already knows how to store and assess: one record per (package, vulnerability, fixed version).
const NAME = /^[a-z0-9][a-z0-9+_.-]{0,199}$/i, VERSION = /^[0-9][A-Za-z0-9._+~-]{0,199}$/, ID = /^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d+)$/i;
const MAX_PACKAGES = 100000, MAX_BYTES = 256 * 1024 * 1024;

/**
 * A fix lists the identifiers of one vulnerability side by side (its CVE, its GitHub and Go
 * ids) without saying which belong together. The CVE ids are reported; the other identifiers
 * only when the fix names no CVE at all, so that one vulnerability is not reported three times.
 */
function identifiers(list) {
	const ids = [...new Set((Array.isArray(list) ? list : []).filter(id => typeof id === 'string' && ID.test(id)).map(id => id.toUpperCase().startsWith('GHSA-') ? 'GHSA-' + id.slice(5).toLowerCase() : id.toUpperCase()))];
	const cves = ids.filter(id => id.startsWith('CVE-'));
	return cves.length ? cves : ids;
}
function recordsFromSecdb(document, ecosystem) {
	if (!document || typeof document !== 'object' || !Array.isArray(document.packages) || document.packages.length > MAX_PACKAGES) throw Error('invalid security database');
	const records = [];
	for (const entry of document.packages) {
		const name = entry?.pkg?.name, fixes = entry?.pkg?.secfixes;
		if (typeof name !== 'string' || !NAME.test(name) || !fixes || typeof fixes !== 'object') continue;
		for (const [version, list] of Object.entries(fixes)) {
			// "0" records that the package was never affected: nothing to report.
			if (version === '0' || !VERSION.test(version)) continue;
			// A finding is shown under the vulnerability's own identifier.
			for (const id of identifiers(list)) records.push({ id, aliases: [id],
				affected: [{ package: { ecosystem, name }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: version }] }] }] });
		}
	}
	if (!records.length) throw Error('security database holds no fix');
	return records;
}
/** Download the repositories of a scope and return their records. */
async function fetchRecords(scope, opts = {}) {
	const records = [];
	for (const repository of scope.secdb) {
		const response = await require('..').getResource('wolfi', 'secdb', { repository }, { fetcher: opts.fetcher, streaming: true, noStore: true, signal: opts.signal });
		if (!response.ok) throw Error(`${repository} security database HTTP ${response.status}`);
		const bytes = Buffer.from(await response.arrayBuffer());
		if (!bytes.length || bytes.length > MAX_BYTES) throw Error(`${repository} security database is empty or exceeds its size limit`);
		for (const record of recordsFromSecdb(JSON.parse(bytes.toString('utf8')), scope.ecosystem)) records.push(record);
	}
	return records;
}

module.exports = { recordsFromSecdb, fetchRecords, identifiers };
