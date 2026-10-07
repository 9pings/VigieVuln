/**
 * CERT-FR mirror: every avis / alerte becomes an advisory asset (its own page), and each
 * CVE gets the list of advisories that cite it. The incremental index is fad's own
 * (lib/certfr.js): only advisories new or revised since the last run are fetched.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { fad } = require("../fad");

const PREFIX = "certfr:";

function advisoryAsset(ref, e) {
	const url = fad("certfr").certfrUrl(e.kind, ref);
	return {
		type: "advisory", key: PREFIX + ref, title: e.title || ref, summary: e.title || null, aliases: [ref],
		data: { source: "certfr", ref, kind: e.kind, rev: e.rev, title: e.title || "", cves: e.cves || [], url },
		sources: [{ name: "CERT-FR (ANSSI)", licence: "Licence Ouverte / Etalab 2.0", url }],
	};
}

async function run({ assets, fetcher }) {
	const { refreshCertFrIndex, indexByCve } = fad("certfr");
	const entries = {};
	for await (const { key, data } of assets.iteratePrefix("advisory", PREFIX))
		entries[key.slice(PREFIX.length)] = { kind: data.kind, rev: data.rev, title: data.title, cves: data.cves };
	// CVEs cited before the refresh: a revised advisory may drop one, which must lose it.
	const citedBefore = new Set(Object.values(entries).flatMap(e => e.cves || []));
	const index = { meta: { fetchedAt: 0 }, entries };
	const { changed, failed } = await refreshCertFrIndex(index, { fetcher, cacheDir: false });
	if (!changed.length) return `no change${failed ? ` (${failed} failed)` : ""}`;
	await assets.transaction(async t => { for (const ref of changed) await t.upsert(advisoryAsset(ref, index.entries[ref])); });
	const byCve = indexByCve(index.entries);
	const rows = Object.entries(byCve).map(([cve, list]) => [cve, list.map(a => ({ ref: a.ref, kind: a.kind, title: a.title }))]);
	for (const cve of citedBefore) if (!byCve[cve]) rows.push([cve, null]);
	await assets.setSignal("certfr", rows);
	return `${changed.length} advisories updated · ${Object.keys(byCve).length} CVEs cited${failed ? ` · ${failed} failed` : ""}`;
}

module.exports = { run, advisoryAsset, PREFIX };
