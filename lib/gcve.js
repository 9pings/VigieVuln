/**
 * lib/gcve.js — the GCVE identifier of a CVE.
 *
 * GCVE (Global CVE allocation system, run by CIRCL, Luxembourg) lets independent
 * numbering authorities (GNAs) allocate vulnerability ids without MITRE. Every CVE id
 * lives in the reserved GNA 0 namespace: CVE-2021-44228 is GCVE-0-2021-44228, served
 * by the public GCVE database at db.gcve.eu. The mapping is DEFINED by the GCVE
 * rules, so it needs no request and works offline.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

/** "CVE-2021-44228" → "GCVE-0-2021-44228"; anything that is not a CVE id → null. */
function gcveId(cveId) {
	const m = /^CVE-(\d{4})-(\d{4,})$/i.exec(String(cveId || "").trim());
	return m ? `GCVE-0-${m[1]}-${m[2]}` : null;
}

/** Public page of a GCVE id in the GCVE database. */
function gcveUrl(id) {
	return `https://db.gcve.eu/vuln/${encodeURIComponent(id)}`;
}

/** Enrich matches in place: cve.gcve = "GCVE-0-…" for every CVE. Pure, no network. */
function enrichGcve(matches) {
	for (const m of matches || []) {
		const id = gcveId(m.cve?.id);
		if (id) m.cve.gcve = id;
	}
	return matches;
}

module.exports = { gcveId, gcveUrl, enrichGcve };
