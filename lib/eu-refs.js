/**
 * lib/eu-refs.js — the European references of one CVE (EUVD, GCVE, CERT-FR), as one
 * list shared by the report and every export, so a reference reads the same in the
 * HTML, the SBOM, the CSAF and the SARIF.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { gcveUrl } = require("./gcve");
const { certfrUrl } = require("./certfr");

/** cve → [{ id, source, url, title? }]: EUVD first, then GCVE, then CERT-FR newest first. */
function europeanReferences(cve) {
	const out = [];
	if (cve?.euvd?.id) out.push({ id: cve.euvd.id, source: "ENISA EUVD",
		url: `https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(cve.euvd.id)}` });
	if (cve?.gcve) out.push({ id: cve.gcve, source: "GCVE", url: gcveUrl(cve.gcve) });
	for (const a of cve?.certfr || []) out.push({ id: a.ref, source: "CERT-FR", url: certfrUrl(a.kind, a.ref), ...(a.title ? { title: a.title } : {}) });
	return out;
}

/** ENISA lists the CVE as exploited (exploitedSince is a date, or "" when ENISA gives none). */
const euvdExploited = cve => cve?.euvd?.exploitedSince != null;

module.exports = { europeanReferences, euvdExploited };
