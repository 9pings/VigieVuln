/**
 * Server-rendered pages. No client script at all: the CSP forbids it, and a page that
 * needs JavaScript to show a CVE is a page that breaks for half its readers.
 *
 * Everything that comes from a source — descriptions, titles, product names, URLs — is
 * untrusted: escaped on output, and a link is only emitted for an http(s) URL.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const safeUrl = u => /^https?:\/\//i.test(String(u || "")) ? String(u) : null;
const link = (url, text) => safeUrl(url) ? `<a href="${esc(url)}" rel="noopener noreferrer nofollow">${esc(text ?? url)}</a>` : esc(text ?? url ?? "");
const day = v => (v ? String(v).slice(0, 10) : "");

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]);
const badge = (sev, score) => {
	const s = SEVERITIES.has(String(sev || "").toUpperCase()) ? String(sev).toUpperCase() : "";
	return s || score != null ? `<span class="badge sev-${s}">${esc(s || "?")}${score != null ? " " + esc(Number(score).toFixed(1)) : ""}</span>` : "";
};

function layout({ t, locale, title, body, q = "", path = "/" }) {
	const other = locale === "fr" ? "en" : "fr";
	const sep = path.includes("?") ? "&" : "?";
	return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · fad-service</title>
<link rel="stylesheet" href="/static/site.css">
</head>
<body>
<header>
<a class="brand" href="/?lang=${locale}">fad · vulnerabilities</a>
<nav><a href="/sources?lang=${locale}">${t("Data sources")}</a><a href="/legal?lang=${locale}">${t("Legal notice")}</a><a href="${esc(path + sep + "lang=" + other)}" hreflang="${other}">${other.toUpperCase()}</a></nav>
</header>
<main>
<form class="search" action="/search" method="get" role="search">
<input type="search" name="q" value="${esc(q)}" placeholder="${esc(t("CVE, EUVD, GCVE or CERT-FR id, product, keyword…"))}" aria-label="${esc(t("Search CVEs, advisories, packages"))}" maxlength="200">
<input type="hidden" name="lang" value="${locale}">
<button type="submit">${t("Search")}</button>
</form>
${body}
</main>
<footer>${t("Data from the sources listed on each page, under their own licences.")} · <a href="/legal?lang=${locale}">${t("Legal notice")}</a></footer>
</body>
</html>`;
}

function home({ t, counts }) {
	return `<h1>${t("Search CVEs, advisories, packages")}</h1>
<p class="lead">${t("Vulnerability data hosted in Europe, for fad-checker and for you.")}</p>
<div class="stats">
<div><b>${esc((counts.cve || 0).toLocaleString("fr-FR"))}</b>${t("Published vulnerabilities")}</div>
<div><b>${esc((counts.advisory || 0).toLocaleString("fr-FR"))}</b>${t("Advisories")}</div>
</div>`;
}

const assetHref = (type, key, locale) => type === "cve" ? `/cve/${encodeURIComponent(key)}?lang=${locale}`
	: type === "advisory" && key.startsWith("certfr:") ? `/advisory/certfr/${encodeURIComponent(key.slice(7))}?lang=${locale}` : null;

function results({ t, locale, q, rows }) {
	if (!rows.length) return `<p>${t("No result for “{q}”.", { q: esc(q) })}</p>`;
	return `<p class="muted">${t(rows.length === 1 ? "{n} result" : "{n} results", { n: rows.length })}</p>` + rows.map(r => {
		const href = assetHref(r.type, r.key, locale);
		const name = r.type === "advisory" ? r.key.replace(/^certfr:/, "") : r.key;
		return `<div class="result">${href ? `<a href="${esc(href)}">${esc(name)}</a>` : esc(name)} <span class="muted">· ${esc(t(r.type))}</span>
<div>${esc(r.title || "")}</div></div>`;
	}).join("\n");
}

function sourcesTable(t, sources) {
	return `<div class="table-wrap"><table><thead><tr><th>${t("Source")}</th><th>${t("Licence")}</th></tr></thead><tbody>${
		sources.map(s => `<tr><td>${link(s.url, s.name)}</td><td>${esc(s.licence || "")}</td></tr>`).join("")}</tbody></table></div>`;
}

function cvePage({ t, locale, asset, signals, euvdUrl, gcve, gcveUrl, certfrUrl }) {
	const d = asset.data;
	const sig = signals || {};
	const flags = [];
	if (sig.kev) flags.push(`<span class="flag">${t("Known exploited (CISA KEV) · added {date}", { date: esc(sig.kev.dateAdded || "?") })}</span>`);
	if (sig.euvd_exploited_since != null) flags.push(`<span class="flag">${sig.euvd_exploited_since ? t("Exploited per ENISA since {date}", { date: esc(sig.euvd_exploited_since) }) : t("Exploited per ENISA")}</span>`);
	const kv = [];
	if (d.state) kv.push([t("State"), esc(d.state)]);
	if (d.published) kv.push([t("Published"), esc(day(d.published))]);
	if (d.updated) kv.push([t("Updated"), esc(day(d.updated))]);
	if (d.assigner) kv.push([t("Assigner"), esc(d.assigner)]);
	if (sig.epss_score != null) kv.push(["EPSS", esc(t("EPSS {score} · percentile {pct} ({date})", {
		score: (sig.epss_score * 100).toFixed(2) + " %", pct: Math.round(sig.epss_percentile * 100), date: sig.epss_date || "?" }))]);
	if (flags.length) kv.push([t("Exploitation"), flags.join("<br>")]);

	const eu = [];
	if (sig.euvd_id) eu.push(`<li>ENISA EUVD · ${link(euvdUrl(sig.euvd_id), sig.euvd_id)}</li>`);
	if (gcve) eu.push(`<li>GCVE · ${link(gcveUrl(gcve), gcve)}</li>`);
	const certfr = Array.isArray(sig.certfr) ? sig.certfr : [];

	const sources = [...asset.sources];
	if (sig.kev) sources.push({ name: "CISA Known Exploited Vulnerabilities", licence: "CC0 1.0", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" });
	if (sig.epss_score != null) sources.push({ name: "EPSS (FIRST.org)", licence: "FIRST — attribution requested", url: "https://www.first.org/epss/" });
	if (sig.euvd_id || sig.euvd_exploited_since != null) sources.push({ name: "ENISA EUVD", licence: "ENISA — reproduction authorised, source acknowledged", url: "https://euvd.enisa.europa.eu/" });
	if (certfr.length) sources.push({ name: "CERT-FR (ANSSI)", licence: "Licence Ouverte / Etalab 2.0", url: "https://www.cert.ssi.gouv.fr/" });

	const refs = Array.isArray(d.references) ? d.references : [];
	return `<h1>${esc(d.id)}</h1>
<p>${badge(d.severity, d.score)} ${esc(d.title && d.title !== d.description?.slice(0, 140) ? d.title : "")}</p>
${kv.length ? `<dl class="kv">${kv.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>` : ""}
${d.description ? `<h2>${t("Description")}</h2><p class="desc">${esc(d.description)}</p>` : ""}
${d.cvss?.length ? `<h2>${t("Scores")}</h2><div class="table-wrap"><table><thead><tr><th>${t("Version")}</th><th>${t("Score")}</th><th>${t("Vector")}</th><th>${t("Scored by")}</th></tr></thead><tbody>${
	d.cvss.map(c => `<tr><td>CVSS ${esc(c.version)}</td><td>${badge(c.severity, c.score)}</td><td>${esc(c.vector || "")}</td><td>${esc(c.source || "")}</td></tr>`).join("")}</tbody></table></div>` : ""}
${d.cwes?.length ? `<h2>${t("Weaknesses (CWE)")}</h2><ul class="plain">${d.cwes.map(c => `<li>${link(`https://cwe.mitre.org/data/definitions/${c.slice(4)}.html`, c)}</li>`).join("")}</ul>` : ""}
${eu.length ? `<h2>${t("European references")}</h2><ul class="plain">${eu.join("")}</ul>` : ""}
${certfr.length ? `<h2>${t("CERT-FR advisories")}</h2><ul class="plain">${certfr.slice(0, 30).map(a => `<li><a href="/advisory/certfr/${encodeURIComponent(a.ref)}?lang=${locale}">${esc(a.ref)}</a> — ${esc(a.title || "")} · ${link(certfrUrl(a.kind, a.ref), "cert.ssi.gouv.fr")}</li>`).join("")}${certfr.length > 30 ? `<li class="muted">${t("+{n} more", { n: certfr.length - 30 })}</li>` : ""}</ul>` : ""}
${d.affected?.length ? `<h2>${t("Affected products")}</h2><div class="table-wrap"><table><tbody>${d.affected.slice(0, 20).map(a => `<tr><td>${esc([a.vendor, a.product].filter(x => x && x !== "n/a").join(" · ") || a.packageName || "")}</td><td>${
	esc((a.versions || []).slice(0, 6).map(v => [v.status, v.version, v.lessThan ? "< " + v.lessThan : "", v.lessThanOrEqual ? "≤ " + v.lessThanOrEqual : ""].filter(Boolean).join(" ")).join(" ; "))}</td></tr>`).join("")}</tbody></table></div>` : ""}
${refs.length ? `<h2>${t("References")}</h2><ul class="plain">${refs.slice(0, 50).map(r => `<li>${link(r.url)}</li>`).join("")}${refs.length > 50 ? `<li class="muted">${t("+{n} more", { n: refs.length - 50 })}</li>` : ""}</ul>` : ""}
<h2>${t("Sources")}</h2>${sourcesTable(t, sources)}`;
}

function advisoryPage({ t, locale, asset }) {
	const d = asset.data;
	return `<h1>${esc(d.ref)}</h1>
<p>${esc(d.title || "")}</p>
<dl class="kv"><dt>${t("Source")}</dt><dd>CERT-FR · ${esc(d.kind === "alerte" ? t("Alert") : t("Advisory"))}</dd>
<dt>${t("Last update")}</dt><dd>${esc(day(d.rev))}</dd>
<dt>URL</dt><dd>${link(d.url)}</dd></dl>
${d.cves?.length ? `<h2>${t("CVEs cited")} (${d.cves.length})</h2><ul class="plain">${d.cves.slice(0, 500).map(c => `<li><a href="/cve/${encodeURIComponent(c)}?lang=${locale}">${esc(c)}</a></li>`).join("")}</ul>` : ""}
<h2>${t("Sources")}</h2>${sourcesTable(t, asset.sources)}`;
}

function sourcesPage({ t, jobs }) {
	return `<h1>${t("Data sources")}</h1>
<div class="table-wrap"><table><thead><tr><th>${t("Source")}</th><th>${t("Last update")}</th><th>${t("Status")}</th></tr></thead><tbody>${
	jobs.map(j => `<tr><td>${esc(j.label)}</td><td>${j.lastFinished ? esc(new Date(j.lastFinished).toISOString().replace("T", " ").slice(0, 16)) + " UTC" : t("never")}</td><td>${esc(j.status === "never" ? t("never") : j.status)} <span class="muted">${esc(j.detail)}</span></td></tr>`).join("")}</tbody></table></div>`;
}

/** The attributions every source requires. Kept in English and French alike: legal text. */
function legalPage({ t }) {
	return `<h1>${t("Legal notice")}</h1>
<p>fad-service — Apache-2.0. ${t("Data from the sources listed on each page, under their own licences.")}</p>
<div class="table-wrap"><table><thead><tr><th>${t("Source")}</th><th>${t("Licence")}</th></tr></thead><tbody>
<tr><td>${link("https://www.cve.org/", "CVE List (CVEProject cvelistV5)")}</td><td>CVE Program Terms of Use — Copyright © 1999–${new Date().getUTCFullYear()}, The MITRE Corporation. CVE and the CVE logo are registered trademarks of The MITRE Corporation. ${link("https://www.cve.org/Legal/TermsOfUse", "Terms of use")}</td></tr>
<tr><td>${link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA KEV")}</td><td>CC0 1.0. No endorsement by CISA is implied.</td></tr>
<tr><td>${link("https://www.first.org/epss/", "EPSS (FIRST.org)")}</td><td>FIRST — attribution requested.</td></tr>
<tr><td>${link("https://euvd.enisa.europa.eu/", "ENISA EUVD")}</td><td>Reproduction authorised, source acknowledged (ENISA legal notice).</td></tr>
<tr><td>${link("https://gcve.eu/", "GCVE")}</td><td>Identifiers from the GCVE allocation rules (GNA 0 = CVE).</td></tr>
<tr><td>${link("https://www.cert.ssi.gouv.fr/", "CERT-FR (ANSSI)")}</td><td>Licence Ouverte / Etalab 2.0 — source and date of last update shown on each advisory; linked, never framed.</td></tr>
</tbody></table></div>`;
}

function notFound({ t }) {
	return `<h1>${t("Not found")}</h1><p>${t("This item is not in the service.")}</p>`;
}

module.exports = { layout, home, results, cvePage, advisoryPage, sourcesPage, legalPage, notFound, esc, safeUrl, assetHref };
