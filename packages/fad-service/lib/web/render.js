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

const date = v => /^\d{4}-\d{2}-\d{2}$/.test(day(v)) ? `<time datetime="${esc(day(v))}">${esc(day(v))}</time>` : esc(day(v));
const searchForm = (t, locale, q = "") => `<form class="search" action="/search" method="get" role="search">
<label for="query">${t("Search CVEs, advisories, packages")}</label>
<div class="search-controls"><input id="query" type="search" name="q" value="${esc(q)}" placeholder="${esc(t("Identifier, product or keyword"))}" aria-describedby="search-help" maxlength="200">
<input type="hidden" name="lang" value="${locale}"><button type="submit">${t("Search")}</button></div>
<p id="search-help" class="muted">${t("CVE, EUVD, GCVE or CERT-FR id, product, keyword…")}</p>
</form>`;

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]);
const badge = (sev, score) => {
	const s = SEVERITIES.has(String(sev || "").toUpperCase()) ? String(sev).toUpperCase() : "";
	return s || score != null ? `<span class="badge sev-${s}">${esc(s || "?")}${score != null ? " " + esc(Number(score).toFixed(1)) : ""}</span>` : "";
};

const DEFAULT_NAME = "fad · vulnerabilities";

function layout({ t, locale, title, body, q = "", path = "/", site = {} }) {
	const brand = site.brand || {};
	const name = brand.name || DEFAULT_NAME;
	const other = locale === "fr" ? "en" : "fr";
	const sep = path.includes("?") ? "&" : "?";
	const canonical = brand.baseUrl ? `<link rel="canonical" href="${esc(brand.baseUrl.replace(/\/$/, "") + path)}">` : "";
	const contact = safeUrl(brand.contact) || (/^mailto:[^\s"<>]+$/i.test(String(brand.contact || "")) ? brand.contact : null);
	return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · ${esc(name)}</title>
${canonical}
<link rel="stylesheet" href="/static/site.css${site.assetVersions?.css ? "?v=" + site.assetVersions.css : ""}">
${brand.accent ? `<link rel="stylesheet" href="/static/brand.css${site.assetVersions?.brand ? "?v=" + site.assetVersions.brand : ""}">` : ""}
${site.analyticsHead || ""}
</head>
<body>
<a class="skip-link" href="#content">${t("Skip to content")}</a>
<header class="site-header">
<a class="brand" href="/?lang=${locale}">${brand.hasLogo ? `<img src="/static/logo${site.assetVersions?.logo ? "?v=" + site.assetVersions.logo : ""}" alt="" height="28"> ` : ""}${esc(name)}</a>
<nav aria-label="${esc(t("Main navigation"))}"><a href="/cves?list=critical&amp;lang=${locale}">${t("Latest critical")}</a><a href="/cves?list=libraries&amp;lang=${locale}">${t("Critical in libraries")}</a><a href="/cves?list=exploited&amp;lang=${locale}">${t("Most exploited")}</a><a href="/sources?lang=${locale}">${t("Data sources")}</a><a href="/legal?lang=${locale}">${t("Legal notice")}</a><a href="${esc(path + sep + "lang=" + other)}" hreflang="${other}" lang="${other}" aria-label="${esc(t("Language"))}: ${esc(t(other === "fr" ? "French" : "English"))}">${other.toUpperCase()}</a></nav>
${path !== "/" ? searchForm(t, locale, q) : ""}
</header>
<main id="content" tabindex="-1">
${path === "/" ? `<section class="hero"><h1>${t("Search CVEs, advisories, packages")}</h1><p class="lead">${site.brand?.tagline ? esc(site.brand.tagline) : t("Vulnerability data hosted in Europe, for fad-checker and for you.")}</p>${searchForm(t, locale)}</section>` : path === "/search" && !body ? `<h1>${t("Search")}</h1><p>${t("Enter an identifier, product or keyword to begin.")}</p>` : ""}
${body}
</main>
<footer><p>${brand.footer ? esc(brand.footer) + " · " : ""}${t("Data from the sources listed on each page, under their own licences.")}</p><nav aria-label="${esc(t("Service information"))}"><a href="/sources?lang=${locale}">${t("Data sources")}</a><a href="/dumps?lang=${locale}">${t("Data dumps")}</a><a href="/legal?lang=${locale}">${t("Legal notice")}</a>${contact ? `<a href="${esc(contact)}">${t("Contact")}</a>` : ""}</nav></footer>
</body>
</html>`;
}

/** The CVE lists of the home page and of /cves: what each one is, said on the page. */
const CVE_LISTS = {
	critical: { title: "Latest critical vulnerabilities",
		intro: "Published CVEs whose headline CVSS score — from the CNA or from NVD — is 9.0 or more, newest first." },
	libraries: { title: "Libraries recently hit by a critical vulnerability",
		intro: "One row per library, from its newest critical CVE (CVSS 9.0 or more, from the CNA or NVD) that an OSV / GitHub advisory ties to it: the affected versions, the weakness, the fix." },
	exploited: { title: "Most likely to be exploited",
		intro: "Highest EPSS probability (FIRST.org) of exploitation activity in the next 30 days, across every published CVE." },
	kev: { title: "Recently added to CISA KEV",
		intro: "Latest additions to the CISA Known Exploited Vulnerabilities catalogue: exploitation observed in the wild." },
};
const severityOf = score => score == null ? null : score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : score > 0 ? "LOW" : "NONE";
const pct = x => x == null ? "" : `${(x * 100).toFixed(x >= 0.1 ? 0 : 1)}\u00a0%`;
const cveLink = (cve, locale) => `<a href="/cve/${encodeURIComponent(cve)}?lang=${locale}">${esc(cve)}</a>`;
const kevMark = (t, kev) => kev ? `<span class="flag" title="${esc(t("Known exploited (CISA KEV) · added {date}", { date: kev.dateAdded || "?" }))}">KEV</span>` : "";

/**
 * The CNA's versions of one product (CVE 5 `affected[].versions`), short: "10.2.0 – < 10.2.9-h1",
 * "≤ 4.1", "≥ 2.0"; when the CNA lists only unaffected versions: "fixed in 22.2R1, 22.7R2".
 */
function cnaVersionsText(t, versions) {
	const parts = [], fixes = [];
	for (const v of versions || []) {
		const from = v.version && v.version !== "0" ? String(v.version) : null;
		if (v.status === "affected") {
			if (v.lessThan === "*") parts.push(from ? `≥ ${from}` : "*");
			else if (v.lessThan) parts.push(from ? `${from} – < ${v.lessThan}` : `< ${v.lessThan}`);
			else if (v.lessThanOrEqual) parts.push(from === String(v.lessThanOrEqual) ? from : from ? `${from} – ${v.lessThanOrEqual}` : `≤ ${v.lessThanOrEqual}`);
			else if (from) parts.push(from);
		} else if (v.status === "unaffected" && from && /^v?\d/i.test(from) && (!v.lessThan || v.lessThan === "*" || /\*$/.test(v.lessThan))) fixes.push(from);
	}
	const cap = list => list.length > 3 ? list.slice(0, 3).join(" ; ") + " ; …" : list.join(" ; ");
	if (parts.length) return cap([...new Set(parts)]);
	return fixes.length ? `${t("fixed in")} ${cap([...new Set(fixes)]).replace(/ ; /g, ", ")}` : "";
}

/** What is vulnerable: the packages advisories name (with their versions), else the CNA's products. */
function affectedCell(t, locale, r, { max = 2 } = {}) {
	if (r.packages?.length) {
		const more = (r.packagesTotal || r.packages.length) - Math.min(max, r.packages.length);
		return r.packages.slice(0, max).map(p => `${libraryLink(locale, p)} <code>${esc(affectedText(p.entries))}</code>`).join("<br>")
			+ (more > 0 ? `<br><span class="muted">${t("+{n} more", { n: more })}</span>` : "");
	}
	const products = (r.products || []).filter(p => p.product && !/^n\/?a$/i.test(p.product));
	if (!products.length) return `<span class="muted">—</span>`;
	return products.slice(0, max).map(p => {
		const name = [p.vendor, p.product].filter(x => x && !/^n\/?a$/i.test(x)).join(" ");
		const v = cnaVersionsText(t, p.versions);
		return `<b>${esc(name)}</b>${v ? ` <code>${esc(v)}</code>` : ""}`;
	}).join("<br>") + (products.length > max ? `<br><span class="muted">${t("+{n} more", { n: products.length - max })}</span>` : "");
}

/** Compact form for the home page: id, score, KEV, what is vulnerable, title. */
function cveMiniList(t, locale, rows) {
	if (!rows.length) return `<p class="muted">${t("Nothing yet — the data is being imported.")}</p>`;
	return `<ol class="cve-mini">${rows.map(r => `<li><span class="cve-mini-head">${cveLink(r.cve, locale)} ${badge(severityOf(r.score), r.score)} ${kevMark(t, r.kev)}</span><span class="cve-mini-what">${affectedCell(t, locale, r, { max: 1 })}</span>${r.title ? `<span class="muted">${esc(r.title.length > 110 ? r.title.slice(0, 107) + "…" : r.title)}</span>` : ""}</li>`).join("")}</ol>`;
}

function cveTable(t, locale, rows) {
	return `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">CVE</th><th scope="col">${t("Library / product — vulnerable versions")}</th><th scope="col">${t("Title")}</th><th scope="col">${t("Severity")}</th><th scope="col">${t("Published")}</th><th scope="col">EPSS</th><th scope="col">${t("Exploitation")}</th></tr></thead><tbody>${
		rows.map(r => `<tr><td class="nw">${cveLink(r.cve, locale)}</td><td>${affectedCell(t, locale, r)}</td><td${r.title && r.title.length > 140 ? ` title="${esc(r.title)}"` : ""}>${esc(r.title && r.title.length > 140 ? r.title.slice(0, 137) + "…" : r.title || "")}</td><td class="nw">${badge(severityOf(r.score), r.score)}</td><td class="nw">${r.published ? date(r.published) : ""}</td><td class="nw">${pct(r.epss)}</td><td class="nw">${kevMark(t, r.kev)}${r.kev?.dateAdded ? `<br><span class="muted">${date(r.kev.dateAdded)}</span>` : ""}</td></tr>`).join("")}</tbody></table></div>`;
}

const pkgParts = key => { const m = /^pkg:([a-z]+)\/(.+)$/.exec(key); return m ? { eco: m[1], name: m[2] } : { eco: "", name: key }; };
/** A library: its page when it has one, else the advisory that names it. */
function libraryLink(locale, r) {
	const { eco, name } = pkgParts(r.key);
	const href = r.hasPage ? `${pkgPath(r.key)}?lang=${locale}` : assetHref("advisory", r.advisory, locale);
	return `<a href="${esc(href)}"><b>${esc(name)}</b></a> <span class="muted">${esc(ECOSYSTEM_LABEL[eco] || eco)}</span>`;
}

/**
 * The affected versions of one package, short: "< 3.88.0", "2.0 – < 2.15.0", "≤ 3.0.0-beta3",
 * "≥ 1.2" (no fix), or the advisory's explicit list. The advisory's own bounds, nothing inferred.
 */
function affectedText(entries) {
	const parts = [];
	for (const e of entries) {
		for (const r of e.ranges || []) {
			let from = null;
			for (const ev of r.events || []) {
				if (ev.introduced != null) from = String(ev.introduced) === "0" ? null : String(ev.introduced);
				else if (ev.fixed != null) { parts.push(from ? `${from} – < ${ev.fixed}` : `< ${ev.fixed}`); from = undefined; }
				else if (ev.last_affected != null) { parts.push(from === String(ev.last_affected) ? from : from ? `${from} – ${ev.last_affected}` : `≤ ${ev.last_affected}`); from = undefined; }
			}
			if (from !== undefined) parts.push(from ? `≥ ${from}` : "*");
		}
		if (!(e.ranges || []).length && (e.versions || []).length) parts.push(e.versions.slice(0, 3).join(", ") + (e.versions.length > 3 ? ", …" : ""));
	}
	const all = [...new Set(parts)];
	return all.length > 3 ? all.slice(0, 3).join(" ; ") + " ; …" : all.join(" ; ");
}

const CWE_NAMES = (() => { try { const { fadData } = require("../fad"); return { en: fadData("cwe-names.json"), fr: fadData("cwe-names-fr.json") }; } catch { return { en: {}, fr: {} }; } })();
const cweTitle = (id, locale) => (CWE_NAMES[locale] || {})[id] || CWE_NAMES.en[id] || "";
/** "CWE-89 SQL Injection" (+n), or the CVE's title when it carries no CWE. */
function weaknessText(locale, r, max = 110) {
	if (r.cwes?.length) {
		const c = r.cwes[0], name = cweTitle(c, locale);
		return `<abbr title="${esc(CWE_NAMES.en[c] || c)}">${esc(c)}</abbr>${name ? " " + esc(name) : ""}${r.cwes.length > 1 ? ` <span class="muted">+${r.cwes.length - 1}</span>` : ""}`;
	}
	return r.title ? `<span class="muted">${esc(r.title.length > max ? r.title.slice(0, max - 3) + "…" : r.title)}</span>` : "";
}
const otherCriticals = (t, r) => r.criticalCount > 1 ? ` <span class="muted">${t("{n} critical CVEs", { n: r.criticalCount })}</span>` : "";

function librariesTable(t, locale, rows) {
	return `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Library")}</th><th scope="col">${t("Affected versions")}</th><th scope="col">${t("Severity")}</th><th scope="col">${t("Weakness")}</th><th scope="col">CVE</th><th scope="col">${t("Fixed in")}</th></tr></thead><tbody>${
		rows.map(r => `<tr><td>${libraryLink(locale, r)}${otherCriticals(t, r)}</td><td><code>${esc(affectedText(r.entries))}</code></td><td class="nw">${badge(severityOf(r.score), r.score)}${r.kev ? " " + kevMark(t, r.kev) : ""}</td><td>${weaknessText(locale, r)}</td><td class="nw">${cveLink(r.cve, locale)}${r.published ? `<br><span class="muted">${date(r.published)}</span>` : ""}</td><td>${fixCell(t, r.entries)}</td></tr>`).join("")}</tbody></table></div>`;
}

/** Home page: "name — versions — CRITICAL 9.8 : CWE-89 SQL Injection". */
function libraryMiniList(t, locale, rows) {
	if (!rows.length) return `<p class="muted">${t("Nothing yet — the data is being imported.")}</p>`;
	return `<ol class="cve-mini">${rows.map(r => `<li><span class="cve-mini-head">${libraryLink(locale, r)} <code>${esc(affectedText(r.entries))}</code></span><span>${badge(severityOf(r.score), r.score)} ${weaknessText(locale, r, 80)}</span><span class="muted">${cveLink(r.cve, locale)}${otherCriticals(t, r)}</span></li>`).join("")}</ol>`;
}

function cveListPage({ t, locale, kind, rows }) {
	const L = CVE_LISTS[kind];
	const tabs = Object.keys(CVE_LISTS).map(k => k === kind ? `<b>${t(CVE_LISTS[k].title)}</b>` : `<a href="/cves?list=${k}&amp;lang=${locale}">${t(CVE_LISTS[k].title)}</a>`).join(" · ");
	return `<h1>${t(L.title)}</h1>
<p class="lead">${t(L.intro)}</p>
<p class="list-tabs">${tabs}</p>
${rows.length ? (kind === "libraries" ? librariesTable(t, locale, rows) : cveTable(t, locale, rows)) : `<div class="empty-state"><p>${t("Nothing yet — the data is being imported.")}</p></div>`}`;
}

function home({ t, locale = "en", counts, lists = null }) {
	const block = kind => lists?.[kind] ? `<section><h2>${t(CVE_LISTS[kind].title)}</h2>${(kind === "libraries" ? libraryMiniList : cveMiniList)(t, locale, lists[kind])}<p><a href="/cves?list=${kind}&amp;lang=${locale}">${t("See the full list")}</a></p></section>` : "";
	return `<div class="stats">
<div><b>${esc((counts.cve || 0).toLocaleString("fr-FR"))}</b>${t("Published vulnerabilities")}</div>
<div><b>${esc((counts.advisory || 0).toLocaleString("fr-FR"))}</b>${t("Advisories")}</div>
</div>
${lists ? `<div class="cve-lists">${block("critical")}${block("libraries")}${block("exploited")}${block("kev")}</div>` : ""}
<section class="home-sources"><h2>${t("Public data, traceable sources")}</h2>
<p>${t("CVE records and NVD scores, OSV/GHSA package advisories and CERT-FR publications, brought together in one place.")}</p>
<p>${t("CISA KEV, ENISA and EPSS add exploitation context. Each record links to its sources and licences.")}</p></section>`;
}

const pkgPath = key => { const m = /^pkg:([a-z]+)\/(.+)$/.exec(key); return m ? `/pkg/${m[1]}/${m[2].split("/").map(encodeURIComponent).join("/")}` : null; };
const assetHref = (type, key, locale) => type === "package" ? `${pkgPath(key)}?lang=${locale}`
	: type === "cve" ? `/cve/${encodeURIComponent(key)}?lang=${locale}`
	: type === "advisory" && key.startsWith("certfr:") ? `/advisory/certfr/${encodeURIComponent(key.slice(7))}?lang=${locale}`
	: type === "advisory" && key.startsWith("osv:") ? `/advisory/osv/${encodeURIComponent(key.slice(4))}?lang=${locale}` : null;
const assetName = key => key.replace(/^(certfr|osv):/, "");

function results({ t, locale, q, rows }) {
	const heading = `<h1>${t("Search results")}</h1>`;
	if (!rows.length) return heading + `<div class="empty-state"><p>${t("No result for “{q}”.", { q: esc(q) })}</p><p>${t("Try a broader keyword or a complete identifier.")}</p></div>`;
	return heading + `<p class="muted">${t(rows.length === 1 ? "{n} result" : "{n} results", { n: rows.length })}</p>` + rows.map(r => {
		const href = assetHref(r.type, r.key, locale);
		const name = r.type === "advisory" ? assetName(r.key) : r.key;
		const eyebrow = r.type === "advisory" ? (r.key.startsWith("certfr:") ? "CERT-FR" : "OSV / GHSA") + " · " + t("advisory")
			: r.type === "package" ? `${t("package")} · ${r.key.slice(4, r.key.indexOf("/"))}` : t(r.type);
		const label = r.type === "package" ? (r.title || r.key) : name;
		return `<article class="result"><p class="eyebrow">${esc(eyebrow)}</p><h2>${href ? `<a href="${esc(href)}">${esc(label)}</a>` : esc(label)}</h2>
<p>${esc(r.title || "")}</p></article>`;
	}).join("\n");
}

function sourcesTable(t, sources) {
	return `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Source")}</th><th scope="col">${t("Licence")}</th></tr></thead><tbody>${
		sources.map(s => `<tr><td>${link(s.url, s.name)}</td><td>${esc(s.licence || "")}</td></tr>`).join("")}</tbody></table></div>`;
}

function cvePage({ t, locale, asset, signals, euvdUrl, gcve, gcveUrl, certfrUrl, nvd = null, advisories = [] }) {
	const d = asset.data;
	const cvss = [...(d.cvss || []), ...(nvd?.metrics || []).map(m => ({ ...m, source: `NVD${m.source ? " · " + m.source : ""}${m.type ? " (" + m.type + ")" : ""}` }))];
	const cwes = [...new Set([...(d.cwes || []), ...(nvd?.cwes || [])])];
	const cpes = [];
	const walk = n => { for (const m of n?.cpeMatch || []) if (m.vulnerable) cpes.push(m); for (const c of n?.children || []) walk(c); };
	for (const c of nvd?.configurations || []) for (const n of c.nodes || []) walk(n);
	const sig = signals || {};
	const flags = [];
	if (sig.kev) flags.push(`<span class="flag">${t("Known exploited (CISA KEV) · added {date}", { date: esc(sig.kev.dateAdded || "?") })}</span>`);
	if (sig.euvd_exploited_since != null) flags.push(`<span class="flag">${sig.euvd_exploited_since ? t("Exploited per ENISA since {date}", { date: esc(sig.euvd_exploited_since) }) : t("Exploited per ENISA")}</span>`);
	const kv = [[t("Severity"), badge(d.severity, d.score) || t("Not available")]];
	if (flags.length) kv.push([t("Exploitation"), flags.join("<br>")]);
	if (sig.epss_score != null) kv.push(["EPSS", esc(t("EPSS {score} · percentile {pct} ({date})", {
		score: (sig.epss_score * 100).toFixed(2) + " %", pct: sig.epss_percentile == null ? "?" : Math.round(sig.epss_percentile * 100), date: sig.epss_date || "?" }))]);
	if (d.state) kv.push([t("State"), esc(d.state)]);
	if (d.published) kv.push([t("Published"), date(d.published)]);
	if (d.updated) kv.push([t("Updated"), date(d.updated)]);
	if (d.assigner) kv.push([t("Assigner"), esc(d.assigner)]);
	if (nvd?.vulnStatus) kv.push([t("NVD status"), esc(nvd.vulnStatus)]);


	const eu = [];
	if (sig.euvd_id) eu.push(`<li>ENISA EUVD · ${link(euvdUrl(sig.euvd_id), sig.euvd_id)}</li>`);
	if (gcve) eu.push(`<li>GCVE · ${link(gcveUrl(gcve), gcve)}</li>`);
	const certfr = Array.isArray(sig.certfr) ? sig.certfr : [];

	const sources = [...asset.sources];
	if (sig.kev) sources.push({ name: "CISA Known Exploited Vulnerabilities", licence: "CC0 1.0", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" });
	if (sig.epss_score != null) sources.push({ name: "EPSS (FIRST.org)", licence: "FIRST — attribution requested", url: "https://www.first.org/epss/" });
	if (sig.euvd_id || sig.euvd_exploited_since != null) sources.push({ name: "ENISA EUVD", licence: "ENISA — reproduction authorised, source acknowledged", url: "https://euvd.enisa.europa.eu/" });
	if (certfr.length) sources.push({ name: "CERT-FR (ANSSI)", licence: "Licence Ouverte / Etalab 2.0", url: "https://www.cert.ssi.gouv.fr/" });
	if (nvd) sources.push({ name: "NVD (NIST) via fkie-cad/nvd-json-data-feeds", licence: "Public domain — this product uses data from the NVD API but is not endorsed or certified by the NVD", url: `https://nvd.nist.gov/vuln/detail/${d.id}` });

	const refs = Array.isArray(d.references) ? d.references : [];
	return `<h1>${esc(d.id)}</h1>
<p class="record-title">${esc(d.title && d.title !== d.description?.slice(0, 140) ? d.title : "")}</p>
${kv.length ? `<section class="summary"><h2>${t("At a glance")}</h2><dl class="kv">${kv.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl></section>` : ""}
${d.description ? `<h2>${t("Description")}</h2><p class="desc">${esc(d.description)}</p>` : ""}
${cvss.length ? `<h2>${t("Scores")}</h2><div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Version")}</th><th scope="col">${t("Score")}</th><th scope="col">${t("Vector")}</th><th scope="col">${t("Scored by")}</th></tr></thead><tbody>${
	cvss.map(c => `<tr><td>CVSS ${esc(c.version)}</td><td>${badge(c.severity, c.score)}</td><td>${esc(c.vector || "")}</td><td>${esc(c.source || "")}</td></tr>`).join("")}</tbody></table></div>` : ""}
${cwes.length ? `<h2>${t("Weaknesses (CWE)")}</h2><ul class="plain">${cwes.map(c => `<li>${link(`https://cwe.mitre.org/data/definitions/${c.slice(4)}.html`, c)}</li>`).join("")}</ul>` : ""}
${advisories.length ? `<h2>${t("Advisories")}</h2><ul class="plain">${advisories.map(a => `<li><a href="${esc(assetHref("advisory", a.key, locale))}">${esc(assetName(a.key))}</a> — ${esc(a.title || "")}</li>`).join("")}</ul>` : ""}
${eu.length ? `<h2>${t("European references")}</h2><ul class="plain">${eu.join("")}</ul>` : ""}
${certfr.length ? `<h2>${t("CERT-FR advisories")}</h2><ul class="plain">${certfr.slice(0, 30).map(a => `<li><a href="/advisory/certfr/${encodeURIComponent(a.ref)}?lang=${locale}">${esc(a.ref)}</a> — ${esc(a.title || "")} · ${link(certfrUrl(a.kind, a.ref), "cert.ssi.gouv.fr")}</li>`).join("")}${certfr.length > 30 ? `<li class="muted">${t("+{n} more", { n: certfr.length - 30 })}</li>` : ""}</ul>` : ""}
${cpes.length ? `<h2>${t("Affected configurations (NVD CPE)")}</h2><ul class="plain">${cpes.slice(0, 40).map(m => `<li><code>${esc(m.criteria)}</code>${[
	m.versionStartIncluding ? " ≥ " + esc(m.versionStartIncluding) : "", m.versionStartExcluding ? " > " + esc(m.versionStartExcluding) : "",
	m.versionEndExcluding ? " < " + esc(m.versionEndExcluding) : "", m.versionEndIncluding ? " ≤ " + esc(m.versionEndIncluding) : ""].join("")}</li>`).join("")}${cpes.length > 40 ? `<li class="muted">${t("+{n} more", { n: cpes.length - 40 })}</li>` : ""}</ul>` : ""}
${d.affected?.length ? `<h2>${t("Affected products")}</h2><div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Product")}</th><th scope="col">${t("Versions")}</th></tr></thead><tbody>${d.affected.slice(0, 20).map(a => `<tr><td>${esc([a.vendor, a.product].filter(x => x && x !== "n/a").join(" · ") || a.packageName || "")}</td><td>${
	esc((a.versions || []).slice(0, 6).map(v => [v.status, v.version, v.lessThan ? "< " + v.lessThan : "", v.lessThanOrEqual ? "≤ " + v.lessThanOrEqual : ""].filter(Boolean).join(" ")).join(" ; "))}</td></tr>`).join("")}</tbody></table></div>` : ""}
${refs.length ? `<h2>${t("References")}</h2><ul class="plain">${refs.slice(0, 50).map(r => `<li>${link(r.url)}</li>`).join("")}${refs.length > 50 ? `<li class="muted">${t("+{n} more", { n: refs.length - 50 })}</li>` : ""}</ul>` : ""}
<h2>${t("Sources")}</h2>${sourcesTable(t, sources)}`;
}

function advisoryPage({ t, locale, asset }) {
	const d = asset.data;
	return `<h1>${esc(d.ref)}</h1>
<p class="record-title">${esc(d.title || "")}</p>
<section class="summary"><h2>${t("At a glance")}</h2><dl class="kv"><dt>${t("Source")}</dt><dd>CERT-FR · ${esc(d.kind === "alerte" ? t("Alert") : t("Advisory"))}</dd>
<dt>${t("Last update")}</dt><dd>${date(d.rev)}</dd>
<dt>${t("Original publication")}</dt><dd>${link(d.url)}</dd></dl></section>
${d.cves?.length ? `<h2>${t("CVEs cited")} (${d.cves.length})</h2><ul class="plain">${d.cves.slice(0, 500).map(c => `<li><a href="/cve/${encodeURIComponent(c)}?lang=${locale}">${esc(c)}</a></li>`).join("")}</ul>` : ""}
<h2>${t("Sources")}</h2>${sourcesTable(t, asset.sources)}`;
}

const rangeText = r => (r.events || []).map(e => e.introduced != null ? `introduced ${e.introduced}` : e.fixed != null ? `fixed ${e.fixed}`
	: e.last_affected != null ? `last affected ${e.last_affected}` : e.limit != null ? `limit ${e.limit}` : "").filter(Boolean).join(", ");

function osvAdvisoryPage({ t, locale, asset }) {
	const d = asset.data;
	const cves = (d.aliases || []).filter(a => /^CVE-\d{4}-\d{4,}$/.test(a));
	const others = (d.aliases || []).filter(a => !cves.includes(a));
	return `<h1>${esc(d.id)}</h1>
<p class="record-title">${esc(d.summary || "")}</p>
${d.withdrawn ? `<p class="flag">${t("Withdrawn")} · ${date(d.withdrawn)}</p>` : ""}
<section class="summary"><h2>${t("At a glance")}</h2><dl class="kv">
${d.published ? `<dt>${t("Published")}</dt><dd>${date(d.published)}</dd>` : ""}
${d.modified ? `<dt>${t("Updated")}</dt><dd>${date(d.modified)}</dd>` : ""}
${cves.length ? `<dt>CVE</dt><dd>${cves.map(c => `<a href="/cve/${encodeURIComponent(c)}?lang=${locale}">${esc(c)}</a>`).join(", ")}</dd>` : ""}
${others.length ? `<dt>${t("Aliases")}</dt><dd>${esc(others.join(", "))}</dd>` : ""}
${(d.severity || []).map(s => `<dt>${esc(s.type || "")}</dt><dd>${esc(s.score || "")}</dd>`).join("")}
</dl></section>
${d.details ? `<h2>${t("Description")}</h2><p class="desc">${esc(d.details)}</p>` : ""}
${d.affected?.length ? `<h2>${t("Affected packages")}</h2><div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Package")}</th><th scope="col">${t("Versions")}</th></tr></thead><tbody>${
	d.affected.slice(0, 50).map(a => `<tr><td>${esc(a.ecosystem || "")} · <b>${esc(a.name || "")}</b></td><td>${esc((a.ranges || []).map(rangeText).filter(Boolean).join(" ; ") || (a.versions || []).slice(0, 20).join(", "))}</td></tr>`).join("")}</tbody></table></div>` : ""}
${d.references?.length ? `<h2>${t("References")}</h2><ul class="plain">${d.references.slice(0, 50).map(r => `<li>${link(r.url)}${r.type ? ` <span class="muted">${esc(r.type)}</span>` : ""}</li>`).join("")}</ul>` : ""}
<h2>${t("Sources")}</h2>${sourcesTable(t, asset.sources)}`;
}

const ECOSYSTEM_LABEL = { npm: "npm", pypi: "PyPI", maven: "Maven", gem: "RubyGems", composer: "Packagist", nuget: "NuGet", golang: "Go" };
const verdict = (t, v) => v === true ? `<span class="flag">${t("Affected")}</span>` : v === false ? t("Not affected") : `<span class="muted">${t("Undetermined")}</span>`;

/**
 * advisories: [{ key, title, data, entries }] — entries = the record's `affected` items for
 * this package; versionAffected(type, version, entries) → true | false | null.
 */
/**
 * The versions panel (right of a package and of each of its versions): every version the
 * registry listed, newest first, with how many advisories affect it. verdicts: Map(version →
 * { hit, unknown }) computed once per package by the caller (versions × advisories).
 */
function versionsPanel({ t, locale, asset, verdicts, current = null }) {
	const list = asset.data.versions || [];
	if (!list.length) return "";
	const cell = v => {
		const x = verdicts.get(v.version);
		if (!x) return "";
		return x.hit ? `<span class="flag" title="${esc(t("affected by {n} advisory(ies)", { n: x.hit }))}">${x.hit}</span>`
			: x.unknown ? `<span class="muted" title="${esc(t("{n} advisory(ies) without a verdict", { n: x.unknown }))}">?</span>`
			: `<span class="ok" title="${esc(t("No known advisory affects it"))}">✓</span>`;
	};
	return `<aside class="versions-panel" aria-label="${esc(t("Versions"))}"><h2>${t("Versions")} <span class="muted">(${list.length})</span></h2><ol>${
		list.map(v => `<li${v.version === current ? ' class="current"' : ""}><a href="${esc(versionHref(asset.key, v.version, locale))}"${v.version === current ? ' aria-current="page"' : ""}>${esc(v.version)}</a>${
			v.deprecated ? ` <span class="badge">${t("deprecated")}</span>` : ""}${v.yanked ? ` <span class="badge">${t("yanked")}</span>` : ""}<span class="v-meta">${v.date ? date(v.date) : ""} ${cell(v)}</span></li>`).join("")}</ol>
<p class="muted">${t("“?” : the advisory gives no range that can be evaluated exactly for this ecosystem.")}</p></aside>`;
}
const withPanel = (main, panel) => panel ? `<div class="pkg-layout"><div class="pkg-main">${main}</div>${panel}</div>` : main;

/** Withdrawn advisories: kept visible (they are part of the record), never counted. */
function withdrawnList(t, locale, withdrawn) {
	if (!withdrawn.length) return "";
	return `<h2>${t("Withdrawn advisories")} (${withdrawn.length})</h2><p class="muted">${t("Withdrawn by their publisher: they affect no version and are not counted above.")}</p><ul class="plain">${
		withdrawn.map(a => `<li><a href="${esc(assetHref("advisory", a.key, locale))}">${esc(assetName(a.key))}</a> <span class="muted">${esc(a.title || "")}${a.data?.withdrawn ? ` · ${t("withdrawn")} ${date(a.data.withdrawn)}` : ""}</span></li>`).join("")}</ul>`;
}

function packagePage({ t, locale, asset, advisories = [], withdrawn = [], versionAffected, verdicts = new Map() }) {
	const d = asset.data;
	const type = d.type;
	const latestVerdicts = advisories.map(a => versionAffected(type, d.latest, a.entries));
	const kv = [[t("Ecosystem"), esc(ECOSYSTEM_LABEL[type] || type)]];
	if (d.latest) kv.push([t("Latest version"), `${esc(d.latest)}${d.latestDate ? ` · ${date(d.latestDate)}` : ""}`]);
	if (d.license) kv.push([t("Licence"), esc(d.license)]);
	if (d.deprecated) kv.push([t("Status"), `<span class="flag">${esc(d.deprecated)}</span>`]);
	if (advisories.length) {
		const hit = latestVerdicts.filter(v => v === true).length, unknown = latestVerdicts.filter(v => v === null).length;
		kv.push([t("Vulnerability status"), hit ? `<span class="flag">${t("affected by {n} advisory(ies)", { n: hit })}</span>`
			: unknown ? `<span class="muted">${t("{n} advisory(ies) without a verdict", { n: unknown })}</span>` : t("No known advisory affects it")]);
	}
	if (d.homepage) kv.push([t("Homepage"), link(d.homepage)]);
	if (d.repository) kv.push([t("Repository"), link(d.repository)]);
	const rangeOf = entries => esc(entries.flatMap(e => (e.ranges || []).map(rangeText)).filter(Boolean).join(" ; ") || entries.flatMap(e => (e.versions || []).slice(0, 10)).join(", "));
	return withPanel(`<h1>${esc(d.name)}</h1>
${d.description ? `<p class="record-title">${esc(d.description)}</p>` : ""}
<section class="summary"><h2>${t("At a glance")}</h2><dl class="kv">${kv.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl></section>
<h2>${t("Advisories")} (${advisories.length})</h2>
${advisories.length ? `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Advisory")}</th><th scope="col">${t("Affected versions")}</th><th scope="col">${t("Latest version")}</th></tr></thead><tbody>${
	advisories.map((a, i) => `<tr><td><a href="${esc(assetHref("advisory", a.key, locale))}">${esc(assetName(a.key))}</a><br><span class="muted">${esc(a.title || "")}</span></td><td>${rangeOf(a.entries)}</td><td>${verdict(t, latestVerdicts[i])}</td></tr>`).join("")}</tbody></table></div>`
	: `<p>${t("No advisory in the mirrored databases names this package.")}</p>`}
${withdrawnList(t, locale, withdrawn)}
${d.dependencies?.length ? `<h2>${t("Dependencies of the latest version")}</h2><ul class="plain">${d.dependencies.slice(0, 100).map(x => `<li><code>${esc(x.name)}</code> ${esc(x.range || "")} <span class="muted">${esc(x.scope || "")}</span></li>`).join("")}</ul>` : ""}
<h2>${t("Sources")}</h2>${sourcesTable(t, asset.sources)}`, versionsPanel({ t, locale, asset, verdicts }));
}

const versionHref = (key, version, locale) => `${pkgPath(key)}?version=${encodeURIComponent(version)}&lang=${locale}`;
/**
 * The "fixed in" cell, range by range: the fix, or — for a branch the advisory leaves
 * without one (a last_affected bound, or an open range) — said so, so "fixed 2.25.4" never
 * reads as covering a 3.x branch that has no fix at all.
 */
function fixCell(t, entries) {
	const parts = [];
	for (const e of entries) for (const r of e.ranges || []) {
		const ev = r.events || [];
		const fixed = ev.filter(x => x.fixed != null).map(x => esc(x.fixed));
		const last = ev.filter(x => x.last_affected != null).map(x => String(x.last_affected));
		if (fixed.length) parts.push(...fixed);
		else if (last.length) parts.push(`<span class="muted">≤ ${esc(last.join(", "))}, ${t("no fix")}</span>`);
		else if (ev.some(x => x.introduced != null)) parts.push(`<span class="muted">${t("no fix published")}</span>`);
	}
	return [...new Set(parts)].join(", ") || `<span class="muted">${t("no fix published")}</span>`;
}

/**
 * One version of a package: the advisories that affect it (exact verdicts only), those that
 * cannot be evaluated exactly, and the closest newer version no advisory affects.
 * advisories: [{ key, title, entries, cves: [{ cve, score, kev, epss }] }]
 */
function versionPage({ t, locale, asset, version, advisories = [], withdrawn = [], versionAffected, panelVerdicts = new Map() }) {
	const d = asset.data, type = d.type;
	const list = d.versions || [];
	const at = list.findIndex(v => v.version === version);
	const info = list[at] || { version };
	const verdicts = advisories.map(a => versionAffected(type, version, a.entries));
	const hit = advisories.filter((a, i) => verdicts[i] === true);
	const unknown = advisories.filter((a, i) => verdicts[i] === null);
	// versions are newest first: the closest newer clean one is the nearest index below.
	const clean = v => advisories.every(a => versionAffected(type, v, a.entries) === false);
	let upgrade = null;
	if (hit.length) for (let i = at - 1; i >= 0; i--) if (clean(list[i].version)) { upgrade = list[i].version; break; }
	const worst = a => Math.max(-1, ...a.cves.map(c => c.score ?? -1));
	hit.sort((x, y) => worst(y) - worst(x));
	const kv = [[t("Package"), `<a href="${esc(pkgPath(asset.key))}?lang=${locale}">${esc(d.name)}</a> <span class="muted">${esc(ECOSYSTEM_LABEL[type] || type)}</span>`]];
	if (info.date) kv.push([t("Published"), date(info.date)]);
	if (info.deprecated) kv.push([t("Status"), `<span class="badge">${t("deprecated")}</span>`]);
	if (info.yanked) kv.push([t("Status"), `<span class="badge">${t("yanked")}</span>`]);
	kv.push([t("Vulnerability status"), hit.length ? `<span class="flag">${t("affected by {n} advisory(ies)", { n: hit.length })}</span>`
		: unknown.length ? `<span class="muted">${t("{n} advisory(ies) without a verdict", { n: unknown.length })}</span>` : t("No known advisory affects it")]);
	if (hit.length) kv.push([t("Closest safe upgrade"), upgrade ? `<a href="${esc(versionHref(asset.key, upgrade, locale))}">${esc(upgrade)}</a>`
		: `<span class="muted">${t("No newer version is free of known advisories")}</span>`]);
	if (d.latest && d.latest !== version) kv.push([t("Latest version"), `<a href="${esc(versionHref(asset.key, d.latest, locale))}">${esc(d.latest)}</a>`]);
	const rows = items => `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Advisory")}</th><th scope="col">CVE</th><th scope="col">${t("Severity")}</th><th scope="col">${t("Fixed in")}</th></tr></thead><tbody>${
		items.map(a => `<tr><td><a href="${esc(assetHref("advisory", a.key, locale))}">${esc(assetName(a.key))}</a><br><span class="muted">${esc(a.title || "")}</span></td><td>${
			a.cves.map(c => `${cveLink(c.cve, locale)}${c.kev ? " " + kevMark(t, c.kev) : ""}${c.epss != null ? ` <span class="muted">EPSS\u00a0${pct(c.epss)}</span>` : ""}`).join("<br>") || `<span class="muted">—</span>`}</td><td>${
			badge(severityOf(worst(a) >= 0 ? worst(a) : null), worst(a) >= 0 ? worst(a) : null) || `<span class="muted">?</span>`}</td><td>${fixCell(t, a.entries)}</td></tr>`).join("")}</tbody></table></div>`;
	return withPanel(`<h1>${esc(d.name)} <span class="muted">${esc(version)}</span></h1>
<section class="summary"><h2>${t("At a glance")}</h2><dl class="kv">${kv.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl></section>
<h2>${t("Advisories affecting this version")} (${hit.length})</h2>
${hit.length ? rows(hit) : `<p>${t("No advisory in the mirrored databases affects this version.")}</p>`}
${unknown.length ? `<h2>${t("Advisories without an exact verdict")} (${unknown.length})</h2><p class="muted">${t("These advisories name the package, but give no range that can be evaluated exactly for this ecosystem: check them by hand.")}</p>${rows(unknown)}` : ""}
${withdrawnList(t, locale, withdrawn)}
<h2>${t("Sources")}</h2>${sourcesTable(t, asset.sources)}`, versionsPanel({ t, locale, asset, verdicts: panelVerdicts, current: version }));
}

const mb = n => `${(n / 1048576).toFixed(1)} MB`;
function dumpsPage({ t, builds = [], fingerprint }) {
	return `<h1>${t("Data dumps")}</h1>
<p class="lead">${t("Signed builds of the published data, to seed a local instance or an air-gapped relay.")}</p>
${fingerprint ? `<p>${t("Signing key")} : <a href="/dumps/signing-key.pem">signing-key.pem</a> · <code>${esc(fingerprint)}</code></p>` : `<p class="muted">${t("Builds are not signed on this instance.")}</p>`}
${builds.length ? `<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Build")}</th><th scope="col">${t("Created")}</th><th scope="col">${t("Size")}</th><th scope="col">${t("Download")}</th></tr></thead><tbody>${
	builds.map(b => {
		const f = n => `/dumps/files/${encodeURIComponent(n)}`;
		const links = [`<a href="${f(b.payload.file)}">${t("data")}</a>`, `<a href="${f(b.id + ".manifest.json")}">manifest</a>`,
			`<a href="${f(b.id + ".manifest.sig")}">sig</a>`, ...(b.torrent ? [`<a href="${f(b.torrent.file)}">torrent</a>`, `<a href="${esc(b.torrent.magnet)}">magnet</a>`] : [])];
		return `<tr><td><code>${esc(b.id)}</code>${b.delta ? ` <span class="badge">${t("delta since {date}", { date: esc(String(b.since).slice(0, 10)) })}</span>` : ""}<br><span class="muted">sha256 ${esc(b.payload.sha256.slice(0, 16))}…</span></td><td>${date(b.createdAt)}</td><td>${esc(mb(b.payload.bytes))}</td><td>${links.join(" · ")}</td></tr>`;
	}).join("")}</tbody></table></div>` : `<p>${t("No public build yet.")}</p>`}
<h2>${t("Use a build")}</h2>
<pre><code>fad-service verify fad-public-….manifest.json --trust-key signing-key.pem
fad-service restore fad-public-….manifest.json --trust-key signing-key.pem
fad-checker serve-cache --seed fad-private-….manifest.json --trust-key signing-key.pem</code></pre>`;
}

function sourcesPage({ t, jobs }) {
	return `<h1>${t("Data sources")}</h1>
<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Source")}</th><th scope="col">${t("Last update")}</th><th scope="col">${t("Status")}</th></tr></thead><tbody>${
	jobs.map(j => `<tr><td>${esc(j.label)}</td><td>${j.lastFinished ? esc(new Date(j.lastFinished).toISOString().replace("T", " ").slice(0, 16)) + " UTC" : t("never")}</td><td>${esc(j.status === "never" ? t("never") : j.status)}</td></tr>`).join("")}</tbody></table></div>`;
}

/** The attributions every source requires. Kept in English and French alike: legal text. */
function party(t, label, p) {
	if (!p || typeof p !== "object") return "";
	const rows = [["Name", p.name], ["Address", p.address], ["Publication director", p.director], ["Contact", p.contact]].filter(([, v]) => v);
	return rows.length ? `<h2>${t(label)}</h2><dl class="kv">${rows.map(([k, v]) => `<dt>${t(k)}</dt><dd>${safeUrl(v) ? link(v) : esc(v)}</dd>`).join("")}</dl>` : "";
}

function legalPage({ t, site = {} }) {
	const brand = site.brand || {};
	return `<h1>${t("Legal notice")}</h1>
${party(t, "Publisher", brand.publisher)}
${party(t, "Host", brand.host)}
<h2>${t("Software and data")}</h2>
<p>${esc(brand.name || DEFAULT_NAME)} — ${link("https://github.com/9pings/fad-checker", "fad-service")} (Apache-2.0). ${t("Data from the sources listed on each page, under their own licences.")}</p>
<div class="table-wrap" tabindex="0" role="region" aria-label="${esc(t("Scrollable table"))}"><table><thead><tr><th scope="col">${t("Source")}</th><th scope="col">${t("Licence")}</th></tr></thead><tbody>
<tr><td>${link("https://www.cve.org/", "CVE List (CVEProject cvelistV5)")}</td><td>CVE Program Terms of Use — Copyright © 1999–${new Date().getUTCFullYear()}, The MITRE Corporation. CVE and the CVE logo are registered trademarks of The MITRE Corporation. ${link("https://www.cve.org/Legal/TermsOfUse", "Terms of use")}</td></tr>
<tr><td>${link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA KEV")}</td><td>CC0 1.0. No endorsement by CISA is implied.</td></tr>
<tr><td>${link("https://www.first.org/epss/", "EPSS (FIRST.org)")}</td><td>FIRST — attribution requested.</td></tr>
<tr><td>${link("https://euvd.enisa.europa.eu/", "ENISA EUVD")}</td><td>Reproduction authorised, source acknowledged (ENISA legal notice).</td></tr>
<tr><td>${link("https://nvd.nist.gov/", "NVD (NIST)")}</td><td>Public domain. This product uses data from the NVD API but is not endorsed or certified by the NVD. Mirrored through ${link("https://github.com/fkie-cad/nvd-json-data-feeds", "fkie-cad/nvd-json-data-feeds")}.</td></tr>
<tr><td>${link("https://osv.dev/", "OSV.dev")}</td><td>Each record under its database's licence, shown on its page: GitHub Advisory Database, PyPA, Go (CC-BY 4.0), OpenSSF Malicious Packages (Apache-2.0), RustSec (CC0)…</td></tr>
<tr><td>${link("https://gcve.eu/", "GCVE")}</td><td>Identifiers from the GCVE allocation rules (GNA 0 = CVE).</td></tr>
<tr><td>${link("https://www.cert.ssi.gouv.fr/", "CERT-FR (ANSSI)")}</td><td>Licence Ouverte / Etalab 2.0 — source and date of last update shown on each advisory; linked, never framed.</td></tr>
</tbody></table></div>`;
}

function notFound({ t }) {
	return `<h1>${t("Not found")}</h1><p>${t("This item is not in the service.")}</p>`;
}

module.exports = { layout, home, cveListPage, versionPage, versionHref, CVE_LISTS, results, cvePage, advisoryPage, osvAdvisoryPage, packagePage, pkgPath, dumpsPage, sourcesPage, legalPage, notFound, esc, safeUrl, assetHref };
