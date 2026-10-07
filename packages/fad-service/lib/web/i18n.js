/**
 * The site's own wording, FR/EN. Same rule as the fad report (lib/i18n.js): the English
 * string is the key, so a missing French entry degrades to English, and text that comes
 * from a data source (CVE descriptions, advisory titles) is evidence — never translated.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const FR = {
	"Search": "Rechercher",
	"Search CVEs, advisories, packages": "Rechercher une CVE, un avis, un paquet",
	"CVE, EUVD, GCVE or CERT-FR id, product, keyword…": "Identifiant CVE, EUVD, GCVE ou CERT-FR, produit, mot-clé…",
	"Vulnerability data hosted in Europe, for fad-checker and for you.": "Des données de vulnérabilités hébergées en Europe, pour fad-checker et pour vous.",
	"Published vulnerabilities": "Vulnérabilités publiées",
	"Advisories": "Avis",
	"Data sources": "Sources de données",
	"Legal notice": "Mentions légales",
	"No result for “{q}”.": "Aucun résultat pour « {q} ».",
	"{n} result": "{n} résultat",
	"{n} results": "{n} résultats",
	"Not found": "Introuvable",
	"This item is not in the service.": "Cet élément n'est pas dans le service.",
	"Description": "Description",
	"Severity": "Sévérité",
	"Scores": "Scores",
	"Score": "Score",
	"Version": "Version",
	"Vector": "Vecteur",
	"Scored by": "Évalué par",
	"Weaknesses (CWE)": "Faiblesses (CWE)",
	"Published": "Publiée",
	"Updated": "Mise à jour",
	"Assigner": "Attribuée par",
	"State": "État",
	"Exploitation": "Exploitation",
	"Known exploited (CISA KEV) · added {date}": "Exploitation connue (CISA KEV) · ajoutée le {date}",
	"Exploited per ENISA since {date}": "Exploitée selon l'ENISA depuis le {date}",
	"Exploited per ENISA": "Exploitée selon l'ENISA",
	"EPSS {score} · percentile {pct} ({date})": "EPSS {score} · centile {pct} ({date})",
	"European references": "Références européennes",
	"CERT-FR advisories": "Avis du CERT-FR",
	"Affected products": "Produits affectés",
	"References": "Références",
	"Sources": "Sources",
	"Source": "Source",
	"Licence": "Licence",
	"CVEs cited": "CVE citées",
	"Advisory": "Avis",
	"Alert": "Alerte",
	"Last update": "Dernière mise à jour",
	"Status": "État",
	"never": "jamais",
	"Language": "Langue",
	"Data from the sources listed on each page, under their own licences.": "Données issues des sources indiquées sur chaque page, sous leurs propres licences.",
	"+{n} more": "+{n} autres",
	"cve": "CVE",
	"advisory": "avis",
};

const CATALOG = { en: {}, fr: FR };

function pickLocale(query, acceptLanguage) {
	const q = String(query || "").toLowerCase();
	if (q === "fr" || q === "en") return q;
	return /^\s*fr\b/i.test(String(acceptLanguage || "")) ? "fr" : "en";
}

function makeT(locale) {
	const table = CATALOG[locale] || {};
	return (key, vars = {}) => String(table[key] ?? key).replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}

module.exports = { pickLocale, makeT, CATALOG };
