const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normaliseLocale, makeT, CATALOG } = require("../lib/i18n");
const { generateHtmlReport, generateWordReport } = require("../lib/cve-report");
const { makeDepRecord } = require("../lib/dep-record");

test("normaliseLocale accepts what a human would type, and refuses to guess", () => {
	for (const x of ["fr", "FR", "fr-FR", "fr_FR", " fr "]) assert.equal(normaliseLocale(x), "fr", x);
	for (const x of ["en", "us", "US", "en-US", "en_GB"]) assert.equal(normaliseLocale(x), "en", x);
	// An unsupported language falls back to English rather than rendering raw keys.
	for (const x of ["de", "es", "zz", "", null, undefined, 42]) assert.equal(normaliseLocale(x), "en", String(x));
});

test("English is pass-through: the key IS the string, so an en report cannot regress", () => {
	const t = makeT("en");
	assert.equal(t("Copy table"), "Copy table");
	assert.equal(t("a string nobody translated"), "a string nobody translated");
	assert.deepEqual(CATALOG.en, {}, "there is no English table to drift from the source");
});

test("a missing French entry degrades to English, never to a raw key", () => {
	const t = makeT("fr");
	assert.equal(t("Dependency"), "Dépendance");
	assert.equal(t("CISA KEV"), "CISA KEV", "identifiers are deliberately untranslated");
	assert.equal(t("something only in the source"), "something only in the source");
});

test("placeholders interpolate, so a sentence can be reordered in translation", () => {
	assert.equal(makeT("en")("{n} of {total}", { n: 3, total: 9 }), "3 of 9");
});

const dep = makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0.0", manifestPath: "/p/pom.xml" });
const payload = locale => ({
	cveMatches: [{ dep, cve: { id: "CVE-2021-44228", severity: "CRITICAL", score: 10, description: "Log4Shell text from the advisory", fixVersion: "2.15.0", published: "2021-12-10", cwes: ["CWE-502"] }, confidence: "exact" }],
	eolResults: [], obsoleteResults: [], outdatedResults: [],
	projectInfo: { name: "demo", src: "/p", generatedAt: "2026-09-19" }, locale,
});

test("the French report translates its own chrome and leaves the evidence alone", () => {
	const fr = generateHtmlReport(payload("fr"));
	assert.match(fr, /Rapport VigieVuln/);
	assert.match(fr, /<th>Dépendance<\/th>/);
	assert.match(fr, /Version corrigée/);
	// Advisory text is evidence. Paraphrasing it in an audit report would be wrong, so it
	// is never translated — and neither is the CVE id.
	assert.match(fr, /Log4Shell text from the advisory/);
	assert.match(fr, /CVE-2021-44228/);
});

test("a French CWE title carries MITRE's English original with it", () => {
	// MITRE publishes CWE in English only, so the translation is fad's own. Dropping the
	// original would leave a reader unable to find the weakness on cwe.mitre.org.
	const fr = generateHtmlReport(payload("fr"));
	assert.match(fr, /Désérialisation de données non fiables/);
	assert.match(fr, /MITRE: Deserialization of Untrusted Data/);
	const en = generateHtmlReport(payload("en"));
	assert.match(en, /Deserialization of Untrusted Data/);
	assert.doesNotMatch(en, /MITRE:/, "no redundant original when the title already is the original");
});

test("Word column widths survive translation", () => {
	// They keyed on the English header text until this was caught: a French report lost the
	// <colgroup> on seven of its eight tables, and Word laid them out on content width.
	const counts = ["en", "fr"].map(l => (generateWordReport(payload(l)).match(/<colgroup>/g) || []).length);
	assert.ok(counts[0] > 0, "English has colgroups");
	assert.equal(counts[0], counts[1], `en ${counts[0]} vs fr ${counts[1]}`);
});

// Every file that renders report chrome. A key lives in exactly one of them.
const CHROME_SOURCES = ["lib/cve-report.js", "lib/charts.js", "lib/codecs/recipes.js"];
function chromeSource() {
	const fs = require("fs"), path = require("path");
	return CHROME_SOURCES.map(f => fs.readFileSync(path.join(__dirname, "..", f), "utf8")).join("\n");
}
// The keys the source hands to the translator as literals: t("…"), and the two plural
// helpers, whose two forms are two keys. Keys reached through a table (REF_LABELS,
// WARNING_HEADINGS, the recipes' noFix/pinSection/…) are literals in the same files, so
// the reachability check below covers them from the other direction.
function literalKeys(src) {
	const keys = new Set();
	const q = `("(?:[^"\\\\]|\\\\.)*"|'(?:[^'\\\\]|\\\\.)*')`;
	const unquote = s => s[0] === '"' ? JSON.parse(s) : s.slice(1, -1).replace(/\\'/g, "'");
	for (const m of src.matchAll(new RegExp(`\\bt\\(\\s*${q}`, "g"))) keys.add(unquote(m[1]));
	for (const m of src.matchAll(new RegExp(`\\b(?:plural|pluralZero)\\([^,]*,\\s*${q}\\s*,\\s*${q}`, "gs"))) {
		keys.add(unquote(m[1])); keys.add(unquote(m[2]));
	}
	for (const m of src.matchAll(new RegExp(`\\bpl\\(t,\\s*cnt,\\s*${q},\\s*${q}`, "gs"))) {
		keys.add(unquote(m[1])); keys.add(unquote(m[2]));
	}
	return [...keys].filter(k => k.trim());
}

test("the catalogue and the source agree, in both directions", () => {
	// This is the whole i18n contract in one test. An entry the source can no longer reach
	// is dead weight a translator still has to read; a key the source reaches with no entry
	// is a sentence that renders in English at a French-speaking client. Neither is allowed
	// to accumulate, so the count is zero rather than a tolerated budget.
	const src = chromeSource();
	// A key holding a quote appears escaped in the source it came from, so look for both
	// spellings before calling it unreachable.
	const inSource = k => src.includes(k) || src.includes(JSON.stringify(k).slice(1, -1));
	const orphans = Object.keys(CATALOG.fr).filter(k => !inSource(k));
	assert.deepEqual(orphans, [], `unreachable translations: ${orphans.slice(0, 6).join(" | ")}`);

	const untranslated = literalKeys(src).filter(k => CATALOG.fr[k] == null);
	assert.deepEqual(untranslated, [], `chrome with no French wording: ${untranslated.slice(0, 6).join(" | ")}`);
});

test("a French entry may carry both plural forms, and the count picks one", () => {
	// English leaves "1 obsolete" and "3 obsolete" alone; French does not, and "1 obsolètes"
	// is exactly the kind of detail an auditor notices. The English side is untouched by
	// this — CATALOG.en is empty, so the source string is always what comes back.
	const fr = makeT("fr"), en = makeT("en");
	assert.equal(fr("obsolete", { n: 1 }), "obsolète");
	assert.equal(fr("obsolete", { n: 3 }), "obsolètes");
	assert.equal(fr("+{n} more", { n: 1 }), "+1 autre");
	assert.equal(fr("+{n} more", { n: 4 }), "+4 autres");
	assert.equal(en("obsolete", { n: 1 }), "obsolete");
	assert.equal(en("+{n} more", { n: 4 }), "+4 more");
});

test("writeReports forwards the locale — it was accepted and silently dropped", () => {
	// The CLI threaded --lang into the payload, writeReports destructured the fields it
	// knew about, and `locale` was not one of them: every report rendered in English while
	// the flag appeared to work. A signature that quietly ignores an option is worse than
	// one that rejects it.
	const fs = require("fs"), path = require("path");
	const src = fs.readFileSync(path.join(__dirname, "..", "lib", "cve-report.js"), "utf8");
	const sig = /async function writeReports\(\{([^}]*)\}\)/.exec(src);
	assert.ok(sig, "writeReports signature not found");
	assert.match(sig[1], /\blocale\b/, "writeReports must accept a locale");
	const payload = /\n\tconst payload = \{([^}]*)\};/.exec(src);
	assert.ok(payload, "writeReports payload not found");
	assert.match(payload[1], /\blocale\b/, "writeReports must pass the locale on to the renderers");
});

test("the clipboard affordances are translated too — buttons AND the strings built in the browser", () => {
	// The copy script is a module constant, so it cannot call t(): its labels stayed English
	// while the rest of the report was French. It now reads a table the page supplies.
	const fr = generateHtmlReport(payload("fr"));
	assert.match(fr, /📋 Copier le tableau/);
	assert.match(fr, /Copier seulement une partie/);
	assert.match(fr, /window\.__FAD_T=\{/, "the page carries the browser-side strings");
	assert.match(fr, /"First 5 rows":"Les 5 premières lignes"/);
	assert.match(fr, /"Copied!":"Copié !"/);

	const en = generateHtmlReport(payload("en"));
	// The helper in the script always names __FAD_T; what English must not carry is the
	// assignment, i.e. a table of translations.
	assert.doesNotMatch(en, /window\.__FAD_T=\{/, "English emits no translation table");
	assert.match(en, /📋 Copy table/);
});

test("the COPIED executive summary is translated, not just the one on screen", () => {
	// The clipboard flavours are built as sentences in JS ("The library X version Y is
	// vulnerable to Z"), so they stayed English while the page around them was French.
	const eolDep = makeDepRecord({ ecosystem: "maven", namespace: "org.springframework", name: "spring-core", version: "4.3.16", manifestPath: "/p/pom.xml" });
	const p = locale => ({
		cveMatches: [{ dep, cve: { id: "CVE-2021-44228", severity: "CRITICAL", score: 10, description: "d", cwes: ["CWE-502"] }, confidence: "exact" }],
		eolResults: [{ dep: eolDep, product: "Spring Framework", productSlug: "spring-framework", cycle: "4.3", status: "eol", eol: "2020-12-31", latest: "7.0.9" }],
		obsoleteResults: [], outdatedResults: [],
		projectInfo: { name: "demo", src: "/p", generatedAt: "2026-09-19" }, locale,
	});
	const plain = html => /class="exec-copy-plain"[^>]*>([\s\S]*?)<\/textarea>/.exec(html)[1];

	const fr = plain(generateHtmlReport(p("fr")));
	assert.match(fr, /SYNTHÈSE/);
	assert.match(fr, /dépendances analysées/);
	assert.match(fr, /La bibliothèque .* est vulnérable à/);
	assert.match(fr, /est en fin de vie depuis le 2020-12-31/);
	assert.match(fr, /la dernière est 7\.0\.9/);
	assert.doesNotMatch(fr, /The library|is vulnerable to|end-of-life since|Everything else/);
	// The count is a placeholder, not a prefix: "Top 2 les plus critiques" is not French.
	assert.doesNotMatch(fr, /Top \d/);

	const en = plain(generateHtmlReport(p("en")));
	assert.match(en, /EXECUTIVE SUMMARY/);
	assert.match(en, /The library .* is vulnerable to/);
	assert.match(en, /end-of-life since 2020-12-31/);
	assert.match(en, /latest is 7\.0\.9/);

	// The rich (Word) flavour too, where the values are bolded around the sentence.
	const richFr = /class="exec-copy-rich">([\s\S]*?)<\/template>/.exec(generateHtmlReport(p("fr")))[1];
	assert.match(richFr, /La bibliothèque/);
	assert.match(richFr, /<b>/, "values stay bolded through the translation");
	assert.doesNotMatch(richFr, /The library/);
});

// ---------------------------------------------------------------------------------------
// A WHOLE report, every chapter lit up. The tests above check the catalogue; these check
// what a client actually receives.

const buildFull = require("./fixtures/report-payload/full");

/** The text a reader sees: element content plus the tooltips, which are chrome too. */
function visibleText(html) {
	return html
		.replace(/<script[\s\S]*?<\/script>/g, "")
		.replace(/<style[\s\S]*?<\/style>/g, "")
		.replace(/<[a-z-]+\b([^>]*)>/gi, (m, attrs) =>
			[...attrs.matchAll(/(?:title|aria-label)="([^"]*)"/g)].map(x => " " + x[1]).join("") + " ")
		.replace(/<[^>]+>/g, " ")
		.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
		.replace(/&quot;/g, '"').replace(/&nbsp;/g, " ")
		.replace(/\s+/g, " ");
}

// One string per area of the report, chosen so that a chapter losing its translation shows
// up here. Each is asserted to be PRESENT in English as well, so the list cannot quietly
// rot into a set of strings that match nothing at all.
const ENGLISH_CHROME = [
	"Expand all", "Collapse all", "Click a section header or a CVE row to toggle.",
	"Executive Summary", "Everything else:", "dependencies scanned", "most critical", "end-of-life frameworks",
	"defined in:", "version managed by:", "pulled in via:", "parent POM",
	"Base score", "Known exploited", "Match confidence", "External links", "Security advisory", "Mailing list",
	"Recommended action", "Priority / severity", "Fix Version", "pulled in by",
	"Direct dependencies", "Transitive dependencies", "Out of active support", "Security fixes until", "matched via",
	"Unmanaged / unversioned components", "Certificates & key material", "Maintenance / EOL",
	"Scan context & limitations", "Warnings & scan-completeness", "Changes since baseline", "New CVE findings:",
	"Maven coordinates discovered inside committed", "no known CVE", "CVE detail:",
	"Committed native binaries", "should-be-managed", "not recognised by any source", "pristine",
	"Standalone JavaScript libraries committed", "no known vuln",
	"Cryptographic material committed into the source tree", "PRIVATE KEY", "public key",
	"private key committed", "expiring soon",
	"Directories the scan", "How this report was produced", "Limitations — vigievuln does not assess:",
	"Reachability / exploitability in your app.", "These entries were initially matched by name",
	"Strong copyleft (GPL)", "Every direct dep with at least one CVE matched",
	"manual triage", "no clean fix declared", "Paste into the root POM", "Or update the direct dependencies",
	"Possibly private / internal packages", "Manifests without a lockfile", "ranges / no lockfile",
	"Overview charts", "CWE — direct vulns", "Most vulnerable components", "Fix priority",
	"not warmed", "ecosystems", "Vulns",
];

test("a full French report has no English chrome left in it", () => {
	// The report a client receives, not a fragment: production / dev / embedded / filtered
	// CVE, retire.js, native binaries, crypto material, both EOL bands, obsolete, outdated,
	// licenses, excluded dirs, warnings, a baseline diff and the provenance manifest.
	const fr = visibleText(generateHtmlReport(buildFull("fr")));
	const en = visibleText(generateHtmlReport(buildFull("en")));
	const absentFromEnglish = ENGLISH_CHROME.filter(s => !en.includes(s));
	assert.deepEqual(absentFromEnglish, [], "these no longer exist in the English report either — fix the list, not the translation");
	const leftInFrench = ENGLISH_CHROME.filter(s => fr.includes(s));
	assert.deepEqual(leftInFrench, [], "untranslated chrome in the French report");
	// The vendored-JS library row pluralises its advisory count, and French inflects.
	// The catalogue's established short form is "vuln." — same pill as the inventory
	// chapter — so the grouped count stays French without widening the column.
	assert.ok(fr.includes("2 vuln."), "the grouped vendored-JS count is French");
	assert.ok(en.includes("2 vulns"), "the English report keeps its own wording");
	assert.ok(fr.includes("Fichiers"), "the vendored-JS file list heading is translated");
});

test("a full French report still quotes its evidence verbatim, and keeps NVD's vocabulary", () => {
	const fr = visibleText(generateHtmlReport(buildFull("fr")));
	// Evidence: an advisory description, a deprecation reason, an endoflife note, a scan
	// warning's message and a data-source detail all come from outside fad. Paraphrasing
	// any of them in an audit would be wrong, so they travel through untouched.
	for (const marker of ["EVIDENCE_ADVISORY_TEXT", "EVIDENCE_RETIRE_TEXT", "EVIDENCE_DEPRECATION_REASON",
		"EVIDENCE_EOL_NOTE", "EVIDENCE_WARNING_MSG", "EVIDENCE_SOURCE_DETAIL"]) {
		assert.ok(fr.includes(marker), `evidence was altered: ${marker}`);
	}
	// A CVSS severity is the finding's value in NVD's own vocabulary, so the badge keeps it;
	// what gets translated is the report's label next to it.
	assert.ok(fr.includes("CRITICAL"), "severity badges keep NVD's wording");
	assert.ok(fr.includes("CVE-2021-44228"), "identifiers are never translated");
	assert.ok(fr.includes("Sévérité") || fr.includes("Priorité / sévérité"), "…but the labels around them are French");
});

test("the French report declares its language, so Word and screen readers know", () => {
	assert.match(generateHtmlReport(buildFull("fr")), /<html lang="fr">/);
	assert.match(generateHtmlReport(buildFull("en")), /<html lang="en">/);
});

test("every chapter of the Word output is translated too — it is the same body", () => {
	// The .doc is what most clients open. It renders from buildBody like the HTML does, so a
	// chapter that is French on screen must be French in Word; the only difference allowed
	// is the interactive chrome Word cannot use, which is stripped.
	const fr = visibleText(generateWordReport(buildFull("fr")));
	const leftInFrench = ENGLISH_CHROME
		.filter(s => !["Expand all", "Collapse all", "Click a section header or a CVE row to toggle."].includes(s))
		.filter(s => fr.includes(s));
	assert.deepEqual(leftInFrench, [], "untranslated chrome in the Word report");
});
