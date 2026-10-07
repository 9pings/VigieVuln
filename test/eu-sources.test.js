// European sources: ENISA EUVD (id + exploited catalogue), GCVE (GNA 0 = CVE) and the
// CERT-FR advisories citing a CVE. Zero network: every fetch is a mock, every cache a
// temp dir, and the offline paths run behind a fetcher that fails the test if touched.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { gcveId, enrichGcve } = require("../lib/gcve");
const { enrichEuvd, parseMappingCsv, parseExploitedPage, euvdDate } = require("../lib/euvd");
const { enrichCertFr, advisoryCves, staleAdvisories, indexByCve } = require("../lib/certfr");
const { europeanReferences, euvdExploited } = require("../lib/eu-refs");
const { getProvider } = require("../lib/providers");
const { makeDepRecord } = require("../lib/dep-record");

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-eu-"));
const json = body => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
const tripwire = async url => { throw new Error(`network touched offline: ${url}`); };
const matchesFor = (...ids) => ids.map(id => ({ cve: { id } }));

// ---------------------------------------------------------------- GCVE
test("GCVE: a CVE id lives in the reserved GNA 0 namespace, and nothing else maps", () => {
	assert.equal(gcveId("CVE-2021-44228"), "GCVE-0-2021-44228");
	assert.equal(gcveId("cve-2024-123456"), "GCVE-0-2024-123456");
	for (const x of ["GHSA-jfh8-c2jp-5v3q", "WF-123", "", null, "CVE-21-1"]) assert.equal(gcveId(x), null, String(x));
	const ms = enrichGcve([{ cve: { id: "CVE-2021-44228" } }, { cve: { id: "GHSA-x" } }]);
	assert.equal(ms[0].cve.gcve, "GCVE-0-2021-44228");
	assert.equal(ms[1].cve.gcve, undefined);
});

// ---------------------------------------------------------------- EUVD
const CSV = "euvd_id,cve_id\nEUVD-2021-34768,CVE-2021-44228\nEUVD-2017-0001,CVE-2017-5638\nbroken line\n";
const page = (items, total) => ({ items, total });

test("EUVD parsers: mapping CSV, ENISA's date format, exploited aliases", () => {
	assert.deepEqual(parseMappingCsv(CSV), { "CVE-2021-44228": "EUVD-2021-34768", "CVE-2017-5638": "EUVD-2017-0001" });
	assert.equal(euvdDate("Oct 2, 2026, 12:00:00 AM"), "2026-10-02");
	assert.equal(euvdDate("garbage"), null);
	assert.deepEqual(parseExploitedPage(page([
		{ aliases: "GHSA-jfh8-c2jp-5v3q\nCVE-2021-44228\n", exploitedSince: "Dec 10, 2021, 12:00:00 AM" },
		{ aliases: "CVE-2026-0001", exploitedSince: null },
	])), { "CVE-2021-44228": "2021-12-10", "CVE-2026-0001": "" });
});

function euvdFetcher(calls) {
	return async url => {
		calls.push(url);
		if (url.endsWith("/dump/cve-euvd-mapping")) return new Response(CSV, { status: 200, headers: { "content-type": "text/csv" } });
		if (/exploited=true.*page=0/.test(url)) return json(page([{ aliases: "CVE-2021-44228", exploitedSince: "Dec 10, 2021, 12:00:00 AM" }], 1));
		throw new Error(`unexpected ${url}`);
	};
}

test("EUVD: bulk reads only — the project's CVE ids are never sent; then offline from cache", async () => {
	const dir = tmp(), calls = [];
	try {
		const ms = await enrichEuvd(matchesFor("CVE-2021-44228", "CVE-2017-5638", "CVE-2099-0001"), { fetcher: euvdFetcher(calls), cacheDir: dir });
		assert.deepEqual(ms[0].cve.euvd, { id: "EUVD-2021-34768", exploitedSince: "2021-12-10" });
		assert.deepEqual(ms[1].cve.euvd, { id: "EUVD-2017-0001", exploitedSince: null });
		assert.equal(ms[2].cve.euvd, undefined);
		assert.equal(calls.length, 2, "one mapping dump + one exploited page");
		assert.ok(calls.every(u => !u.includes("CVE-")), "no CVE id of the project leaves the machine");

		const off = await enrichEuvd(matchesFor("CVE-2021-44228"), { offline: true, fetcher: tripwire, cacheDir: dir });
		assert.equal(off[0].cve.euvd.id, "EUVD-2021-34768");
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("EUVD: a failed refresh keeps serving the stale snapshot", async () => {
	const dir = tmp();
	try {
		fs.writeFileSync(path.join(dir, "euvd-cache.json"), JSON.stringify({ _fetchedAt: 0,
			body: { byCve: { "CVE-2021-44228": "EUVD-2021-34768" }, exploited: {}, count: 1 } }));
		const ms = await enrichEuvd(matchesFor("CVE-2021-44228"), { fetcher: async () => new Response("", { status: 503 }), cacheDir: dir });
		assert.equal(ms[0].cve.euvd.id, "EUVD-2021-34768");
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------- CERT-FR
const LISTING_AVIS = [
	{ reference: "CERTFR-2021-AVI-951", last_revision_date: "2021-12-14T00:00:00", title: "Vulnérabilité dans Apache Log4j", json_url: "/avis/CERTFR-2021-AVI-951/json/" },
	{ reference: "CERTFR-2022-AVI-016", last_revision_date: "2022-01-07T00:00:00", title: "Multiples vulnérabilités", json_url: "/avis/CERTFR-2022-AVI-016/json/" },
];
const LISTING_ALERTE = [{ reference: "CERTFR-2021-ALE-022", last_revision_date: "2021-12-20T00:00:00", title: "[MaJ] Vulnérabilité dans Apache Log4j" }];
const ADVISORIES = {
	"CERTFR-2021-AVI-951": { cves: [{ name: "CVE-2021-44228" }, { name: "cve-2021-44228" }] },
	"CERTFR-2022-AVI-016": { cves: [{ name: "CVE-2021-44228" }, { name: "CVE-2021-45046" }] },
	"CERTFR-2021-ALE-022": { cves: [{ name: "CVE-2021-44228" }] },
};
function certfrFetcher(calls, listing = { avis: LISTING_AVIS, alerte: LISTING_ALERTE }) {
	return async url => {
		calls.push(url);
		const idx = /cert\.ssi\.gouv\.fr\/(avis|alerte)\/json\/$/.exec(url);
		if (idx) return json(listing[idx[1]]);
		const adv = /\/(avis|alerte)\/(CERT[^/]+)\/json\/$/.exec(url);
		if (adv && ADVISORIES[adv[2]]) return json(ADVISORIES[adv[2]]);
		if (adv) return new Response("", { status: 404 });
		throw new Error(`unexpected ${url}`);
	};
}

test("CERT-FR pure helpers: CVE extraction, staleness by revision, newest-first index", () => {
	assert.deepEqual(advisoryCves(ADVISORIES["CERTFR-2021-AVI-951"]), ["CVE-2021-44228"]);
	const entries = { "CERTFR-2021-AVI-951": { rev: "2021-12-14T00:00:00" } };
	assert.deepEqual(staleAdvisories(LISTING_AVIS, entries, "avis").map(a => a.ref), ["CERTFR-2022-AVI-016"]);
	const byCve = indexByCve({ "CERTFR-2021-AVI-951": { kind: "avis", cves: ["CVE-1"] }, "CERTFR-2022-AVI-016": { kind: "avis", cves: ["CVE-1"] } });
	assert.deepEqual(byCve["CVE-1"].map(a => a.ref), ["CERTFR-2022-AVI-016", "CERTFR-2021-AVI-951"]);
});

test("CERT-FR: cold run indexes every advisory, a later run fetches only what was revised", async () => {
	const dir = tmp();
	try {
		const calls = [];
		const ms = await enrichCertFr(matchesFor("CVE-2021-44228", "CVE-2021-45046", "CVE-2099-0001"), { fetcher: certfrFetcher(calls), cacheDir: dir });
		assert.deepEqual(ms[0].cve.certfr.map(a => a.ref), ["CERTFR-2022-AVI-016", "CERTFR-2021-AVI-951", "CERTFR-2021-ALE-022"]);
		assert.equal(ms[0].cve.certfr.find(a => a.ref === "CERTFR-2021-ALE-022").kind, "alerte");
		assert.deepEqual(ms[1].cve.certfr.map(a => a.ref), ["CERTFR-2022-AVI-016"]);
		assert.equal(ms[2].cve.certfr, undefined);
		assert.equal(calls.length, 2 + 3, "two listings + three advisories");
		assert.ok(calls.every(u => !/CVE-/.test(u)), "no CVE id of the project is sent");

		// Expire the listing stamp; one advisory revised, one new one that has no JSON (404).
		const file = path.join(dir, "certfr-cache.json");
		const data = JSON.parse(fs.readFileSync(file, "utf8"));
		data.meta.fetchedAt = 0;
		fs.writeFileSync(file, JSON.stringify(data));
		const revised = [{ ...LISTING_AVIS[0], last_revision_date: "2022-02-01T00:00:00" }, LISTING_AVIS[1],
			{ reference: "CERTFR-2026-AVI-0001", last_revision_date: "2026-01-01T00:00:00", title: "x" }];
		const again = [];
		await enrichCertFr(matchesFor("CVE-2021-44228"), { fetcher: certfrFetcher(again, { avis: revised, alerte: LISTING_ALERTE }), cacheDir: dir });
		const fetched = again.filter(u => /\/CERT/.test(u)).map(u => /\/(CERT[^/]+)\//.exec(u)[1]).sort();
		assert.deepEqual(fetched, ["CERTFR-2021-AVI-951", "CERTFR-2026-AVI-0001"]);
		const after = JSON.parse(fs.readFileSync(file, "utf8"));
		assert.deepEqual(after.entries["CERTFR-2026-AVI-0001"].cves, [], "a 404 is an answer: recorded, not retried");
		assert.ok(after.meta.fetchedAt > 0);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("CERT-FR: offline reads the index and never touches the network", async () => {
	const dir = tmp();
	try {
		await enrichCertFr(matchesFor("CVE-2021-44228"), { fetcher: certfrFetcher([]), cacheDir: dir });
		const ms = await enrichCertFr(matchesFor("CVE-2021-44228"), { offline: true, fetcher: tripwire, cacheDir: dir });
		assert.equal(ms[0].cve.certfr.length, 3);
		// Cold offline: no index, no finding, no error.
		const cold = tmp();
		try { assert.equal((await enrichCertFr(matchesFor("CVE-2021-44228"), { offline: true, fetcher: tripwire, cacheDir: cold }))[0].cve.certfr, undefined); }
		finally { fs.rmSync(cold, { recursive: true, force: true }); }
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------- providers
test("providers: EUVD and CERT-FR build only well-formed requests", () => {
	const euvd = getProvider("euvd"), certfr = getProvider("certfr");
	assert.match(euvd.build("cve-mapping", {}).url, /euvdservices\.enisa\.europa\.eu\/api\/dump\/cve-euvd-mapping$/);
	assert.match(euvd.build("exploited", { page: 3 }).url, /exploited=true&size=100&page=3$/);
	assert.throws(() => euvd.build("exploited", { page: "1;x" }));
	assert.equal(certfr.build("advisory", { kind: "avis", ref: "CERTFR-2021-AVI-951" }).url, "https://www.cert.ssi.gouv.fr/avis/CERTFR-2021-AVI-951/json/");
	assert.equal(certfr.build("index", { kind: "alerte" }).url, "https://www.cert.ssi.gouv.fr/alerte/json/");
	assert.throws(() => certfr.build("advisory", { kind: "avis", ref: "../../etc" }));
	assert.throws(() => certfr.build("index", { kind: "actualite" }));
});

// ---------------------------------------------------------------- report + exports
const EU_CVE = {
	id: "CVE-2021-44228", severity: "CRITICAL", score: 10, gcve: "GCVE-0-2021-44228",
	euvd: { id: "EUVD-2021-34768", exploitedSince: "2021-12-10" },
	certfr: [{ ref: "CERTFR-2021-ALE-022", kind: "alerte", title: "EVIDENCE_Vulnérabilité dans Apache Log4j" }],
};

test("europeanReferences: one list, EUVD then GCVE then CERT-FR, with public links", () => {
	const refs = europeanReferences(EU_CVE);
	assert.deepEqual(refs.map(r => r.id), ["EUVD-2021-34768", "GCVE-0-2021-44228", "CERTFR-2021-ALE-022"]);
	assert.equal(refs[0].url, "https://euvd.enisa.europa.eu/vulnerability/EUVD-2021-34768");
	assert.equal(refs[1].url, "https://db.gcve.eu/vuln/GCVE-0-2021-44228");
	assert.equal(refs[2].url, "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2021-ALE-022/");
	assert.equal(euvdExploited(EU_CVE), true);
	assert.equal(euvdExploited({ euvd: { id: "x", exploitedSince: null } }), false);
	assert.deepEqual(europeanReferences({ id: "GHSA-x" }), []);
});

test("report: the detail panel links EUVD, GCVE and CERT-FR, in both languages; CERT-FR titles stay as written", () => {
	const { generateHtmlReport } = require("../lib/cve-report");
	const dep = makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0.0", manifestPath: "/p/pom.xml" });
	const render = locale => generateHtmlReport({ cveMatches: [{ dep, cve: { ...EU_CVE }, confidence: "exact" }],
		eolResults: [], obsoleteResults: [], outdatedResults: [], projectInfo: { name: "demo", src: "/p", generatedAt: "2026-10-07" }, locale });
	const en = render("en");
	assert.match(en, /href="https:\/\/euvd\.enisa\.europa\.eu\/vulnerability\/EUVD-2021-34768"/);
	assert.match(en, /exploited since 2021-12-10/);
	assert.match(en, /href="https:\/\/db\.gcve\.eu\/vuln\/GCVE-0-2021-44228"/);
	assert.match(en, /CERT-FR advisories/);
	assert.match(en, /EVIDENCE_Vulnérabilité dans Apache Log4j/);
	const fr = render("fr");
	assert.match(fr, /Avis du CERT-FR/);
	assert.match(fr, /exploitée depuis le 2021-12-10/);
	assert.match(fr, /EVIDENCE_Vulnérabilité dans Apache Log4j/);
});

test("exports carry the European references: JSON, CycloneDX, CSAF, SARIF", () => {
	const dep = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1", manifestPath: "/proj/pom.xml" });
	const resolved = new Map([[dep.coordKey, dep]]);
	const matches = [{ dep, cve: { ...EU_CVE }, source: "osv" }];

	const { buildFindings } = require("../lib/json-export");
	const doc = buildFindings({ cveMatches: matches, eolResults: [], outdatedResults: [], resolvedDeps: resolved,
		projectInfo: { name: "demo", src: "/proj", generatedAt: "2026-10-07T00:00:00Z" }, toolVersion: "0" });
	const f = doc.cve.find(x => x.id === "CVE-2021-44228");
	assert.equal(f.euvd, "EUVD-2021-34768");
	assert.equal(f.euvdExploited, true);
	assert.equal(f.euvdExploitedSince, "2021-12-10");
	assert.equal(f.gcve, "GCVE-0-2021-44228");
	assert.deepEqual(f.certfr, ["CERTFR-2021-ALE-022"]);

	const bom = require("../lib/sbom-export").buildCycloneDx(resolved, matches, { projectInfo: { name: "demo" }, toolVersion: "0" });
	const v = bom.vulnerabilities[0];
	assert.deepEqual(v.references.map(r => r.id), ["EUVD-2021-34768", "GCVE-0-2021-44228", "CERTFR-2021-ALE-022"]);
	assert.equal(v.references[0].source.name, "ENISA EUVD");
	assert.ok(v.properties.some(p => p.name === "fad:euvdExploited" && p.value === "2021-12-10"));

	const csaf = require("../lib/csaf-export").buildCsaf(resolved, matches, {});
	const cv = csaf.vulnerabilities[0];
	assert.ok(cv.references.some(r => r.url === "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2021-ALE-022/" && r.category === "external"));

	const sarif = require("../lib/sarif-export").buildSarif(matches, { projectInfo: { src: "/proj" }, toolVersion: "0" });
	const result = sarif.runs[0].results[0];
	assert.equal(result.properties.euvdExploited, true);
	assert.deepEqual(result.properties.europeanReferences, ["EUVD-2021-34768", "GCVE-0-2021-44228", "CERTFR-2021-ALE-022"]);
	assert.ok(sarif.runs[0].tool.driver.rules[0].properties.tags.includes("enisa-exploited"));
});
