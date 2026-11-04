const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { unzipSync, strFromU8 } = require("fflate");
const { parseStringPromise } = require("xml2js");
const { buildXlsx, writeXlsx } = require("../lib/xlsx-export");

const match = {
	findingId: "fad-cve-test", applicationIds: ["wordpress:site"], ownerComponentIds: ["wordpress:site:core"],
	dep: { ecosystem: "composer", namespace: "vendor", name: "lib", version: "1.0.0", scope: "prod",
		manifestPaths: ["/audit/site/composer.lock"] },
	cve: { id: "CVE-2099-1234", severity: "HIGH", score: 7.5, description: '=HYPERLINK("https://invalid.example", "click") & <unsafe>',
		fixVersion: "1.1.0" }, source: "osv+packagist",
};

test("XLSX is a valid OOXML package with typed audit rows and inert advisory text", async () => {
	const bytes = buildXlsx({ cveMatches: [match], projectInfo: { name: "audit", src: "/audit", generatedAt: "2026-09-23",
		provenance: { mode: "offline", configuration: { osv: false }, dataSources: [{ id: "osv", label: "OSV", status: "disabled" }] } },
		toolVersion: "2.7.0", applications: [{ id: "wordpress:site", type: "wordpress", root: "site" }],
		coverage: [{ applicationId: "wordpress:site", capability: "advisories", sourceId: "wordfence-v3", execution: "not-run",
			result: "indeterminate", diagnostic: "CMS_PROVIDER_UNCONFIGURED" }] });
	assert.equal(bytes.subarray(0, 2).toString(), "PK");
	const zip = unzipSync(bytes);
	for (const name of ["[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/worksheets/sheet1.xml"])
		assert.ok(zip[name], `${name} is required`);
	const workbook = await parseStringPromise(strFromU8(zip["xl/workbook.xml"]));
	const names = workbook.workbook.sheets[0].sheet.map(s => s.$.name);
	for (const name of ["Summary", "CVE", "Applications", "Coverage", "Provenance", "Configuration", "Data sources"])
		assert.ok(names.includes(name), `${name} sheet exists`);
	assert.ok(!names.includes("Warnings"), "empty categories do not create blank tabs");
	for (const [name, data] of Object.entries(zip).filter(([name]) => name.endsWith(".xml") || name.endsWith(".rels")))
		await assert.doesNotReject(parseStringPromise(strFromU8(data)), `${name} parses`);
	const cveXml = strFromU8(zip[`xl/worksheets/sheet${names.indexOf("CVE") + 1}.xml`]);
	assert.match(cveXml, /CVE-2099-1234/);
	assert.match(cveXml, /<c r="D2" t="n"><v>7\.5<\/v><\/c>/);
	assert.match(cveXml, /<c r="U2" t="inlineStr"><is><t xml:space="preserve">=HYPERLINK/);
	assert.match(cveXml, /&amp; &lt;unsafe&gt;/);
	assert.doesNotMatch(cveXml, /<f>/, "source text never becomes a formula");
	const coverageXml = strFromU8(zip[`xl/worksheets/sheet${names.indexOf("Coverage") + 1}.xml`]);
	assert.match(coverageXml, /CMS_PROVIDER_UNCONFIGURED/);
});

test("XLSX writer preserves short values and marks long cells without losing the workbook", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-xlsx-"));
	try {
		const file = path.join(dir, "findings.xlsx");
		writeXlsx({ cveMatches: [match] }, file);
		const original = fs.readFileSync(file);
		assert.equal(original.subarray(0, 2).toString(), "PK");
		writeXlsx({ cveMatches: [{ ...match, cve: { ...match.cve, description: "x".repeat(32768) } }] }, file);
		const zip = unzipSync(fs.readFileSync(file));
		assert.match(strFromU8(zip["xl/worksheets/sheet2.xml"]), /TRUNCATED: Excel cell limit/);
		assert.notDeepEqual(fs.readFileSync(file), original, "the complete workbook is regenerated");
		assert.throws(() => writeXlsx({}, path.join(dir, "mislabelled.xls")), /must end in \.xlsx/);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('oversized cells remain within Excel limits, keep Unicode intact and cannot create formulas', async () => {
	for (const text of ['x'.repeat(32767), '=HYPERLINK("x")' + '😀'.repeat(20000), 'z'.repeat(100000)]) {
		const zip = unzipSync(buildXlsx({ cveMatches: [{ ...match, cve: { ...match.cve, description: text } }, { ...match, findingId: 'second-finding' }] }));
		const sheet = await parseStringPromise(strFromU8(zip['xl/worksheets/sheet2.xml']));
		const rows = sheet.worksheet.sheetData[0].row;
		assert.equal(rows.length, 3, 'the rest of the workbook survives a long cell');
		const cell = rows[1].c.find(c => c.$.r === 'U2');
		assert.equal(cell.$.t, 'inlineStr');
		assert.equal(cell.f, undefined);
		const value = cell.is[0].t[0]._;
		assert.ok(value.length <= 32767);
		assert.equal(value.isWellFormed(), true);
		assert.ok(!value.includes('\uFFFD'), 'no split surrogate is introduced');
		if (text.length <= 32767) assert.equal(value, text);
		else assert.match(value, /\[TRUNCATED: Excel cell limit; export JSON for the full value\]$/);
	}
});
