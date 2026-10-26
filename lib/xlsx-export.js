/** Excel OOXML export. Uses the existing fflate dependency; no office runtime needed. */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { zipSync, strToU8 } = require("fflate");
const { buildFindings } = require("./json-export");

const MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships";
const MAX_ROWS = 1048576;
const MAX_CELL = 32767;

function xml(value) {
	return String(value ?? "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g, "")
		.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function colName(index) {
	let out = "";
	for (let n = index + 1; n; n = Math.floor((n - 1) / 26)) out = String.fromCharCode(65 + (n - 1) % 26) + out;
	return out;
}

function valueCell(value, address, header = false) {
	const style = header ? ' s="1"' : "";
	if (value === null || value === undefined) return `<c r="${address}"${style}/>`;
	if (typeof value === "number" && Number.isFinite(value)) return `<c r="${address}"${style} t="n"><v>${value}</v></c>`;
	if (typeof value === "boolean") return `<c r="${address}"${style} t="b"><v>${value ? 1 : 0}</v></c>`;
	// Inline strings are never formulas, even for source-controlled text beginning
	// with =, +, -, or @. This is essential for an audit export opened in Excel.
	const raw = (typeof value === "object" ? JSON.stringify(value) : String(value)) ?? "";
	if (raw.length > MAX_CELL) throw new Error(`Excel cell ${address} exceeds ${MAX_CELL} characters`);
	return `<c r="${address}"${style} t="inlineStr"><is><t xml:space="preserve">${xml(raw)}</t></is></c>`;
}

function worksheet(headers, rows) {
	if (rows.length + 1 > MAX_ROWS) throw new Error(`Excel sheet exceeds ${MAX_ROWS} rows`);
	if (headers.length > 16384) throw new Error("Excel sheet exceeds 16384 columns");
	const rowXml = (values, row, header = false) => `<row r="${row}">${values.map((v, i) => valueCell(v, `${colName(i)}${row}`, header)).join("")}</row>`;
	const data = rowXml(headers, 1, true) + rows.map((r, i) => rowXml(r, i + 2)).join("");
	const end = `${colName(headers.length - 1)}${rows.length + 1}`;
	const widths = headers.map((h, i) => `<col min="${i + 1}" max="${i + 1}" width="${Math.min(48, Math.max(14, String(h).length + 4))}" customWidth="1"/>`).join("");
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<worksheet xmlns="${MAIN}"><dimension ref="A1:${end}"/>` +
		`<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>` +
		`<selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>` +
		`<sheetFormatPr defaultRowHeight="15"/><cols>${widths}</cols><sheetData>${data}</sheetData>` +
		`<autoFilter ref="A1:${end}"/></worksheet>`;
}

const joined = value => Array.isArray(value) ? value.map(item => typeof item === "object" ? JSON.stringify(item) : item).join("; ") : value ?? "";
const dep = value => value?.dep || {};
const base = item => [dep(item).ecosystem, dep(item).coord, dep(item).version, dep(item).scope,
	joined(dep(item).manifestPaths), joined(item.applicationIds), joined(item.ownerComponentIds)];

/** One row per finding/record, preserving the machine-readable IDs and coverage verdicts. */
function sheets(doc) {
	const summary = [
		["Tool", `${doc.tool?.name || "VigieVuln"} ${doc.tool?.version || ""}`],
		["Project", doc.project?.name], ["Source", doc.project?.src], ["Generated", doc.generatedAt],
		...Object.entries(doc.summary || {}).map(([key, value]) => [key, value]),
	];
	return [
		["Summary", ["Metric", "Value"], summary],
		["CVE", ["Finding ID", "Advisory", "Severity", "CVSS", "EPSS", "KEV", "Priority", "Ecosystem", "Coordinate", "Version", "Scope", "Manifest paths", "Applications", "Owner components", "Fix version", "CWE", "Source", "Confidence", "Suppressed", "CPE filtered", "Description", "References"],
			(doc.cve || []).map(f => [f.findingId, f.id, f.severity, f.cvss, f.epss, f.kev, f.priority?.band, ...base(f), f.fixVersion, joined(f.cwes), f.source, f.confidence, f.suppressed, f.cpeFiltered, f.description, joined(f.references)])],
		["Vendored CVE", ["Finding ID", "Advisory", "Severity", "Ecosystem", "Coordinate", "Version", "Scope", "Manifest paths", "Applications", "Owner components", "Fix version", "Source", "Description"],
			(doc.vendored || []).map(f => [f.findingId, f.id, f.severity, ...base(f), f.fixVersion, f.source, f.description])],
		["EOL", ["Product", "Status", "Cycle", "EOL date", "Support", "Target", "Ecosystem", "Coordinate", "Version", "Scope", "Manifest paths", "Source rule"],
			(doc.eol || []).map(f => [f.product, f.status, f.cycle, f.eol, f.support, f.latest, dep(f).ecosystem, dep(f).coord, dep(f).version, dep(f).scope, joined(dep(f).manifestPaths), `${f.via || ""}: ${f.viaKey || ""}`])],
		["Obsolete", ["Ecosystem", "Coordinate", "Version", "Scope", "Manifest paths", "Replacement", "Reason", "Source"],
			(doc.obsolete || []).map(f => [...base(f).slice(0, 5), f.replacement, f.reason, f.source])],
		["Outdated", ["Ecosystem", "Coordinate", "Version", "Scope", "Manifest paths", "Latest", "Release date"],
			(doc.outdated || []).map(f => [...base(f).slice(0, 5), f.latest, f.releaseDate])],
		["Licenses", ["Ecosystem", "Coordinate", "Version", "Scope", "Manifest paths", "Category", "Licenses", "Source"],
			(doc.licenses || []).map(f => [...base(f).slice(0, 5), f.category, joined(f.licenses), f.source])],
		["Applications", ["ID", "Type", "Root", "Version", "Data"],
			(doc.applications || []).map(a => [a.id, a.type, a.root, a.version, a])],
		["Components", ["ID", "Application", "Kind", "Name", "Version", "Visibility", "Path", "Catalogue status"],
			(doc.applicationInventory || []).map(c => [c.id, c.applicationId, c.kind, c.name, c.version, c.visibility, c.path, c.catalogueStatus])],
		["Relations", ["Application", "Owner component", "Dependency", "Version", "Manifest", "Relation", "Proof", "Path"],
			(doc.applicationRelations || []).map(r => [r.applicationId, r.ownerComponentId, r.depCoordKey, r.version, r.manifestPath, r.applicationRelation, r.proof, joined(r.dependencyPath)])],
		["Coverage", ["Application", "Component", "Capability", "Source", "Execution", "Result", "Expected", "Executed", "Diagnostic", "Snapshot"],
			(doc.coverage || []).map(c => [c.applicationId, c.occurrenceId, c.capability, c.sourceId, c.execution, c.result, c.expected, c.executed, c.diagnostic, c.sourceSnapshot])],
		["Warnings", ["Type", "Code", "Application", "Capability", "Source", "Count", "Message", "Items"],
			(doc.warnings || []).map(w => [w.type, w.code || w.diagnostic, w.applicationId, w.capability, w.sourceId, w.count, w.message, w.items])],
		["Unmanaged", ["File", "Identity", "Version", "Integrity", "Malicious", "SHA-256", "Data"],
			(doc.unmanaged || []).map(u => [u.path, u.identity?.name, u.identity?.version, u.integrity, u.knownMalicious, u.hashes?.sha256, u])],
		["Embedded", ["Archive", "Coordinate", "Version", "CVEs", "Severity", "Data"],
			(doc.embedded || []).map(e => [e.archive, e.coord || `${e.groupId || ""}:${e.artifactId || ""}`, e.version, e.vulnCount, e.maxSeverity, e])],
		["Vendored JS", ["Library", "Version", "File", "Vulnerable", "Count", "Severity", "Data"],
			(doc.vendoredJs || []).map(v => [v.component, v.version, v.file, v.vulnerable, v.vulnCount, v.maxSeverity, v])],
		["Certificates", ["File", "Kind", "Algorithm", "Bits", "Expires", "Issues", "SHA-256"],
			(doc.certificates || []).map(c => [c.path, c.kind, c.algorithm, c.bits, c.notAfter, (c.issues || []).map(i => i.type).join("; "), c.sha256])],
		["Typosquats", ["Package", "Suspected target", "Reason", "Data"],
			(doc.typosquat || []).map(t => [t.dep?.coordKey || t.coord || t.package, t.target || t.popularPackage, t.reason, t])],
		["Excluded dirs", ["Directory", "Rule", "Reason"],
			(doc.excludedDirs || []).map(e => [e.dir, e.type, e.reason])],
		["Provenance", ["Field", "Value"], Object.entries(doc.provenance || {}).filter(([key]) => key !== "dataSources" && key !== "configuration")],
		["Configuration", ["Option", "Value"], Object.entries(doc.provenance?.configuration || {})],
		["Data sources", ["ID", "Source", "Status", "As of", "Detail"],
			(doc.provenance?.dataSources || []).map(s => [s.id, s.label, s.status, s.asOf, s.detail])],
		["Diff", ["Category", "Added", "Removed", "Unchanged", "Unassessed"],
			Object.entries(doc.diff?.summary || {}).filter(([, value]) => value && typeof value === "object")
				.map(([category, value]) => [category, value.added, value.removed, value.unchanged, value.unassessed])],
	];
}

function buildXlsx(payload) {
	const doc = payload?.schema === "fad-findings/1" ? payload : buildFindings(payload);
	const tabs = sheets(doc).filter(([name, , rows]) => name === "Summary" || rows.length);
	const contentTypes = [`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`,
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`,
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`,
		`<Default Extension="xml" ContentType="application/xml"/>`,
		`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`,
		`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`,
		...tabs.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`),
		`</Types>`].join("");
	const files = {
		"[Content_Types].xml": strToU8(contentTypes),
		"_rels/.rels": strToU8(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="${PKG_REL}"><Relationship Id="rId1" Type="${REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>`),
		"xl/workbook.xml": strToU8(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="${MAIN}" xmlns:r="${REL}"><sheets>${tabs.map(([name], i) => `<sheet name="${xml(name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join("")}</sheets></workbook>`),
		"xl/_rels/workbook.xml.rels": strToU8(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="${PKG_REL}">${tabs.map((_, i) => `<Relationship Id="rId${i + 1}" Type="${REL}/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join("")}<Relationship Id="rId${tabs.length + 1}" Type="${REL}/styles" Target="styles.xml"/></Relationships>`),
		"xl/styles.xml": strToU8(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="${MAIN}"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`),
	};
	for (let i = 0; i < tabs.length; i++) files[`xl/worksheets/sheet${i + 1}.xml`] = strToU8(worksheet(tabs[i][1], tabs[i][2]));
	return Buffer.from(zipSync(files, { level: 6 }));
}

function writeXlsx(payload, outputPath) {
	if (path.extname(outputPath).toLowerCase() !== ".xlsx") throw new Error("Excel output path must end in .xlsx");
	const bytes = buildXlsx(payload);
	const temporary = path.join(path.dirname(path.resolve(outputPath)), `.${path.basename(outputPath)}.${crypto.randomBytes(6).toString("hex")}.tmp`);
	try {
		fs.writeFileSync(temporary, bytes, { flag: "wx" });
		fs.renameSync(temporary, outputPath);
	} finally {
		try { fs.unlinkSync(temporary); } catch (err) { if (err.code !== "ENOENT") throw err; }
	}
	return outputPath;
}

module.exports = { buildXlsx, writeXlsx, sheets };
