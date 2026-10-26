/**
 * lib/sarif-export.js — emit a SARIF 2.1.0 log from CVE matches.
 *
 * SARIF is the integration standard for GitHub Code Scanning and GitLab: any
 * tool that emits it shows up in their dashboards with no custom glue. One
 * `reportingDescriptor` (rule) per unique CVE, one `result` per (CVE, dep)
 * match, located at the manifest that declares the dep.
 *
 * buildSarif is pure; writeSarif writes the JSON to disk.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { purlFor } = require("./purl");
const { europeanReferences, euvdExploited } = require("./eu-refs");

// CVSS/severity → SARIF result level.
function sarifLevel(sev) {
	switch ((sev || "").toUpperCase()) {
		case "CRITICAL":
		case "HIGH": return "error";
		case "MEDIUM": return "warning";
		default: return "note";
	}
}

function relUri(p, srcRoot) {
	if (!p) return null;
	if (srcRoot && path.isAbsolute(p)) {
		const r = path.relative(srcRoot, p);
		if (r && !r.startsWith("..")) return r.split(path.sep).join("/");
	}
	return String(p).split(path.sep).join("/");
}

function depCoord(dep) {
	const ns = dep.namespace || dep.groupId || "";
	const name = dep.name || dep.artifactId;
	if (dep.ecosystem === "maven" && ns) return `${ns}:${name}`;
	if (dep.ecosystem === "composer" && ns) return `${ns}/${name}`;
	return name;
}

// Certificate / key-material finding-type metadata → SARIF rule + level. Keyed by
// the analyze.js issue `type`. security-severity is a CVSS-like number for GitHub.
const CERT_RULES = {
	"private-key-committed": { level: "error", score: "9.8", desc: "Committed private key" },
	"keystore-committed": { level: "warning", score: "5.0", desc: "Committed keystore" },
	"public-key-committed": { level: "note", score: "2.0", desc: "Committed public key" },
	"cert-expired": { level: "error", score: "7.5", desc: "Expired certificate" },
	"cert-expiring": { level: "warning", score: "4.0", desc: "Certificate expiring soon" },
	"cert-weak-key": { level: "error", score: "7.5", desc: "Weak certificate key" },
	"cert-weak-signature": { level: "error", score: "7.5", desc: "Weak certificate signature algorithm" },
	"cert-self-signed": { level: "note", score: "2.0", desc: "Self-signed certificate" },
};

/**
 * Build a SARIF 2.1.0 object from matches.
 * opts: { projectInfo, toolVersion, certFindings }
 */
function buildSarif(matches, opts = {}) {
	const { projectInfo = {}, toolVersion = "0", certFindings = [] } = opts;
	const srcRoot = projectInfo.src && projectInfo.src.startsWith("(") ? null : projectInfo.src;

	const rulesById = new Map();
	const results = [];

	for (const m of matches || []) {
		const id = m.cve?.id;
		if (!id) continue;
		const cve = m.cve;

		if (!rulesById.has(id)) {
			const rule = {
				id,
				name: id,
				shortDescription: { text: `${id} affecting ${depCoord(m.dep)}` },
				helpUri: String(m.source || "").includes("wordfence-v3") ?
					((cve.osvRefs || []).find(r => /^https?:\/\//i.test(r.url || ""))?.url || "https://www.wordfence.com/threat-intel/vulnerabilities/") :
					String(m.source || "").includes("drupal-security-advisories") ?
						((cve.osvRefs || []).find(r => /^https?:\/\//i.test(r.url || ""))?.url || "https://www.drupal.org/security") :
					id.startsWith("CVE-") ? `https://nvd.nist.gov/vuln/detail/${id}` : `https://osv.dev/vulnerability/${id}`,
				properties: {},
			};
			// GitHub Code Scanning reads `security-severity` (a CVSS number string).
			if (cve.score != null) rule.properties["security-severity"] = String(cve.score);
			const tags = ["security", "external/cwe", "dependency"];
			if (cve.kev) tags.push("known-exploited", "cisa-kev");
			if (euvdExploited(cve)) tags.push("enisa-exploited");
			rule.properties.tags = tags;
			if (Array.isArray(cve.cwes)) rule.properties.cwe = cve.cwes;
			rulesById.set(id, rule);
		}

		const coord = depCoord(m.dep);
		const purl = purlFor(m.dep);
		const bits = [`${coord}@${m.dep.version || "?"}`];
		if (cve.kev) bits.push("CISA-KEV (exploited)");
		if (cve.epssPercentile != null) bits.push(`EPSS ${Math.round(cve.epssPercentile * 100)}%`);
		if (cve.fixVersion) bits.push(`fix ≥ ${cve.fixVersion}`);
		const text = `${id} in ${bits.join(" · ")}${cve.description ? ` — ${cve.description.slice(0, 300)}` : ""}`;

		const locations = (m.dep.manifestPaths || m.dep.pomPaths || [])
			.map(p => relUri(p, srcRoot))
			.filter(Boolean)
			.map(uri => ({ physicalLocation: { artifactLocation: { uri } } }));

		const props = {};
		if (purl) props.purl = purl;
		if (cve.epssScore != null) props.epss = cve.epssScore;
		if (cve.epssPercentile != null) props.epssPercentile = cve.epssPercentile;
		if (cve.kev) props.kev = true;
		if (euvdExploited(cve)) props.euvdExploited = true;
		const euRefs = europeanReferences(cve);
		if (euRefs.length) props.europeanReferences = euRefs.map(r => r.id);
		if (cve.priority?.band) props.priorityBand = cve.priority.band;
		if (m.dep.provenance && m.dep.provenance !== "manifest") props.provenance = m.dep.provenance;
		if (m.cpeFiltered) props.cpeFiltered = true;
		if (m.source) props.sources = m.source;
		if (m.findingId) props.findingId = m.findingId;
		if (m.applicationIds?.length) props.applicationIds = m.applicationIds;
		if (m.ownerComponentIds?.length) props.ownerComponentIds = m.ownerComponentIds;
		if (m.applicationRelation) props.applicationRelation = m.applicationRelation;

		results.push({
			ruleId: id,
			level: sarifLevel(cve.severity),
			message: { text },
			...(locations.length ? { locations } : {}),
			partialFingerprints: { fadKey: m.findingId || `${coord}@${m.dep.version || "?"}|${id}` },
			properties: props,
		});
	}

	// Certificate / key-material findings: one rule per finding-type, one result per
	// (file, issue). Located at the file itself (not a manifest).
	for (const c of certFindings || []) {
		for (const issue of c.issues || []) {
			const meta = CERT_RULES[issue.type];
			if (!meta) continue;
			const ruleId = `FAD-${issue.type.toUpperCase()}`;
			if (!rulesById.has(ruleId)) {
				rulesById.set(ruleId, {
					id: ruleId, name: ruleId,
					shortDescription: { text: meta.desc },
					properties: { "security-severity": meta.score, tags: ["security", "cryptography", "key-material"] },
				});
			}
			const uri = relUri(c.path, srcRoot);
			const vis = c.keyVisibility ? ` [${c.keyVisibility} key]` : "";
			results.push({
				ruleId,
				level: meta.level,
				message: { text: `${meta.desc}${vis}: ${issue.message} — ${uri || c.path}` },
				...(uri ? { locations: [{ physicalLocation: { artifactLocation: { uri } } }] } : {}),
				partialFingerprints: { fadKey: `${c.sha256 || c.path}|${issue.type}` },
				properties: {
					kind: c.kind,
					...(c.keyVisibility ? { keyVisibility: c.keyVisibility } : {}),
					...(c.algorithm ? { algorithm: c.algorithm } : {}),
					...(c.format ? { format: c.format } : {}),
					...(c.sha256 ? { sha256: c.sha256 } : {}),
				},
			});
		}
	}

	return {
		$schema: "https://json.schemastore.org/sarif-2.1.0.json",
		version: "2.1.0",
		runs: [{
			tool: {
				driver: {
					name: "VigieVuln",
					version: String(toolVersion),
					informationUri: "https://github.com/9pings/VigieVuln",
					rules: [...rulesById.values()],
				},
			},
			results,
		}],
	};
}

function writeSarif(matches, outputPath, opts = {}) {
	const doc = buildSarif(matches, opts);
	fs.writeFileSync(outputPath, JSON.stringify(doc, null, 2) + "\n");
	return doc;
}

module.exports = { buildSarif, writeSarif, sarifLevel };
