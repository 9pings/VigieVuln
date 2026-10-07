/**
 * lib/csaf-export.js — emit a CSAF 2.0 VEX (csaf_vex) document from the resolved
 * deps + matches. buildCsaf is pure; writeCsaf writes the JSON to disk.
 *
 * Spec: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { purlFor } = require("./purl");
const { variantsFor, matchingVariants } = require("./application-exports");
const { europeanReferences, euvdExploited } = require("./eu-refs");

function humanName(dep) {
	const ns = dep.namespace || dep.groupId || "";
	const name = dep.name || dep.artifactId;
	const base = dep.ecosystem === "composer" && ns ? `${ns}/${name}` : (ns && dep.ecosystem === "maven" ? `${ns}:${name}` : name);
	return dep.version ? `${base}@${dep.version}` : base;
}

// NVD "CVSS:3.1" → CVSS v3 JSON `version` field, or null when not a v3 score.
// Tolerates the legacy "CVSS:V31"/"CVSS:V30" labels still sitting in pre-fix NVD
// caches (the producer now emits "CVSS:3.1"; this keeps offline caches working).
function cvssV3Version(cvssVersion) {
	const v = String(cvssVersion || "");
	if (v.includes("3.1") || /v31\b/i.test(v)) return "3.1";
	if (v.includes("3.0") || v === "CVSS:3" || /v30\b/i.test(v)) return "3.0";
	return null;
}

// CVSS v3 `baseSeverity` is a closed enum (NONE|LOW|MEDIUM|HIGH|CRITICAL). OSV/GHSA
// often yield "UNKNOWN", which fails CSAF schema validation — derive it from the
// base score's standard v3 bands when the label isn't a valid enum value.
function cvssV3Severity(severity, score) {
	const s = String(severity || "").toUpperCase();
	if (["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(s)) return s;
	if (typeof score !== "number") return "NONE";
	if (score === 0) return "NONE";
	if (score < 4) return "LOW";
	if (score < 7) return "MEDIUM";
	if (score < 9) return "HIGH";
	return "CRITICAL";
}

/**
 * Build a CSAF 2.0 csaf_vex object.
 * opts: { projectInfo, toolVersion, timestamp }
 */
function buildCsaf(resolvedDeps, cveMatches, opts = {}) {
	const { projectInfo = {}, toolVersion = "0", timestamp } = opts;
	const now = timestamp || projectInfo.generatedAt || "1970-01-01T00:00:00Z";

	// Stable product ids + coordKey → product_id lookup.
	const full_product_names = [];
	const productVariantsByCoord = new Map();
	let n = 0;
	for (const dep of resolvedDeps.values()) {
		const entries = variantsFor(dep, projectInfo.src).map(variant => {
			const pid = `PROD-${n++}`;
			const purl = purlFor(variant.dep);
			full_product_names.push({ product_id: pid,
				name: humanName(variant.dep) + (variant.location ? ` (${variant.location})` : ""),
				...(purl ? { product_identification_helper: { purl } } : {}) });
			return { ...variant, pid };
		});
		productVariantsByCoord.set(dep.coordKey, entries);
	}
	const dynamicByKey = new Map();

	// One vulnerability per CVE, listing every affected product id.
	const byCve = new Map();
	for (const m of cveMatches || []) {
		const id = m.cve?.id;
		if (!id) continue;
		const entries = productVariantsByCoord.get(m.dep?.coordKey) || [];
		let pids = matchingVariants(m, entries, projectInfo.src).map(e => e.pid);
		// A match whose dep isn't in resolvedDeps (e.g. a Snyk-only finding) has no
		// product yet — register it on the fly so the CVE never ends up with an empty
		// known_affected[] (which is schema-invalid: product_status lists need ≥1 item).
		if (!pids.length && m.dep && m.dep.coordKey) {
			const key = `${m.dep.coordKey}\0${m.dep.version}\0${m.dep.manifestPaths?.[0] || ""}`;
			let pid = dynamicByKey.get(key);
			if (!pid) {
				pid = `PROD-${n++}`;
				dynamicByKey.set(key, pid);
				const purl = purlFor(m.dep);
				full_product_names.push({
					product_id: pid,
					name: humanName(m.dep),
					...(purl ? { product_identification_helper: { purl } } : {}),
				});
			}
			pids = [pid];
		}
		let v = byCve.get(id);
		if (!v) {
			const cve = m.cve;
			const notes = [];
			if (cve.description) notes.push({ category: "description", text: cve.description, title: "Description" });
			const extras = [];
			if (cve.epssPercentile != null) extras.push(`EPSS percentile ${Math.round(cve.epssPercentile * 100)}%`);
			if (cve.kev) extras.push(`CISA KEV (known exploited)${cve.kevDueDate ? `, remediate by ${cve.kevDueDate}` : ""}`);
			if (euvdExploited(cve)) extras.push(`ENISA EUVD (exploited${cve.euvd.exploitedSince ? ` since ${cve.euvd.exploitedSince}` : ""})`);
			if (cve.priority?.band) extras.push(`fad-checker priority: ${cve.priority.band}${cve.priority.score != null ? ` (${cve.priority.score}/100)` : ""}`);
			if (extras.length) notes.push({ category: "other", text: extras.join("; "), title: "Prioritization" });

			const v3ver = cvssV3Version(cve.cvssVersion);
			const scores = (v3ver && cve.score != null) ? [{
				cvss_v3: {
					version: v3ver,
					baseScore: cve.score,
					baseSeverity: cvssV3Severity(cve.severity, cve.score),
					// Only carry the vector when it actually IS a v3 vector — a v4 (or
					// mismatched) vector string fails the v3 schema's vectorString pattern.
					...((cve.cvssVector && /^CVSS:3\.[01]\//.test(cve.cvssVector)) ? { vectorString: cve.cvssVector } : {}),
				},
				products: [],
			}] : [];

			v = {
				...(id.startsWith("CVE-") ? { cve: id } : {
					ids: [{ system_name: String(m.source || "").includes("wordfence-v3") ? "Wordfence" :
						String(m.source || "").includes("drupal-security-advisories") ? "Drupal Security Advisory" : "Advisory",
						text: String(m.source || "").includes("wordfence-v3") && id.startsWith("WF-") ? id.slice(3) : id }],
				}),
				...(notes.length ? { notes } : {}),
				product_status: { known_affected: [] },
				...(scores.length ? { scores } : {}),
				...(cve.kev ? { flags: [{ label: "exploited", product_ids: [] }] } : {}),
				...(europeanReferences(cve).length ? { references: europeanReferences(cve).map(r => ({ category: "external", summary: r.title ? `${r.source} ${r.id} — ${r.title}` : `${r.source} ${r.id}`, url: r.url })) } : {}),
			};
			byCve.set(id, v);
		}
		if (id.startsWith("CVE-") && m.advisoryId) {
			const system_name = String(m.source || "").includes("wordfence-v3") ? "Wordfence" :
				String(m.source || "").includes("drupal-security-advisories") ? "Drupal Security Advisory" : "Advisory";
			if (!(v.ids || []).some(item => item.system_name === system_name && item.text === m.advisoryId))
				v.ids = [...(v.ids || []), { system_name, text: m.advisoryId }];
		}
		for (const pid of pids) if (pid && !v.product_status.known_affected.includes(pid)) {
			v.product_status.known_affected.push(pid);
			if (v.scores?.[0]) v.scores[0].products.push(pid);
			if (v.flags?.[0]) v.flags[0].product_ids.push(pid);
		}
	}

	return {
		document: {
			category: "csaf_vex",
			csaf_version: "2.0",
			title: `Vulnerability disclosure (VEX) — ${projectInfo.name || "project"}`,
			publisher: {
				category: "vendor",
				name: "fad-checker",
				namespace: "https://github.com/9pings/fad-checker",
			},
			tracking: {
				id: `fad-checker-${(projectInfo.name || "project").replace(/[^A-Za-z0-9._-]/g, "-")}-${String(now).slice(0, 10)}`,
				status: "final",
				version: "1",
				generator: { engine: { name: "fad-checker", version: String(toolVersion) } },
				initial_release_date: now,
				current_release_date: now,
				revision_history: [{ number: "1", date: now, summary: "Initial automated VEX from fad-checker scan" }],
			},
		},
		product_tree: { full_product_names },
		// Drop any vulnerability that ended up with zero affected products (e.g. a
		// match with no usable dep) — an empty product_status is schema-invalid.
		vulnerabilities: [...byCve.values()].filter(v => v.product_status.known_affected.length > 0),
	};
}

function writeCsaf(resolvedDeps, cveMatches, outputPath, opts = {}) {
	const doc = buildCsaf(resolvedDeps, cveMatches, opts);
	fs.writeFileSync(outputPath, JSON.stringify(doc, null, 2) + "\n");
	return doc;
}

module.exports = { buildCsaf, writeCsaf };
