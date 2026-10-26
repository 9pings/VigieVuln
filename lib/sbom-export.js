/**
 * lib/sbom-export.js — emit a CycloneDX 1.6 SBOM with vulnerabilities inline
 * (a VDR — Vulnerability Disclosure Report) from the resolved deps + matches.
 *
 * buildCycloneDx is pure (testable); writeCycloneDx writes the JSON to disk.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { purlFor } = require("./purl");
const { variantsFor, matchingVariants } = require("./application-exports");
const { europeanReferences, euvdExploited } = require("./eu-refs");

// NVD "CVSS:3.1" → CycloneDX rating method enum. Tolerates the legacy
// "CVSS:V31"/"V30"/"V40"/"V2" labels left in pre-fix NVD caches.
function cvssMethod(cvssVersion) {
	const v = String(cvssVersion || "");
	if (v.includes("4.0") || /v40\b/i.test(v)) return "CVSSv4";
	if (v.includes("3.1") || /v31\b/i.test(v)) return "CVSSv31";
	if (v.includes("3.0") || v === "CVSS:3" || /v30\b/i.test(v)) return "CVSSv3";
	if (v.includes("2.0") || v === "CVSS:2" || /v2\b/i.test(v)) return "CVSSv2";
	return "other";
}

// Point the advisory source at the right database for the id type — a GHSA/OSV id
// has no page on nvd.nist.gov, so the old hardcoded NVD url was a dead link.
function advisorySource(id, source) {
	if (String(source || "").includes("wordfence-v3")) return { name: "Wordfence", url: "https://www.wordfence.com/threat-intel/vulnerabilities/" };
	if (String(source || "").includes("drupal-security-advisories")) return { name: "Drupal Security Advisories", url: "https://www.drupal.org/security" };
	if (/^CVE-/i.test(id)) return { name: "NVD", url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}` };
	if (/^GHSA-/i.test(id)) return { name: "GitHub Advisory Database", url: `https://github.com/advisories/${encodeURIComponent(id)}` };
	return { name: (source || "").includes("nvd") ? "NVD" : "OSV", url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` };
}

// Stable, UNIQUE bom-ref. Declared deps use their purl (unchanged). Embedded
// binaries get a location-qualified ref so two copies of the same coordinate
// (one declared, one shaded into a jar) don't collide on the same bom-ref.
function bomRefFor(dep, purl) {
	if (dep.provenance === "embedded") return dep.coordKey; // already "embedded:<path>" — unique
	return purl || null;
}

function cdxSeverity(sev) {
	const s = (sev || "unknown").toLowerCase();
	return ["critical", "high", "medium", "low", "none", "info"].includes(s) ? s : "unknown";
}

function cweNum(c) {
	const m = String(c).match(/(\d+)/);
	return m ? parseInt(m[1], 10) : null;
}

function licenseEntry(ids) {
	// CycloneDX: {license:{id}} for SPDX ids, {license:{name}} otherwise.
	return (ids || []).map(x => /^[A-Za-z0-9.+-]+$/.test(x) && /[A-Z]/.test(x) ? { license: { id: x } } : { license: { name: x } });
}

/**
 * Build a CycloneDX 1.6 object.
 * opts: { projectInfo, toolVersion, timestamp, licenseResults }
 */
function buildCycloneDx(resolvedDeps, cveMatches, opts = {}) {
	const { projectInfo = {}, toolVersion = "0", timestamp, licenseResults } = opts;

	// coordKey → [spdx ids] for component licenses (optional).
	const licByCoord = new Map();
	for (const e of licenseResults?.assessed || []) {
		const key = e.dep?.coordKey || `${e.dep?.namespace || ""}:${e.dep?.name}`;
		const ids = (e.ids || []).concat(e.raw || []);
		if (ids.length) licByCoord.set(key, ids);
	}

	const components = [];
	const variantsByCoord = new Map();
	const dynamicComponents = new Map();
	for (const dep of resolvedDeps.values()) {
		const variants = variantsFor(dep, projectInfo.src);
		variantsByCoord.set(dep.coordKey, variants);
		for (const variant of variants) {
			const item = variant.dep;
			const purl = purlFor(item);
			const comp = { type: "library", name: item.name || item.artifactId, version: item.version || undefined };
			if (item.namespace || item.groupId) comp.group = item.namespace || item.groupId;
			const ref = variant.ref || bomRefFor(item, purl);
			if (ref) comp["bom-ref"] = ref;
			if (purl) comp.purl = purl;
			const lic = licByCoord.get(dep.coordKey);
			if (lic) comp.licenses = licenseEntry(lic);
			if (variant.location) comp.properties = [{ name: "fad:location", value: variant.location }];
			if (item.provenance === "embedded") {
				comp.properties = [
					{ name: "fad:provenance", value: "embedded" },
					...((item.manifestPaths || [])[0] ? [{ name: "fad:location", value: item.manifestPaths[0] }] : []),
				];
			}
			components.push(comp);
		}
	}

	// One vulnerability entry per CVE id, aggregating affected component refs.
	const byCve = new Map();
	for (const m of cveMatches || []) {
		const id = m.cve?.id;
		if (!id) continue;
		const variants = variantsByCoord.get(m.dep?.coordKey) || [];
		let refs = variants.length ? matchingVariants(m, variants, projectInfo.src).map(v => v.ref) :
			[bomRefFor(m.dep, purlFor(m.dep))];
		if ((!variants.length || !refs.filter(Boolean).length) && m.dep?.provenance === "application") {
			const purl = purlFor(m.dep);
			const location = m.dep.manifestPaths?.[0] || "";
			const ref = `${purl || m.dep.coordKey}|${location}`;
			if (!dynamicComponents.has(ref)) {
				dynamicComponents.set(ref, true);
				components.push({ type: "application", name: m.dep.name || m.dep.artifactId,
					version: m.dep.version || undefined, "bom-ref": ref, ...(purl ? { purl } : {}),
					...(location ? { properties: [{ name: "fad:location", value: location }] } : {}) });
			}
			refs = [ref];
		}
		let v = byCve.get(id);
		if (!v) {
			const cve = m.cve;
			v = {
				"bom-ref": `vuln-${id}`,
				id,
				source: advisorySource(id, m.source),
				ratings: cve.score != null ? [{
					source: { name: String(m.source || "").includes("wordfence-v3") ? "Wordfence" :
						String(m.source || "").includes("drupal-security-advisories") ? "Drupal Security Advisories" : "NVD" },
					score: cve.score,
					severity: cdxSeverity(cve.severity),
					method: cvssMethod(cve.cvssVersion),
					...(cve.cvssVector ? { vector: cve.cvssVector } : {}),
				}] : [],
				...(Array.isArray(cve.cwes) && cve.cwes.length ? { cwes: cve.cwes.map(cweNum).filter(n => n != null) } : {}),
				...(cve.description ? { description: cve.description } : {}),
				...(europeanReferences(cve).length ? { references: europeanReferences(cve).map(r => ({ id: r.id, source: { name: r.source, url: r.url } })) } : {}),
				affects: [],
				properties: buildVulnProps(cve),
			};
			byCve.set(id, v);
		}
		for (const ref of refs) if (ref && !v.affects.some(a => a.ref === ref)) v.affects.push({ ref });
		if (m.cpeFiltered) v.properties.push({ name: "fad:cpe-filtered", value: "true" });
		// One property per physical occurrence: consumers must be able to relate the SBOM
		// entry to the report's finding identity and its application relation.
		if (m.findingId) v.properties.push({ name: "fad:finding", value: `${m.findingId}=${m.applicationRelation || "none"}` });
	}

	const bom = {
		bomFormat: "CycloneDX",
		specVersion: "1.6",
		version: 1,
		metadata: {
			...(timestamp ? { timestamp } : {}),
			tools: { components: [{ type: "application", name: "VigieVuln", version: String(toolVersion) }] },
			component: { type: "application", name: projectInfo.name || "project" },
		},
		components,
		vulnerabilities: [...byCve.values()],
	};
	return bom;
}

function buildVulnProps(cve) {
	const props = [];
	if (cve.epssScore != null) props.push({ name: "fad:epss", value: String(cve.epssScore) });
	if (cve.epssPercentile != null) props.push({ name: "fad:epssPercentile", value: String(cve.epssPercentile) });
	if (cve.kev) props.push({ name: "fad:kev", value: "true" });
	if (euvdExploited(cve)) props.push({ name: "fad:euvdExploited", value: cve.euvd.exploitedSince || "true" });
	if (cve.priority?.band) props.push({ name: "fad:priorityBand", value: cve.priority.band });
	if (cve.priority?.score != null) props.push({ name: "fad:priorityScore", value: String(cve.priority.score) });
	return props;
}

function writeCycloneDx(resolvedDeps, cveMatches, outputPath, opts = {}) {
	const bom = buildCycloneDx(resolvedDeps, cveMatches, opts);
	fs.writeFileSync(outputPath, JSON.stringify(bom, null, 2) + "\n");
	return bom;
}

module.exports = { buildCycloneDx, writeCycloneDx, cvssMethod, cdxSeverity };
