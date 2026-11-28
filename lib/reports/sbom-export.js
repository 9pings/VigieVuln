/**
 * lib/reports/sbom-export.js — emit a CycloneDX 1.6 SBOM with vulnerabilities inline
 * (a VDR — Vulnerability Disclosure Report) from the resolved deps + matches.
 *
 * buildCycloneDx is pure (testable); writeCycloneDx writes the JSON to disk.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { purlFor } = require("../inventory/purl");
const { variantsFor, matchingVariants } = require("../applications/exports");
const { europeanReferences, euvdExploited } = require("../findings/eu-refs");

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
	const sources = new Set(String(source || "cache").split('+'));
	if (sources.has("wordfence-v3")) return { name: "Wordfence", url: "https://www.wordfence.com/threat-intel/vulnerabilities/" };
	if (sources.has("drupal-security-advisories")) return { name: "Drupal Security Advisories", url: "https://www.drupal.org/security" };
	if (sources.has("CVEProject") && /^CVE-/i.test(id)) return { name: "CVEProject", url: `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}` };
	if (sources.has("osv")) return { name: "OSV", url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` };
	if (sources.has("nvd") && /^CVE-/i.test(id)) return { name: "NVD", url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}` };
	return { name: source || "cache" };
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
		// These ecosystems retain every scanned version on one coordinate record.
		// Keep each version so findings can reference the correct component.
		const versions = ["maven", "npm", "pypi"].includes(dep.ecosystem) && !dep.artifactTargetId && dep.provenance !== "embedded"
			? [...new Set((dep.versions || []).filter(v => v && !/\$\{/.test(String(v))))] : [];
		const variants = (versions.length
			? versions.flatMap(version => variantsFor({ ...dep, version }, projectInfo.src))
			: variantsFor(dep, projectInfo.src)).map(v => dep.artifactTargetId ? { ...v, ref: dep.coordKey } : v);
		variantsByCoord.set(dep.coordKey, variants);
		for (const variant of variants) {
			const item = variant.dep;
			const purl = purlFor(item);
			const comp = { type: "library", name: item.name || item.artifactId, version: item.version || undefined };
			if (item.namespace || item.groupId) comp.group = item.namespace || item.groupId;
			const ref = item.artifactTargetId ? item.coordKey : (variant.ref || bomRefFor(item, purl));
			if (ref) comp["bom-ref"] = ref;
			if (purl) comp.purl = purl;
			const lic = licByCoord.get(dep.coordKey);
			if (lic) comp.licenses = licenseEntry(lic);
			if (variant.location) comp.properties = [{ name: "fad:location", value: variant.location }];
			if (item.artifactTargetId) comp.properties = [...(comp.properties || []), { name: "fad:artifact-id", value: String(item.artifactTargetId) }, ...(item.artifactPath ? [{ name: "fad:artifact-path", value: String(item.artifactPath) }] : [])];
			if (item.artifactTargetId) {
				for (const [key, value] of Object.entries({ manager: item.manager, sourceName: item.sourceName, sourceVersion: item.sourceVersion, distribution: item.distribution && JSON.stringify(item.distribution), binaryEvidence: item.binaryEvidence && JSON.stringify(item.binaryEvidence), installEvidence: item.installEvidence && JSON.stringify(item.installEvidence), sbomEvidence: item.sbomEvidence && JSON.stringify(item.sbomEvidence), osPackageOwners: item.osPackageOwners?.length && JSON.stringify(item.osPackageOwners) }))
					if (value) comp.properties.push({ name: `fad:${key}`, value: String(value) });
			}
			if (item.provenance === "embedded") {
				comp.properties = [...(comp.properties || []),
					{ name: "fad:provenance", value: "embedded" },
					...(!variant.location && (item.manifestPaths || [])[0] ? [{ name: "fad:location", value: item.manifestPaths[0] }] : []),
				];
			}
			components.push(comp);
		}
	}

	// One vulnerability entry per CVE id, aggregating affected component refs.
	const byCve = new Map();
	// An advisory that is beyond the detail limit on every component it affects keeps its
	// identity, rating and affected references, not its texts and evidence (lib/reports/detail.js).
	const beyond = require('./detail').beyondDetailLimit(cveMatches);
	const detailedIds = new Set((cveMatches || []).filter(m => !beyond.has(m)).map(m => m.cve?.id));
	for (const m of cveMatches || []) {
		const id = m.cve?.id;
		if (!id) continue;
		const compact = !detailedIds.has(id);
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
			const risk=require('../findings/risk-evidence'), scoreSafe=!risk.relatedRisk(cve,'scoreSource'), severitySafe=!risk.relatedRisk(cve,'severitySource');
			const score=scoreSafe?cve.score:null;
			const ownSeverity=severitySafe && cve.severity && String(cve.severity).toUpperCase()!=='UNKNOWN';
			v = {
				"bom-ref": `vuln-${id}`,
				id,
				source: advisorySource(id, m.source),
				ratings: score != null || (!scoreSafe && ownSeverity) ? [{
					// A merged finding does not identify which source supplied the score.
					...(m.source && !m.source.includes('+') ? { source: { name: advisorySource(id, m.source).name } } : {}),
					...(score != null ? {score,method:cvssMethod(cve.cvssVersion)} : {}),
					...(severitySafe ? {severity:cdxSeverity(cve.severity)} : {}),
					...(score != null && cve.cvssVector ? { vector: cve.cvssVector } : {}),
				}] : [],
				...(Array.isArray(cve.cwes) && cve.cwes.length ? { cwes: cve.cwes.map(cweNum).filter(n => n != null) } : {}),
				...(cve.description && !compact ? { description: cve.description } : {}),
				...(!compact && europeanReferences(cve).length ? { references: europeanReferences(cve).map(r => ({ id: r.id, source: { name: r.source, url: r.url } })) } : {}),
				affects: [],
				properties: compact ? [{ name: 'vigievuln:detail', value: 'compact' }, ...buildVulnProps(cve).filter(p => p.name !== 'vigievuln:related-risk-evidence')] : buildVulnProps(cve),
			};
			byCve.set(id, v);
		}
		const evidence=compact ? {} : require('../findings/risk-evidence').evidenceObject(m.cve);
		if(Object.keys(evidence).length){const value=JSON.stringify(evidence);if(!v.properties.some(p=>p.name==='vigievuln:related-risk-evidence' && p.value===value))v.properties.push({name:'vigievuln:related-risk-evidence',value});}
		if(m.cve.historicalEvidence){const value=JSON.stringify({refs:refs.filter(Boolean),evidence:m.cve.historicalEvidence});if(!v.properties.some(p=>p.name==='vigievuln:historical-evidence'&&p.value===value))v.properties.push({name:'vigievuln:historical-evidence',value});}
		for(const evidence of compact ? [] : require('../findings/applicability-evidence').applicabilityEvidence(m.cve)){const value=JSON.stringify({refs:refs.filter(Boolean),...evidence});if(!v.properties.some(p=>p.name==='vigievuln:applicability-evidence'&&p.value===value))v.properties.push({name:'vigievuln:applicability-evidence',value});}
		if(m.cve.vendorEvidence){const value=JSON.stringify({refs:refs.filter(Boolean),evidence:m.cve.vendorEvidence});if(!v.properties.some(p=>p.name==='vigievuln:vendor-evidence'&&p.value===value))v.properties.push({name:'vigievuln:vendor-evidence',value});}
		for (const source of String(m.source || 'cache').split('+').filter(Boolean))
			if (!v.properties.some(p => p.name === 'vigievuln:source' && p.value === source)) v.properties.push({ name: 'vigievuln:source', value: source });
		for (const ref of refs) if (ref && !v.affects.some(a => a.ref === ref)) v.affects.push({ ref });
		// Triage is per affected component, not per CVE. A global analysis.state
		// would incorrectly clear other products sharing the same advisory.
		if (m.suppressed) v.properties.push({ name: "vigievuln:triage", value: JSON.stringify({
			refs: refs.filter(Boolean), suppressed: true, reason: m.suppressedReason || "ignored",
			...(m.suppressionStatus ? { status: m.suppressionStatus } : {}),
		}) });
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
	const risk=require('../findings/risk-evidence');const evidence=risk.evidenceObject(cve);
	if(Object.keys(evidence).length)props.push({name:'vigievuln:related-risk-evidence',value:JSON.stringify(evidence)});
	if (cve.epssScore != null && !risk.relatedSignal(cve,'epss')) props.push({ name: "fad:epss", value: String(cve.epssScore) });
	if (cve.epssPercentile != null && !risk.relatedSignal(cve,'epss')) props.push({ name: "fad:epssPercentile", value: String(cve.epssPercentile) });
	if (cve.kev && !risk.relatedSignal(cve,'kev')) props.push({ name: "fad:kev", value: "true" });
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
