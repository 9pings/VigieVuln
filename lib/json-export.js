/**
 * lib/json-export.js — emit a single machine-readable findings document.
 *
 * Unlike the CycloneDX SBOM (component-centric) or CSAF VEX (status-centric),
 * this is fad-checker's own flat findings format: every chapter (CVE, EOL,
 * obsolete, outdated, licenses, vendored) in one JSON, easy to diff between
 * audits and post-process. buildFindings is pure; writeFindings writes it.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { purlFor } = require("./purl");
const { summarizeFindings, uniqueFindings } = require("./finding-summary");
const { europeanReferences, euvdExploited } = require("./eu-refs");

function coordOf(dep) {
	const ns = dep.namespace || dep.groupId || "";
	const name = dep.name || dep.artifactId;
	if (dep.ecosystem === "maven" && ns) return `${ns}:${name}`;
	if (dep.ecosystem === "composer" && ns) return `${ns}/${name}`;
	return name;
}

function depBrief(dep) {
	return {
		ecosystem: dep.ecosystem,
		coord: coordOf(dep),
		version: dep.version || null,
		scope: dep.scope || null,
		isDev: !!dep.isDev,
		provenance: dep.provenance || "manifest",
		purl: purlFor(dep),
		manifestPaths: dep.manifestPaths || dep.pomPaths || [],
		// When the version was backfilled from an import/platform BOM, record which BOM
		// supplied it — { via: "bom", bom: "g:a:v" } — so the finding is traceable.
		versionSource: dep.versionSource || null,
	};
}

function cveFinding(m) {
	const c = m.cve;
	return {
		id: c.id,
		aliases: c.aliases || [],
		description: c.description || null,
		copyrightNotice: c.copyrightNotice || null,
		references: (c.osvRefs || []).map(r => r.url).filter(u => typeof u === "string" && /^https?:\/\//i.test(u)),
		findingId: m.findingId || null,
		applicationIds: m.applicationIds || [],
		applicationExposures: m.applicationExposures || [],
		ownerComponentIds: m.ownerComponentIds || [],
		applicationRelation: m.applicationRelation || null,
		attributionStatus: m.attributionStatus || null,
		dependencyPaths: m.dependencyPaths || [],
		severity: c.severity || "UNKNOWN",
		severityOriginal: c.severityOriginal || null,
		severityScheme: c.severityScheme || null,
		cvss: c.score ?? null,
		cvssVector: c.cvssVector || null,
		epss: c.epssScore ?? null,
		epssPercentile: c.epssPercentile ?? null,
		kev: !!c.kev,
		kevDueDate: c.kevDueDate || null,
		euvd: c.euvd?.id || null,
		euvdExploited: euvdExploited(c),
		euvdExploitedSince: c.euvd?.exploitedSince || null,
		gcve: c.gcve || null,
		certfr: (c.certfr || []).map(a => a.ref),
		priority: c.priority ? { band: c.priority.band, score: c.priority.score } : null,
		cwes: c.cwes || [],
		fixVersion: c.fixVersion || null,
		source: m.source || null,
		confidence: m.confidence || null,
		malicious: !!m.malicious,
		cpeFiltered: !!m.cpeFiltered,
		suppressed: !!m.suppressed,
		suppressedReason: m.suppressedReason || null,
		dep: depBrief(m.dep),
	};
}

/**
 * Build the findings document.
 * payload: { cveMatches, retireMatches, eolResults, obsoleteResults,
 *            outdatedResults, licenseResults, resolvedDeps, projectInfo, toolVersion }
 */
function buildFindings(payload = {}) {
	const {
		cveMatches = [], retireMatches = [], vendoredJsInventory = [], certFindings = [], eolResults = [], obsoleteResults = [],
		outdatedResults = [], licenseResults = null, resolvedDeps, projectInfo = {}, toolVersion = "0",
		typosquats = [], excludedDirs = [], diff = null,
		applications = [], applicationInventory = [], applicationRelations = [], coverage = [], warnings = [],
	} = payload;

	const { buildInventory } = require("./unmanaged");
	const unmanaged = resolvedDeps ? buildInventory(resolvedDeps) : [];

	const { buildEmbeddedInventory } = require("./embedded");
	const embeddedMatches = cveMatches.filter(m => m.dep?.provenance === "embedded");
	const embedded = resolvedDeps ? buildEmbeddedInventory(resolvedDeps, embeddedMatches) : [];

	const uniqueCveMatches = uniqueFindings(cveMatches);
	const findingSummary = summarizeFindings(uniqueCveMatches);

	return {
		schema: "fad-findings/1",
		tool: { name: "fad-checker", version: String(toolVersion) },
		generatedAt: projectInfo.generatedAt || null,
		project: { name: projectInfo.name || null, src: projectInfo.src || null },
		// Scan-provenance manifest (data-source freshness + run configuration) for a
		// reproducible/defensible audit. Null if the caller didn't supply one.
		provenance: projectInfo.provenance || payload.provenance || null,
		summary: {
			dependencies: resolvedDeps?.size ?? null,
			cve: { ...findingSummary.bySeverity, kev: findingSummary.kev, total: findingSummary.total },
			eol: eolResults.length,
			unsupported: eolResults.filter(e => e.status === "unsupported").length,
			obsolete: obsoleteResults.length,
			outdated: outdatedResults.length,
			licensesFlagged: licenseResults?.flagged?.length || 0,
			vendored: retireMatches.length,
			unmanaged: unmanaged.length,
			embedded: embedded.length,
			vendoredJs: vendoredJsInventory.length,
			certificates: certFindings.length,
			certPrivateKeys: certFindings.filter(c => c.kind === "private-key").length,
			suppressed: uniqueCveMatches.filter(m => m.suppressed).length,
			malicious: uniqueCveMatches.filter(m => m.malicious && !m.suppressed).length,
			typosquat: typosquats.length,
			excludedDirs: excludedDirs.length,
			applications: applications.length,
			applicationComponents: applicationInventory.length,
			coverageIncomplete: coverage.filter(c => c.execution === "partial" || c.execution === "not-run" || c.execution === "failed").length,
		},
		findingSummary,
		cve: uniqueCveMatches.map(cveFinding),
		vendored: retireMatches.map(cveFinding),
		eol: eolResults.map(e => ({
			product: e.product, productSlug: e.productSlug || null, via: e.via || null, viaKey: e.viaKey || null,
			eol: e.eol,
			// For a dead cycle `latest` is the MIGRATION TARGET, not the branch's final patch;
			// `supportedCycle` names the cycle it comes from. A machine consumer needs the
			// version to move to, which is the whole point of the finding.
			latest: e.latest || null, supportedCycle: e.supportedCycle || null,
			// Lifecycle level: "eol" (no fixes at all) | "unsupported" (bug-fix support ended,
			// security fixes still provided — only present with --eol-support).
			status: e.status || "eol",
			cycle: e.cycle || null,
			support: e.support ?? null,
			// Paid support beyond the OSS end of life: a future date, "true" (offered, no date), or null.
			extendedSupport: e.extendedSupport || null,
			// The last PUBLIC release of the cycle; the build of THIS branch every CVE found needs
			// ({fixed}|{after}, cves, withBound); the newest vendor build when a vendor repository
			// is configured ({version, meetsBranchFix}).
			cycleLatest: e.cycleLatest || null,
			branchFix: e.branchFix || null,
			latestCommercial: e.latestCommercial || null,
			// Grouped framework finding (one row per framework/manifest/cycle): the anchor that
			// determined the cycle + every component at that cycle.
			anchor: e.anchor || null,
			components: e.components || null,
			dep: depBrief(e.dep),
		})),
		obsolete: obsoleteResults.map(o => ({ reason: o.reason || null, replacement: o.replacement || null, source: o.source || null, dep: depBrief(o.dep) })),
		outdated: outdatedResults.map(o => ({ latest: o.latest, releaseDate: o.releaseDate || null, dep: depBrief(o.dep) })),
		licenses: (licenseResults?.assessed || []).map(e => ({ category: e.category, licenses: e.ids.concat(e.raw), source: e.source || null, dep: depBrief(e.dep) })),
		unmanaged,
		embedded,
		vendoredJs: vendoredJsInventory,
		certificates: certFindings,
		typosquat: typosquats,
		applications,
		applicationInventory,
		applicationRelations,
		coverage,
		warnings,
		excludedDirs,
		// Differential audit vs a --baseline document (summary + per-category deltas).
		// Null when no baseline was provided.
		diff: diff || null,
	};
}

function writeFindings(payload, outputPath) {
	const doc = buildFindings(payload);
	fs.writeFileSync(outputPath, JSON.stringify(doc, null, 2) + "\n");
	return doc;
}

module.exports = { buildFindings, writeFindings };
