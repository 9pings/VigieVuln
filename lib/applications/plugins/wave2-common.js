const path = require("node:path");

const join = (dir, file) => dir === "." ? file : `${dir}/${file}`;
const posix = value => String(value || "").split(path.sep).join("/");
const within = (child, parent) => parent === "." || child === parent || child.startsWith(parent + "/");

function readJson(ctx, relative, maxBytes = 1024 * 1024) {
	try {
		const value = JSON.parse(ctx.readText(relative, maxBytes));
		return value && typeof value === "object" && !Array.isArray(value) ? value : null;
	} catch { return null; }
}

function composerOccurrences(app, ctx) {
	const lock = join(app.root, "composer.lock");
	const matches = [];
	for (const dep of ctx.resolvedDeps.values()) {
		if (dep.ecosystem !== "composer") continue;
		const coord = `${dep.namespace}/${dep.name}`.toLowerCase();
		for (const occurrence of dep.occurrences || []) {
			const relative = posix(path.relative(ctx.srcRoot, occurrence.manifestPath));
			// A composer.json constraint describes intent, not an installed version.
			// Even an exact root requirement cannot prove the code was installed.
			if (relative !== lock) continue;
			matches.push({ coord, occurrence, relative });
		}
	}
	return matches;
}

function composerComponent(app, entry, kind) {
	const { coord, occurrence, relative } = entry;
	return { id: `${app.id}:${coord}@${occurrence.version}`, applicationId: app.id,
		kind, coord, name: coord, version: occurrence.version, rawVersion: occurrence.version,
		versionStatus: "locked", scope: occurrence.scope,
		managerRelation: occurrence.managerRelation || "unknown", visibility: "unknown",
		activation: "unknown", evidence: [{ path: relative, field: `packages[name=${coord}].version` }] };
}

function composerCoverageDiagnostic(app, ctx) {
	const manifest = ctx.index.hasFile(join(app.root, "composer.json"));
	const lock = ctx.index.hasFile(join(app.root, "composer.lock"));
	if (!manifest && !lock) return null;
	if (!lock) return { code: "CMS_LOCKFILE_MISSING", applicationId: app.id,
		message: "composer.json has no composer.lock; declared package constraints do not prove installed versions" };
	if (ctx.activeCodecIds.includes("composer")) return null;
	return { code: "CMS_CODEC_DISABLED", applicationId: app.id,
		message: "Composer collection is disabled; locked package versions and dependency origins are incomplete" };
}

/**
 * True when the component's coordinate is a Composer dependency of the scanned tree
 * (lock pin or best-effort manifest), i.e. its advisory evaluation IS the report's own
 * dependency lanes (OSV.dev, Packagist, NVD) — the same principle as the
 * Symfony/Laravel coverage: a component the dependency lanes scanned must not read
 * as a gap a CMS-style publisher feed would have filled.
 */
function coveredByDependencyLanes(component, ctx) {
	if (!component || !component.coord || !ctx || !ctx.resolvedDeps) return false;
	const coord = String(component.coord).toLowerCase();
	for (const dep of ctx.resolvedDeps.values())
		if (dep && dep.ecosystem === "composer"
			&& `${dep.namespace || ""}/${dep.name}`.toLowerCase() === coord) return true;
	return false;
}

function finishInventory(app, components, diagnostics = [], sourceId = "application-advisories", options = {}) {
	const unknown = components.filter(component => !component.version);
	return { components, diagnostics: [...diagnostics, ...unknown.map(component => ({ code: "CMS_VERSION_UNKNOWN",
		applicationId: app.id, componentId: component.id,
		message: `version unavailable for ${component.kind} ${component.name || component.coord || component.id}` }))],
		coverage: [
			{ applicationId: app.id, capability: "inventory", execution: unknown.length || diagnostics.length ? "partial" : "completed",
				result: unknown.length || diagnostics.length ? "indeterminate" : "not-applicable",
				expected: components.length, executed: components.length - unknown.length,
				...(unknown.length ? { diagnostic: "CMS_VERSION_UNKNOWN" } : diagnostics.length ? { diagnostic: diagnostics[0].code } : {}) },
			// A plugin with a qualified advisory lane reports that lane from assess() instead
			// (CMS_PROVIDER_UNCONFIGURED when unconfigured); the generic not-qualified entry
			// would then understate a coverage that actually ran.
			...(options.advisories === false ? [] :
				// Per component: a coordinate the dependency lanes scanned is covered
				// (stated as such, never a gap); a component with no advisory source
				// anywhere keeps its honest not-qualified row.
				components.map(component => component.visibility === "private"
					? { applicationId: app.id, occurrenceId: component.id, capability: "advisories",
						sourceId: "internal-advisories", expected: 1, executed: 0, execution: "not-run",
						result: "indeterminate", diagnostic: "CMS_PRIVATE_COMPONENT" }
					: coveredByDependencyLanes(component, options.ctx)
						? { applicationId: app.id, occurrenceId: component.id, capability: "advisories",
							sourceId: "dependency-lanes", expected: 1, executed: 1, execution: "completed",
							result: "not-applicable" }
						: { applicationId: app.id, occurrenceId: component.id, capability: "advisories", sourceId,
							expected: 1, executed: 0, execution: "not-run", result: "indeterminate",
							diagnostic: "CMS_ADVISORY_NOT_QUALIFIED" })), 
			{ applicationId: app.id, capability: "lifecycle", sourceId: "application-lifecycle", execution: "not-run",
				result: "indeterminate", expected: 1, executed: 0,
				diagnostic: "CMS_LIFECYCLE_NOT_QUALIFIED" },
		] };
}

/**
 * Provenance of a locally read advisory snapshot. An operator-supplied file is
 * "operator-declared"; a file the tool itself fetched and cached — auto-reused
 * under --offline from ~/.fad-checker/advisory-snapshots/ — reports the stamp it
 * carries (tool-fetched, its source URL), not a declaration the operator never made.
 */
function localSourceSnapshot(ctx, snapshotPath, bytes, stat, snapshot) {
	const { createHash } = require("node:crypto");
	const { declaredCollectedAt } = require("../../advisories/freshness");
	const declared = declaredCollectedAt(snapshot);
	const autoCached = ctx.autoCachedSources?.has(snapshotPath) || false;
	const stamp = snapshot && typeof snapshot === "object" ? snapshot._fadSnapshot : null;
	return { sha256: createHash("sha256").update(bytes).digest("hex"),
		fileModifiedAt: stat.mtime.toISOString(),
		completeness: autoCached ? (stamp?.completeness || "tool-fetched") : "operator-declared",
		...(autoCached && stamp?.sourceUrl ? { sourceUrl: stamp.sourceUrl } : {}),
		...(declared ? { collectedAt: declared.toISOString() } : {}) };
}

module.exports = { join, posix, within, readJson, composerOccurrences, composerComponent,
	composerCoverageDiagnostic, finishInventory, coveredByDependencyLanes, localSourceSnapshot };
