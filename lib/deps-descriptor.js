/**
 * lib/deps-descriptor.js — serialize / deserialize an *anonymized* descriptor of
 * the resolved dependency set, for air-gapped offline→online→offline audits.
 *
 * Phase 1 (offline): collect deps → serializeDeps → write JSON. Remove manifest
 *   paths and registry URLs; retain coordinates, scope and filtered version hints.
 *   Private coordinates cannot be identified offline: review before transfer.
 * Phase 2 (online): read JSON → deserializeDeps → run the scan flow to warm the
 *   coordinate-keyed caches, then `--export-cache`.
 * Phase 3 (offline): `--import-cache` + a normal `--offline` scan re-collects the
 *   source locally (real paths) and gets cache hits → full detailed report.
 *
 * See the anonymized-deps-descriptor design spec.
 *
 * Pure functions: no I/O, no console. The caller does file read/write.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { makeDepRecord, coordKeyFor } = require("./dep-record");

const SCHEMA = "fad-deps/1";

// Fields kept in the descriptor — everything required to query the public vuln
// databases and to group the report. Anything path/URL/host-bearing is dropped:
//   manifestPath(s) / pomPaths, resolved (registry URL), integrity, from
//   (parent chain), depth, lockType.
const ANON_NOTE = "Dependency coordinates and filtered version hints only. Private coordinates cannot be identified offline: exclude them and review before transfer.";

function cleanVersion(value) {
	if (typeof value !== "string") return null;
	const v = value.trim();
	// URL/file-installed dependencies have no portable registry version. Preserve
	// their coordinate with an unknown version instead of exporting a source URL.
	return v && !/[\\/:\x00-\x1f\x7f]|\$\{/.test(v) ? v : null;
}

function filterVersionProperties(properties, referenced = []) {
	const out = {};
	const names = new Set(referenced);
	for (const [name, value] of Object.entries(properties || {})) {
		if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(name)
			|| /password|passwd|secret|token|credential|api[._-]?key|private[._-]?key/i.test(name)) continue;
		const versionName = /(?:version$|^version[._-]|[._-]version[._-])/i.test(name)
			|| ["revision", "changelist", "sha1"].includes(name) || names.has(name);
		if (!versionName || typeof value !== "string") continue;
		const v = value.trim();
		// Keep Maven numeric versions, ranges and well-known qualifiers; do not
		// accept an arbitrary string just because its property ends in ".version".
		if (name === "changelist" && (v === "" || v === "SNAPSHOT")) out[name] = v;
		else if (cleanVersion(v) && /^(?:v?\d[0-9A-Za-z._+,-]*|[\[(][0-9A-Za-z._+,\s()[\]-]+[\])]|SNAPSHOT|RELEASE|LATEST)$/.test(v))
			out[name] = v;
	}
	return out;
}

/**
 * serializeDeps(resolvedMap, opts) -> descriptor object (ready for JSON.stringify).
 *
 * opts:
 *   generator    — tool id/version string for traceability (no env info)
 *   generatedAt  — ISO timestamp (override for deterministic tests)
 *   note         — human-readable banner (defaults to the anonymization notice)
 */
// Sanitize a parent/BOM coordinate to the three public fields only (never carry paths,
// registry URLs or other record cruft into the descriptor).
function cleanCoord(c) {
	return (c && typeof c.groupId === "string" && typeof c.artifactId === "string"
		&& /^[A-Za-z0-9_.-]+$/.test(c.groupId) && /^[A-Za-z0-9_.-]+$/.test(c.artifactId) && cleanVersion(c.version))
		? { groupId: String(c.groupId), artifactId: String(c.artifactId), version: cleanVersion(c.version) } : null;
}

function serializeDeps(resolvedMap, opts = {}) {
	const { generator = "fad-checker", generatedAt = new Date().toISOString(), note = ANON_NOTE } = opts;
	const deps = [];
	const byEcosystem = {};
	for (const d of resolvedMap.values()) {
		if (!d || !d.ecosystem || !d.name) continue;
		const rawVersions = Array.isArray(d.versions) && d.versions.length
			? [...new Set(d.versions)]
			: (d.version ? [d.version] : []);
		const versions = [...new Set(rawVersions.map(cleanVersion).filter(Boolean))];
		deps.push({
			ecosystem: d.ecosystem,
			ecosystemType: d.ecosystemType || d.ecosystem,
			namespace: d.namespace || "",
			name: d.name,
			version: cleanVersion(d.version) || (versions[0] || null),
			versions,
			scope: d.scope || "prod",
			isDev: !!d.isDev,
		});
		byEcosystem[d.ecosystem] = (byEcosystem[d.ecosystem] || 0) + 1;
	}
	// Stable order so two runs over the same tree produce identical files (easier
	// to diff/review and to detect tampering during transfer).
	deps.sort((a, b) => (a.ecosystem + "\0" + a.namespace + "\0" + a.name).localeCompare(b.ecosystem + "\0" + b.namespace + "\0" + b.name));
	// Maven resolution hints: the EXTERNAL parent + import-BOM coords that manage the
	// versionless deps, plus the project's version-property overrides. These let a Phase-2
	// online run (no source tree) resolve `spring-boot-starter-actuator`'s version and warm
	// its CVE cache in ONE round-trip — the alternative is two exchanges (see docs/USAGE.md).
	// Public coords + version strings only; the auditor reviews before transfer like the rest.
	const externalParents = (opts.externalParents || []).map(cleanCoord).filter(Boolean);
	const importBoms = (opts.importBoms || []).map(cleanCoord).filter(Boolean);
	const propertyOverrides = filterVersionProperties(opts.propertyOverrides, opts.versionPropertyNames);
	const omitted = Object.keys(opts.propertyOverrides || {}).length - Object.keys(propertyOverrides).length;
	if (omitted) opts.onOmittedProperties?.(omitted);
	const hasMavenHints = externalParents.length || importBoms.length || Object.keys(propertyOverrides).length;
	// Application identities: the CMS/framework PRODUCT coordinates (type + core
	// version) and its inventoried PUBLIC component identities — vendor catalogue
	// info, no paths, private components never included. They are what no package
	// coordinate carries: the WordPress checksums reference is pinned by core
	// version, and a module/theme is inventoried from its .info.yml without ever
	// appearing in the lock. A Phase-2 online run warms the per-publisher advisory
	// snapshots from them, so the air-gapped Phase 3 (and the online reference scan
	// — same command, same options) auto-consumes them.
	const applications = (opts.applications || [])
		.filter(a => a && typeof a.type === "string" && a.type.trim())
		.map(a => ({
			type: String(a.type).trim(),
			version: typeof a.version === "string" && a.version.trim() ? String(a.version).trim() : null,
			...(Array.isArray(a.components) && a.components.length ? { components: a.components } : {}),
		}));
	return {
		schema: SCHEMA,
		generator,
		generatedAt,
		note,
		summary: { total: deps.length, byEcosystem, ...(applications.length ? { applications: applications.length } : {}) },
		...(hasMavenHints ? { maven: { externalParents, importBoms, propertyOverrides } } : {}),
		...(applications.length ? { applications } : {}),
		deps,
	};
}

/**
 * deserializeDeps(descriptor) -> { resolved, activeIds, runMaven, runNpm }.
 *
 * Rebuilds depRecords with EMPTY manifestPaths (the descriptor carries none) and
 * a RECOMPUTED coordKey (never trusts the input). Throws on schema mismatch.
 */
function deserializeDeps(descriptor) {
	if (!descriptor || typeof descriptor !== "object") throw new Error("invalid descriptor: not an object");
	if (descriptor.schema !== SCHEMA) {
		throw new Error(`unsupported descriptor schema: got "${descriptor.schema}", expected "${SCHEMA}"`);
	}
	const list = Array.isArray(descriptor.deps) ? descriptor.deps : [];
	const resolved = new Map();
	const ecosystems = new Set();
	for (const e of list) {
		if (!e || !e.ecosystem || !e.name) continue;
		const rec = makeDepRecord({
			ecosystem: e.ecosystem,
			ecosystemType: e.ecosystemType || e.ecosystem,
			namespace: e.namespace || "",
			name: e.name,
			version: e.version || null,
			scope: e.scope || "prod",
			isDev: !!e.isDev,
			// manifestPath intentionally omitted → manifestPaths/pomPaths = []
		});
		// Restore the full multi-version set (makeDepRecord only derives it from the
		// single `version`); CVE/OSV matching iterates `versions`.
		if (Array.isArray(e.versions) && e.versions.length) rec.versions = [...new Set(e.versions)];
		resolved.set(coordKeyFor(e.ecosystem, e.namespace || "", e.name), rec);
		ecosystems.add(e.ecosystem);
	}
	const activeIds = [...ecosystems];
	// Maven resolution hints (absent on legacy descriptors → empty). The import flow replays
	// the external-parent / import-BOM backfill from these so a no-source-tree online warm run
	// resolves the versionless deps' versions.
	const mvn = (descriptor.maven && typeof descriptor.maven === "object") ? descriptor.maven : {};
	const applications = (Array.isArray(descriptor.applications) ? descriptor.applications : [])
		.filter(a => a && typeof a.type === "string" && a.type.trim())
		.map(a => ({
			type: String(a.type).trim(),
			version: typeof a.version === "string" && a.version.trim() ? String(a.version).trim() : null,
			...(Array.isArray(a.components) && a.components.length ? { components: a.components.map(String) } : {}),
		}));
	return {
		resolved,
		activeIds,
		runMaven: ecosystems.has("maven"),
		runNpm: ecosystems.has("npm") || ecosystems.has("yarn"),
		externalParents: Array.isArray(mvn.externalParents) ? mvn.externalParents : [],
		importBoms: Array.isArray(mvn.importBoms) ? mvn.importBoms : [],
		propertyOverrides: (mvn.propertyOverrides && typeof mvn.propertyOverrides === "object") ? mvn.propertyOverrides : {},
		applications,
	};
}

module.exports = { serializeDeps, deserializeDeps, filterVersionProperties, SCHEMA, ANON_NOTE };
