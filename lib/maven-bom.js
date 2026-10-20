/**
 * lib/maven-bom.js — resolve EXTERNAL import-scope BOMs (e.g. spring-boot-dependencies)
 * from Maven Central and backfill the versions of declared deps that the BOM manages.
 *
 * core.js follows LOCAL `<scope>import</scope>` BOMs (their POM is in the source tree)
 * but cannot enumerate an external BOM's managed-version table without fetching it. So
 * in a typical Spring Boot project every `spring-boot-starter-*` (declared without a
 * version, version pinned by the imported BOM) ends up unresolved — flooding chapter 0
 * and dropping out of the CVE/EOL/outdated scans.
 *
 * This module fetches each external import BOM via transitive.js#effectivePom (which
 * already merges the parent chain, resolves `${properties}` and recursively expands
 * nested import BOMs), builds a g:a → version map, and fills it into the versionless
 * declared deps. Network + cached (poms-cache, immutable) + offline-aware (the caller
 * skips it offline). Pure except for the injected/real effectivePom fetch.
 */
const transitive = require("./transitive");
const core = require("./core");

/**
 * Walk each parsed pom's LOCAL parent chain and collect the distinct EXTERNAL parent
 * coordinates — the parent POMs referenced by a `<parent>` element but NOT present in
 * the source tree (e.g. `spring-boot-starter-parent`, whose own parent
 * `spring-boot-dependencies` holds the managed-version table). Maven inherits their
 * `<dependencyManagement>` into the child, which is how a versionless
 * `spring-boot-starter-actuator` gets its version — but core.js only follows LOCAL
 * parents, so without this those versions stay unresolved and drop out of the scan.
 *
 * Deduped by g:a:v; unresolved (`${…}`) or incomplete coords are skipped. The result
 * is fed to resolveBomManagedVersions/backfillVersions exactly like an import BOM.
 * @param store the metadata store (byPath[pom].parentInfo + byId), as built by core.js
 * @returns [{ groupId, artifactId, version }]
 */
function collectExternalParents(store) {
	if (!store || !store.byPath) return [];
	const seen = new Set();
	const out = [];
	for (const pomPath of Object.keys(store.byPath)) {
		let cur = pomPath;
		const localSeen = new Set();
		while (cur && !localSeen.has(cur)) {
			localSeen.add(cur);
			const meta = store.byPath[cur];
			if (!meta) break;
			const parentPath = core.resolveParentPath(cur, meta.parentInfo, store);
			if (parentPath) { cur = parentPath; continue; }   // local parent → keep climbing
			// No local parent POM: if a <parent> is declared, it's EXTERNAL.
			const p = meta.parentInfo;
			if (p && p.groupId && p.artifactId && p.version && !/\$\{/.test(String(p.version))) {
				const k = `${p.groupId}:${p.artifactId}:${p.version}`;
				if (!seen.has(k)) { seen.add(k); out.push({ groupId: p.groupId, artifactId: p.artifactId, version: p.version }); }
			}
			break;
		}
	}
	return out;
}

/**
 * Collect the version-property OVERRIDES a project declares in its own `<properties>`
 * blocks — the Maven mechanism for patching a coord managed by an external parent
 * (e.g. `<log4j2.version>2.17.1</log4j2.version>` overrides spring-boot-dependencies'
 * default). Fed to effectivePom as `propertyOverrides` so the parent's managed table
 * resolves to the version actually on the classpath, not the framework default.
 *
 * Source is each pom's OWN declared props (store.byPath[pom].properties, raw xml2js
 * `{name:[value]}`) — NOT the merged/inherited map — so we never mistake an inherited
 * builtin for an override. `project.*`/`pom.*` model expressions and unresolved `${…}`
 * values are excluded. Merged across modules (last wins); real-world overrides live in
 * the root and are consistent, so the common case is exact.
 * @returns { [propName]: value }
 */
function collectPropertyOverrides(store) {
	const out = {};
	if (!store || !store.byPath) return out;
	for (const meta of Object.values(store.byPath)) {
		const raw = meta && meta.properties;
		if (!raw || typeof raw !== "object") continue;
		for (const [k, val] of Object.entries(raw)) {
			if (k.startsWith("project.") || k.startsWith("pom.")) continue;
			const v = Array.isArray(val) ? val[0] : val;
			if (typeof v !== "string" || /\$\{/.test(v)) continue;
			out[k] = v;
		}
	}
	return out;
}

/** Custom version-property names used in local models, including profiles.
 * External parents are not available on a cold offline machine; conventional
 * version property names are also accepted by the descriptor's filter.
 */
function collectVersionPropertyNames(store) {
	const names = new Set(), seen = new WeakSet();
	function visit(value) {
		if (!value || typeof value !== "object" || seen.has(value)) return;
		seen.add(value);
		for (const [key, child] of Object.entries(value)) {
			if (key === "properties") continue;
			if (key === "version") {
				for (const match of String(child).matchAll(/\$\{([^}]+)\}/g)) names.add(match[1]);
			} else visit(child);
		}
	}
	visit(store?.byPath);
	return [...names];
}

/**
 * Extract the distinct external import-BOM coordinates from the parsed poms' merged
 * dependencyManagement. `version` is resolved against each pom's property map; entries
 * that stay unresolved (`${…}`) or lack a g/a are skipped.
 * @param propsByPom map pomPath → { properties, dependencyManagement } (xml2js-shaped)
 * @returns [{ groupId, artifactId, version }] deduped by g:a:v
 */
function collectImportBoms(propsByPom) {
	const seen = new Set();
	const out = [];
	for (const pom of Object.keys(propsByPom || {})) {
		const entry = propsByPom[pom];
		if (!entry) continue;
		const props = entry.properties || {};
		for (const d of (entry.dependencyManagement || [])) {
			if (d?.scope?.[0] !== "import") continue;
			const g = transitive.resolveProps(d.groupId?.[0], props);
			const a = transitive.resolveProps(d.artifactId?.[0], props);
			const v = transitive.resolveProps(d.version?.[0], props);
			if (!g || !a || !v || /\$\{/.test(String(v))) continue;
			const k = `${g}:${a}:${v}`;
			if (seen.has(k)) continue;
			seen.add(k);
			out.push({ groupId: g, artifactId: a, version: v });
		}
	}
	return out;
}

/**
 * Resolve each import BOM to its managed-version table and merge them into one map.
 * First BOM to manage a given g:a wins (mirrors Maven's declaration-order precedence).
 *
 * Each value is `{ version, bom }` where `bom` is the `groupId:artifactId:version` of the
 * TOP-LEVEL platform/import BOM that supplied the version (e.g. spring-boot-dependencies),
 * not the nested BOM it may import (spring-batch-bom) — that's the coordinate the user wrote
 * in `platform(...)`/`<scope>import</scope>` and recognizes. Carried so backfillVersions can
 * record per-dep provenance ("version managed by <bom>").
 */
async function resolveBomManagedVersions(boms, opts = {}) {
	const effectivePom = opts.effectivePom || transitive.effectivePom;
	// `via` labels where the managed version came from: "bom" (import BOM, the default)
	// or "parent" (an external <parent> chain). Only stamped when non-default so the
	// import-BOM entry shape stays byte-identical to before.
	const via = opts.via && opts.via !== "bom" ? opts.via : null;
	const map = new Map();
	for (const bom of boms) {
		let eff = null;
		try { eff = await effectivePom(bom.groupId, bom.artifactId, bom.version, opts); }
		catch { eff = null; }
		if (!eff || !eff.depMgmt) continue;
		const bomCoord = `${bom.groupId}:${bom.artifactId}:${bom.version}`;
		for (const d of eff.depMgmt) {
			if (!d.groupId || !d.artifactId) continue;
			const k = `${d.groupId}:${d.artifactId}`;
			if (map.has(k)) continue;
			if (d.version && !/\$\{/.test(String(d.version))) map.set(k, { version: String(d.version), bom: bomCoord, ...(via ? { via } : {}) });
		}
	}
	return map;
}

/**
 * Fill the version of every Maven dep that has no concrete version (null or `${…}`)
 * from the BOM-managed map. Mutates the resolvedDeps Map entries in place. Each filled
 * dep is stamped with `versionSource = { via: "bom", bom: "<coord>" }` so the report can
 * disclose that the version came from a BOM (e.g. "version managed by spring-boot-dependencies")
 * rather than the manifest it's declared in — the usual versionless Spring Boot / Gradle case.
 * @returns number of deps filled
 */
function backfillVersions(resolvedDeps, mgmtMap) {
	let filled = 0;
	for (const dep of resolvedDeps.values()) {
		if (dep.ecosystem !== "maven") continue;
		if (dep.provenance === "embedded" || dep.provenance === "binary") continue;
		if (dep.version && !/\$\{/.test(String(dep.version))) continue; // already concrete
		const entry = mgmtMap.get(`${dep.groupId}:${dep.artifactId}`);
		if (!entry) continue;
		const v = entry.version;
		dep.version = v;
		if (!Array.isArray(dep.versions)) dep.versions = [];
		if (!dep.versions.includes(v)) dep.versions.push(v);
		dep.versionSource = { via: entry.via || "bom", bom: entry.bom };
		filled++;
	}
	return filled;
}

/**
 * One-shot: collect external import BOMs from the poms, resolve their managed versions
 * online, and backfill the versionless declared deps.
 * @returns { boms, filled, mgmtSize }
 */
async function resolveAndBackfill(propsByPom, resolvedDeps, opts = {}) {
	const boms = collectImportBoms(propsByPom);
	if (!boms.length) return { boms: 0, filled: 0, mgmtSize: 0 };
	const map = await resolveBomManagedVersions(boms, opts);
	const filled = backfillVersions(resolvedDeps, map);
	return { boms: boms.length, filled, mgmtSize: map.size };
}

module.exports = { collectExternalParents, collectPropertyOverrides, collectVersionPropertyNames, collectImportBoms, resolveBomManagedVersions, backfillVersions, resolveAndBackfill };
