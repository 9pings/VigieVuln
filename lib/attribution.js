/**
 * lib/attribution.js — attribute each MATCH to the manifest/module that actually
 * resolves the version it was matched on.
 *
 * A depRecord is COORD-WIDE: the collectors merge every occurrence of a g:a across the
 * whole scan root into ONE record, so `versions[]` and `manifestPaths[]` are both
 * coord-wide sets with no link between them, and `scope` is a single merged value. A
 * MATCH, by contrast, carries exactly ONE version (matchOne clones the record per
 * version). Left alone that clone inherits the coord-wide manifest list and the merged
 * scope — so every version is reported against every manifest holding the coord.
 *
 * Invisible on a single reactor; wrong on the real-world shape fad is pointed at: an
 * audit root holding SEVERAL INDEPENDENT projects (each pom with its own external
 * parent, no shared reactor). Project A pins jackson-databind 2.15.3, project B pins
 * 2.17.0 → both projects get reported as holding BOTH versions, and each version's CVEs
 * land on both. Same class of error for a version the per-module overlay recovered: it
 * is a TRANSITIVE of one module, not the direct declaration the record describes —
 * unattributed it tops the exec summary's "direct production dependencies" pointing at
 * the very pom that pins the fixed version.
 *
 * Two provenance sources, checked per match:
 *   - `maskedVersions[]` (lib/maven-reactor) — the version is a transitive of ONE
 *     module: re-stamp scope/via/depth and file it under that module.
 *   - `versionPaths{}` (lib/dep-record, maintained by the collectors) — the version is
 *     DECLARED in a known subset of manifests: narrow the match to that subset.
 * A version with neither (e.g. a global-pass transitive) is left untouched.
 *
 * Runs ONCE, after every match source is merged (CVE index, OSV, snyk) and before
 * anything reads scope/paths (exec summary, charts, chapters, exports, gate).
 * Pure w.r.t. the scan set: replaces `m.dep` with a clone, never mutating the shared
 * record — other matches still reference it.
 */

/** manifestPaths and pomPaths must stay the SAME array (dep-record.js invariant). */
function withPaths(dep, paths) {
	const p = paths.slice();
	return { ...dep, manifestPaths: p, pomPaths: p };
}

function sameList(a, b) {
	const x = a || [], y = b || [];
	return x.length === y.length && x.every((v, i) => v === y[i]);
}

/**
 * @param matches the merged match set (mutated: each m.dep may be replaced by a clone)
 * @returns number of matches re-attributed
 */
function attributeMatchOrigins(matches) {
	let fixed = 0;
	for (const m of matches || []) {
		const dep = m && m.dep;
		if (!dep || !dep.version) continue;
		const ver = String(dep.version);

		// A DECLARED version always wins over a transitive provenance for the same version.
		// The overlay may legitimately also reach it as a transitive of some other module, but
		// a manifest that writes `<version>` for a coord is the authority on that version.
		// Without this precedence, xstream:1.4.10 — declared outright in
		// dubbo-registry-eureka — was re-stamped from a test-scoped transitive provenance in
		// dubbo-config-api and demoted out of production.
		const declaredHere = dep.versionPaths && dep.versionPaths[ver];
		const isDeclared = Array.isArray(declaredHere) && declaredHere.length > 0;

		// 1. Recovered by the per-module overlay → a transitive of ONE module.
		// ALL entries for this version, not the first: the same version is routinely masked in
		// several modules, and they can disagree on scope. On Dubbo, jackson-databind:2.10.4 is
		// test-scoped in dubbo-config-spring but COMPILE-scoped in dubbo-configcenter-nacos —
		// taking whichever entry happened to be recorded first would call it dev and drop a
		// genuine production finding out of the count and out of --fail-on.
		const maskedAll = !isDeclared && Array.isArray(dep.maskedVersions)
			? dep.maskedVersions.filter(x => String(x.version) === ver)
			: [];
		if (maskedAll.length) {
			// Dev only when EVERY module resolving this version does so at test scope. Entries
			// written before the overlay recorded scope have none — treat those as unknown and
			// leave the coord-wide flag alone rather than guessing.
			const scoped = maskedAll.filter(x => x.scope);
			const isDev = scoped.length === maskedAll.length && scoped.every(x => x.scope === "test");
			// Show the production path when there is one: it is the chain an auditor must act on.
			const masked = maskedAll.find(x => x.scope && x.scope !== "test") || maskedAll[0];
			const modules = [...new Set(maskedAll.map(x => x.module).filter(Boolean))];
			m.dep = {
				...withPaths(dep, modules),
				scope: "transitive",
				via: masked.via || [],
				viaPaths: masked.viaPaths || (masked.via ? [masked.via] : []),
				depth: masked.depth,
				...(scoped.length ? { isDev } : {}),
			};
			fixed++;
			continue;
		}

		// 2. Declared → narrow to the manifest(s) that declare THIS version, and take the
		// scope from those declarations. `isDev` on the record is coord-wide, so a version
		// declared only at test scope would otherwise inherit the coordinate's production
		// flag. Dev only when EVERY declaration of this version is test/dev — the same
		// widest-wins rule the masked branch uses.
		const declared = dep.versionPaths && dep.versionPaths[ver];
		if (Array.isArray(declared) && declared.length) {
			const scopes = dep.versionScopes && dep.versionScopes[ver];
			const isDev = Array.isArray(scopes) && scopes.length
				? scopes.every(s => s === "test" || s === "dev")
				: undefined;
			const narrow = !sameList(declared, dep.manifestPaths);
			const occurrences = Array.isArray(dep.occurrences)
				? dep.occurrences.filter(o => String(o.version) === ver) : undefined;
			if (narrow || (isDev !== undefined && isDev !== !!dep.isDev) ||
				(occurrences && occurrences.length !== dep.occurrences.length)) {
				m.dep = { ...withPaths(dep, declared),
					...(isDev !== undefined ? { isDev } : {}),
					...(occurrences ? { occurrences } : {}),
					// One record per name across lockfiles: when this version has a single
					// declared scope, it is THIS version's scope (npm: ms@1 dev-only, ms@2 prod).
					...((dep.ecosystem === "composer" || dep.ecosystem === "npm") && scopes?.length === 1 ? { scope: scopes[0] } : {}),
				};
				fixed++;
			}
		}
	}
	return fixed;
}

module.exports = { attributeMatchOrigins };
