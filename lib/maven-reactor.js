/**
 * lib/maven-reactor.js — the Maven scan set, resolved MODULE BY MODULE.
 *
 * Maven never resolves "the reactor"; it resolves each module with that module's own
 * effective model: its local parent chain, its external <parent>, the BOMs it imports, the
 * <properties> of its own chain. fad used to resolve one merged tree for the whole scan root
 * (one global <dependencyManagement> = the highest version of every coord, every external
 * parent's managed table first-wins, every pom's property overrides applied everywhere) and
 * then patch the result with an additive per-module overlay. On a scan root holding several
 * projects that is wrong in both directions: project B's pins re-version project A's
 * transitives (false positives on versions no classpath holds) and hide project A's real
 * versions (false negatives); a depMgmt value a module overrides was still scanned as a
 * direct dependency of the pom that declared it.
 *
 * Here every module is resolved on its own, and the scan set is the UNION of what the
 * modules really hold:
 *   - its directs: own + inherited from the local parent chain (closest wins) + the
 *     <dependencies> of its external parent chain; the version from the declaration, else
 *     the module's managed version; the scope from the declaration, else the managed scope;
 *     exclusions declared ∪ managed; a version range resolved like Maven (highest published
 *     version inside it); <optional> directs included (optional only affects CONSUMERS);
 *   - its transitives, resolved against ITS managed versions/exclusions only.
 * The maven-codec records are then rebuilt from that union: `versions[]`, `versionPaths`
 * (version → declaring pom) and `maskedVersions[]` (version → resolving module, chain, scope —
 * what lib/attribution.js narrows each match with). A coordinate no module holds leaves the
 * scan set, whatever <dependencyManagement> mentions it.
 *
 * Gradle records (ecosystemType "gradle"), embedded and binary records are not touched.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const core = require("./core");
const { effectivePom, resolveTransitiveDeps, fetchMetadataVersions, managedKey } = require("./transitive");
const { resolveDepVersion } = require("./cve-match");
const { isVersionRange, resolveVersionRange, compareMavenVersions } = require("./maven-version");

const coord = core.coord;
const isConcrete = v => v != null && v !== "" && !/\$\{/.test(String(v)) && !isVersionRange(String(v));

function exclusionsOf(node, props) {
	return (node.exclusions?.[0]?.exclusion || []).map(e => ({
		groupId: resolveDepVersion(coord(e.groupId?.[0]) || "*", props),
		artifactId: resolveDepVersion(coord(e.artifactId?.[0]) || "*", props),
	}));
}

/** Local parent chain, child first, and the first EXTERNAL parent above it. */
function localChain(pomPath, store) {
	const chain = [];
	const seen = new Set();
	let cur = pomPath;
	let externalParent = null;
	while (cur && !seen.has(cur)) {
		seen.add(cur);
		chain.push(cur);
		const meta = store.byPath[cur];
		if (!meta) break;
		const parentPath = core.resolveParentPath(cur, meta.parentInfo, store);
		if (!parentPath) {
			const p = meta.parentInfo;
			if (p?.groupId && p?.artifactId && p?.version && !/\$\{/.test(String(p.version))) {
				externalParent = { groupId: p.groupId, artifactId: p.artifactId, version: p.version };
			}
			break;
		}
		cur = parentPath;
	}
	return { chain, externalParent };
}

/** The module's OWN chain's <properties> (child wins) — what overrides its external parent's. */
function chainPropertyOverrides(chain, store) {
	const out = {};
	for (const pom of [...chain].reverse()) {
		for (const [k, val] of Object.entries(store.byPath[pom]?.properties || {})) {
			if (k.startsWith("project.") || k.startsWith("pom.")) continue;
			const v = Array.isArray(val) ? val[0] : val;
			if (typeof v === "string" && !/\$\{/.test(v)) out[k] = v;
		}
	}
	return out;
}

/**
 * The module's effective <dependencyManagement>, with Maven's precedence:
 *   1. explicit entries of the local chain (closest wins; local import BOMs are expanded
 *      inline by core.getAllInheritedProps and count here);
 *   2. explicit entries of the external parent chain;
 *   3. EXTERNAL import BOMs declared in the local chain (first declared wins);
 *   4. what the external parent chain itself imported.
 * → Map<g:a, { version, scope, exclusions, source }>, source = { via, bom } for an external one.
 */
async function moduleManagement(chain, externalParent, store, propsByPom, opts) {
	const out = new Map();
	const setIf = (k, e) => { if (k && !out.has(k) && isConcrete(e.version)) out.set(k, e); };
	const externalBoms = [];
	for (const pom of chain) {
		const entry = propsByPom[pom];
		if (!entry) continue;
		const props = entry.properties || {};
		for (const node of entry.dependencyManagement || []) {
			const g = resolveDepVersion(coord(node.groupId?.[0]), props);
			const a = resolveDepVersion(coord(node.artifactId?.[0]), props);
			if (!g || !a) continue;
			const v = resolveDepVersion(coord(node.version?.[0]), props);
			if (node.scope?.[0] === "import") {
				const local = (v && store.byId[`${g}:${a}:${v}`]) || store.byId[`${g}:${a}`];
				if (!local && isConcrete(v)) externalBoms.push({ groupId: g, artifactId: a, version: v });
				continue;
			}
			const type = resolveDepVersion(coord(node.type?.[0]) || 'jar', props), classifier = resolveDepVersion(coord(node.classifier?.[0]) || '', props);
			setIf(managedKey({groupId:g,artifactId:a,type,classifier}), { version: v, scope: coord(node.scope?.[0]) || null, exclusions: exclusionsOf(node, props), source: null });
		}
	}
	const imported = [];
	if (externalParent) {
		const coordStr = `${externalParent.groupId}:${externalParent.artifactId}:${externalParent.version}`;
		let eff = null;
		try { eff = await effectivePom(externalParent.groupId, externalParent.artifactId, externalParent.version, { ...opts, propertyOverrides: chainPropertyOverrides(chain, store) }); } catch { eff = null; }
		for (const d of eff?.depMgmt || []) {
			const e = { version: d.version, scope: d.scopeDeclared ? d.scope : null, exclusions: d.exclusions || [], source: { via: "parent", bom: coordStr } };
			if (d.fromImport) imported.push([managedKey(d), e]);
			else setIf(managedKey(d), e);
		}
	}
	for (const bom of externalBoms) {
		const coordStr = `${bom.groupId}:${bom.artifactId}:${bom.version}`;
		let eff = null;
		try { eff = await effectivePom(bom.groupId, bom.artifactId, bom.version, opts); } catch { eff = null; }
		for (const d of eff?.depMgmt || []) setIf(managedKey(d), { version: d.version, scope: d.scopeDeclared ? d.scope : null, exclusions: d.exclusions || [], source: { via: "bom", bom: coordStr } });
	}
	for (const [k, e] of imported) setIf(k, e);
	return out;
}

/**
 * The module's direct dependencies, as Maven sees them in ITS model.
 * → [{ groupId, artifactId, version, scope, exclusions, declaredIn, versionSource }]
 */
async function moduleDirects(pomPath, chain, externalParent, mgmt, store, propsByPom, opts) {
	const props = propsByPom[pomPath]?.properties || {};
	const out = [];
	const seen = new Map();
	const add = async (d) => {
		const key = `${d.groupId}:${d.artifactId}`;
		if (opts.deps2Exclude && opts.deps2Exclude.test(d.groupId)) return;   // -e: private, never scanned
		if (/\$\{/.test(key)) return;
		if (seen.has(key)) {
			if (seen.get(key) !== managedKey(d)) opts.onVariantCollision?.({groupId:d.groupId,artifactId:d.artifactId});
			return;
		}
		seen.set(key, managedKey(d));
		const m = mgmt.get(managedKey(d));
		let version = d.version;
		let versionSource = null;
		if (!isConcrete(version) && !isVersionRange(String(version || ""))) {
			version = m?.version || null;
			versionSource = m?.source || null;
		}
		if (version && isVersionRange(String(version))) {
			version = resolveVersionRange(version, await fetchMetadataVersions(d.groupId, d.artifactId, opts));
		}
		const scope = d.scope || m?.scope || "compile";
		if (scope === "system" || scope === "import") return;
		if (scope === "test" && !opts.includeTestDeps) return;
		const ex = [...(d.exclusions || []), ...(m?.exclusions || [])];
		out.push({ groupId: d.groupId, artifactId: d.artifactId, version: isConcrete(version) ? String(version) : null,
			scope, exclusions: ex, type:d.type || 'jar', classifier:d.classifier || '', declaredIn: d.declaredIn, versionSource, optional: !!d.optional });
	};
	for (const pom of chain) {
		for (const node of propsByPom[pom]?.dependencies || []) {
			const g = resolveDepVersion(coord(node.groupId?.[0]), props);
			const a = resolveDepVersion(coord(node.artifactId?.[0]), props);
			if (!g || !a) continue;
			await add({ groupId: g, artifactId: a, version: resolveDepVersion(coord(node.version?.[0]), props) || null,
				scope: coord(node.scope?.[0]) || null, type:resolveDepVersion(coord(node.type?.[0]) || 'jar', props), classifier:resolveDepVersion(coord(node.classifier?.[0]) || '', props), exclusions: exclusionsOf(node, props),
				optional: node.optional?.[0] === "true", declaredIn: pom });
		}
	}
	// An EXTERNAL parent's own <dependencies> are inherited too (spark-parent / flink-parent
	// style). They used to be dropped: the parent was only scanned as a coordinate.
	if (externalParent) {
		let eff = null;
		try { eff = await effectivePom(externalParent.groupId, externalParent.artifactId, externalParent.version, { ...opts, propertyOverrides: chainPropertyOverrides(chain, store) }); } catch { eff = null; }
		for (const d of eff?.deps || []) {
			await add({ groupId: d.groupId, artifactId: d.artifactId, version: d.version || null,
				scope: d.scopeDeclared ? d.scope : null, type:d.type, classifier:d.classifier, exclusions: d.exclusions || [], optional: d.optional,
				declaredIn: pomPath, inheritedFrom: `${externalParent.groupId}:${externalParent.artifactId}:${externalParent.version}` });
		}
	}
	return out;
}

/** Resolve one module: { pomPath, directs, transitives }. */
async function resolveModule(pomPath, store, propsByPom, opts) {
	const { chain, externalParent } = localChain(pomPath, store);
	const mgmt = await moduleManagement(chain, externalParent, store, propsByPom, opts);
	const directs = await moduleDirects(pomPath, chain, externalParent, mgmt, store, propsByPom, opts);
	let transitives = new Map();
	if (opts.transitive !== false) {
		const rootDepMgmt = new Map([...mgmt].map(([k, e]) => [k, { version: e.version, exclusions: e.exclusions || [] }]));
		try {
			transitives = await resolveTransitiveDeps(directs.filter(d => d.version), {
				...opts,
				rootDepMgmt,
				maxDepth: opts.maxDepth || 6,
				includedScopes: opts.includeTestDeps ? ["compile", "runtime", "provided", "test"] : ["compile", "runtime", "provided"],
			});
		} catch {
			// Preserve a usable partial report, but never make a failed traversal
			// indistinguishable from a complete graph with no transitives.
			opts.onResolutionError?.();
			transitives = new Map();
		}
	}
	return { pomPath, directs, transitives };
}

const DEV_SCOPES = new Set(["test"]);

/**
 * Resolve every module and rebuild the maven-codec records of `resolved` from the union.
 * Mutates `resolved`. → { modules, dropped: [coord…] }
 *
 * opts: fetcher, cacheDir, repos, offline, verbose, maxDepth, includeTestDeps, transitive,
 *       effCache, makeRecord(input) (lib/dep-record#makeDepRecord)
 */
async function resolveReactor(resolved, store, propsByPom, opts = {}) {
	const { makeDepRecord } = require("./dep-record");
	const o = { ...opts, includeTestDeps: opts.includeTestDeps !== false, effCache: opts.effCache || new Map() };
	const isMavenCodec = r => r && r.ecosystem === "maven" && (r.ecosystemType || "maven") === "maven"
		&& r.provenance !== "embedded" && r.provenance !== "binary" && r.scope !== "parent";

	const results = [];
	for (const pomPath of Object.keys(propsByPom || {})) {
		if (!store.byPath[pomPath]) continue;
		results.push(await resolveModule(pomPath, store, propsByPom, o));
	}

	// Rebuild: the records keep their identity (other structures may hold them), only the
	// version bookkeeping is recomputed from what the modules really hold.
	const before = new Map();
	for (const [k, r] of resolved) {
		if (!isMavenCodec(r)) continue;
		before.set(k, { version: r.version });
		r.versions = [];
		// Same array object (dep-record invariant: pomPaths === manifestPaths), emptied: only
		// the poms that DECLARE the dependency go back in — a pom that merely manages its
		// version is not where it is defined.
		if (Array.isArray(r.manifestPaths)) r.manifestPaths.length = 0;
		r.versionPaths = {};
		r.versionScopes = {};
		r.maskedVersions = [];
		r._held = false;
		r._declared = false;
	}
	const ensure = (key, g, a, seed) => {
		let r = resolved.get(key);
		if (r && !isMavenCodec(r)) return null;      // a Gradle/embedded record of the same key: leave it
		if (!r) {
			r = makeDepRecord({ ecosystem: "maven", namespace: g, name: a, version: seed.version, manifestPath: seed.manifestPath || null, scope: seed.scope || "transitive", isDev: false });
			r.versions = []; r.versionPaths = {}; r.versionScopes = {}; r.maskedVersions = [];
			resolved.set(key, r);
		}
		return r;
	};
	const addVersion = (r, v) => { if (v && !r.versions.includes(v)) r.versions.push(v); };

	for (const { pomPath, directs, transitives } of results) {
		for (const d of directs) {
			const key = `${d.groupId}:${d.artifactId}`;
			const r = ensure(key, d.groupId, d.artifactId, { version: d.version, manifestPath: d.declaredIn, scope: d.scope });
			if (!r) continue;
			r._held = true;
			r._declared = true;
			if (!r.manifestPaths.includes(d.declaredIn)) r.manifestPaths.push(d.declaredIn);
			if (!d.version) continue;                      // declared, version unknown: chapter-0 warning
			addVersion(r, d.version);
			(r.versionPaths[d.version] ||= []).includes(d.declaredIn) || r.versionPaths[d.version].push(d.declaredIn);
			(r.versionScopes[d.version] ||= []).includes(d.scope) || r.versionScopes[d.version].push(d.scope);
			if (d.versionSource && !r.versionSource) r.versionSource = d.versionSource;
		}
		for (const [key, t] of transitives) {
			if (opts.deps2Exclude && opts.deps2Exclude.test(t.groupId)) continue;
			const r = ensure(key, t.groupId, t.artifactId, { version: t.version, scope: "transitive" });
			if (!r) continue;
			r._held = true;
			addVersion(r, t.version);
			if (!r.maskedVersions.some(x => x.version === t.version && x.module === pomPath)) {
				r.maskedVersions.push({ version: t.version, via: t.via, viaPaths: t.viaPaths, module: pomPath, depth: t.depth, scope: t.scope });
			}
		}
	}

	const dropped = [];
	for (const [key, r] of [...resolved]) {
		if (!isMavenCodec(r)) continue;
		const held = r._held;
		const declared = r._declared;
		delete r._held; delete r._declared;
		if (!held) {
			// Mentioned only by a <dependencyManagement> (or a pom no module resolves): on no
			// classpath. Leaves the scan set — no CVE against a jar no build ships.
			resolved.delete(key);
			dropped.push(`${key}${before.get(key)?.version ? ":" + before.get(key).version : ""}`);
			continue;
		}
		delete r.managedOnly;
		if (r.versions.length) r.version = [...r.versions].sort(compareMavenVersions).at(-1);
		else if (!declared) { resolved.delete(key); dropped.push(key); continue; }
		else r.version = null;
		if (declared) {
			const scopes = Object.values(r.versionScopes).flat();
			if (scopes.length) {
				r.isDev = scopes.every(s => DEV_SCOPES.has(s));
				r.scope = scopes.find(s => s === "compile") || scopes.find(s => s === "runtime") || scopes[0];
			}
			// A declared coord also reached transitively elsewhere keeps its declarations as
			// the record's identity; the transitive versions travel in maskedVersions.
		} else {
			const first = r.maskedVersions.find(x => !DEV_SCOPES.has(x.scope)) || r.maskedVersions[0];
			r.scope = "transitive";
			r.isDev = r.maskedVersions.every(x => DEV_SCOPES.has(x.scope));
			r.via = first.via;
			r.viaPaths = first.viaPaths;
			r.depth = first.depth;
			const mods = [...new Set(r.maskedVersions.map(x => x.module))];
			r.manifestPaths.length = 0;
			r.manifestPaths.push(...mods);
			if (r.pomPaths !== r.manifestPaths) r.pomPaths = r.manifestPaths;
		}
		if (!r.maskedVersions.length) delete r.maskedVersions;
	}
	return { modules: results.length, dropped };
}

module.exports = { resolveReactor, resolveModule, moduleManagement, moduleDirects, localChain, chainPropertyOverrides };
