/**
 * lib/transitive.js — resolve transitive dependencies for a set of direct deps
 * by walking POMs fetched from Maven Central.
 *
 * Implements a pragmatic subset of Maven's resolution rules:
 *   - parent POM chain (recursive)
 *   - <dependencyManagement> from parent + BOM imports (scope=import)
 *   - property substitution with project.version / project.groupId
 *   - scope propagation: compile/runtime/provided → compile/runtime/provided,
 *     test → not propagated, system → not propagated
 *   - <exclusion> blocks
 *   - <optional>true</optional> stops propagation
 *   - nearest-wins dependency mediation (BFS guarantees this naturally)
 *   - root-level dependencyManagement overrides transitive versions
 *
 * Out of scope (for simplicity / accuracy tradeoff):
 *   - <profile> activation inside transitive POMs (assumed dormant)
 *   - <relocation> handling (rare in modern artifacts)
 *   - non-central repositories (everything fetched from repo1.maven.org)
 *   - SNAPSHOT version resolution (we just return the literal version)
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { parseStringPromise } = require("xml2js");
const { normalizeHardPin, isVersionRange, resolveVersionRange, compareMavenVersions } = require("./maven-version");

const POM_CACHE_DIR = path.join(require("./cache-directory").getCacheDir(), "poms-cache");
const MAVEN_CENTRAL = "https://repo1.maven.org/maven2";

// Maven's scope-propagation matrix (rows: direct dep scope, cols: transitive scope)
// Value is the resulting scope for the transitive, or null = not included.
const SCOPE_MATRIX = {
	compile:  { compile: "compile",  provided: null,        runtime: "runtime", test: null, system: null },
	provided: { compile: "provided", provided: null,        runtime: "provided", test: null, system: null },
	runtime:  { compile: "runtime",  provided: null,        runtime: "runtime", test: null, system: null },
	test:     { compile: "test",     provided: null,        runtime: "test",    test: null, system: null },
};

function coord(v) { return v == null ? null : String(v).trim() || null; }

function pomPath(g, a, v) {
	const gPath = g.replace(/\./g, "/");
	return `${MAVEN_CENTRAL}/${gPath}/${a}/${v}/${a}-${v}.pom`;
}

function cachePath(g, a, v, dir = POM_CACHE_DIR) {
	// One path segment, always: a coordinate comes from a scanned repository and must not be
	// able to walk out of the cache dir (see lib/osv.js#cacheKey, where a URL-as-version did
	// exactly that). The allowed set covers every well-formed Maven coord, so warm caches
	// written before this are still found.
	const seg = x => String(x == null ? "" : x).replace(/[^A-Za-z0-9._+-]/g, "%");
	return path.join(dir, `${seg(g)}__${seg(a)}__${seg(v)}.pom`);
}

async function fetchPom(g, a, v, opts = {}) {
	const { verbose, offline, fetcher = globalThis.fetch, cacheDir = POM_CACHE_DIR, repos } = opts;
	const cf = cachePath(g, a, v, cacheDir);
	if (fs.existsSync(cf)) {
		const xml = await fs.promises.readFile(cf, "utf8");
		if (xml === "__NOT_FOUND__") return null;
		return xml;
	}
	if (offline) return null;
	// Multi-repo path: try every user-configured repo, fall back to Maven
	// Central via lib/maven-repo. Falling back to the legacy single-URL
	// fetch only when no repos array is passed (keeps existing tests green).
	if (Array.isArray(repos)) {
		try {
			const { fetchPomFromRepos } = require("./maven-repo");
			const hit = await fetchPomFromRepos(repos, g, a, v, { fetcher, userAgent: "vigievuln-transitive" });
			if (hit?.body) {
				await fs.promises.mkdir(cacheDir, { recursive: true });
				await fs.promises.writeFile(cf, hit.body);
				return hit.body;
			}
			await fs.promises.mkdir(cacheDir, { recursive: true });
			await fs.promises.writeFile(cf, "__NOT_FOUND__");
			if (verbose) console.warn(`   not found in any repo: ${g}:${a}:${v}`);
			return null;
		} catch (err) {
			if (verbose) console.warn(`   multi-repo fetch failed: ${g}:${a}:${v} — ${err.message}`);
			return null;
		}
	}
	const url = pomPath(g, a, v);
	try {
		const res = await require("./providers").getResource("maven", "artifact",
			{ path: `${g.replace(/\./g, "/")}/${a}/${v}/${a}-${v}.pom` },
			{ fetcher, headers: { "User-Agent": "vigievuln-transitive" } });
		if (res.status === 404) {
			await fs.promises.mkdir(cacheDir, { recursive: true });
			await fs.promises.writeFile(cf, "__NOT_FOUND__");
			if (verbose) console.warn(`   404: ${g}:${a}:${v}`);
			return null;
		}
		if (!res.ok) {
			if (verbose) console.warn(`   HTTP ${res.status}: ${g}:${a}:${v}`);
			return null;
		}
		const xml = await res.text();
		await fs.promises.mkdir(cacheDir, { recursive: true });
		await fs.promises.writeFile(cf, xml);
		return xml;
	} catch (err) {
		if (verbose) console.warn(`   fetch failed: ${g}:${a}:${v} — ${err.message}`);
		return null;
	}
}

/**
 * Parse a POM XML into a minimal descriptor.
 * Returns: { groupId, artifactId, version, parent, properties, deps, depMgmt }
 *   parent : { groupId, artifactId, version } | null
 *   deps   : array of { groupId, artifactId, version, scope, optional, exclusions: [{g,a}] }
 *   depMgmt: same shape as deps
 *   properties: { key: value }  (no resolution yet)
 */
async function parsePomXml(xml) {
	let json;
	try { json = await parseStringPromise(xml); }
	catch { return null; }
	const project = json?.project || {};
	const parent = project.parent?.[0];
	const parentRef = parent ? {
		groupId: coord(parent.groupId?.[0]),
		artifactId: coord(parent.artifactId?.[0]),
		version: coord(parent.version?.[0]),
	} : null;

	const groupId = coord(project.groupId?.[0]) || parentRef?.groupId || null;
	const artifactId = coord(project.artifactId?.[0]);
	const version = coord(project.version?.[0]) || parentRef?.version || null;

	const properties = {};
	const propsNode = project.properties?.[0];
	if (propsNode && typeof propsNode !== "string") {
		for (const [k, v] of Object.entries(propsNode)) {
			properties[k] = Array.isArray(v) ? v[0] : v;
		}
	}

	const readDeps = (depsBlock) => {
		if (!depsBlock?.dependency) return [];
		return depsBlock.dependency.map(d => ({
			groupId: coord(d.groupId?.[0]),
			artifactId: coord(d.artifactId?.[0]),
			version: normalizeHardPin(coord(d.version?.[0])),
			scope: coord(d.scope?.[0]) || "compile",
			// Whether the POM SAYS the scope. An absent <scope> takes the managed one (Maven's
			// dependencyManagement injection), which "compile" as a default would hide.
			scopeDeclared: !!coord(d.scope?.[0]),
			optional: d.optional?.[0] === "true",
			type: coord(d.type?.[0]) || "jar",
			exclusions: (d.exclusions?.[0]?.exclusion || []).map(e => ({
				groupId: coord(e.groupId?.[0]),
				artifactId: coord(e.artifactId?.[0]),
			})),
		})).filter(d => d.groupId && d.artifactId);
	};

	return {
		groupId, artifactId, version,
		parent: parentRef,
		properties,
		deps: readDeps(project.dependencies?.[0]),
		depMgmt: readDeps(project.dependencyManagement?.[0]?.dependencies?.[0]),
	};
}

/**
 * Resolve ${prop} substitutions in a string using a properties map.
 * Implements project.groupId/artifactId/version as built-ins.
 * Loops if a property references another property.
 */
function resolveProps(value, props, builtins, depth = 0) {
	if (value == null || depth > 10) return value;
	const out = String(value).replace(/\$\{\s*([\w._-]+)\s*\}/g, (m, k) => {
		if (builtins && Object.prototype.hasOwnProperty.call(builtins, k)) return builtins[k];
		if (props && Object.prototype.hasOwnProperty.call(props, k)) return resolveProps(props[k], props, builtins, depth + 1);
		return m;
	});
	return out;
}

/**
 * Build the "effective" POM for a g:a:v by walking the parent chain.
 * Merges properties, depMgmt, and deps (child overrides parent).
 * BOM imports inside depMgmt are recursively expanded.
 */
async function effectivePom(g, a, v, opts = {}, seen = new Set()) {
	// A downstream project inheriting this POM as its <parent> can override a version
	// property in its own <properties> (the Spring Boot way to patch a managed coord).
	// opts.propertyOverrides models that: they win over this chain's own property values
	// when resolving depMgmt. They're part of the cache key so an override-free resolution
	// (import-BOM path) and an overridden one (parent path) don't collide in effCache.
	const ovKeys = opts.propertyOverrides ? Object.keys(opts.propertyOverrides) : [];
	const ovSuffix = ovKeys.length ? "|ov:" + ovKeys.sort().map(k => `${k}=${opts.propertyOverrides[k]}`).join(",") : "";
	const key = `${g}:${a}:${v}${ovSuffix}`;
	if (seen.has(key)) return null;
	// Opt-in cross-call memo (used by the per-module overlay, which resolves the
	// same shared parents/BOMs once per module). Immutable POMs → the effective
	// result for a g:a:v is stable, so caching the finished object is safe; callers
	// only READ eff.depMgmt/eff.deps. Only active when opts.effCache is supplied,
	// so existing single-shot callers are byte-for-byte unchanged.
	if (opts.effCache && opts.effCache.has(key)) return opts.effCache.get(key);
	seen.add(key);

	const xml = await fetchPom(g, a, v, opts);
	if (!xml) { if (opts.effCache) opts.effCache.set(key, null); return null; }
	const pom = await parsePomXml(xml);
	if (!pom) { if (opts.effCache) opts.effCache.set(key, null); return null; }

	let merged = {
		groupId: pom.groupId,
		artifactId: pom.artifactId,
		version: pom.version,
		properties: { ...pom.properties },
		depMgmt: [...pom.depMgmt],
		deps: [...pom.deps],
	};

	if (pom.parent) {
		const parentEff = await effectivePom(pom.parent.groupId, pom.parent.artifactId, pom.parent.version, opts, seen);
		if (parentEff) {
			merged.properties = { ...parentEff.properties, ...merged.properties };
			merged.parentVersion = parentEff.version;
			merged.parentGroupId = parentEff.groupId;
			merged.parentArtifactId = parentEff.artifactId;
			// The parent's effective depMgmt keeps its `fromImport` marks: an entry the parent
			// declared explicitly still beats this POM's imported BOMs, one it only imported
			// does not (precedence settled below).
			merged.depMgmt = [...parentEff.depMgmt.map(d => ({ ...d, inherited: true })), ...merged.depMgmt];
			// Maven inherits the parent's <dependencies>, but a child that REDECLARES one
			// overrides it: concatenating both let the BFS pick the parent's first (a
			// child pinning X:2.0 over an inherited X:1.0 resolved as 1.0).
			const own = new Set(merged.deps.map(d => `${d.groupId}:${d.artifactId}`));
			merged.deps = [...parentEff.deps.filter(d => !own.has(`${d.groupId}:${d.artifactId}`)), ...merged.deps];
		}
	}

	// Resolve property references in depMgmt and deps now that the property map
	// is finalised (child + parent merged).
	const builtins = {
		"project.groupId": merged.groupId,
		"project.artifactId": merged.artifactId,
		"project.version": merged.version,
		"pom.groupId": merged.groupId,
		"pom.artifactId": merged.artifactId,
		"pom.version": merged.version,
		// ${project.parent.version} pins sibling modules in many multi-module projects; left
		// unresolved, the dependency was dropped (a false negative).
		"project.parent.version": merged.parentVersion || pom.parent?.version,
		"project.parent.groupId": merged.parentGroupId || pom.parent?.groupId,
		"project.parent.artifactId": merged.parentArtifactId || pom.parent?.artifactId,
		"parent.version": merged.parentVersion || pom.parent?.version,
	};
	// Child overrides win over this chain's own property values (Maven: a child's
	// <properties> override an inherited parent's). Applies to the PARENT chain only —
	// import-BOM managed versions resolve in the BOM's own context (stripped below).
	const effProps = ovKeys.length ? { ...merged.properties, ...opts.propertyOverrides } : merged.properties;
	const resolveDep = d => ({
		...d,
		groupId: resolveProps(d.groupId, effProps, builtins),
		artifactId: resolveProps(d.artifactId, effProps, builtins),
		version: normalizeHardPin(resolveProps(d.version, effProps, builtins)),
	});
	merged.depMgmt = merged.depMgmt.map(resolveDep);
	merged.deps = merged.deps.map(resolveDep);

	// Expand BOM imports inside depMgmt: any entry with scope=import + type=pom
	// is replaced by the depMgmt entries from that imported POM. A <scope>import</scope>
	// BOM resolves its managed versions in ITS OWN property context — the importing
	// project's overrides do NOT reach it — so drop propertyOverrides across this boundary.
	//
	// Precedence (Maven): an EXPLICIT entry — this POM's, or one inherited from a parent that
	// declared it explicitly — beats any imported BOM; among imports, the FIRST declared wins.
	// The previous last-wins pass let a later import override both. Each key appears once in
	// the result, so buildMgmt's last-wins has nothing left to get wrong.
	const importOpts = ovKeys.length ? { ...opts, propertyOverrides: undefined } : opts;
	const keyOf = d => `${d.groupId}:${d.artifactId}`;
	const explicit = new Map();                 // later (child) entries override earlier (parent)
	for (const dm of merged.depMgmt) if (dm.scope !== "import" && !dm.fromImport) explicit.set(keyOf(dm), dm);
	const result = new Map(explicit);
	for (const dm of merged.depMgmt) {          // own imports, in declaration order — first wins
		if (dm.scope !== "import" || dm.inherited) continue;
		const imported = await effectivePom(dm.groupId, dm.artifactId, dm.version, importOpts, new Set(seen));
		for (const e of imported?.depMgmt || []) if (!result.has(keyOf(e))) result.set(keyOf(e), { ...e, fromImport: true });
	}
	for (const dm of merged.depMgmt) {          // what an ancestor imported comes after
		if (dm.fromImport && dm.inherited && !result.has(keyOf(dm))) result.set(keyOf(dm), dm);
		if (dm.scope === "import" && dm.inherited) {
			const imported = await effectivePom(dm.groupId, dm.artifactId, dm.version, importOpts, new Set(seen));
			for (const e of imported?.depMgmt || []) if (!result.has(keyOf(e))) result.set(keyOf(e), { ...e, fromImport: true });
		}
	}
	merged.depMgmt = [...result.values()].map(d => { const { inherited, ...rest } = d; return rest; });

	if (opts.effCache) opts.effCache.set(key, merged);
	return merged;
}

/**
 * Build a map of managed versions from a list of depMgmt entries.
 * Keyed by "g:a"; value is the entry (we use its version + scope).
 */
function buildMgmt(depMgmt) {
	const m = new Map();
	for (const d of depMgmt) {
		if (d.groupId && d.artifactId) m.set(`${d.groupId}:${d.artifactId}`, d);
	}
	return m;
}

// Scope breadth, for Maven's "the widest scope wins" when one coordinate is reached by
// several paths (JavaScopeSelector): compile > runtime > provided > test.
const SCOPE_BREADTH = { compile: 4, runtime: 3, provided: 2, test: 1 };
const wider = (a, b) => (SCOPE_BREADTH[a] || 0) > (SCOPE_BREADTH[b] || 0);

const METADATA_TTL_MS = 24 * 3600 * 1000;
/**
 * Every published version of g:a (maven-metadata.xml), to resolve a version RANGE the way
 * Maven does: the highest version inside it. Cached beside the POMs; 24 h online, any age
 * offline (a warm cache is the only source there), never blocks.
 */
async function fetchMetadataVersions(g, a, opts = {}) {
	const { offline, fetcher = globalThis.fetch, cacheDir = POM_CACHE_DIR, repos } = opts;
	const seg = x => String(x == null ? "" : x).replace(/[^A-Za-z0-9._+-]/g, "%");
	// Maven Central's list and the configured repositories' list are cached apart: a vendor
	// repository answering first lists builds Central does not have, and "absent from
	// Central" is exactly what identifies a commercial build (lib/commercial-support.js).
	const cf = path.join(cacheDir, `${seg(g)}__${seg(a)}__maven-metadata${Array.isArray(repos) && repos.length ? "-repos" : ""}.xml`);
	const parse = xml => [...String(xml).matchAll(/<version>([^<]+)<\/version>/g)].map(m => m[1].trim()).filter(Boolean);
	try {
		const st = fs.statSync(cf);
		if (offline || (!require("./providers").hasHostedProxy() && Date.now() - st.mtimeMs < METADATA_TTL_MS)) return parse(fs.readFileSync(cf, "utf8"));
	} catch { /* not cached */ }
	if (offline) return [];
	let body = null;
	try {
		if (Array.isArray(repos)) {
			const hit = await require("./maven-repo").fetchMavenMetadata(repos, g, a, { fetcher });
			body = hit?.body || null;
		} else {
			const res = await require("./providers").getResource("maven", "artifact",
				{ path: `${g.replace(/\./g, "/")}/${a}/maven-metadata.xml` }, { fetcher, headers: { "User-Agent": "vigievuln-transitive" } });
			if (res.ok) body = await res.text();
		}
	} catch { body = null; }
	if (!body) return [];
	try { fs.mkdirSync(cacheDir, { recursive: true }); fs.writeFileSync(cf, body); } catch { /* cache is best-effort */ }
	return parse(body);
}

/** Map over `items` with at most `limit` in flight, results in INPUT order. */
async function mapLimit(items, limit, fn) {
	const out = new Array(items.length);
	let next = 0;
	await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
		while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); }
	}));
	return out;
}

/**
 * BFS the transitive graph from a set of root deps, with Maven's mediation:
 *
 *   - NEAREST WINS, then FIRST DECLARED: the graph is walked LEVEL BY LEVEL, and within a
 *     level in declaration order. POMs of one level are fetched in parallel, but the
 *     results are applied in order. The previous worker pool claimed a coordinate when
 *     the first POM *arrived*, so the version depended on network latency: A→C→D:3.0
 *     (depth 3) beat B→D:2.0 (depth 2) whenever B's POM was slower — non-deterministic,
 *     and wrong, which also broke --baseline / --fail-on-new.
 *   - The WINNER keeps its version; a later path with a WIDER scope only widens the scope
 *     (and that widening is re-propagated to the winner's subtree), like Maven's
 *     JavaScopeSelector. Adopting the later path's version (what this did before) reported
 *     a version Maven had discarded as a conflict loser, and lost the real one.
 *   - Version: the root's managed pin > the declared version > the POM's own managed one; a
 *     version RANGE resolves to the highest published version inside it (metadata).
 *   - A dependency with no <scope>/<exclusions> takes the POM's managed ones.
 *
 * rootDepMgmt — Map<g:a, { version, exclusions? } | "version">
 * Returns Map<g:a, { groupId, artifactId, version, scope, depth, via, viaPaths }>, the
 * directs EXCLUDED (the caller has those).
 */
async function resolveTransitiveDeps(directDeps, opts = {}) {
	const {
		rootDepMgmt = new Map(),
		maxDepth = 6,
		verbose = false,
		offline = false,
		includedScopes = ["compile", "runtime", "provided"],
		concurrency = 8,
		fetcher,                    // optional injected fetch (used by tests)
		cacheDir,                   // optional override of disk cache dir (used by tests)
		repos,                      // optional repo list (lib/maven-repo). Falls back to repo1.maven.org alone.
		effCache,
	} = opts;
	const fetchOpts = { verbose, offline, fetcher, cacheDir, repos, ...(effCache ? { effCache } : {}) };

	// A managed entry is `{ version, exclusions? }` (global pass) or a bare version string
	// (per-module management). Reading `.version` off a string gave
	// `undefined` and the child was silently SKIPPED — every transitive a module pins (a
	// netty-bom import, a <dependencyManagement> override) vanished from the overlay.
	const managed = key => {
		const m = rootDepMgmt.get(key);
		if (m == null) return null;
		return typeof m === "string" ? { version: m, exclusions: [] } : { version: m.version, exclusions: m.exclusions || [], minimum: !!m.minimum };
	};
	const concrete = async (g, a, v) => {
		if (!v) return null;
		if (isVersionRange(v)) return resolveVersionRange(v, await fetchMetadataVersions(g, a, fetchOpts));
		return /\$\{/.test(v) ? null : v;
	};

	const visited = new Set();
	const out = new Map();
	let level = [];
	for (const dep of directDeps) {
		if (!dep.groupId || !dep.artifactId || !dep.version) continue;
		const v = await concrete(dep.groupId, dep.artifactId, dep.version);
		if (!v) continue;
		level.push({
			groupId: dep.groupId, artifactId: dep.artifactId, version: v,
			scope: dep.scope || "compile", depth: 0, via: [],
			// Maven applies a <dependencyManagement> entry's <exclusions> to the managed dep
			// wherever it appears, on top of the ones declared on the dependency itself.
			rootExclusions: [...(dep.exclusions || []), ...(managed(`${dep.groupId}:${dep.artifactId}`)?.exclusions || [])],
		});
		visited.add(`${dep.groupId}:${dep.artifactId}`);
	}

	const widened = [];
	for (let depth = 0; level.length && depth < maxDepth; depth++) {
		const effs = await mapLimit(level, concurrency, n =>
			effectivePom(n.groupId, n.artifactId, n.version, fetchOpts).catch(() => null));
		const next = [];
		for (let i = 0; i < level.length; i++) {
			const node = level[i];
			const eff = effs[i];
			if (!eff) continue;
			const mgmt = buildMgmt(eff.depMgmt);
			const nodeKey = `${node.groupId}:${node.artifactId}`;
			for (const dep of eff.deps) {
				if (!dep.groupId || !dep.artifactId) continue;
				if (dep.optional) continue;
				const childKey = `${dep.groupId}:${dep.artifactId}`;

				// Exclusion check against ancestors
				if (node.rootExclusions?.some(e =>
					(!e.groupId || e.groupId === dep.groupId || e.groupId === "*") &&
					(!e.artifactId || e.artifactId === dep.artifactId || e.artifactId === "*"))) continue;

				// Maven's dependencyManagement injection: a dependency that declares no <scope>
				// takes the scope its POM's (inherited) <dependencyManagement> gives it, and one
				// that declares no <exclusions> takes the managed ones. uadetector-resources
				// declares logback-classic bare, its parent manages it <scope>test</scope> —
				// read as compile, logback-classic:1.1.2 landed on a production classpath it is
				// not on, with a CRITICAL.
				const own = mgmt.get(childKey);
				const depScope = dep.scopeDeclared === false && own?.scope && own.scope !== "import" ? own.scope : (dep.scope || "compile");
				const depExclusions = (dep.exclusions && dep.exclusions.length) ? dep.exclusions : (own?.exclusions || []);

				const propagated = SCOPE_MATRIX[node.scope]?.[depScope];
				if (!propagated || !includedScopes.includes(propagated)) continue;

				const via = [...node.via, nodeKey];
				if (visited.has(childKey)) {
					// Already mediated (nearer, or same depth and declared earlier): the winner
					// keeps its version. Record the alternate chain; widen the scope if needed.
					const existing = out.get(childKey);
					if (existing) {
						const sig = via.join("→");
						if (!existing.viaPaths.some(p => p.join("→") === sig)) existing.viaPaths.push(via);
						if (wider(propagated, existing.scope)) { existing.scope = propagated; widened.push(childKey); }
					}
					continue;
				}

				// Version: root pin > declared > the POM's own managed version.
				const pinned = managed(childKey);
				let resolvedVersion = (pinned && pinned.version) || dep.version || (own && own.version) || null;
				// A floor (a Gradle constraint), not a force: the requested version wins when higher.
				if (pinned?.minimum && dep.version && !isVersionRange(dep.version) && !/\$\{/.test(dep.version)
					&& compareMavenVersions(dep.version, pinned.version) > 0) resolvedVersion = dep.version;
				resolvedVersion = await concrete(dep.groupId, dep.artifactId, resolvedVersion);
				if (!resolvedVersion) continue;

				visited.add(childKey);
				out.set(childKey, {
					groupId: dep.groupId,
					artifactId: dep.artifactId,
					version: resolvedVersion,
					scope: propagated,
					depth: node.depth + 1,
					via,
					viaPaths: [via],
					declScope: depScope,
					parentKey: nodeKey,
				});
				next.push({
					groupId: dep.groupId, artifactId: dep.artifactId, version: resolvedVersion,
					scope: propagated, depth: node.depth + 1, via,
					rootExclusions: [...(node.rootExclusions || []), ...depExclusions, ...(pinned?.exclusions || [])],
				});
			}
		}
		level = next;
		if (verbose && process.stdout.isTTY) process.stdout.write(`\r   resolved ${out.size} transitives, depth ${depth + 1}          `);
	}

	// A widened winner widens its subtree too (Maven re-derives the children's scope from the
	// winner's). Entries in depth order, so a parent is settled before its children.
	if (widened.length) {
		const byDepth = [...out.values()].sort((x, y) => x.depth - y.depth);
		for (const e of byDepth) {
			const parent = out.get(e.parentKey);
			if (!parent) continue;
			const s = SCOPE_MATRIX[parent.scope]?.[e.declScope];
			if (s && wider(s, e.scope)) e.scope = s;
		}
	}
	for (const e of out.values()) { delete e.declScope; delete e.parentKey; }

	if (verbose && process.stdout.isTTY) process.stdout.write(`\r   resolved ${out.size} transitives                              \n`);
	else if (verbose && out.size) console.log(`   resolved ${out.size} transitives`);
	return out;
}

module.exports = {
	pomCachePath: cachePath,   // exported so the one-path-segment invariant is testable
	resolveTransitiveDeps,
	fetchMetadataVersions,
	effectivePom,
	parsePomXml,
	fetchPom,
	resolveProps,
	buildMgmt,
	POM_CACHE_DIR,
	SCOPE_MATRIX,
};
