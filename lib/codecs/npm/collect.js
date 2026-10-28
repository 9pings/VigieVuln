/**
 * lib/npm/collect.js — walk a JS project root, parse every manifest /
 * lockfile, and produce a Map<key, depRecord> matching the shape that
 * lib/cve-match.collectResolvedDeps produces for Maven.
 *
 *   key:        "npm:<name>"   (deliberately namespaced so it never
 *                                collides with Maven "g:a" keys)
 *   depRecord:  { groupId: "", artifactId: name, version, scope, pomPaths,
 *                 ecosystem: "npm", resolved, integrity, lockType,
 *                 manifestPaths: [absolute paths of files mentioning it],
 *                 versionRelations: { [version]: ["direct" | "transitive" | "unknown"] } }
 *
 * Conflict resolution between manifests for the same package:
 *   - lockfile entries WIN over package.json range specs (concrete version)
 *   - if two lockfiles disagree, keep the highest semver-comparable version
 *   - dev/optional/peer downgrade to prod if any manifest puts the dep in prod
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const path = require("path");
const fs = require("fs");
const { parsePackageJson, parsePackageLock, parseYarnLockV1, parsePnpmLock, findJsManifests } = require("./parse");
const { makeDepRecord } = require("../../dep-record");
const { normaliseNpmVersion } = require("./parse");

const SCOPE_RANK = { prod: 4, peer: 3, optional: 2, dev: 1, transitive: 0 };

function rankScope(s) { return SCOPE_RANK[s] || 0; }

function semverCompare(a, b) {
	// Lightweight semver compare — good enough for "keep highest"; not
	// canonical (doesn't fully implement build metadata ordering). For CVE
	// matching we'll defer to ecosystem-aware comparators when needed.
	const norm = v => String(v || "").replace(/^[v=]+/, "").split(/[-+]/)[0].split(".").map(n => parseInt(n, 10) || 0);
	const ax = norm(a), bx = norm(b);
	const n = Math.max(ax.length, bx.length);
	for (let i = 0; i < n; i++) {
		const d = (ax[i] || 0) - (bx[i] || 0);
		if (d !== 0) return d > 0 ? 1 : -1;
	}
	return 0;
}

function isResolvedVersion(v) {
	// Reject ranges/specifiers like "^1.0.0", "~2.0", ">=1.0.0", "*", "latest", "git+..."
	if (!v) return false;
	if (/^[\^~>=<*]/.test(v)) return false;
	if (/^(latest|next|workspace:|git\+|file:|link:|http)/i.test(v)) return false;
	// Bare semver-ish strings only (digits and at most one dash for prerelease tag)
	return /^\d+\.\d+(\.\d+)?([.\-+]\S+)?$/.test(v) || /^\d+$/.test(v);
}

/**
 * --ignore-test: what a production install would NOT ship. Optional and declared-dev
 * scopes as before, plus a transitive reachable only through dev deps (isDev). A
 * declared devDependency that a prod dep ALSO pulls in (isDev === false) ships, so it
 * stays.
 */
function isDevOnly(scope, isDev) {
	if (isDev) return true;
	if (scope === "optional") return true;
	return scope === "dev" && isDev !== false;
}

/** Relations describe occurrences, independently of installation scope and isDev. */
function graphRelations(dep) {
	// Yarn/pnpm have already merged nodes of the same name+version. Only the
	// surviving graph evidence is available here; do not invent a second relation.
	if (dep.depth > 0 || dep.via?.length || dep.from) return ["transitive"];
	if (dep.depth === 0 && ["prod", "dev", "optional", "peer"].includes(dep.scope)) return ["direct"];
	// In particular, yarn/pnpm orphans have scope=transitive but no graph path.
	return ["unknown"];
}

/**
 * npm's depth is a physical install depth: a hoisted package is not necessarily
 * direct, and v1's scope does not encode relations at all. Use declarations and
 * installed dependency edges, without changing the parser's scan classification.
 */
function packageLockRelations(file, parsed, manifest) {
	const result = new Map();
	try {
		const lock = JSON.parse(fs.readFileSync(file, "utf8"));
		const flat = parsed.lockfileVersion >= 2 && lock.packages;
		const nodes = new Map();
		if (flat) {
			for (const [key, entry] of Object.entries(lock.packages)) {
				if (!key.includes("node_modules/") || entry.link || !key.split("node_modules/").pop()) continue;
				nodes.set(key, { entry, relations: new Set() });
			}
		} else {
			const walk = (deps, base = "") => {
				for (const [name, entry] of Object.entries(deps || {})) {
					const key = `${base ? base + "/" : ""}node_modules/${name}`;
					nodes.set(key, { entry, relations: new Set() });
					walk(entry.dependencies, key);
				}
			};
			walk(lock.dependencies);
		}
		// Both traversals preserve the parser's occurrence order, including aliases.
		// Fail closed if a future parser changes which occurrences it emits.
		if (nodes.size !== parsed.deps.length) return result;
		const resolve = (base, name) => {
			for (;;) {
				const node = nodes.get(`${base ? base + "/" : ""}node_modules/${name}`);
				if (node) return node;
				if (!base) return null;
				base = path.posix.dirname(base);
				if (base === ".") base = "";
			}
		};
		const sections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
		if (flat) {
			// Includes workspace declarations; linked workspace packages are not scanned.
			for (const [base, entry] of Object.entries(lock.packages)) {
				if (base.includes("node_modules/")) continue;
				for (const section of sections) {
					for (const name of Object.keys(entry[section] || {})) resolve(base, name)?.relations.add("direct");
				}
			}
		}
		// v1 has no root declarations; a sibling package.json supplies that evidence.
		for (const dep of manifest?.deps || []) resolve("", dep.alias || dep.name)?.relations.add("direct");
		let index = 0;
		for (const [key, node] of nodes) {
			const dep = parsed.deps[index++];
			if (key.split("node_modules/").pop() !== (dep.alias || dep.name)) return new Map();
			result.set(dep, node.relations);
			if (dep.depth > 0) node.relations.add("transitive");
			const edges = flat
				? { ...node.entry.dependencies, ...node.entry.optionalDependencies, ...node.entry.peerDependencies }
				: node.entry.requires;
			for (const name of Object.keys(edges || {})) resolve(key, name)?.relations.add("transitive");
		}
	} catch { return new Map(); } // Additional metadata must never prevent the existing scan.
	return result;
}

function upsert(out, dep, manifestPath, lockType, relations) {
	const key = `npm:${dep.name}`;
	const existing = out.get(key);
	// ecosystemType narrows "ecosystem" to the tool that produced the lockfile:
	//   "npm"  for package-lock.json
	//   "yarn" for yarn.lock
	// Used by the report to split sections per tool.
	const ecosystemType = (lockType || "").startsWith("package-lock") ? "npm"
		: (lockType || "").startsWith("yarn") ? "yarn"
		: "npm";
	const record = makeDepRecord({
		ecosystem: "npm",
		ecosystemType,
		namespace: "",
		name: dep.name,
		version: normaliseNpmVersion(dep.version),
		manifestPath,
		scope: dep.scope || "prod",
		isDev: !!dep.isDev,
	});
	// npm-specific extras (not part of the shared depRecord contract)
	record.lockType = lockType;
	record.depth = dep.depth ?? null;
	record.resolved = dep.resolved || null;
	record.integrity = dep.integrity || null;
	record.from = dep.from || null;
	// The record is keyed by the REAL package name; the alias(es) it is installed under
	// are kept for display only — they name nothing on the registry.
	if (dep.alias) record.aliases = [dep.alias];
	// A transitive's chain from its root direct dep, in the Maven resolver's shape
	// (["npm:<root>", …, "npm:<parent>"]): the report's "pulled in via", the charts'
	// per-root grouping and the action cell's "pulled in by" all read it.
	if (record.scope === "transitive" && Array.isArray(dep.via) && dep.via.length) {
		record.via = dep.via.slice();
		record.viaPaths = [dep.via.slice()];
	}
	// Per-version provenance for lib/attribution.js: the record is coord-wide (one per
	// name across every lockfile), but a match carries ONE version, and two versions of
	// one name are routinely classified differently (ms@2.1.3 under a prod dep,
	// ms@1.0.0 only under jest). "dev" marks a dev-only occurrence; attribution reads a
	// version as dev only when EVERY occurrence of it is.
	const scopeToken = dep.isDev ? "dev" : (record.scope || "prod");
	record.versionScopes = {};
	for (const v of record.versions) record.versionScopes[v] = [scopeToken];
	// Union evidence per version before the coordinate-wide scope/depth merge.
	// Keep unknown occurrences too: another manifest's proof does not explain them.
	const relationTokens = relations?.length ? relations : ["unknown"];
	record.versionRelations = {};
	for (const v of record.versions) record.versionRelations[v] = relationTokens.slice();
	if (!existing) {
		out.set(key, record);
		return;
	}
	// Merge. NB: pomPaths shares the manifestPaths array reference (makeDepRecord),
	// so we push once — pushing to both would duplicate the entry.
	if (!existing.manifestPaths.includes(manifestPath)) {
		existing.manifestPaths.push(manifestPath);
	}
	for (const v of record.versions) {
		const paths = Object.hasOwn(existing.versionPaths, v) ? existing.versionPaths[v] : (existing.versionPaths[v] = []);
		if (!paths.includes(manifestPath)) paths.push(manifestPath);
		if (!existing.versionScopes) existing.versionScopes = {};
		const scopes = Object.hasOwn(existing.versionScopes, v) ? existing.versionScopes[v] : (existing.versionScopes[v] = []);
		if (!scopes.includes(scopeToken)) scopes.push(scopeToken);
		const knownRelations = Object.hasOwn(existing.versionRelations, v) ? existing.versionRelations[v] : (existing.versionRelations[v] = []);
		for (const relation of relationTokens) if (!knownRelations.includes(relation)) knownRelations.push(relation);
	}
	for (const a of record.aliases || []) {
		if (!existing.aliases) existing.aliases = [];
		if (!existing.aliases.includes(a)) existing.aliases.push(a);
	}
	// Prefer the resolved (lockfile) version over a range from package.json
	const incoming = record.version;
	const have = existing.version;
	if (isResolvedVersion(incoming) && !isResolvedVersion(have)) {
		existing.version = incoming;
	} else if (isResolvedVersion(incoming) && isResolvedVersion(have)) {
		if (semverCompare(incoming, have) > 0) existing.version = incoming;
	} else if (!have && incoming) {
		existing.version = incoming;
	}
	// Every DISTINCT concrete version is scanned, not just the highest: a JS tree
	// routinely pins the same package at several versions (nested node_modules),
	// and a CVE may affect only a lower one. cve-match.js / osv.js iterate
	// dep.versions, so we union them here (makeDepRecord seeds `versions` with the
	// record's own concrete version).
	for (const v of record.versions || []) {
		if (!existing.versions.includes(v)) existing.versions.push(v);
	}
	// Stronger scope wins (prod > peer > optional > dev)
	if (rankScope(record.scope) > rankScope(existing.scope)) existing.scope = record.scope;
	// A dep is "dev" overall only if every occurrence is dev. Any prod use → not dev.
	const wasDev = existing.isDev;
	if (!record.isDev) existing.isDev = false;
	// The chain only means something while the coordinate is a transitive everywhere: a
	// direct occurrence anywhere makes it a direct dep, and a direct dep has no "via".
	if (existing.scope !== "transitive") {
		delete existing.via;
		delete existing.viaPaths;
	} else if (record.via) {
		const sig = record.via.join("→");
		existing.viaPaths = existing.viaPaths || [];
		const known = existing.viaPaths.some(p => p.join("→") === sig);
		// A production chain outranks a dev-only one: it is the one to act on.
		if (!existing.via || (wasDev && !record.isDev)) {
			existing.via = record.via.slice();
			if (!known) existing.viaPaths.unshift(record.via.slice());
			existing.depth = record.depth;
		} else if (!known) {
			existing.viaPaths.push(record.via.slice());
		}
	}
	// First non-null resolved/integrity wins
	if (!existing.resolved && record.resolved) existing.resolved = record.resolved;
	if (!existing.integrity && record.integrity) existing.integrity = record.integrity;
}

/**
 * Walk `rootDir`, parse every manifest, return { deps, warnings }.
 *
 * Returns:
 *   {
 *     deps:     Map<key, depRecord>,   // unchanged shape from before
 *     warnings: [                       // surfaced into console + report
 *       { type: "no-lockfile", manifestPath, message }, ...
 *     ],
 *   }
 *
 * Lockfile policy: we ONLY collect deps from a lockfile (package-lock.json or
 * yarn.lock). A package.json without a sibling lockfile is intentionally
 * skipped — its values are ranges ("^1.0.0") that can't be queried against
 * OSV and create false negatives. The caller is warned so they can either
 * run `npm install` / `yarn install` to generate a lock, or accept the gap.
 *
 * opts:
 *   ignoreTest    — skip dev / optional dependencies (mirrors Maven's --ignore-test)
 *   deps2Exclude  — RegExp tested against the npm name (covers private @scope/* packages)
 *   verbose
 */
function collectNpmDeps(rootDir, opts = {}) {
	const { ignoreTest, deps2Exclude, verbose } = opts;
	const out = new Map();
	const warnings = [];
	// Caller may pass pre-discovered manifest groups (e.g. from the parallel
	// findJsManifestsAsync walk) to avoid a second, serial tree traversal.
	const manifestGroups = opts.manifestGroups || findJsManifests(rootDir);
	let parsedCount = 0;
	const parsedManifests = [];

	for (const group of manifestGroups) {
		for (const f of [group.packageJson, group.packageLock, group.yarnLock, group.pnpmLock]) if (f) parsedManifests.push(f);
		const pj = group.packageJson ? safeParse(parsePackageJson, group.packageJson, verbose) : null;
		const pl = group.packageLock ? safeParse(parsePackageLock, group.packageLock, verbose) : null;
		const yl = group.yarnLock ? safeParse(parseYarnLockV1, group.yarnLock, verbose) : null;
		const pn = group.pnpmLock ? safeParse(parsePnpmLock, group.pnpmLock, verbose) : null;
		const hasLock = !!(pl || yl || pn);

		// package.json without lockfile → best-effort fallback (changed contract):
		// scan pinned exact versions ("1.2.3"), skip ranges ("^1.0.0"), and warn
		// that results are partial. Previously this manifest was skipped entirely.
		if (pj && !hasLock) {
			let pinned = 0, ranges = 0;
			for (const d of pj.deps) {
				if (ignoreTest && (d.scope === "dev" || d.scope === "optional")) continue;
				if (deps2Exclude && deps2Exclude.test(d.name)) continue;
				if (isResolvedVersion(d.version)) {
					upsert(out, { name: d.name, version: d.version, scope: d.scope || "prod", isDev: !!d.isDev }, group.packageJson, "package-json-nolock", ["direct"]);
					pinned++;
				} else {
					ranges++;
				}
			}
			warnings.push({
				type: "no-lockfile",
				manifestPath: group.packageJson,
				packageName: pj.packageName || null,
				message: `package.json without lockfile — best-effort: ${pinned} pinned dep(s) scanned, ${ranges} range(s) skipped (run "npm install" or "yarn install" for full coverage)`,
			});
			if (verbose) console.warn(`⚠️  ${group.packageJson}: no lockfile — best-effort (${pinned} pinned, ${ranges} ranges skipped)`);
		}

		// Yarn-Berry lockfile that failed to parse → warning (deps still empty).
		if (yl?.parseError) {
			warnings.push({
				type: "parse-error",
				manifestPath: group.yarnLock,
				message: `yarn 2+/Berry lockfile parse failed: ${yl.parseError}`,
			});
			if (verbose) console.warn(`⚠️  ${group.yarnLock}: yarn-berry parse failed — ${yl.parseError}`);
		}

		// Used only as a source of scope info — never emits deps on its own. Keyed by
		// the DECLARED name, which for an alias is the alias, not the real package.
		const directScopes = pj ? new Map(pj.deps.map(d => [d.alias || d.name, d.scope])) : null;

		if (pl) {
			parsedCount++;
			const relations = packageLockRelations(group.packageLock, pl, pj);
			for (const d of pl.deps) {
				// In v1 npm dev/optional propagate; in v2/v3 the `dev` flag is reliable.
				// A transitive that merely shares its name with a direct dep (a nested
				// lodash@3 under a direct lodash@4) is not that direct dep.
				const explicit = d.scope === "transitive" ? undefined : directScopes?.get(d.alias || d.name);
				const scope = explicit || d.scope || "prod";
				if (ignoreTest && isDevOnly(scope, d.isDev)) continue;
				if (deps2Exclude && deps2Exclude.test(d.name)) continue;
				upsert(out, { ...d, scope }, group.packageLock, `package-lock-v${pl.lockfileVersion}`, [...(relations.get(d) || [])]);
			}
		}
		// yarn / pnpm: the parser already classified every entry by walking the graph
		// from the package.json roots (direct vs transitive, dev-only vs prod), so the
		// name-keyed package.json override above must NOT be re-applied — it would turn
		// a transitive into a direct dep just for sharing a declared name.
		if (yl) {
			parsedCount++;
			const lockType = yl.lockfileVersion === "berry" ? "yarn-berry" : "yarn-v1";
			for (const d of yl.deps) {
				const scope = d.scope || "prod";
				if (ignoreTest && isDevOnly(scope, d.isDev)) continue;
				if (deps2Exclude && deps2Exclude.test(d.name)) continue;
				upsert(out, { ...d, scope }, group.yarnLock, lockType, graphRelations(d));
			}
		}
		if (pn) {
			parsedCount++;
			for (const d of pn.deps) {
				const scope = d.scope || "prod";
				if (ignoreTest && isDevOnly(scope, d.isDev)) continue;
				if (deps2Exclude && deps2Exclude.test(d.name)) continue;
				upsert(out, { ...d, scope }, group.pnpmLock, "pnpm", graphRelations(d));
			}
		}
	}

	if (verbose) console.log(`📦 npm/yarn: parsed ${parsedCount} manifests, ${out.size} unique packages${warnings.length ? `, ${warnings.length} warnings` : ""}`);
	// Backward compat: the Map carries the warnings under a non-enumerable prop
	// so existing callers that iterate `for (const [k,v] of map)` still work.
	Object.defineProperty(out, "warnings", { value: warnings, enumerable: false });
	Object.defineProperty(out, "parsedManifests", { value: parsedManifests, enumerable: false });
	return out;
}

function safeParse(fn, file, verbose) {
	try { return fn(file); }
	catch (e) {
		if (verbose) console.warn(`⚠️  parse failed: ${file} — ${e.message}`);
		return null;
	}
}

/**
 * WebJars are client-side JS libraries shipped as Maven artifacts. Derive the
 * upstream npm coordinate from a WebJar dep so it can flow through the npm
 * pipeline (registry deprecation/outdated + endoflife EOL) instead of being
 * special-cased.
 *
 *   org.webjars.npm  — deterministic npm mirror. artifactId == npm name;
 *                      a scoped "@scope/name" is encoded as "scope__name".
 *   org.webjars      — hand-curated catalogue; artifactId is the JS lib name
 *                      (mostly aligned with npm, e.g. jquery/bootstrap).
 *   org.webjars.bower* — Bower mirrors; best-effort name match.
 *
 * Versions match the upstream package. Returns { name, version } or null for a
 * non-WebJar coordinate.
 */
function webjarToNpm(dep) {
	const g = dep.groupId || "";
	if (g !== "org.webjars" && !g.startsWith("org.webjars.")) return null;
	let name = dep.artifactId || "";
	if (!name) return null;
	if (name.includes("__")) name = "@" + name.replace(/__/g, "/");
	return { name, version: dep.version || null };
}

function hasJsManifests(rootDir) {
	try {
		const stack = [rootDir];
		const skip = new Set([
			"node_modules", "bower_components", "jspm_packages",
			".git", ".idea", ".vscode", ".gradle", ".mvn",
			"dist", "build", "out", "target", "coverage", ".next", ".nuxt",
		]);
		while (stack.length) {
			const cur = stack.pop();
			let entries;
			try { entries = fs.readdirSync(cur, { withFileTypes: true }); }
			catch { continue; }
			for (const e of entries) {
				if (e.isFile() && (e.name === "package.json" || e.name === "package-lock.json" || e.name === "yarn.lock" || e.name === "pnpm-lock.yaml")) return true;
				if (e.isDirectory() && !skip.has(e.name)) stack.push(path.join(cur, e.name));
			}
		}
	} catch { /* ignore */ }
	return false;
}

module.exports = { collectNpmDeps, hasJsManifests, semverCompare, webjarToNpm };
