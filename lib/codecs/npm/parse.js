/**
 * lib/npm/parse.js — parse package.json, package-lock.json (v1/v2/v3),
 * and yarn.lock v1. Pure functions: no I/O scheduling, no console output.
 *
 * The shape returned by each parser is normalised to:
 *   {
 *     manifestPath,           // absolute path to the parsed file
 *     manifestType,           // "package.json" | "package-lock" | "yarn.lock"
 *     packageName,            // top-level project name (if known)
 *     packageVersion,         // top-level project version (if known)
 *     deps: [                 // every package present (direct + transitive)
 *       {
 *         name,               // "lodash" | "@scope/pkg" — the REAL package name, never an npm alias
 *         version,            // resolved (lockfile) or range (package.json)
 *         alias,              // the alias it is installed under, when it is one
 *         scope,              // "prod" | "dev" | "peer" | "optional" (direct) | "transitive"
 *         isDev,              // reachable ONLY through dev roots
 *         depth,              // 0 for direct; >0 for transitive in lockfile tree
 *         via,                // yarn/pnpm transitives: ["npm:<root>", …, "npm:<parent>"]
 *         from,               // transitives: parent chain as "a > b"
 *       },
 *     ],
 *   }
 *
 * The collector (lib/npm/collect.js) is responsible for merging across
 * files and applying exclusion rules.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");

function isWorkspaceVersion(v) {
	// npm v9+ uses "*" / "" for workspace-local refs; yarn uses "workspace:*"
	if (!v) return true;
	return v === "*" || v === "" || String(v).startsWith("workspace:") || String(v).startsWith("file:") || String(v).startsWith("link:");
}

function pickName(pkgKey) {
	// npm v2/v3 lockfile keys look like "node_modules/foo" or "node_modules/foo/node_modules/bar"
	const parts = pkgKey.split("node_modules/");
	const last = parts[parts.length - 1];
	return last || null;
}

function depthFromKey(pkgKey) {
	// "node_modules/a/node_modules/b" → depth 2
	const n = (pkgKey.match(/node_modules\//g) || []).length;
	return Math.max(0, n - 1);
}

/**
 * "name@range" / "@scope/name@range" → { name, range }. The separator is the FIRST "@"
 * after a leading scope "@" — NOT the last one: an alias descriptor
 * ("lodash-legacy@npm:lodash@4.17.20") and a git URL ("x@git+ssh://git@host/…") both carry
 * further "@"s in the range, and splitting on the last one names a package that does
 * not exist ("lodash-legacy@npm:lodash").
 */
function splitDescriptor(d) {
	const s = String(d || "").trim().replace(/^"|"$/g, "");
	const at = s.indexOf("@", s.startsWith("@") ? 1 : 0);
	if (at <= 0) return null;
	return { name: s.slice(0, at), range: s.slice(at + 1) };
}

/**
 * npm alias spec "npm:<real>@<range>" → { name: real, range }, else null. The alias is
 * only the folder the package is installed under: the registry, OSV and the purl all
 * know the package by its REAL name, so recording the alias means every CVE of the real
 * package is silently never queried. "npm:^1.2.0" (Berry's default protocol, no alias)
 * yields null.
 */
function parseNpmAlias(spec) {
	const s = String(spec == null ? "" : spec).trim();
	if (!s.startsWith("npm:")) return null;
	const d = splitDescriptor(s.slice(4));
	return d && d.name ? d : null;
}

const GRAPH_SCOPE_RANK = { prod: 4, peer: 3, optional: 2, dev: 1, transitive: 0 };

/**
 * Classify every node of a lockfile dependency graph from its package.json roots — the
 * yarn/pnpm counterpart of what the package-lock path reads off npm's own flags:
 *   - a direct dep (a root) keeps the scope it is declared with (prod/optional/peer/dev),
 *     depth 0;
 *   - anything else reachable is scope "transitive", depth = shortest distance from a
 *     root, `via` = the chain of coordKeys from that root down to its parent (the shape
 *     the Maven transitive resolver produces, so report/charts/attribution read it
 *     unchanged);
 *   - isDev ⇔ reachable ONLY through dev roots. A package reachable from a prod root AND
 *     a dev root ships with production, so it is prod — and its `via` is the production
 *     chain, the one an auditor has to act on;
 *   - an orphan (in the lock, reachable from no root) mirrors the package-lock path's
 *     not-a-root rule: "transitive", isDev from the lock's own dev flag when it has one
 *     (pnpm v5/v6), else false. Never a direct prod dep — nothing declares it.
 * Several nodes may share one name@version (pnpm peer variants, Berry patches, yarn
 * alias blocks): they are merged — strongest scope wins, dev only if every node is dev.
 *
 * @param nodes Map<id, { name, version, children: Set<id>, aliases: Set<string>, devFlag, resolved, integrity }>
 * @param roots [{ id, scope }]
 * @returns deps[] in the parse.js normalised shape
 */
function classifyLockGraph(nodes, roots) {
	const directScope = new Map();
	for (const r of roots) {
		if (!r || !nodes.has(r.id)) continue;
		const cur = directScope.get(r.id);
		if (!cur || GRAPH_SCOPE_RANK[r.scope] > GRAPH_SCOPE_RANK[cur]) directScope.set(r.id, r.scope);
	}
	// Breadth-first, so the first time a node is reached is through a shortest chain.
	const reach = seeds => {
		const seen = new Map();
		const queue = [];
		for (const id of seeds) { if (!seen.has(id)) { seen.set(id, { depth: 0, via: [] }); queue.push(id); } }
		for (let i = 0; i < queue.length; i++) {
			const id = queue[i];
			const cur = seen.get(id);
			const via = [...cur.via, `npm:${nodes.get(id).name}`];
			for (const c of nodes.get(id).children) {
				if (seen.has(c) || !nodes.has(c)) continue;
				seen.set(c, { depth: cur.depth + 1, via });
				queue.push(c);
			}
		}
		return seen;
	};
	const seeds = dev => [...directScope].filter(([, s]) => (s === "dev") === dev).map(([id]) => id);
	const prodReach = reach(seeds(false));
	const devReach = reach(seeds(true));

	const out = new Map();
	for (const [id, node] of nodes) {
		const p = prodReach.get(id), d = devReach.get(id), ds = directScope.get(id);
		let cls;
		if (ds) cls = { scope: ds, depth: 0, via: null, isDev: !p };
		else if (p || d) cls = { scope: "transitive", depth: (p || d).depth, via: (p || d).via.slice(), isDev: !p };
		else cls = { scope: "transitive", depth: null, via: null, isDev: node.devFlag === true };
		const dep = {
			name: node.name,
			version: node.version,
			...cls,
			from: cls.via && cls.via.length ? cls.via.map(v => v.slice("npm:".length)).join(" > ") : null,
			resolved: node.resolved || null,
			integrity: node.integrity || null,
		};
		const alias = [...(node.aliases || [])].find(a => a !== node.name);
		if (alias) dep.alias = alias;
		const k = `${node.name}@${node.version}`;
		const prev = out.get(k);
		if (!prev) { out.set(k, dep); continue; }
		// Same package+version reached as two nodes: keep the most significant reading.
		const better = (a, b) => {
			const ra = GRAPH_SCOPE_RANK[a.scope], rb = GRAPH_SCOPE_RANK[b.scope];
			if (ra !== rb) return ra > rb;
			if (a.isDev !== b.isDev) return !a.isDev;
			return (a.depth ?? Infinity) < (b.depth ?? Infinity);
		};
		const isDev = prev.isDev && dep.isDev;
		if (better(dep, prev)) Object.assign(prev, { scope: dep.scope, depth: dep.depth, via: dep.via, from: dep.from });
		prev.isDev = isDev;
		if (!prev.alias && dep.alias) prev.alias = dep.alias;
	}
	return [...out.values()];
}

function readJsonSafe(p) {
	try { return JSON.parse(fs.readFileSync(p, "utf8")); }
	catch { return null; }
}

/**
 * Expand package.json `workspaces` globs ("packages/*", "!packages/legacy") to member
 * dirs, relative to `base`, POSIX-separated. A shallow bounded walk is enough: workspace
 * globs name source dirs, never anything under node_modules.
 */
function expandWorkspaces(base, patterns) {
	const { minimatch } = require("minimatch");
	const inc = [], exc = [];
	for (const p of patterns || []) {
		const s = String(p).trim().replace(/^\.\//, "").replace(/\/+$/, "");
		if (!s || s === "!") continue;
		if (s.startsWith("!")) exc.push(s.slice(1).replace(/^\.\//, ""));
		else inc.push(s);
	}
	if (!inc.length) return [];
	const found = [];
	const walk = (rel, depth) => {
		if (depth > 6) return;
		let entries;
		try { entries = fs.readdirSync(path.join(base, rel), { withFileTypes: true }); }
		catch { return; }
		for (const e of entries) {
			if (!e.isDirectory() || e.name === "node_modules" || e.name.startsWith(".")) continue;
			const r = rel ? `${rel}/${e.name}` : e.name;
			if (inc.some(g => minimatch(r, g)) && !exc.some(g => minimatch(r, g))) found.push(r);
			walk(r, depth + 1);
		}
	};
	walk("", 0);
	return found;
}

/**
 * The package.json files whose declarations are the ROOTS of a lockfile beside them: the
 * sibling package.json plus, for a workspaces monorepo, every member's (one yarn.lock
 * covers them all, and the members' deps are what it mostly holds).
 * → [{ dir: "." | "packages/web", pkg }]
 */
function loadRootManifests(lockDir) {
	const root = readJsonSafe(path.join(lockDir, "package.json"));
	if (!root || typeof root !== "object") return [];
	const out = [{ dir: ".", pkg: root }];
	const ws = Array.isArray(root.workspaces) ? root.workspaces : (root.workspaces && root.workspaces.packages) || [];
	for (const rel of expandWorkspaces(lockDir, ws)) {
		const pkg = readJsonSafe(path.join(lockDir, rel, "package.json"));
		if (pkg && typeof pkg === "object") out.push({ dir: rel, pkg });
	}
	return out;
}

/** A package.json's declarations as graph roots: [{ name, range, scope }]. */
function manifestRoots(pkg) {
	const out = [];
	const add = (obj, scope) => {
		for (const [name, range] of Object.entries(obj || {})) {
			if (isWorkspaceVersion(range)) continue;
			out.push({ name, range: String(range), scope });
		}
	};
	add(pkg.dependencies, "prod");
	add(pkg.optionalDependencies, "optional");
	// A peer only counts when the lock actually installed it — the caller's descriptor
	// lookup simply finds nothing for one that was not.
	add(pkg.peerDependencies, "peer");
	add(pkg.devDependencies, "dev");
	return out;
}

/**
 * Descriptor → node id resolver shared by the yarn parsers. Exact descriptor first (what
 * the lockfile keys on); else, by real package name, the ONE node carrying it — a guess
 * between several versions would invent a classification, so an ambiguous name resolves
 * to nothing.
 */
function makeResolver(byDescriptor, nodes) {
	const byName = new Map();
	for (const [id, n] of nodes) {
		if (!byName.has(n.name)) byName.set(n.name, new Set());
		byName.get(n.name).add(id);
	}
	return (desc) => {
		const hit = byDescriptor.get(desc);
		if (hit) return hit;
		const sd = splitDescriptor(desc);
		if (!sd) return null;
		const al = parseNpmAlias(sd.range);
		const ids = byName.get(al ? al.name : sd.name);
		return ids && ids.size === 1 ? [...ids][0] : null;
	};
}

/* -------- package.json ---------- */
function parsePackageJson(filePath) {
	const raw = fs.readFileSync(filePath, "utf8");
	let json;
	try { json = JSON.parse(raw); }
	catch (e) { throw new Error(`package.json parse failed (${filePath}): ${e.message}`); }
	const deps = [];
	const push = (obj, scope) => {
		for (const [name, version] of Object.entries(obj || {})) {
			if (isWorkspaceVersion(version)) continue;
			const isDev = scope === "dev";
			// "lodash-legacy": "npm:lodash@4.17.20" → lodash @ 4.17.20 (alias kept).
			const al = parseNpmAlias(version);
			if (al) deps.push({ name: al.name, alias: name, version: al.range, scope, isDev, depth: 0 });
			else deps.push({ name, version: String(version), scope, isDev, depth: 0 });
		}
	};
	push(json.dependencies, "prod");
	push(json.devDependencies, "dev");
	push(json.peerDependencies, "peer");
	push(json.optionalDependencies, "optional");
	return {
		manifestPath: filePath,
		manifestType: "package.json",
		packageName: json.name || null,
		packageVersion: json.version || null,
		workspaces: Array.isArray(json.workspaces) ? json.workspaces : (json.workspaces?.packages || []),
		deps,
	};
}

/* -------- package-lock.json (v1, v2, v3) ---------- */
function parsePackageLock(filePath) {
	const raw = fs.readFileSync(filePath, "utf8");
	let json;
	try { json = JSON.parse(raw); }
	catch (e) { throw new Error(`package-lock parse failed (${filePath}): ${e.message}`); }

	const lockfileVersion = json.lockfileVersion || 1;
	const out = {
		manifestPath: filePath,
		manifestType: "package-lock",
		packageName: json.name || null,
		packageVersion: json.version || null,
		lockfileVersion,
		deps: [],
	};

	if (lockfileVersion >= 2 && json.packages) {
		// v2/v3: flat `packages` map keyed by relative path.
		// The empty-string key is the root project; node_modules/foo → installed dep.
		const root = json.packages[""] || {};
		const directProd = root.dependencies || {};
		const directDev = root.devDependencies || {};
		const directOpt = root.optionalDependencies || {};
		const directPeer = root.peerDependencies || {};
		const isDirect = (name, scope) => {
			if (scope === "prod" && Object.prototype.hasOwnProperty.call(directProd, name)) return true;
			if (scope === "dev" && Object.prototype.hasOwnProperty.call(directDev, name)) return true;
			if (scope === "optional" && Object.prototype.hasOwnProperty.call(directOpt, name)) return true;
			if (scope === "peer" && Object.prototype.hasOwnProperty.call(directPeer, name)) return true;
			return false;
		};
		const isAnyDirect = name =>
			Object.prototype.hasOwnProperty.call(directProd, name) ||
			Object.prototype.hasOwnProperty.call(directDev, name) ||
			Object.prototype.hasOwnProperty.call(directOpt, name) ||
			Object.prototype.hasOwnProperty.call(directPeer, name);

		for (const [pkgKey, entry] of Object.entries(json.packages)) {
			if (pkgKey === "") continue;                  // root
			if (!pkgKey.includes("node_modules/")) continue; // workspace member, not a dep
			if (entry.link) continue;                     // symlink to workspace
			// The folder name is what package.json declares (and so what decides
			// "direct"), but an alias install ("string-width-cjs": "npm:string-width@…")
			// records the REAL package in `entry.name` — that is the package to scan.
			const installName = pickName(pkgKey);
			if (!installName) continue;
			const name = entry.name || installName;
			const depth = depthFromKey(pkgKey);
			// scope inference. npm v3+ flattens transitives into the top-level
			// node_modules/, so depth===0 alone doesn't mean "direct". An entry
			// is direct iff it appears in the root project's dependency lists.
			let scope = "prod";
			if (entry.dev && !entry.devOptional) scope = "dev";
			else if (entry.devOptional) scope = "optional";
			else if (entry.optional) scope = "optional";
			else if (entry.peer) scope = "peer";
			const isDirectDep = depth === 0 && isAnyDirect(installName);
			if (isDirectDep) {
				if (isDirect(installName, "prod")) scope = "prod";
				else if (isDirect(installName, "optional")) scope = "optional";
				else if (isDirect(installName, "peer")) scope = "peer";
				else scope = "dev";
			} else if (depth > 0 || !isAnyDirect(installName)) {
				// Flattened-but-not-direct = transitive. Keep dev/optional flags
				// for filtering, but record it as a transitive.
				scope = "transitive";
			}
			// isDev flag survives the scope reclassification: a flattened
			// transitive of a dev-only dep is still dev-only.
			const directProduction = isDirectDep && ["prod", "optional", "peer"].some(s => isDirect(installName, s));
			// npm's devOptional means both a dev path and an optional production path.
			const isDev = !directProduction && !entry.devOptional && !!(entry.dev || (isDirectDep && isDirect(installName, "dev")));
			// A dev-only direct declaration with a production optional path is
			// indirect in production, even when npm hoists it to the root.
			if (isDirectDep && scope === 'dev' && entry.devOptional) scope = 'transitive';
			out.deps.push({
				name,
				...(name !== installName ? { alias: installName } : {}),
				version: entry.version || null,
				scope,
				isDev,
				depth,
				resolved: entry.resolved || null,
				integrity: entry.integrity || null,
			});
		}
	} else if (json.dependencies) {
		// v1: nested `dependencies` tree
		const walk = (node, depth, parentChain, parentIsDev) => {
			for (const [installName, entry] of Object.entries(node)) {
				let scope = "prod";
				if (entry.dev) scope = "dev";
				else if (entry.optional) scope = "optional";
				if (depth > 0) scope = "transitive";
				const isDev = !!entry.dev || parentIsDev;
				// v1 spells an alias install in the version: "npm:string-width@4.2.3".
				const al = parseNpmAlias(entry.version);
				const name = al ? al.name : installName;
				out.deps.push({
					name,
					...(al ? { alias: installName } : {}),
					version: al ? al.range : (entry.version || null),
					scope,
					isDev,
					depth,
					from: parentChain.length ? parentChain.join(" > ") : null,
					resolved: entry.resolved || null,
					integrity: entry.integrity || null,
				});
				if (entry.dependencies) walk(entry.dependencies, depth + 1, [...parentChain, name], isDev);
			}
		};
		walk(json.dependencies, 0, [], false);
	}

	return out;
}

/* -------- yarn.lock v1 ----------
   Format example:
     "lodash@^4.17.0", lodash@^4.17.21:
       version "4.17.21"
       resolved "https://registry.yarnpkg.com/..."
       integrity sha512-...
       dependencies:
         "another-pkg" "^1.0.0"
   Each block starts at column 0 with one or more comma-separated descriptors,
   ending with ":". Indented lines hold key-value pairs and dependency blocks.

   The lock alone says nothing about dev vs prod or direct vs transitive: that comes
   from walking the graph (each block's `dependencies:` / `optionalDependencies:`) down
   from the sibling package.json roots — see classifyLockGraph. An alias block
   ("lodash-legacy@npm:lodash@4.17.20") is recorded under the real package.
*/
function unquote(s) { return String(s).trim().replace(/^"|"$/g, ""); }

function parseYarnLockV1(filePath) {
	const raw = fs.readFileSync(filePath, "utf8");
	if (raw.includes("__metadata:")) {
		// Berry / yarn 2+ uses YAML — parse it with js-yaml.
		return parseYarnBerry(raw, filePath);
	}
	const out = {
		manifestPath: filePath,
		manifestType: "yarn.lock",
		lockfileVersion: 1,
		deps: [],
	};
	const lines = raw.split(/\r?\n/);
	// node id = "<real name>@<version>": every descriptor resolving to the same version
	// (and an alias block of an already-locked version) is ONE installed package.
	const nodes = new Map();
	const byDescriptor = new Map();
	const edges = new Map();       // id → [descriptor] (resolved once every block is known)
	const kv = body => {
		const m = /^("[^"]*"|\S+)\s+(.*)$/.exec(body);
		return m ? [unquote(m[1]), unquote(m[2])] : null;
	};
	let i = 0;
	while (i < lines.length) {
		const line = lines[i];
		if (!line || /^#/.test(line) || line[0] === " " || line[0] === "\t") { i++; continue; }
		const header = line.replace(/:\s*$/, "");
		const descriptors = header.split(",").map(unquote).filter(Boolean);
		i++;
		// Read the indented body until the next non-indented line
		let version = null, resolved = null, integrity = null, block = null;
		const children = [];
		while (i < lines.length && (lines[i].startsWith(" ") || lines[i].startsWith("\t") || lines[i] === "")) {
			const l = lines[i++];
			const body = l.trim();
			if (!body) continue;
			const indent = l.length - l.trimStart().length;
			if (indent <= 2) {
				block = null;
				if (body === "dependencies:" || body === "optionalDependencies:") { block = "deps"; continue; }
				if (body.endsWith(":")) { block = "other"; continue; }
				const pair = kv(body);
				if (!pair) continue;
				if (pair[0] === "version") version = pair[1];
				else if (pair[0] === "resolved") resolved = pair[1];
				else if (pair[0] === "integrity") integrity = pair[1];
			} else if (block === "deps") {
				const pair = kv(body);
				if (pair) children.push(`${pair[0]}@${pair[1]}`);
			}
		}
		if (!version) continue;
		const parsed = descriptors.map(splitDescriptor).filter(Boolean);
		if (!parsed.length) continue;   // malformed
		const realOf = sd => { const al = parseNpmAlias(sd.range); return al ? al.name : sd.name; };
		const name = realOf(parsed[0]);
		const id = `${name}@${version}`;
		let node = nodes.get(id);
		if (!node) {
			node = { name, version, children: new Set(), aliases: new Set(), devFlag: undefined, resolved, integrity };
			nodes.set(id, node);
			edges.set(id, []);
		}
		for (let k = 0; k < parsed.length; k++) {
			byDescriptor.set(descriptors[k], id);
			if (parsed[k].name !== name) node.aliases.add(parsed[k].name);
		}
		edges.get(id).push(...children);
	}
	const resolve = makeResolver(byDescriptor, nodes);
	const aliasOf = desc => { const sd = splitDescriptor(desc); return sd && parseNpmAlias(sd.range) ? sd.name : null; };
	for (const [id, descs] of edges) {
		for (const desc of descs) {
			const c = resolve(desc);
			if (!c) continue;
			nodes.get(id).children.add(c);
			const al = aliasOf(desc);
			if (al) nodes.get(c).aliases.add(al);
		}
	}
	const roots = [];
	for (const { pkg } of loadRootManifests(path.dirname(filePath))) {
		for (const r of manifestRoots(pkg)) {
			const id = resolve(`${r.name}@${r.range}`);
			if (!id) continue;
			roots.push({ id, scope: r.scope });
			if (parseNpmAlias(r.range)) nodes.get(id).aliases.add(r.name);
		}
	}
	out.deps = classifyLockGraph(nodes, roots);
	return out;
}

/* -------- yarn.lock v2+ (Berry) ----------
   Berry lockfiles are YAML. Top-level keys are comma-separated descriptor lists
   ("lodash@npm:^4.17.0, lodash@npm:^4.17.21:") whose value carries `version`,
   `resolution` (the locator — and, for an alias "lodash-legacy@npm:lodash@4.17.20",
   the REAL package: "lodash@npm:4.17.20") and `dependencies` keyed by descriptor.
   The workspaces' own entries resolve to "@workspace:" — they are not packages but
   their `dependencies` are roots; dev vs prod is read from their package.json (the
   lock does not keep devDependencies apart).
*/
function identFromDescriptor(d) {
	const sd = splitDescriptor(d);
	return sd ? sd.name : null;
}

// Berry keys a bare semver range under the default protocol: "^1.0.0" → "npm:^1.0.0".
function berryRange(range) {
	return /^[a-z][a-z0-9+.-]*:/i.test(range) ? range : `npm:${range}`;
}

function parseYarnBerry(raw, filePath) {
	const out = { manifestPath: filePath, manifestType: "yarn.lock", lockfileVersion: "berry", deps: [] };
	let doc;
	try { doc = yaml.load(raw) || {}; }
	catch (e) { out.parseError = e.message; return out; }
	const nodes = new Map();      // id = resolution (the locator)
	const byDescriptor = new Map();
	const edges = new Map();
	const workspaces = [];
	const childDescs = val => Object.entries({ ...(val.dependencies || {}), ...(val.optionalDependencies || {}) })
		.map(([n, r]) => `${n}@${r}`);
	for (const [key, val] of Object.entries(doc)) {
		if (key === "__metadata") continue;
		if (!val || typeof val !== "object") continue;
		const resolution = String(val.resolution || "");
		if (/@workspace:/.test(resolution)) {      // the local package itself
			workspaces.push({ dir: resolution.slice(resolution.indexOf("@workspace:") + "@workspace:".length) || ".", val });
			continue;
		}
		if (!val.version) continue;
		const version = String(val.version);
		const descriptors = String(key).split(",").map(unquote).filter(Boolean);
		const name = identFromDescriptor(resolution) || identFromDescriptor(descriptors[0]);
		if (!name) continue;
		const id = resolution || `${name}@${version}`;
		if (!nodes.has(id)) {
			nodes.set(id, { name, version, children: new Set(), aliases: new Set(), devFlag: undefined, resolved: resolution || null });
			edges.set(id, []);
		}
		for (const desc of descriptors) {
			byDescriptor.set(desc, id);
			const dn = identFromDescriptor(desc);
			if (dn && dn !== name) nodes.get(id).aliases.add(dn);
		}
		edges.get(id).push(...childDescs(val));
	}
	const resolve = makeResolver(byDescriptor, nodes);
	for (const [id, descs] of edges) {
		for (const desc of descs) {
			const c = resolve(desc);
			if (c) nodes.get(id).children.add(c);
		}
	}
	const roots = [];
	const addRoot = (name, range, scope) => {
		const id = resolve(`${name}@${berryRange(range)}`);
		if (id) roots.push({ id, scope });
	};
	const manifests = loadRootManifests(path.dirname(filePath));
	for (const { pkg } of manifests) {
		for (const r of manifestRoots(pkg)) addRoot(r.name, r.range, r.scope);
	}
	// A workspace whose package.json we could not read still lists its deps in the lock:
	// take them as roots (prod — no evidence of dev) rather than orphan the whole member.
	const loaded = new Set(manifests.map(m => path.posix.normalize(m.dir)));
	for (const ws of workspaces) {
		if (loaded.has(path.posix.normalize(ws.dir))) continue;
		for (const [n, r] of Object.entries({ ...(ws.val.dependencies || {}), ...(ws.val.optionalDependencies || {}) })) {
			if (!isWorkspaceVersion(r)) addRoot(n, String(r), "prod");
		}
	}
	out.deps = classifyLockGraph(nodes, roots);
	return out;
}

/* -------- pnpm-lock.yaml ----------
   YAML. The full resolved set lives in `packages` (v5/v6) and `snapshots` (v9);
   `importers.*` (or, single-project v5/v6, the top-level dependencies/devDependencies/
   optionalDependencies) carry the per-workspace direct deps with dev classification.
   Package keys vary by lockfileVersion:
     v9:  "name@1.2.3"            / "@scope/name@1.2.3"          (+ "(peers)" in snapshots)
     v6:  "/name@1.2.3(peers)"    / "/@scope/name@1.2.3(peers)"
     v5:  "/name/1.2.3_peer@1.0.0" / "/@scope/name/1.2.3"
   A dependency reference is a version ("1.2.3", "1.2.3(react@18.0.0)") or, for an
   alias, the target package's key ("lodash@4.17.20" v9, "/lodash@4.17.20" v6/v5).
   dev vs prod and direct vs transitive come from walking `dependencies` /
   `optionalDependencies` down from the importers (classifyLockGraph); v5/v6's own `dev`
   flag only serves an entry no importer reaches.
*/
function pnpmNameVersion(key) {
	let k = String(key || "");
	if (k.startsWith("/")) k = k.slice(1);
	const paren = k.indexOf("(");           // strip peer-deps suffix (v6/v9)
	if (paren !== -1) k = k.slice(0, paren);
	// v5 slash-form first: its "_peer@1.0.0" suffix has an "@" that the @-form below
	// would mistake for the version separator ("foo/1.0.0_react" @ "18.0.0").
	const v5 = /^(.+)\/(\d+\.\d+\.\d+[^_/]*)(?:_.*)?$/.exec(k);
	if (v5 && v5[1].indexOf("@", v5[1].startsWith("@") ? 1 : 0) === -1) return { name: v5[1], version: v5[2] };
	const at = k.lastIndexOf("@");          // @-form (v6/v9)
	if (at > 0 && /^\d/.test(k.slice(at + 1))) return { name: k.slice(0, at), version: k.slice(at + 1) };
	const slash = k.lastIndexOf("/");       // slash-form (v5)
	if (slash > 0 && /^\d/.test(k.slice(slash + 1))) return { name: k.slice(0, slash), version: k.slice(slash + 1) };
	return null;
}

function parsePnpmLock(filePath) {
	const raw = fs.readFileSync(filePath, "utf8");
	let doc;
	try { doc = yaml.load(raw) || {}; }
	catch (e) { throw new Error(`pnpm-lock parse failed (${filePath}): ${e.message}`); }
	const out = { manifestPath: filePath, manifestType: "pnpm-lock", lockfileVersion: doc.lockfileVersion || null, deps: [] };
	// v9 splits metadata (`packages`, peer-free keys) from the graph (`snapshots`,
	// peer-qualified keys); v5/v6 hold both in `packages`.
	const meta = (doc.packages && typeof doc.packages === "object") ? doc.packages : {};
	const graph = (doc.snapshots && typeof doc.snapshots === "object") ? doc.snapshots : meta;
	const nodes = new Map();
	const edges = new Map();
	for (const [key, rawEntry] of Object.entries(graph)) {
		const entry = rawEntry || {};
		const m = meta[key] || meta[String(key).split("(")[0]] || entry;
		const nv = pnpmNameVersion(key);
		const name = m.name || entry.name || (nv && nv.name);
		const version = String(m.version || entry.version || (nv && nv.version) || "").split("(")[0];
		if (!name || !/^\d/.test(version)) continue;
		const devFlag = entry.dev !== undefined ? entry.dev : m.dev;
		nodes.set(key, { name, version, children: new Set(), aliases: new Set(), devFlag: devFlag === true ? true : (devFlag === false ? false : undefined), integrity: (m.resolution && m.resolution.integrity) || null });
		edges.set(key, Object.entries({ ...(entry.dependencies || {}), ...(entry.optionalDependencies || {}) }));
	}
	const resolve = (name, ref) => {
		if (ref == null) return null;
		const r = String(typeof ref === "object" ? ref.version : ref);
		if (!r || /^(link|file|workspace):/.test(r)) return null;
		for (const k of [r, `${name}@${r}`, `/${name}@${r}`, `/${name}/${r}`, `/${r}`]) if (nodes.has(k)) return k;
		return null;
	};
	// An edge or a root whose name is not the target's real name is an alias install.
	const link = (name, ref) => {
		const id = resolve(name, ref);
		if (id && nodes.get(id).name !== name) nodes.get(id).aliases.add(name);
		return id;
	};
	for (const [id, refs] of edges) {
		for (const [n, ref] of refs) {
			const c = link(n, ref);
			if (c) nodes.get(id).children.add(c);
		}
	}
	const roots = [];
	const importers = doc.importers || ((doc.dependencies || doc.devDependencies || doc.optionalDependencies) ? { ".": doc } : null);
	if (importers && typeof importers === "object") {
		for (const imp of Object.values(importers)) {
			if (!imp || typeof imp !== "object") continue;
			for (const [section, scope] of [["dependencies", "prod"], ["optionalDependencies", "optional"], ["devDependencies", "dev"]]) {
				for (const [n, ref] of Object.entries(imp[section] || {})) {
					const id = link(n, ref);
					if (id) roots.push({ id, scope });
				}
			}
		}
	}
	out.deps = classifyLockGraph(nodes, roots);
	return out;
}

/* -------- discovery ---------- */
// Dirs that hold packaged / generated content — never our own source.
// Conservative list: only well-known build-output / package-cache dirs.
const DEFAULT_JS_SKIP_DIRS = new Set([
	"node_modules", "bower_components", "jspm_packages",
	".git", ".idea", ".vscode", ".gradle", ".mvn",
	"dist", "build", "out", "target", "coverage", ".next", ".nuxt",
]);

function findJsManifests(rootDir, opts = {}) {
	const { skipDirs = DEFAULT_JS_SKIP_DIRS } = opts;
	const skipDir = opts.skipDir || ((child, name) => skipDirs.has(name));
	const found = [];
	const stack = [rootDir];
	while (stack.length) {
		const cur = stack.pop();
		let entries;
		try { entries = fs.readdirSync(cur, { withFileTypes: true }); }
		catch { continue; }
		// Group lockfile per directory so we can prefer lock > package.json
		const here = { dir: cur, packageJson: null, packageLock: null, yarnLock: null, pnpmLock: null };
		for (const e of entries) {
			const p = path.join(cur, e.name);
			if (e.isDirectory()) {
				if (skipDir(p, e.name)) continue;
				stack.push(p);
			} else if (e.isFile()) {
				if (e.name === "package.json") here.packageJson = p;
				else if (e.name === "package-lock.json") here.packageLock = p;
				else if (e.name === "yarn.lock") here.yarnLock = p;
				else if (e.name === "pnpm-lock.yaml") here.pnpmLock = p;
			}
		}
		if (here.packageJson || here.packageLock || here.yarnLock || here.pnpmLock) found.push(here);
	}
	return found;
}

// Parallel equivalent of findJsManifests — concurrent readdir so the walk isn't
// serialized one round-trip at a time on a high-latency filesystem.
async function findJsManifestsAsync(rootDir, opts = {}) {
	const { skipDirs = DEFAULT_JS_SKIP_DIRS } = opts;
	const skipDir = opts.skipDir || ((child, name) => skipDirs.has(name));
	const { walkDirs } = require("../../parallel-walk");
	const found = [];
	await walkDirs(rootDir, {
		skipDir,
		onDir: (cur, entries) => {
			const here = { dir: cur, packageJson: null, packageLock: null, yarnLock: null, pnpmLock: null };
			for (const e of entries) {
				if (!e.isFile()) continue;
				const p = path.join(cur, e.name);
				if (e.name === "package.json") here.packageJson = p;
				else if (e.name === "package-lock.json") here.packageLock = p;
				else if (e.name === "yarn.lock") here.yarnLock = p;
				else if (e.name === "pnpm-lock.yaml") here.pnpmLock = p;
			}
			if (here.packageJson || here.packageLock || here.yarnLock || here.pnpmLock) found.push(here);
		},
	});
	return found;
}

/**
 * npm lockfiles put a URL where a version belongs whenever the dependency was installed
 * from one — package-lock v1 records `"version": "https://registry.npmjs.org/x/-/x-0.12.5.tgz"`.
 * A registry tarball carries the real semver in its filename, so recover it and the package
 * becomes scannable. Anything else (git ref, github: shorthand, file:/link:, a nightly with
 * no version in its name) has NO concrete version: return null so the repo's existing rule
 * applies — only concrete versions are matched, an unresolved dep is reported as unresolved
 * rather than assumed vulnerable to every CVE its coordinate ever had.
 */
function normaliseNpmVersion(v) {
	const s = String(v == null ? "" : v).trim();
	if (!s) return null;
	if (!/^[a-z+]+:/i.test(s)) return s;                       // a plain version or range
	const m = /-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\.tgz(?:[?#].*)?$/.exec(s);
	return m ? m[1] : null;
}

module.exports = {
	normaliseNpmVersion,
	parsePackageJson,
	parsePackageLock,
	parseYarnLockV1,
	parseYarnBerry,
	parsePnpmLock,
	findJsManifests,
	findJsManifestsAsync,
	DEFAULT_JS_SKIP_DIRS,
};
