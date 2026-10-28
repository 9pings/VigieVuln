/**
 * lib/codecs/nuget.codec.js — codec C#/.NET (NuGet).
 *
 * Vuln scanning is OSV (ecosystem "NuGet", wired in Plan A). This codec adds
 * collection (packages.lock.json, else .csproj + Directory.Packages.props CPM,
 * else packages.config), NuGet registration registry (deprecation + outdated),
 * and EOL. NuGet ids are case-insensitive: the key is lowercased, dep.name keeps
 * the original casing for display / OSV.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const N = require("./nuget/parse");
const { mergeVersionEvidence } = require("./version-evidence");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "bin", "obj", "target", "packages"]);
// MSBuild project files share the same <PackageReference> schema — C#, F#, VB.
const PROJ_RE = /\.(csproj|fsproj|vbproj)$/i;

function findNugetDirs(dir, skipDir = (child, name) => SKIP.has(name)) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const files = entries.filter(e => e.isFile()).map(e => e.name);
		const csprojs = files.filter(f => PROJ_RE.test(f));
		if (files.includes("packages.lock.json") || files.includes("packages.config") || csprojs.length) {
			groups.push({ dir: cur, files, csprojs });
		}
		for (const e of entries) if (e.isDirectory() && !skipDir(path.join(cur, e.name), e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

function dirFilter(dir, opts) {
	return require("../path-filter").makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
}

module.exports = {
	id: "nuget",
	label: "NuGet",
	osvEcosystem: "NuGet",
	manifestNames: ["packages.lock.json", "*.csproj", "*.fsproj", "*.vbproj", "packages.config"],

	detect(dir) { return findNugetDirs(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const parsedManifests = [];
		const add = (d, manifestPath) => {
			if (deps2Exclude && deps2Exclude.test(d.name)) return;
			const key = coordKeyFor("nuget", "", d.name);
			const rec = makeDepRecord({ ecosystem: "nuget", namespace: "", name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: d.isDev });
			out.set(key, mergeVersionEvidence(out.get(key), rec, d.managerRelations));
		};
		// Directory.Packages.props applies to every project BELOW it (MSBuild walks
		// UP from the project dir; nearest file wins). Looking only in the project's
		// own directory missed root-level CPM — i.e. every modern centrally-managed
		// solution collected ZERO deps. Memoised per starting dir.
		const cpmMemo = new Map();
		const cpmFor = async (startDir) => {
			if (cpmMemo.has(startDir)) return cpmMemo.get(startDir);
			let found = { map: {}, path: null };
			let cur = startDir;
			while (true) {
				const fp = path.join(cur, "Directory.Packages.props");
				if (fs.existsSync(fp)) {
					try { found = { map: await N.parseDirectoryPackagesProps(fp), path: fp }; }
					catch { /* unparsable props → best-effort without CPM */ }
					break;
				}
				if (path.resolve(cur) === path.resolve(dir)) break;
				const parent = path.dirname(cur);
				if (parent === cur) break;
				cur = parent;
			}
			cpmMemo.set(startDir, found);
			return found;
		};
		for (const g of findNugetDirs(dir, dirFilter(dir, opts))) {
			if (g.files.includes("packages.lock.json")) {
				const fp = path.join(g.dir, "packages.lock.json");
				parsedManifests.push(fp);
				try { const { deps } = await N.parsePackagesLockJson(fp); for (const d of deps) add(d, fp); }
				catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `packages.lock.json parse failed: ${e.message}` }); }
				continue;   // lockfile is authoritative for this directory
			}
			// No lockfile → best-effort from .csproj (+CPM) and packages.config + warning.
			const cpmRes = g.csprojs.length ? await cpmFor(g.dir) : { map: {}, path: null };
			const cpm = cpmRes.map;
			if (cpmRes.path && !parsedManifests.includes(cpmRes.path)) parsedManifests.push(cpmRes.path);
			let pinned = 0, skipped = 0;
			for (const cs of g.csprojs) {
				const fp = path.join(g.dir, cs);
				parsedManifests.push(fp);
				try {
					const { deps, skipped: sk } = await N.parseCsproj(fp, cpm);
					for (const d of deps) { add(d, fp); pinned++; }
					skipped += sk;
				} catch { /* ignore unparsable csproj */ }
			}
			if (g.files.includes("packages.config")) {
				const fp = path.join(g.dir, "packages.config");
				parsedManifests.push(fp);
				try { const { deps } = await N.parsePackagesConfig(fp); for (const d of deps) { add(d, fp); pinned++; } } catch { /* ignore */ }
			}
			if (g.csprojs.length || g.files.includes("packages.config")) {
				warnings.push({ type: "no-lockfile", manifestPath: g.dir, message: `no packages.lock.json — best-effort: ${pinned} pinned, ${skipped} floating/unresolved skipped (enable RestorePackagesWithLockFile)` });
			}
		}
		return { deps: out, warnings, parsedManifests };
	},

	coordKey(d) { return coordKeyFor("nuget", "", d.name); },
	formatCoord(d) { return d.name; },
	osvPackageName(d) { return d.name; },

	async checkRegistry(deps, opts = {}) {
		const { checkNugetRegistryDeps } = require("./nuget/registry");
		return checkNugetRegistryDeps(deps, opts);
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	recipe: require("./recipes").nuget,
	nativeScanners: [],
};
