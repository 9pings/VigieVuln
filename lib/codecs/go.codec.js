/**
 * lib/codecs/go.codec.js — codec Go (modules).
 *
 * Reads go.mod (authoritative on Go ≥1.17 — lists the full pruned graph) and
 * falls back to go.sum. Vuln recall via OSV (ecosystem "Go"); outdated via the
 * Go module proxy. The full module path is the dep name (namespace = "").
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const G = require("./go/parse");
const { mergeVersionEvidence } = require("./version-evidence");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "target", "vendor", "testdata"]);

function findGoDirs(dir, skipDir = (child, name) => SKIP.has(name)) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const names = new Set(entries.filter(e => e.isFile()).map(e => e.name));
		if (names.has("go.mod") || names.has("go.sum")) groups.push({ dir: cur, names });
		for (const e of entries) if (e.isDirectory() && !skipDir(path.join(cur, e.name), e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

function dirFilter(dir, opts) {
	return require("../path-filter").makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
}

module.exports = {
	id: "go",
	label: "Go",
	osvEcosystem: "Go",
	manifestNames: ["go.mod", "go.sum"],

	detect(dir) { return findGoDirs(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const parsedManifests = [];
		const add = (d, manifestPath) => {
			if (deps2Exclude && deps2Exclude.test(d.name)) return;
			const key = coordKeyFor("go", "", d.name);
			const record = makeDepRecord({ ecosystem: "go", namespace: "", name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: false });
			out.set(key, mergeVersionEvidence(out.get(key), record, d.managerRelations));
		};
		for (const g of findGoDirs(dir, dirFilter(dir, opts))) {
			let modHadDeps = false;
			const selectedHere = new Set();
			// Workspace overrides may change a selected version; do not claim root evidence there.
			let workspace = !!process.env.GOWORK && process.env.GOWORK !== "off";
			for (let cur = g.dir; ; cur = path.dirname(cur)) {
				if (fs.existsSync(path.join(cur, "go.work"))) workspace = true;
				if (path.dirname(cur) === cur) break;
			}
			let goMinor = null;
			if (g.names.has("go.mod")) {
				const fp = path.join(g.dir, "go.mod");
				parsedManifests.push(fp);
				try {
					const r = G.parseGoModFile(fp);
					const gm = /^1\.(\d+)/.exec(r.goVersion || "");
					goMinor = gm ? Number(gm[1]) : null;
					for (const d of r.dropped) {
						selectedHere.add(d.name);
						warnings.push({ type: "local-replace", manifestPath: fp, message: `${d.name}@${d.version} is replaced by local path ${d.path} — replacement version unknown, not scanned` });
					}
					if (r.deps.length) {
						for (const d of r.deps) {
							selectedHere.add(d.name);
							add(workspace ? { ...d, managerRelations: ["unknown"] } : d, fp);
						}
						modHadDeps = true;
					}
					// else: go.mod with no require list (rare / very old) → fall through to go.sum.
				} catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `go.mod parse failed: ${e.message}` }); }
			}
			// go.mod lists the FULL pruned graph only from `go 1.17` on. For older
			// (or unversioned) modules it lists direct deps only, so merge the
			// go.sum graph for anything go.mod didn't select — skipping it silently
			// dropped every transitive dep of a pre-1.17 module.
			const needSum = !modHadDeps || goMinor == null || goMinor < 17;
			if (needSum && g.names.has("go.sum")) {
				const fp = path.join(g.dir, "go.sum");
				parsedManifests.push(fp);
				try {
					const r = G.parseGoSumFile(fp);
					for (const d of r.deps) {
						if (selectedHere.has(d.name)) continue; // go.mod's selected version wins
						add(d, fp);
					}
				}
				catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `go.sum parse failed: ${e.message}` }); }
			}
		}
		return { deps: out, warnings, parsedManifests };
	},

	coordKey(d) { return coordKeyFor("go", "", d.name); },
	formatCoord(d) { return d.version ? `${d.name}@${d.version}` : d.name; },
	osvPackageName(d) { return d.name; },

	async checkRegistry(deps, opts = {}) {
		const { checkGoRegistryDeps } = require("./go/registry");
		return checkGoRegistryDeps(deps, opts);
	},
	resolveEolProduct() { return null; },
	recipe: require("./recipes").go,
	nativeScanners: [],
};
