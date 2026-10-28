/**
 * lib/codecs/pypi.codec.js — codec Python/PyPI.
 *
 * Vuln scanning is OSV (ecosystem "PyPI", wired in Plan A). This codec adds
 * collection (poetry.lock/Pipfile.lock/uv.lock/pdm.lock, requirements.txt
 * fallback), PyPI registry (yanked/inactive + outdated), and EOL.
 * Per-directory precedence: a lockfile wins; else requirements.txt best-effort.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const P = require("./pypi/parse");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "target", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", "site-packages"]);
const LOCKS = [
	["poetry.lock", P.parsePoetryLock],
	["Pipfile.lock", P.parsePipfileLock],
	["uv.lock", P.parseUvLock],
	["pdm.lock", P.parsePdmLock],
];

// The whole requirements*.txt family, not just the literal "requirements.txt": projects
// using pip-compile/Dependabot keep their actual pins in requirements-pinned.txt (or
// similar) while requirements.txt holds only ranges. requirements-(dev|test|lint|docs|…)
// are dev/optional tooling.
const REQ_RE = /^requirements.*\.txt$/i;
const DEV_REQ_RE = /requirements[-_.](dev|test|tests|lint|docs?|typing|type|check|ci|mypy|style|format)\b/i;
const reqFilesIn = names => [...names].filter(n => REQ_RE.test(n)).sort();

function findPyDirs(dir, skipDir = (child, name) => SKIP.has(name)) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const names = new Set(entries.filter(e => e.isFile()).map(e => e.name));
		const qualifies = LOCKS.some(l => names.has(l[0])) || names.has("pyproject.toml") || reqFilesIn(names).length > 0;
		if (qualifies) groups.push({ dir: cur, names });
		for (const e of entries) if (e.isDirectory() && !skipDir(path.join(cur, e.name), e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

function pyDirFilter(dir, opts) {
	return require("../path-filter").makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
}

module.exports = {
	id: "pypi",
	label: "PyPI",
	osvEcosystem: "PyPI",
	manifestNames: ["poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "pyproject.toml", "requirements.txt"],

	detect(dir) { return findPyDirs(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { ignoreTest, deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const parsedManifests = [];
		const add = (d, manifestPath) => {
			if (ignoreTest && d.isDev) return;
			if (deps2Exclude && deps2Exclude.test(d.name)) return;
			const key = coordKeyFor("pypi", "", d.name);
			const rec = makeDepRecord({ ecosystem: "pypi", namespace: "", name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: d.isDev });
			const existing = out.get(key);
			if (!existing) { out.set(key, rec); return; }
			// Same package across several requirements files: merge manifests, keep a concrete
			// version, and let prod win over dev (declared prod anywhere ⇒ prod).
			for (const p of rec.manifestPaths) if (!existing.manifestPaths.includes(p)) existing.manifestPaths.push(p);
			if (!existing.version && rec.version) { existing.version = rec.version; if (!existing.versions.includes(rec.version)) existing.versions.push(rec.version); }
			// Two files pinning DIFFERENT versions of the same package: every distinct
			// concrete version is scanned (same convention as Maven), not just the first.
			else if (rec.version && !existing.versions.includes(rec.version)) existing.versions.push(rec.version);
			if (existing.isDev && !rec.isDev) { existing.isDev = false; existing.scope = rec.scope || "prod"; }
		};
		for (const g of findPyDirs(dir, pyDirFilter(dir, opts))) {
			const lock = LOCKS.find(([n]) => g.names.has(n));
			if (lock) {
				const fp = path.join(g.dir, lock[0]);
				parsedManifests.push(fp);
				try { const { deps } = lock[1](fp); for (const d of deps) add(d, fp); }
				catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `${lock[0]} parse failed: ${e.message}` }); }
				continue;   // lockfile is authoritative for this directory
			}
			// No lockfile → best-effort from pyproject.toml and EVERY requirements*.txt file.
			let skipped = 0;
			const sources = [];
			const before = out.size;
			if (g.names.has("pyproject.toml")) {
				const fp = path.join(g.dir, "pyproject.toml");
				parsedManifests.push(fp);
				try {
					const r = P.parsePyprojectToml(fp);
					for (const d of r.deps) add(d, fp);
					skipped += r.skipped;
					if (r.deps.length || r.skipped) sources.push("pyproject.toml");
				} catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `pyproject.toml parse failed: ${e.message}` }); }
			}
			for (const rf of reqFilesIn(g.names)) {
				const fp = path.join(g.dir, rf);
				parsedManifests.push(fp);
				const devFile = DEV_REQ_RE.test(rf);
				try {
					const r = P.parseRequirementsTxt(fp, dir);
					for (const d of r.deps) add(devFile ? { ...d, isDev: true, scope: "dev" } : d, fp);
					skipped += r.skipped;
					sources.push(rf);
					for (const miss of (r.missing || [])) warnings.push({ type: "missing-include", manifestPath: fp, message: `referenced requirements file not found: ${miss}` });
				} catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `${rf} parse failed: ${e.message}` }); }
			}
			if (sources.length) {
				const pinned = out.size - before;
				const shownSrc = sources.length > 4 ? `${sources.slice(0, 4).join(" + ")} + ${sources.length - 4} more` : sources.join(" + ");
				warnings.push({ type: "no-lockfile", manifestPath: g.dir, message: `no lockfile (${shownSrc}) — best-effort: ${pinned} pinned, ${skipped} range(s) skipped` });
			}
		}
		return { deps: out, warnings, parsedManifests };
	},

	coordKey(d) { return coordKeyFor("pypi", "", d.name); },
	formatCoord(d) { return d.name; },
	osvPackageName(d) { return d.name; },

	async checkRegistry(deps, opts = {}) {
		const { checkPypiRegistryDeps } = require("./pypi/registry");
		return checkPypiRegistryDeps(deps, opts);
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	recipe: require("./recipes").pypi,
	nativeScanners: [],
};
