/**
 * lib/inventory/path-filter.js — directory-walk pruning policy shared by every codec walker.
 *
 * Two layers:
 *   - default skips: each walker's own basename set (node_modules, vendor, target,
 *     .git, …). Bypassable with useDefaults=false (CLI --no-default-excludes).
 *   - user globs: --exclude-path / `excludePath` config, matched gitignore-style
 *     against the directory's path RELATIVE to the scan root (`srcRoot`). A bare
 *     `foo/bar` matches that directory and its whole subtree (`foo/bar/**`).
 *
 * makeDirFilter() returns a predicate over a child directory's ABSOLUTE path, so
 * it drops straight into parallel-walk's skipDir and the serial readdir walkers.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { minimatch } = require("minimatch");

/**
 * Compile glob strings into (relPath) → bool matchers. Each glob prunes both the
 * matched directory itself and its whole subtree, so `packages/legacy/**` (or the
 * bare `packages/legacy`) stops the walk at `packages/legacy` — a manifest sitting
 * directly in it is never collected. Each matcher carries `.glob` (the original
 * trimmed pattern) so a caller can report WHICH glob matched (see makeDirFilter's
 * onSkip / collectExcludedDirs).
 */
function compileGlobs(globs) {
	return (globs || []).filter(Boolean).map(String).map(g => g.trim()).filter(Boolean).map(g => {
		// Paths match relative to srcRoot, so they're already root-anchored. Accept
		// `truc`, `/truc` and `./truc` as the same thing (strip a leading ./ or /).
		const base = g.replace(/^\.?\/+/, "").replace(/\/+$/, "");
		const patterns = base.endsWith("/**")
			? [base, base.slice(0, -3).replace(/\/+$/, "")] // dir + its subtree
			: [base, base + "/**"];
		const fn = rel => patterns.some(p => p && minimatch(rel, p, { dot: true }));
		fn.glob = g;
		return fn;
	});
}

/**
 * Superset of every walker's default-skip basename set (Maven core.js, detectCodecs,
 * npm parse.js, the composer/go/nuget/pypi/ruby/gradle/binary codecs, retire.js).
 * Used as the canonical "what the prune policy excludes" set for the report's
 * ignored-directories appendix (collectExcludedDirs). Individual walkers still use
 * their OWN narrower sets — this union is purely for reporting which dirs the scan
 * skipped. Keep in sync when a codec adds a SKIP entry.
 */
const DEFAULT_EXCLUDE_DIRS = new Set([
	// package stores / vendored trees
	"node_modules", "bower_components", "jspm_packages", "vendor", "packages", "site-packages",
	// build output
	"target", "dist", "build", "build-output", "out", "bin", "obj", "coverage", ".next", ".nuxt",
	// language caches / virtualenvs
	"__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".cache", ".m2", "tmp", "testdata",
	// VCS / IDE / tool metadata
	".git", ".svn", ".hg", ".idea", ".vscode", ".gradle", ".mvn",
]);

/**
 * Build a skipDir(absChildDir) predicate.
 *   srcRoot       scan root the globs are relative to
 *   defaultSkip   Set of basenames the walker prunes by default (its own SKIP)
 *   excludePath   user glob strings
 *   useDefaults   when false, ignore defaultSkip entirely (--no-default-excludes)
 *   onSkip        optional (absChild, reason) callback fired when a dir is pruned;
 *                 reason is { type:"default", name } or { type:"exclude-path", glob }.
 */
function makeDirFilter({ srcRoot, defaultSkip = null, excludePath = [], useDefaults = true, onSkip = null } = {}) {
	const matchers = compileGlobs(excludePath);
	return function skipDir(absChild) {
		const name = path.basename(absChild);
		if (useDefaults && defaultSkip && defaultSkip.has(name)) {
			if (onSkip) onSkip(absChild, { type: "default", name });
			return true;
		}
		if (matchers.length && srcRoot) {
			const rel = path.relative(srcRoot, absChild).split(path.sep).join("/");
			if (rel && !rel.startsWith("..")) {
				const hit = matchers.find(m => m(rel));
				if (hit) {
					if (onSkip) onSkip(absChild, { type: "exclude-path", glob: hit.glob });
					return true;
				}
			}
		}
		return false;
	};
}

/**
 * Walk `srcRoot` once and return the ACTUAL directories the scan's prune policy
 * excludes — the report's ignored-directories appendix. Applies the same policy the
 * codec walkers do (DEFAULT_EXCLUDE_DIRS by basename + the user's --exclude-path
 * globs, both honoring --no-default-excludes), records each pruned dir relative to
 * the scan root with WHY it was pruned, and never descends into a pruned dir (so a
 * top-level `node_modules` is reported once, not its thousands of children).
 *
 * Returns [{ dir, type, reason }] sorted by path. `dir` is POSIX-relative to srcRoot.
 */
function collectExcludedDirs({ srcRoot, excludePath = [], defaultExcludes = true } = {}) {
	if (!srcRoot) return [];
	let root;
	try { root = fs.realpathSync(path.resolve(srcRoot)); } catch { root = path.resolve(srcRoot); }
	const found = [];
	const onSkip = (absChild, reason) => {
		const rel = path.relative(root, absChild).split(path.sep).join("/") || ".";
		found.push(reason.type === "default"
			? { dir: rel, type: "default", reason: `default-exclude (${reason.name})` }
			: { dir: rel, type: "exclude-path", reason: `--exclude-path (${reason.glob})` });
	};
	const skipDir = makeDirFilter({ srcRoot: root, defaultSkip: DEFAULT_EXCLUDE_DIRS, excludePath, useDefaults: defaultExcludes !== false, onSkip });
	// Iterative DFS. We only ever descend into NON-pruned dirs, so the heavy trees
	// (node_modules, …) are cut at the top — the walk stays bounded by the real
	// source tree. A high guard backstops a pathological symlink-free deep tree.
	const stack = [root];
	let guard = 0;
	const GUARD_MAX = 2_000_000;
	while (stack.length && guard < GUARD_MAX) {
		const dir = stack.pop();
		let entries;
		try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
		for (const e of entries) {
			if (!e.isDirectory()) continue;   // isDirectory() is false for symlinks → no loops
			guard++;
			const absChild = path.join(dir, e.name);
			if (skipDir(absChild)) continue;  // onSkip recorded it; do NOT descend
			stack.push(absChild);
		}
	}
	found.sort((a, b) => a.dir.localeCompare(b.dir));
	return found;
}

module.exports = { makeDirFilter, compileGlobs, collectExcludedDirs, DEFAULT_EXCLUDE_DIRS };
