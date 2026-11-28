/**
 * lib/inventory/manifest-copy.js — when writing a cleaned tree (`-t`), copy every NON-Maven
 * ecosystem manifest / lockfile from the source into the target at the same relative
 * path, so `snyk test --all-projects` on the cleaned tree scans every ecosystem — not
 * just the cleaned Maven POMs (which are written separately by core.rewritePoms).
 *
 * Maven is excluded (its cleaned POMs are the whole point of the rewrite); the binary
 * codec is excluded (its files aren't dependency manifests). node_modules / vendor and
 * friends are pruned so we copy the project's own lockfiles, not vendored ones.
 */
const fs = require("fs");
const path = require("path");
const { makeDirFilter } = require("./path-filter");
const { allCodecs } = require("../codecs");

// Ecosystems whose manifests/lockfiles Snyk reads off disk.
const COPY_ECOSYSTEMS = new Set(["npm", "nuget", "composer", "pypi", "go", "ruby"]);
// Companion files that aren't a codec's primary manifest but Snyk/the build need.
const COMPANION_FILES = ["Directory.Packages.props", "Directory.Build.props", "nuget.config", "Gemfile", "Pipfile", "go.work", "go.work.sum", "symfony.lock"];
// Directories never worth copying manifests from (installed/vendored trees).
const SKIP_DIRS = new Set([
	"node_modules", "bower_components", "jspm_packages", "vendor",
	".git", ".svn", ".hg", ".idea", ".vscode", ".gradle", ".mvn",
	"target", "dist", "build", "out", "bin", "obj", ".next", ".nuxt", "coverage",
]);

/** Pure: the exact filenames + extensions that count as a copyable manifest. */
function manifestMatchers() {
	const exact = new Set(COMPANION_FILES);
	const exts = [];
	for (const c of allCodecs()) {
		if (!COPY_ECOSYSTEMS.has(c.id)) continue;
		for (const n of c.manifestNames || []) {
			if (n.startsWith("*.")) exts.push(n.slice(1)); // "*.csproj" → ".csproj"
			else exact.add(n);
		}
	}
	return { exact, exts };
}

/** Pure: is this basename a manifest we copy? */
function isManifestName(name, matchers = manifestMatchers()) {
	return matchers.exact.has(name) || matchers.exts.some(e => name.endsWith(e));
}

/**
 * Copy every matching manifest from srcRoot into targetRoot at the same relative path.
 * @returns { copied: number, files: string[] } (files are relative paths)
 */
async function copyEcosystemManifests(srcRoot, targetRoot, opts = {}) {
	const matchers = manifestMatchers();
	const skipDir = makeDirFilter({ srcRoot, defaultSkip: SKIP_DIRS, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
	const files = [];
	const walk = async (dir) => {
		let entries;
		try { entries = await fs.promises.readdir(dir, { withFileTypes: true }); } catch { return; }
		for (const e of entries) {
			const abs = path.join(dir, e.name);
			if (e.isDirectory()) { if (!skipDir(abs, e.name)) await walk(abs); continue; }
			if (!e.isFile()) continue;
			if (!isManifestName(e.name, matchers)) continue;
			const rel = path.relative(srcRoot, abs);
			const dest = path.join(targetRoot, rel);
			try {
				await fs.promises.mkdir(path.dirname(dest), { recursive: true });
				await fs.promises.copyFile(abs, dest);
				files.push(rel);
			} catch { /* best effort per file */ }
		}
	};
	await walk(srcRoot);
	return { copied: files.length, files };
}

module.exports = { manifestMatchers, isManifestName, copyEcosystemManifests, COPY_ECOSYSTEMS };
