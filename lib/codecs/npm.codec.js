/**
 * lib/codecs/npm.codec.js — codec npm.
 *
 * Enveloppe les parsers lib/codecs/npm/parse.js + le collecteur lib/codecs/npm/collect.js
 * (package-lock v1/2/3, yarn.lock v1) et le scanner natif retire.js.
 * Aucune logique nouvelle : extraction derrière l'interface codec.
 *
 * npm.collect ramasse package-lock ET yarn.lock — chaque dep porte son
 * `ecosystemType` ("npm" | "yarn"). Le codec yarn (yarn.codec.js) n'existe que
 * pour fournir son label/recette au report ; il ne re-scanne pas.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { collectNpmDeps, hasJsManifests } = require("./npm/collect");
const { coordKeyFor } = require("../dep-record");

// Scanner natif : retire.js (JS vendored sans lockfile). scan(deps,opts) → {matches,meta}.
const retireScanner = {
	id: "retire",
	kind: "vendored",   // résultats → chapitre vendored-JS (séparé des CVE)
	async scan(_deps, opts = {}) {
		const { scanWithRetireFull } = require("../retire");
		const { matches, inventory, error } = await scanWithRetireFull(opts.src, { verbose: opts.verbose, force: !!opts.retireRefresh, offline: !!opts.offline, excludePath: opts.excludePath, defaultExcludes: opts.defaultExcludes });
		return { matches, meta: { inventory, error } };
	},
};

const base = {
	osvEcosystem: "npm",
	manifestNames: ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
	detect(dir) { return hasJsManifests(dir); },
	coordKey(d) { return coordKeyFor("npm", "", d.name || d.artifactId); },
	formatCoord(d) { return d.name || d.artifactId; },
	osvPackageName(d) { return d.name || d.artifactId; },
	async checkRegistry(deps, opts = {}) {
		const { checkNpmRegistryDeps } = require("./npm/registry");
		const r = await checkNpmRegistryDeps(deps, opts);
		return r;
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	nativeScanners: [retireScanner],
};

module.exports = {
	...base,
	id: "npm",
	label: "npm",
	recipe: require("./recipes").npm,
	// collect ramasse TOUTES les deps JS (package-lock + yarn.lock).
	async collect(dir, opts = {}) {
		// Parallel manifest discovery (concurrent readdir) — much faster than the
		// serial walk on a high-latency filesystem; parsing then runs synchronously.
		const { findJsManifestsAsync, DEFAULT_JS_SKIP_DIRS } = require("./npm/parse");
		const { makeDirFilter } = require("../path-filter");
		const skipDir = makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: DEFAULT_JS_SKIP_DIRS, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
		const manifestGroups = await findJsManifestsAsync(dir, { skipDir });
		const deps = collectNpmDeps(dir, { ...opts, manifestGroups });
		return { deps, warnings: deps.warnings || [], parsedManifests: deps.parsedManifests || [] };
	},
};
