/**
 * lib/codecs/maven.codec.js — codec Maven.
 *
 * N'INTRODUIT AUCUNE LOGIQUE NOUVELLE : enveloppe la résolution POM/BOM de
 * lib/core.js (parse, parent, merge multi-profils, dependencyManagement, imports
 * scope=import), le collecteur lib/cve-match.js, le walker transitif
 * lib/transitive.js et le scanner natif CVE-index (cvelistV5).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const core = require("../core");
const { collectResolvedDeps, expandWithTransitives, matchDepsAgainstCves } = require("../cve-match");
const { coordKeyFor } = require("../dep-record");

// Scanner natif : CVE-index local cvelistV5. scan(deps,opts) → {matches, meta}.
const cveIndexScanner = {
	id: "cve-index",
	kind: "cve",   // résultats → chapitre CVE (mergés avec OSV)
	async scan(deps, opts = {}) {
		const { ensureCveIndex, newIndex, addToIndex } = require("../cve-download");
		if (opts.hostedProxy && !opts.offline && !opts.cveOffline) {
			const keys = new Set();
			for (const dep of deps.values()) {
				if (dep.ecosystem === "npm" || dep.provenance === "binary") continue;
				const group = String(dep.groupId || "").toLowerCase(), artifact = String(dep.artifactId || "").toLowerCase();
				if (group && artifact) keys.add("p:" + group + ":" + artifact);
				if (artifact) keys.add("a:" + artifact);
			}
			const idx = newIndex(), all = [...keys], seen = new Set();
			for (let i = 0; i < all.length; i += 200) {
				const res = await require("../providers").getResource("github", "cve-maven", { keys: all.slice(i, i + 200) }, { noStore: true, streaming: true });
				if (!res.ok) throw new Error(`hosted CVE index unavailable (HTTP ${res.status})`);
				const data = await res.json();
				if (!Array.isArray(data.cves)) throw new Error("invalid hosted CVE index response");
				idx.meta.builtAt = data.builtAt;
				for (const cve of data.cves) if (!seen.has(cve.id)) { seen.add(cve.id); addToIndex(idx, cve); }
			}
			return { matches: matchDepsAgainstCves(deps, idx), meta: { cveDataDate: idx.meta.builtAt } };
		}
		const idx = await ensureCveIndex({
			force: !!opts.cveRefresh && !opts.offline,
			offline: !!opts.cveOffline || !!opts.offline,
			verbose: opts.verbose,
		});
		return { matches: matchDepsAgainstCves(deps, idx), meta: { cveDataDate: idx?.meta?.builtAt || null } };
	},
};

module.exports = {
	id: "maven",
	label: "Maven",
	osvEcosystem: "Maven",
	manifestNames: ["pom.xml"],

	detect(dir) { return core.findPomFiles(dir).length > 0; },

	// collect enveloppe parse + inheritance + collectResolvedDeps existants.
	// Expose _maven (store/propsByPom/pomFiles) pour que l'orchestrateur garde la
	// phase de réécriture des POM nettoyés (lib/core.rewritePoms).
	async collect(dir, opts = {}) {
		const { makeDirFilter } = require("../path-filter");
		const skipDir = makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: core.SKIP_DIRS, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
		const pomFiles = await core.findPomFilesAsync(dir, skipDir);
		const store = core.newMetadataStore();
		const propsByPom = {};
		for (const pom of pomFiles) {
			try { await core.parsePom(pom, store); } catch { /* logged by orchestrator */ }
		}
		for (const pom of Object.keys(store.byPath)) {
			try { await core.getAllInheritedProps(pom, store, propsByPom); } catch { /* logged */ }
		}
		const deps = collectResolvedDeps(store, propsByPom, { ignoreTest: opts.ignoreTest, deps2Exclude: opts.deps2Exclude });
		const warnings = [];
		// Embedded binaries: discover Maven coordinates inside committed .jar/.war/.ear
		// archives (vendored libs, fat-jars). Keyed by physical location so they don't
		// merge with declared deps (they get their own report chapter). Default on;
		// opts.scanJars === false (--no-jars) disables it.
		if (opts.scanJars !== false) {
			try {
				const { scanEmbeddedJars } = require("./maven/jar-scan");
				const { deps: embedded, warnings: jarWarnings } = await scanEmbeddedJars(dir, { srcRoot: opts.srcRoot || dir, excludePath: opts.excludePath, defaultExcludes: opts.defaultExcludes, onProgress: opts.onJarProgress });
				for (const rec of embedded) deps.set(rec.coordKey, rec);
				warnings.push(...jarWarnings);
			} catch (e) { warnings.push({ type: "embedded-jar", message: `embedded-jar scan failed: ${e.message}` }); }
		}
		return { deps, warnings, parsedManifests: pomFiles.slice(), _maven: { store, propsByPom, pomFiles } };
	},

	coordKey(d) { return coordKeyFor("maven", d.namespace || d.groupId, d.name || d.artifactId); },
	formatCoord(d) { return `${d.namespace || d.groupId}:${d.name || d.artifactId}`; },
	osvPackageName(d) { return `${d.namespace || d.groupId}:${d.name || d.artifactId}`; },

	async checkRegistry(deps, opts = {}) {
		const outdated = require("../outdated");
		const out = opts.allLibs ? await outdated.checkOutdatedDeps(deps, opts) : [];
		const deprecated = outdated.checkObsoleteDeps(deps);
		return { outdated: out, deprecated };
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },

	recipe: require("./recipes").maven,

	nativeScanners: [cveIndexScanner],

	// Exposé pour l'orchestrateur (étape transitive, --transitive).
	expandTransitives: expandWithTransitives,
};
