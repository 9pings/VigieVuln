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
		const { ensureCveIndex, loadCveIndex, newIndex, addToIndex, isCurrentCveIndex } = require("../cve-download");
		const store = require("../advisory-store").openAdvisoryStore();
		try {
		const { matchCveStore } = require("../native-advisories");
		const hasStored = () => !!(store.getSourceCoverage('cveproject','*') || store.getSourceCoverage('cveproject-legacy','*'));
		const fallback = err => {
			const idx = loadCveIndex();
			if (!idx && !hasStored()) throw err;
			const result = matchCveStore(deps, store, idx);
			return {matches:result.matches,meta:{cveDataDate:idx?.meta?.builtAt || null,incomplete:true,refreshError:err.message,identityUncertain:result.identityUncertain || (!!idx && !isCurrentCveIndex(idx)),uncertainCandidates:result.uncertainCandidates,oldProjection:!!idx && !isCurrentCveIndex(idx)}};
		};
		if (opts.hostedProxy && !opts.offline && !opts.cveOffline) {
		 try {
			const keys = new Set();
			for (const dep of deps.values()) {
				if ((dep.ecosystem && dep.ecosystem !== "maven") || dep.provenance === "binary") continue;
				const group = String(dep.groupId || "").toLowerCase(), artifact = String(dep.artifactId || "").toLowerCase();
				if (group && artifact) keys.add("p:" + group + ":" + artifact);
				if (artifact) keys.add("a:" + artifact);
			}
			const idx = newIndex(), all = [...keys], seen = new Set(), collected = [];
			let oldestFetchedAt = Infinity, oldestBuiltAt = Infinity, timestampsKnown = true, builtAtKnown = true, staleResponse = false;
			for (let i = 0; i < all.length; i += 200) {
				const res = await require("../providers").getResource("github", "cve-maven", { keys: all.slice(i, i + 200) }, { forceRefresh:true });
				if (!res.ok) throw new Error(`hosted CVE index unavailable (HTTP ${res.status})`);
				const data = await res.json();
				if (!Array.isArray(data.cves)) throw new Error("invalid hosted CVE index response");
				const stamp = Date.parse(res.headers?.get('x-fad-proxy-fetched-at') || '');
				if (!Number.isFinite(stamp) || stamp <= 0 || stamp > Date.now()+300000) timestampsKnown = false;
				else oldestFetchedAt = Math.min(oldestFetchedAt, stamp);
				if (res.headers?.get('x-fad-proxy') === 'stale') staleResponse = true;
				const built = Date.parse(data.builtAt || '');
				if (!Number.isFinite(built) || built <= 0 || built > Date.now()+300000) builtAtKnown = false;
				else oldestBuiltAt = Math.min(oldestBuiltAt, built);
				idx.meta.builtAt = data.builtAt;
				for (const cve of data.cves) if (!seen.has(cve.id)) { seen.add(cve.id); addToIndex(idx, cve); collected.push(cve); }
			}
			const fetchedAt = timestampsKnown && Number.isFinite(oldestFetchedAt) ? oldestFetchedAt : null;
			const provenance = {transport:'proxy'};
			const {projectedCveEnvelope} = require('../native-advisories');
			if (fetchedAt) {
			 for (let i=0;i<collected.length;i+=100) store.commit({records:collected.slice(i,i+100).map(cve=>projectedCveEnvelope(cve,fetchedAt,provenance))});
			 store.commit({coverages:[{source:'cveproject-legacy',ecosystem:'*',fetchedAt,complete:false,provenance}]});
			}
			// A proxy projection cannot prove that a rejected CVE was reinstated.
			// Preserve the native tombstone regardless of the proxy corpus date;
			// only a newer native published revision may replace it in the store.
			let identityUncertain = false;
			const uncertainCandidates=[];
			let matches = matchDepsAgainstCves(deps,idx,{onUncertain:candidate=>{identityUncertain=true;uncertainCandidates.push(candidate);}}), conflict = false;
			const {isWithdrawn} = require('../advisory-store');
			matches = matches.filter(m => {
			 const native = store.getRecord('cveproject',m.cve.id);
			 if (native && isWithdrawn(native)) {conflict=true; return false;}
			 return true;
			});
			// Other native revisions may supersede a complete proxy batch only
			// when their revision is demonstrably newer than its corpus date.
			if (builtAtKnown && Number.isFinite(oldestBuiltAt)) {
			 const nativeResult=matchCveStore(deps,store,null), nativeMatches=nativeResult.matches;
			 identityUncertain ||= nativeResult.identityUncertain;
			 uncertainCandidates.push(...nativeResult.uncertainCandidates);
			 const newer = id => {const r=store.getRecord('cveproject',id);const at=Date.parse(r?.document?.cveMetadata?.dateUpdated || '');return r && Number.isFinite(at) && at > oldestBuiltAt ? r : null;};
			 matches=matches.filter(m=>{const r=newer(m.cve.id);if(r){conflict=true;return false;}return true;});
			 for (const m of nativeMatches) if(newer(m.cve.id)) {conflict=true;matches.push(m);}
			}
			return { matches, meta: { cveDataDate: builtAtKnown && Number.isFinite(oldestBuiltAt) ? new Date(oldestBuiltAt).toISOString() : null, incomplete: true,
				stale: staleResponse || (fetchedAt != null && opts.queryTtlMs != null && Date.now()-fetchedAt >= opts.queryTtlMs), timestampUnknown: !fetchedAt, conflict, identityUncertain, uncertainCandidates } };
		 } catch (err) { return fallback(err); }
		}
		let idx;
		if ((opts.offline || opts.cveOffline) && !loadCveIndex() && (store.getSourceCoverage('cveproject','*') || store.getSourceCoverage('cveproject-legacy','*'))) idx = null;
		else try { idx = await ensureCveIndex({
			force: !!opts.cveRefresh && !opts.offline,
			offline: !!opts.cveOffline || !!opts.offline,
			verbose: opts.verbose,
			ttlMs: opts.queryTtlMs,
		}); } catch (err) { return fallback(err); }
		const result = matchCveStore(deps, store, idx);
		const oldProjection = !!idx && !isCurrentCveIndex(idx);
		// A complete current Maven index is itself a complete projection of the
		// source, even if the separate native-record journal is only partial.
		const snapshot = store.db.prepare("SELECT complete,stale FROM cache_snapshots WHERE namespace='cve_lookup'").get();
		const completeIndex = !!idx && !oldProjection && snapshot?.complete === 1 && snapshot.stale === 0;
		return { matches: result.matches, meta: { cveDataDate: idx?.meta?.builtAt || (result.coverage?.fetchedAt ? new Date(result.coverage.fetchedAt).toISOString() : null), incomplete: !(result.coverage?.complete || completeIndex), identityUncertain:result.identityUncertain || oldProjection, uncertainCandidates:result.uncertainCandidates,oldProjection } };
		} finally { store.close(); }
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
