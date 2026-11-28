/**
 * lib/codecs/gradle.codec.js — codec Gradle.
 *
 * A Gradle dependency IS a Maven coordinate resolved from Maven repositories, so records
 * are emitted with `ecosystem: "maven"` (bare `g:a` coordKey → the Maven CVE-index, OSV
 * "Maven", transitive resolution, import-BOM backfill, outdated and EOL all treat them
 * unchanged) but `ecosystemType: "gradle"` so the report gives them a dedicated "Gradle"
 * chapter and a Gradle fix recipe (cve-report's codecFor() resolves by ecosystemType).
 *
 * Parsing is lockfile-first (gradle.lockfile = resolved, authoritative) and otherwise
 * best-effort over the build scripts + version catalog (see ./gradle/parse.js). `platform()`
 * BOMs are surfaced in `_gradle.platformBoms` for the orchestrator to feed into the existing
 * lib/codecs/maven/bom.js backfill, mirroring Maven's `<scope>import</scope>` BOMs.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../inventory/dep-record");
const { parseGradleLockfile, parseGradleProperties, parseBuildScript } = require("./gradle/parse");
const { parseVersionCatalog } = require("./gradle/catalog");
const { compareMavenVersions } = require("./maven/version");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "out", "target", "build", ".gradle", ".mvn", "bin"]);
const BUILD_FILES = new Set(["build.gradle", "build.gradle.kts"]);
const SETTINGS_FILES = new Set(["settings.gradle", "settings.gradle.kts"]);
const DETECT_HITS = new Set([...BUILD_FILES, ...SETTINGS_FILES, "gradle.lockfile", "libs.versions.toml"]);

function readSafe(fp) { try { return fs.readFileSync(fp, "utf8"); } catch { return ""; } }
function inBuildSrc(fp) { return /(^|[\\/])buildSrc[\\/]/.test(fp); }
// A precompiled convention plugin (buildSrc/src/…/x.gradle.kts) is applied to the projects
// using it, so what it declares reaches them; buildSrc's OWN build script is the plugin
// project's build and reaches nobody.
function isConventionPlugin(fp) { return inBuildSrc(fp) && !BUILD_FILES.has(path.basename(fp)); }

const highest = vs => vs.reduce((a, b) => (a == null || compareMavenVersions(b, a) > 0 ? b : a), null);
/**
 * The version Gradle resolves for a declaration once the pins that reach it apply
 * (docs.gradle.org "Dependency constraints" / "Customizing resolution"): a force (or a
 * `strictly`) wins over everything, even as a downgrade; otherwise conflict resolution
 * takes the highest of the declared and the constrained versions — and a constraint
 * supplies the version of a declaration that has none.
 */
function pinnedVersion(dep, pins) {
	const mine = pins.filter(p => p.group === dep.group && p.name === dep.name && p.version);
	const forced = highest(mine.filter(p => p.kind === "force").map(p => p.version));
	if (forced) return forced;
	const constrained = highest(mine.map(p => p.version));
	if (!constrained) return dep.version || null;
	return dep.version ? highest([dep.version, constrained]) : constrained;
}

function dirFilter(dir, opts) {
	return require("../inventory/path-filter").makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
}

// One walk → classify every relevant Gradle file.
function walkGradle(dir, skipDir) {
	const buildFiles = [], catalogFiles = [], propsFiles = [];
	const lockByDir = new Map();
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		for (const e of entries) {
			const p = path.join(cur, e.name);
			if (e.isDirectory()) { if (!skipDir(p, e.name)) stack.push(p); continue; }
			if (!e.isFile()) continue;
			if (BUILD_FILES.has(e.name)) buildFiles.push(p);
			else if (SETTINGS_FILES.has(e.name)) { /* structure only; not a dep source */ }
			else if (e.name === "gradle.lockfile") lockByDir.set(cur, p);
			else if (e.name === "libs.versions.toml" || e.name.endsWith(".versions.toml")) catalogFiles.push(p);
			else if (e.name === "gradle.properties") propsFiles.push(p);
			else if (e.name.endsWith(".gradle.kts") || e.name.endsWith(".gradle")) buildFiles.push(p); // precompiled convention plugins (buildSrc)
		}
	}
	return { buildFiles, catalogFiles, propsFiles, lockByDir };
}

// Merge every version catalog in the tree into one resolution table (root + buildSrc).
function mergeCatalogs(files) {
	const merged = { versions: {}, libraries: {}, plugins: {}, _byAccessor: {} };
	for (const f of files) {
		const c = parseVersionCatalog(readSafe(f));
		Object.assign(merged.versions, c.versions);
		Object.assign(merged.libraries, c.libraries);
		Object.assign(merged.plugins, c.plugins);
		Object.assign(merged._byAccessor, c._byAccessor);
	}
	return merged;
}

module.exports = {
	id: "gradle",
	label: "Gradle",
	osvEcosystem: "Maven",
	manifestNames: ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile", "*.versions.toml"],

	detect(dir) {
		const skipDir = (p, name) => SKIP.has(name);
		const stack = [dir];
		while (stack.length) {
			const cur = stack.pop();
			let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
			for (const e of entries) {
				if (e.isFile() && (DETECT_HITS.has(e.name) || e.name.endsWith(".versions.toml"))) return true;
				if (e.isDirectory() && !skipDir(path.join(cur, e.name), e.name)) stack.push(path.join(cur, e.name));
			}
		}
		return false;
	},

	async collect(dir, opts = {}) {
		const { deps2Exclude } = opts;
		const skipDir = dirFilter(dir, opts);
		const { buildFiles, catalogFiles, propsFiles, lockByDir } = walkGradle(dir, skipDir);

		const catalog = mergeCatalogs(catalogFiles);
		const properties = {};
		for (const f of propsFiles) Object.assign(properties, parseGradleProperties(readSafe(f)));

		const out = new Map();
		const warnings = [];
		const platformBoms = [];

		const addRec = (d, manifestPath, extra = {}) => {
			if (!d.group || !d.name) return;
			// -e is a groupId regex everywhere else (Maven collector, cleaned-POM rewrite).
			if (deps2Exclude && deps2Exclude.test(d.group)) return;
			const rec = makeDepRecord({ ecosystem: "maven", ecosystemType: "gradle", namespace: d.group, name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: d.isDev });
			if (d.configurations) rec.gradleConfigurations = [...d.configurations];
			if (d.gradleDeclarations) rec.gradleDeclarations = d.gradleDeclarations.map(x => ({ configuration: x.configuration, exclusions: [...x.exclusions] }));
			if (extra.versionUnresolved) rec.versionUnresolved = true;
			if (d.exclusionSets) rec.exclusionSets = d.exclusionSets.map(x => [...x]);
			if (extra.managedOnly) rec.managedOnly = true;
			// A constraint (not a force/strictly) is a FLOOR for transitives: Gradle keeps the
			// higher of the constrained and the requested version.
			if (extra.pinMinimum) rec.pinMinimum = true;
			// A gradle.lockfile lists the RESOLVED graph, transitives included: its entries
			// are not resolution roots (re-walking them resurrects modules the lock excluded).
			if (extra.fromLockfile) rec.fromLockfile = true;
			const existing = out.get(rec.coordKey);
			if (!existing) { out.set(rec.coordKey, rec); return; }
			for (const p of rec.manifestPaths) if (!existing.manifestPaths.includes(p)) existing.manifestPaths.push(p);
			for (const v of rec.versions) if (!existing.versions.includes(v)) existing.versions.push(v);
			for (const [v, ps] of Object.entries(rec.versionPaths || {})) {
				const into = existing.versionPaths[v] || (existing.versionPaths[v] = []);
				for (const p of ps) if (!into.includes(p)) into.push(p);
			}
			// The record's single `version` is what pins transitives (rootDepMgmt): keep the
			// highest, as the Maven collector does, not whichever module was walked first.
			if (rec.version && (!existing.version || compareMavenVersions(rec.version, existing.version) > 0)) existing.version = rec.version;
			// Prod scope wins over dev — scope AND isDev, or a dep declared at test scope in
			// the first module walked kept scope "test" with isDev false.
			if (rec.isDev === false && existing.isDev !== false) { existing.isDev = false; existing.scope = rec.scope; }
			if (rec.exclusionSets) existing.exclusionSets = (existing.exclusionSets || []).concat(rec.exclusionSets);
			if (rec.gradleConfigurations) existing.gradleConfigurations = [...new Set([...(existing.gradleConfigurations || []), ...rec.gradleConfigurations])];
			if (rec.gradleDeclarations) existing.gradleDeclarations = (existing.gradleDeclarations || []).concat(rec.gradleDeclarations);
			if (rec.versionUnresolved) existing.versionUnresolved = true;
			if (!extra.managedOnly && existing.managedOnly) delete existing.managedOnly;
		};

		// gradle.lockfile = authoritative resolved versions (transitives incl.) for its project.
		// Constraints, forces and excludes are ALREADY applied in it — nothing below touches
		// a lock-governed project.
		const lockedDirs = new Set(lockByDir.keys());
		for (const [, fp] of lockByDir) {
			for (const d of parseGradleLockfile(readSafe(fp)).deps) addRec(d, fp, { fromLockfile: true });
		}

		// Pass 1 — what reaches OTHER build scripts: version pins and configuration excludes
		// declared in an `allprojects { }` / `subprojects { }` block, or in a buildSrc
		// convention plugin (applied to every project using it). Everything else in a build
		// script is that project's alone: a constraint in module B does not pin module A.
		const scripts = buildFiles.map(fp => ({ fp, text: readSafe(fp), kotlin: fp.endsWith(".kts") }));
		const globalPins = [];
		const globalExcludes = [];
		for (const s of scripts) {
			const r = parseBuildScript(s.text, { catalog, properties, kotlin: s.kotlin });
			for (const b of r.platformBoms) {
				if (b.inferred && buildFiles.length !== 1) {
					// The current collector merges coordinates across scripts, losing which
					// module owns a versionless occurrence. Do not apply one module's implicit
					// Boot BOM to its neighbours until per-module Gradle resolution exists.
					warnings.push({ type: "dependency-coverage", manifestPath: s.fp, message: "Implicit Spring Boot BOM not applied: multiple Gradle scripts require module-scoped resolution. Use a resolved Gradle lockfile or scan this module separately." });
					continue;
				}
				if (b.group && b.name && !platformBoms.some(x => x.group === b.group && x.name === b.name)) platformBoms.push(b.inferred ? { ...b, manifestPath: s.fp } : b);
			}
			const everything = isConventionPlugin(s.fp);
			for (const c of r.constraints) if (everything || c.global) globalPins.push({ ...c, fp: s.fp });
			for (const e of r.configExcludes) if (everything || e.global) globalExcludes.push({ ...e, fp: s.fp });
		}

		// Pass 2 — dependencies (skipped for a lock-governed top-level project), with the
		// versions Gradle would actually resolve once constraints and forces apply.
		const pins = []; // every pin that applies somewhere → managedOnly records below
		for (const s of scripts) {
			const fp = s.fp;
			const d = path.dirname(fp);
			const lockGoverned = lockedDirs.has(d) && !inBuildSrc(fp);
			if (lockGoverned) continue; // lockfile already provided resolved deps for this dir
			const r = parseBuildScript(s.text, { catalog, properties, kotlin: s.kotlin, extraExcludes: globalExcludes.filter(e => e.fp !== fp) });
			const applicable = r.constraints.map(c => ({ ...c, fp })).concat(globalPins.filter(p => p.fp !== fp));
			pins.push(...r.constraints.map(c => ({ ...c, fp })));
			for (const dep of r.deps) addRec({ ...dep, version: pinnedVersion(dep, applicable) }, fp, {
				versionUnresolved: r.unresolved.some(u => u.group === dep.group && u.name === dep.name),
			});
			if (!inBuildSrc(fp)) warnings.push({ type: "no-lockfile", manifestPath: fp, message: `no gradle.lockfile next to ${path.relative(dir, fp) || path.basename(fp)} — versions are resolved best-effort from the build script and version catalog. Without native Gradle resolution or a lockfile, POM-based transitive resolution can choose different versions than Gradle, causing incorrect alerts and omissions. Enable Gradle dependency locking for the configurations you need to audit.` });
			for (const u of r.unresolved) {
				if (pinnedVersion({ group: u.group, name: u.name, version: null }, applicable)) continue; // a constraint supplies it
				warnings.push({ type: "unresolved-versions", manifestPath: fp, message: `could not resolve the version variable for ${u.group}:${u.name} (${u.raw}) — excluded from CVE matching` });
			}
		}
		pins.push(...globalPins.filter(p => !pins.some(q => q.fp === p.fp && q.group === p.group && q.name === p.name && q.version === p.version && q.kind === p.kind)));

		// A constraint / force nothing DECLARES is a version pin, not a dependency: Gradle
		// applies it only if something brings the module in. Same contract as a Maven
		// <dependencyManagement>-only entry (lib/advisories/cve-match.js): flagged `managedOnly`, it pins
		// transitive versions (rootDepMgmt), never seeds resolution, becomes a transitive if
		// the graph reaches it, and is otherwise dropped by settleManagedOnly(). It used to be
		// a DIRECT dependency carrying every CVE of the pinned version.
		const pinGroups = new Map();
		for (const p of pins) {
			const key = coordKeyFor("maven", p.group, p.name);
			if (out.has(key) && !out.get(key).managedOnly) continue;
			const g = pinGroups.get(key) || { group: p.group, name: p.name, all: [], paths: [] };
			g.all.push(p);
			if (!g.paths.includes(p.fp)) g.paths.push(p.fp);
			pinGroups.set(key, g);
		}
		for (const g of pinGroups.values()) {
			const version = pinnedVersion({ group: g.group, name: g.name, version: null }, g.all);
			if (!version) continue;
			const pinMinimum = !g.all.some(p => p.kind === "force");
			for (const fp of g.paths) addRec({ group: g.group, name: g.name, version, scope: "compile", isDev: false }, fp, { managedOnly: true, pinMinimum });
		}

		const parsedManifests = [...buildFiles, ...lockByDir.values(), ...catalogFiles, ...propsFiles];
		return { deps: out, warnings, parsedManifests, _gradle: { platformBoms } };
	},

	coordKey(d) { return coordKeyFor("maven", d.namespace || d.groupId, d.name || d.artifactId); },
	formatCoord(d) { return `${d.namespace || d.groupId}:${d.name || d.artifactId}`; },
	osvPackageName(d) { return `${d.namespace || d.groupId}:${d.name || d.artifactId}`; },

	async checkRegistry(deps, opts = {}) {
		const outdated = require("../maintenance/outdated");
		const out = opts.allLibs ? await outdated.checkOutdatedDeps(deps, opts) : [];
		const deprecated = outdated.checkObsoleteDeps(deps);
		return { outdated: out, deprecated };
	},
	resolveEolProduct(d) { return require("../maintenance/outdated").findEolProduct(d); },

	recipe: require("./recipes").gradle,

	nativeScanners: [],
};
