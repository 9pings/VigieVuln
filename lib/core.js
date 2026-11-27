/**
 * lib/core.js — pure logic for parsing and cleaning Maven POMs.
 * No CLI, no console formatting. Callers pass options explicitly.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { parseStringPromise, Builder } = require("xml2js");

const SKIP_DIRS = new Set([
	"target", "node_modules", "bower_components", "jspm_packages",
	".git", ".idea", ".vscode", ".gradle", ".mvn",
	"dist", "build-output", "out", "coverage", ".next", ".nuxt",
	// NOTE: "build" is intentionally NOT skipped — Maven multi-module projects
	// sometimes use a "build/" module to hold a BOM or shared parent.
]);

const coord = v => (v == null ? null : String(v).trim() || null);

/**
 * Interpolate `${…}` in a single string against a POM property map. Values arrive from
 * xml2js as arrays, hence the unwrap. Resolution is recursive (`${a}` → `${b}` → value),
 * bounded, and stops when it stops making progress; an unknown reference is left verbatim
 * so it still surfaces downstream as an unresolved version rather than a wrong one.
 *
 * Deliberately local to core.js: the equivalent in cve-match.js can't be reused without
 * making core depend on it, and cve-match already depends on core.
 */
function interpolate(value, props) {
	if (value == null) return value;
	let out = String(value);
	for (let i = 0; i < 10 && out.includes("${"); i++) {
		const next = out.replace(/\$\{\s*([\w._-]+)\s*\}/g, (m, k) => {
			const val = props?.[k];
			if (Array.isArray(val)) return val[0];
			return val != null ? val : m;
		});
		if (next === out) break;
		out = next;
	}
	return out;
}

/**
 * A dependencyManagement node with its coordinate resolved against `props`. Returns a NEW
 * node — these xml2js structures are shared across POMs, so mutating one corrupts every
 * other reader of the same parsed document.
 */
function resolveDepNodeProps(dep, props) {
	if (!dep || !props) return dep;
	const out = { ...dep };
	for (const field of ["groupId", "artifactId", "version"]) {
		const raw = dep[field]?.[0];
		if (raw == null) continue;
		const resolved = interpolate(raw, props);
		if (resolved !== raw) out[field] = [resolved];
	}
	return out;
}

const defaultPomSkip = child => SKIP_DIRS.has(path.basename(child));

function findPomFiles(dir, skipDir = defaultPomSkip) {
	const out = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries;
		try { entries = fs.readdirSync(cur, { withFileTypes: true }); }
		catch { continue; }
		for (const e of entries) {
			if (e.isDirectory()) {
				const child = path.join(cur, e.name);
				if (skipDir(child, e.name)) continue;
				stack.push(child);
			} else if (e.name === "pom.xml") {
				out.push(path.join(cur, e.name));
			}
		}
	}
	return out.sort();
}

// Parallel equivalent of findPomFiles — same result, but readdir runs concurrently
// so the walk isn't serialized one round-trip at a time on a high-latency filesystem.
async function findPomFilesAsync(dir, skipDir = defaultPomSkip) {
	const { walkDirs } = require("./parallel-walk");
	const out = [];
	await walkDirs(dir, {
		skipDir,
		onDir: (cur, entries) => {
			for (const e of entries) if (e.isFile() && e.name === "pom.xml") out.push(path.join(cur, e.name));
		},
	});
	return out.sort();
}

function newMetadataStore() {
	return {
		byPath: {},
		byId: {},
		duplicateGavs: new Set(),
		excludedById: {},
		missingById: {},
		anyMissingById: {},
	};
}

async function parsePom(pomPath, allPomMetadata) {
	const xml = fs.readFileSync(pomPath, "utf8");
	// Skip POM templates that use literal `\${...}` placeholders.
	if (/\\\$\{/g.test(xml)) return;

	let json;
	try { json = await parseStringPromise(xml); }
	catch (e) { throw new Error(`xml parse failed: ${e.message}`); }

	const project = json?.project || {};
	const parent = project?.parent?.[0];
	const parentInfo = parent ? {
		groupId: coord(parent.groupId?.[0]),
		artifactId: coord(parent.artifactId?.[0]),
		version: coord(parent.version?.[0]),
		relativePath: parent.relativePath?.[0],
	} : null;

	const groupId = coord(project.groupId?.[0]) || parentInfo?.groupId || null;
	const artifactId = coord(project.artifactId?.[0]);
	const version = coord(project.version?.[0]) || parentInfo?.version || null;

	let profilesById = null;
	let defaultProfileId = null;
	if (project.profiles?.[0]?.profile) {
		profilesById = {};
		for (const profile of project.profiles[0].profile) {
			if (!profile.id?.[0]) continue;
			const hasContent = profile.properties?.[0] || profile.dependencyManagement?.[0] || profile.dependencies?.[0];
			if (!hasContent) continue;
			profilesById[profile.id[0]] = {
				dependencyManagement: profile.dependencyManagement?.[0],
				dependencies: profile.dependencies?.[0],
				properties: profile.properties?.[0],
			};
			if (profile.activation?.[0]?.activeByDefault?.[0] === "true") {
				defaultProfileId = profile.id[0];
			}
		}
		if (Object.keys(profilesById).length === 0) profilesById = null;
	}

	const descr = {
		dependencyManagement: project.dependencyManagement?.[0],
		dependencies: project.dependencies?.[0],
		pomPath,
		properties: (project?.properties?.[0] && typeof project.properties[0] !== "string") ? project.properties[0] : {},
		profilesById,
		defaultProfileId,
		parentInfo,
		groupId,
		artifactId,
		version,
		// Maven model expressions for the current project. These are built-ins,
		// not <properties> — ${project.version} always means THIS project's
		// version (never overridable by a property or an imported BOM). The
		// pom.* aliases mirror Maven's legacy synonyms.
		localVars: {
			"project.groupId": groupId,
			"project.artifactId": artifactId,
			"project.version": version,
			"pom.groupId": groupId,
			"pom.artifactId": artifactId,
			"pom.version": version,
			...(parentInfo?.groupId ? { "project.parent.groupId": parentInfo.groupId } : {}),
			...(parentInfo?.artifactId ? { "project.parent.artifactId": parentInfo.artifactId } : {}),
			...(parentInfo?.version ? { "project.parent.version": parentInfo.version } : {}),
		},
	};

	// Skip indexing by id if we don't have both groupId and artifactId — avoids
	// "undefined:foo" lookup collisions across POMs.
	if (groupId && artifactId) {
		allPomMetadata.byId[`${groupId}:${artifactId}`] = descr;
		if (version) {
			const gav = `${groupId}:${artifactId}:${version}`;
			if (allPomMetadata.byId[gav] && allPomMetadata.byId[gav].pomPath !== pomPath) allPomMetadata.duplicateGavs?.add(gav);
			allPomMetadata.byId[gav] = descr;
		}
	}
	allPomMetadata.byPath[pomPath] = descr;
	return descr;
}

function resolveParentPath(pomPath, parentInfo, allPomMetadata) {
	const self = allPomMetadata.byPath[pomPath];
	if (!parentInfo) return null;

	const rel = (parentInfo.relativePath ?? "../pom.xml").trim();
	if (rel) {
		let resolved = path.resolve(path.dirname(pomPath), rel);
		if (fs.existsSync(resolved)) {
			// Maven appends /pom.xml when relativePath points at a directory.
			try {
				if (fs.statSync(resolved).isDirectory()) resolved = path.join(resolved, "pom.xml");
			} catch { /* ignore */ }
			const candidate = allPomMetadata.byPath[resolved];
			if (candidate && candidate.groupId === parentInfo.groupId && candidate.artifactId === parentInfo.artifactId &&
				(candidate.version === parentInfo.version || interpolate(candidate.version, candidate.properties) === interpolate(parentInfo.version, self.properties))) {
				self.parentDescr = candidate;
				return resolved;
			}
		}
	}

	const keyV = `${parentInfo.groupId}:${parentInfo.artifactId}:${parentInfo.version}`;
	const key = `${parentInfo.groupId}:${parentInfo.artifactId}`;
	if (allPomMetadata.duplicateGavs?.has(keyV)) {
		self.ambiguousParent = keyV;
		return null;
	}
	if (allPomMetadata.byId[keyV]) {
		self.parentDescr = allPomMetadata.byId[keyV];
		return self.parentDescr.pomPath;
	}
	if (!parentInfo.version && allPomMetadata.byId[key]) {
		self.parentDescr = allPomMetadata.byId[key];
		return self.parentDescr.pomPath;
	}
	return null;
}

async function getAllInheritedProps(pomPath, allPomMetadata, cache) {
	if (cache[pomPath]) return cache[pomPath];
	const meta = allPomMetadata.byPath[pomPath];
	if (!meta) return { properties: {}, dependencies: [], dependencyManagement: [] };

	const { dependencyManagement, dependencies, properties, parentInfo, profilesById } = meta;

	const merged = {
		properties: { ...(properties || {}) },
		dependencies: [...(dependencies?.dependency || [])],
		dependencyManagement: [...(dependencyManagement?.dependencies?.[0]?.dependency || [])],
	};

	// Merge every profile so the scan covers any dep any profile could pull in.
	if (profilesById) {
		const ids = Object.keys(profilesById);
		const ordered = meta.defaultProfileId
			? [meta.defaultProfileId, ...ids.filter(id => id !== meta.defaultProfileId)]
			: ids;
		for (const id of ordered) {
			const prof = profilesById[id];
			// The activeByDefault profile IS active in a default build, so its <properties>
			// override the main ones (Maven: profile values are injected over the model's).
			// Any other profile only fills what is missing — it is not active by default,
			// it is merged so its dependencies get scanned.
			if (prof.properties)
				merged.properties = id === meta.defaultProfileId
					? { ...merged.properties, ...prof.properties }
					: { ...prof.properties, ...merged.properties };
			if (prof.dependencies?.dependency)
				merged.dependencies.push(...prof.dependencies.dependency);
			if (prof.dependencyManagement?.dependencies?.[0]?.dependency)
				merged.dependencyManagement.push(...prof.dependencyManagement.dependencies[0].dependency);
		}
	}

	// Resolve local BOM imports (scope=import) — pull their managed deps in.
	const toImport = [];
	const doImports = dep => {
		if (dep.scope?.[0] !== "import") return;
		const g = coord(dep.groupId?.[0]);
		const a = coord(dep.artifactId?.[0]);
		const v = coord(dep.version?.[0]);
		if (!g || !a) return;
		const local = (v && allPomMetadata.byId[`${g}:${a}:${v}`]) || allPomMetadata.byId[`${g}:${a}`];
		if (local) toImport.push(local);
	};
	for (const dep of merged.dependencies) doImports(dep);
	for (const dep of merged.dependencyManagement) doImports(dep);

	for (const pom of toImport) {
		const imported = await getAllInheritedProps(pom.pomPath, allPomMetadata, cache);
		// `<scope>import</scope>` imports a BOM's <dependencyManagement> and NOTHING else.
		// The BOM resolves its managed versions in ITS OWN property context, then those
		// resolved versions are what the importer receives — its <properties> never become
		// the importer's. Merging them (and merging them so the BOM WINS, as this line used
		// to) lets a BOM silently redefine the importing project's own property values.
		//
		// Real case, Apache Dubbo 2.7.8: the reactor root sets
		// <hibernate_validator_version>5.2.4.Final</…>, dubbo-dependencies-bom redefines it
		// to 5.4.1.Final, and dubbo-filter-validation's <version>${hibernate_validator_version}</version>
		// resolved to the wrong one — a different version means a different CVE set.
		// `mvn dependency:tree` reports 5.2.4.Final for that module.
		//
		// So: interpolate the BOM's managed entries against the BOM's properties here, at
		// the import boundary, and drop the properties. (lib/transitive.js#effectivePom
		// already does the equivalent for EXTERNAL import BOMs.)
		merged.dependencies.push(...imported.dependencies);
		merged.dependencyManagement.push(
			...imported.dependencyManagement.map(d => resolveDepNodeProps(d, imported.properties)));
	}

	// Cache the (still-mutating) object BEFORE recursing into the parent so a
	// malformed parent cycle (A→B→A) returns this partial result instead of
	// recursing forever. `merged` is mutated in place afterwards, so the cached
	// reference ends up fully populated.
	cache[pomPath] = merged;

	// Inherit <properties> from a LOCAL parent POM as the BASE layer — the child
	// overrides the parent, exactly like native Maven. (dependencyManagement and
	// parent <dependencies> need no special handling here: collectResolvedDeps
	// already merges them across the whole tree by g:a.) External parents
	// (e.g. spring-boot-starter-parent) aren't in the source tree, so their
	// properties can't be inherited without a network fetch — those versions
	// still surface as unresolved, as before.
	const parentPath = resolveParentPath(pomPath, parentInfo, allPomMetadata);
	if (parentPath && parentPath !== pomPath) {
		const parentMerged = await getAllInheritedProps(parentPath, allPomMetadata, cache);
		merged.properties = { ...parentMerged.properties, ...merged.properties };
	}

	// Built-in project.* coordinates (${project.version}, ${project.groupId}, …).
	// Applied LAST so the current POM's own values win — even over an inherited
	// parent property or an imported BOM's project.* — letting an intra-reactor
	// dep declared "<version>${project.version}</version>" resolve to THIS
	// module's version.
	merged.properties = { ...merged.properties, ...(meta.localVars || {}) };

	cache[pomPath] = merged;
	return merged;
}

const NODES_TO_KEEP = new Set([
	"groupId", "artifactId", "version", "packaging", "modules",
	"properties", "dependencyManagement", "name", "dependencies",
	"modelVersion", "$",
]);

async function rewritePoms(pomPath, allPomMetadata, allPropsByPom, opts) {
	const { srcRoot, targetRoot, deps2Exclude, verbose, readOnly } = opts;
	const descr = allPomMetadata.byPath[pomPath];
	if (!descr) return false;

	const xmlData = fs.readFileSync(pomPath, "utf8").replace("﻿", "");
	const tPom = readOnly ? null : path.join(targetRoot, path.relative(srcRoot, pomPath));

	let json;
	try { json = await parseStringPromise(xmlData); }
	catch (e) { throw new Error(`xml parse failed: ${e.message}`); }

	const props = json.project || {};
	const keep = new Set(NODES_TO_KEEP);

	// Re-resolve parent if first pass missed it.
	if (!descr.parentDescr && descr.parentInfo) {
		const p = descr.parentInfo;
		descr.parentDescr =
			allPomMetadata.byId[`${p.groupId}:${p.artifactId}:${p.version}`] ||
			allPomMetadata.byId[`${p.groupId}:${p.artifactId}`];
	}

	if (!descr.parentDescr && descr.parentInfo) {
		const p = descr.parentInfo;
		const isExcluded = deps2Exclude && deps2Exclude.test(p.groupId || "");
		allPomMetadata.missingById[`${p.groupId}:${p.artifactId}`] = true;
		allPomMetadata.missingById[`${p.groupId}:${p.artifactId}:${p.version}`] = true;
		if (!isExcluded) {
			allPomMetadata.anyMissingById[`${p.groupId}:${p.artifactId}`] = true;
			allPomMetadata.anyMissingById[`${p.groupId}:${p.artifactId}:${p.version}`] = true;
			keep.add("parent");
			if (verbose) console.warn(`⚠️  parent not found locally for ${pomPath} → ${p.groupId}:${p.artifactId}:${p.version} (will be treated as public)`);
		} else if (verbose) {
			console.warn(`⚠️⚠️  excluded parent for ${pomPath} → ${p.groupId}:${p.artifactId}:${p.version} (snyk may fail)`);
		}
	} else if (descr.parentDescr) {
		keep.add("parent");
		const pd = descr.parentDescr;
		props.parent[0].relativePath = [path.relative(path.dirname(pomPath), path.dirname(pd.pomPath))];
		if (pd.version) props.parent[0].version = [pd.version];
	}

	for (const k of Object.keys(props)) {
		if (!keep.has(k)) delete props[k];
	}

	// Interpolate ${…} in coordinates against THIS pom's resolved props (incl. the
	// project.* built-ins via getAllInheritedProps' localVars). A reactor sibling dep
	// declared <groupId>${project.groupId}</groupId> must resolve to the real groupId for
	// the byId/local-module lookup + the "missing/private" classification below — otherwise
	// it's wrongly reported as a private lib (e.g. "${project.groupId}:cnaps-core"). The
	// dep NODE itself is left raw, so the rewritten cleaned POM keeps ${…} for Snyk's mvn.
	const pomProps = (allPropsByPom && allPropsByPom[pomPath] && allPropsByPom[pomPath].properties) || {};
	const interp = (s) => {
		if (s == null) return s;
		let out = String(s);
		for (let i = 0; i < 10 && out.includes("${"); i++) {
			const next = out.replace(/\$\{\s*([\w.\-]+)\s*\}/g, (m, k) => {
				const val = pomProps[k];
				if (val == null) return m;
				return Array.isArray(val) ? String(val[0]) : String(val);
			});
			if (next === out) break;
			out = next;
		}
		return out;
	};

	const cleanDeps = list =>
		list?.filter(dep => {
			const g = interp(coord(dep.groupId?.[0]));
			const a = interp(coord(dep.artifactId?.[0]));
			const v = interp(coord(dep.version?.[0]));
			if (!g || !a) return false;
			if (deps2Exclude) {
				// Versionless deps inside dependencyManagement-merged result are
				// often resolvable via a managed parent — keep them unless we
				// can prove they're excluded.
				if (deps2Exclude.test(g)) {
					const local = (v && allPomMetadata.byId[`${g}:${a}:${v}`]) || allPomMetadata.byId[`${g}:${a}`];
					if (local && dep.scope?.[0] === "import") {
						dep.systemPath = [path.resolve(local.pomPath)];
						return false;
					}
					if (!local && dep.scope?.[0] === "import" && verbose) {
						console.warn(`⚠️  excluded import-scope BOM in ${pomPath}: ${g}:${a}:${v}`);
					}
					allPomMetadata.excludedById[`${g}:${a}`] = true;
					if (v) allPomMetadata.excludedById[`${g}:${a}:${v}`] = true;
					return false;
				}
				allPomMetadata.anyMissingById[`${g}:${a}`] = true;
				if (v) allPomMetadata.anyMissingById[`${g}:${a}:${v}`] = true;
				return true;
			}
			allPomMetadata.anyMissingById[`${g}:${a}`] = true;
			if (v) allPomMetadata.anyMissingById[`${g}:${a}:${v}`] = true;
			return true;
		});

	const propsForPom = allPropsByPom[pomPath] || { properties: {}, dependencies: [], dependencyManagement: [] };

	if (props.dependencies?.[0]?.dependency)
		props.dependencies[0].dependency = cleanDeps(propsForPom.dependencies);
	if (props.dependencyManagement?.[0]?.dependencies?.[0]?.dependency)
		props.dependencyManagement[0].dependencies[0].dependency = cleanDeps(propsForPom.dependencyManagement);
	props.properties = [propsForPom.properties];

	if (!readOnly) {
		await fs.promises.mkdir(path.dirname(tPom), { recursive: true });
		const builder = new Builder();
		fs.writeFileSync(tPom, builder.buildObject(json));
	}
	return true;
}

module.exports = {
	coord,
	SKIP_DIRS,
	findPomFiles,
	findPomFilesAsync,
	newMetadataStore,
	parsePom,
	resolveParentPath,
	getAllInheritedProps,
	rewritePoms,
};
