// Recover an unversioned Gradle declaration from requests made elsewhere in the
// same project's classpaths. This is deliberately separate from Maven mediation.
const { resolveTransitiveDeps } = require("../maven/transitive");

const CLASSPATHS = {
	api: ["compile", "runtime", "testCompile", "testRuntime"],
	implementation: ["compile", "runtime", "testCompile", "testRuntime"],
	compileOnly: ["compile"],
	compileOnlyApi: ["compile"],
	runtimeOnly: ["runtime", "testRuntime"],
	providedCompile: ["compile", "runtime", "testCompile", "testRuntime"],
	providedRuntime: ["runtime", "testRuntime"],
	testImplementation: ["testCompile", "testRuntime"],
	testCompileOnly: ["testCompile"],
	testRuntimeOnly: ["testRuntime"],
};
function classpaths(dep) {
	return [...new Set((dep.gradleConfigurations || []).flatMap(c => CLASSPATHS[c] || [`custom:${c}`]))];
}
function ownClasspaths(dep) {
	const all = classpaths(dep);
	// Production dependencies also reach test classpaths, but test-only requests
	// cannot supply the version of a production declaration.
	return dep.isDev ? all : all.filter(c => !c.startsWith("test"));
}
function exclusions(sets) {
	if (!sets?.length) return [];
	return [...new Set(sets[0])].filter(x => sets.every(s => s.includes(x))).map(x => {
		const i = x.indexOf(":");
		return { groupId: x.slice(0, i), artifactId: x.slice(i + 1) };
	});
}
function exclusionsForClasspath(dep, cp) {
	if (!dep.gradleDeclarations) return exclusions(dep.exclusionSets);
	return exclusions(dep.gradleDeclarations.filter(d => (CLASSPATHS[d.configuration] || [`custom:${d.configuration}`]).includes(cp)).map(d => d.exclusions));
}

// Gradle compares numeric parts numerically; an extra numeric part is higher,
// including a trailing zero. Do not apply Maven's qualifier/range ordering.
function highestRelease(versions) {
	const values = [...new Set(versions)];
	if (values.includes(null)) return null;
	if (values.length === 1) return values[0];
	if (!values.length || values.some(v => !/^\d+(?:\.\d+)*$/.test(v))) return null;
	return values.sort((a, b) => {
		const x = a.split(".").map(BigInt), y = b.split(".").map(BigInt);
		for (let i = 0; i < Math.min(x.length, y.length); i++) {
			if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
		}
		return x.length - y.length;
	}).at(-1);
}

async function recoverVersionlessGradle(deps, opts = {}) {
	const pick = opts.only || (() => true);
	const records = [...deps.values()].filter(d => pick(d) && d.ecosystemType === "gradle"
		&& d.provenance === "manifest" && !d.fromLockfile && !d.versionUnresolved
		&& d.manifestPaths?.length === 1 && (d.versions || []).length <= 1);
	const usableRecords = new Set(records);
	const targets = records.filter(d => !d.version && !d.managedOnly
		&& (opts.includeTestDeps || !d.isDev) && ownClasspaths(d).length);
	if (!targets.length) return 0;
	const groups = new Map();
	for (const target of targets) for (const cp of ownClasspaths(target)) {
		const manifest = target.manifestPaths[0];
		const key = JSON.stringify([manifest, cp]);
		if (!groups.has(key)) groups.set(key, { manifest, cp, targets: [] });
		groups.get(key).targets.push(target);
	}
	const evidence = new Map(targets.map(d => [d.coordKey, []]));
	for (const { manifest, cp, targets: localTargets } of groups.values()) {
		// An omitted root can contribute any version on this classpath. Do not
		// infer from a graph that silently dropped an unresolved or merged record.
		const omittedRoot = [...deps.values()].some(d => d.ecosystemType === "gradle"
			&& d.provenance === "manifest" && !d.fromLockfile && !usableRecords.has(d)
			&& d.manifestPaths?.includes(manifest) && (d.managedOnly || classpaths(d).includes(cp)));
		if (omittedRoot) continue;
		// A cached effective POM may have been built while its parent was unavailable.
		// Keep recovery's cache local to this classpath so missing-parent evidence is not lost.
		const effCache = new Map();
		const local = records.filter(d => d.manifestPaths[0] === manifest && (d.managedOnly || classpaths(d).includes(cp)));
		const keys = new Set(local.filter(d => !d.managedOnly && !d.version).map(d => d.coordKey));
		const rootDepMgmt = new Map(opts.bomDepMgmt || []);
		for (const [key, m] of (opts.gradleBomDepMgmt || [])) if (m.manifestPath === manifest) rootDepMgmt.set(key, m);
		// An ordinary direct version is a request, not a Gradle force. Keep the
		// provenance of actual pins separate from the Maven traversal overrides.
		const provenPins = new Map(rootDepMgmt);
		for (const d of local) if (d.version) rootDepMgmt.set(d.coordKey, {
			version: d.version, exclusions: exclusions(d.mgmtExclusionSets), ...(d.pinMinimum ? { minimum: true } : {}),
		});
		for (const d of local) if (d.version) {
			if (d.managedOnly) provenPins.set(d.coordKey, { version: d.version, minimum: !!d.pinMinimum });
			else {
				const pin = provenPins.get(d.coordKey);
				if ((typeof pin === "string" ? pin : pin?.version) !== d.version) provenPins.delete(d.coordKey);
			}
		}
		let selected = new Map(), finalRequests = null;
		// Re-walk after selecting versions so children belonging only to a discarded
		// version cannot supply another declaration. A cycle/unstable graph stays unknown.
		for (let pass = 0; pass < 8; pass++) {
			const requests = new Map([...keys].map(k => [k, []]));
			const graphRequests = new Map();
			let incomplete = false;
			const roots = local.filter(d => !d.managedOnly && (d.version || selected.get(d.coordKey))).map(d => ({
				...d, version: d.version || selected.get(d.coordKey), exclusions: exclusionsForClasspath(d, cp),
			}));
			const pins = new Map(rootDepMgmt);
			for (const [key, version] of selected) pins.set(key, { version });
			const resolved = await resolveTransitiveDeps(roots, {
				...opts, effCache, rootDepMgmt: pins, gradleComponents:true,
				runtimeDependencies: cp !== "compile" && cp !== "testCompile",
				includedScopes: cp.startsWith("test") ? ["compile", "runtime", "provided", "test"] : ["compile", "runtime", "provided"],
				versionRequestKeys: keys,
				onVersionRequest: r => requests.get(r.key).push(r),
				onGraphRequest: ({ key, version }) => {
					if (!graphRequests.has(key)) graphRequests.set(key, new Set());
					graphRequests.get(key).add(version);
				},
				onMissingPom: info => { incomplete = true; opts.onMissingPom?.(info); },
				onPomCycle: info => { incomplete = true; opts.onPomCycle?.(info); },
				onResolutionError: (...args) => { incomplete = true; opts.onResolutionError?.(...args); },
				onDepthLimit: (...args) => { incomplete = true; opts.onDepthLimit?.(...args); },
			});
			// Maven mediates intermediate conflicts differently from Gradle. Do not
			// infer a target through a graph whose selected intermediate is uncertain.
			for (const [key, versions] of graphRequests) {
				if (keys.has(key)) continue;
				const pin = provenPins.get(key);
				const pinnedVersion = typeof pin === "string" ? pin : pin?.version;
				if (pinnedVersion && !pin?.minimum) continue;
				const effective = [...versions].map(v => pinnedVersion && v && /^\d+(?:\.\d+)*$/.test(v) && /^\d+(?:\.\d+)*$/.test(pinnedVersion) ? highestRelease([v, pinnedVersion]) : v);
				const distinct = new Set(effective);
				if (distinct.has(null)) { incomplete = true; continue; }
				if (distinct.size <= 1) continue;
				const highest = highestRelease([...distinct]);
				const chosen = roots.find(d => d.coordKey === key)?.version || resolved.get(key)?.version;
				if (!highest || chosen !== highest) incomplete = true;
			}
			if (incomplete) break;
			const next = new Map();
			for (const [key, rs] of requests) {
				const version = highestRelease(rs.map(r => r.version));
				if (version) next.set(key, version);
			}
			if (next.size === selected.size && [...next].every(([k, v]) => selected.get(k) === v)) {
				// An unresolved root could itself request a higher version elsewhere.
				if (next.size === keys.size) finalRequests = requests;
				break;
			}
			selected = next;
		}
		if (!finalRequests) continue;
		for (const { coordKey: key } of localTargets) {
			const version = selected.get(key);
			evidence.get(key).push({
				version, paths: finalRequests.get(key).filter(r => r.version === version).map(r => r.via),
			});
		}
	}
	let filled = 0;
	for (const target of targets) {
		const hits = evidence.get(target.coordKey);
		if (hits.length !== ownClasspaths(target).length || new Set(hits.map(h => h.version)).size !== 1) continue;
		const version = hits[0].version;
		target.version = version;
		target.versions = [version];
		target.versionPaths = { [version]: [...target.manifestPaths] };
		target.versionSource = { via: "gradle-graph", paths: [...new Map(hits.flatMap(h => h.paths).map(p => [JSON.stringify(p), p])).values()] };
		filled++;
	}
	return filled;
}

module.exports = { recoverVersionlessGradle };
