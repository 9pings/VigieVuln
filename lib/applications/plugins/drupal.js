const path = require("node:path");
const fs = require("node:fs");
const yaml = require("js-yaml");
const { assessDrupalAdvisories } = require("../../providers/drupal/advisories");
const { fetchDrupalAdvisories, mergeDrupalSnapshots, writeSnapshotAtomically } = require("../live-snapshot");
const { localSourceSnapshot } = require("./wave2-common");

const join = (dir, file) => dir === "." ? file : `${dir}/${file}`;
const posix = value => value.split(path.sep).join("/");
const within = (child, parent) => child === parent || child.startsWith(parent + "/");

/** Submodules of a distributed project live inside its directory; they inherit its identity as probable. */
function groupSubmodules(components) {
	const ordered = components.filter(c => c.kind !== "core" && c.path)
		.sort((a, b) => posix(a.path).split("/").length - posix(b.path).split("/").length);
	for (const child of ordered) {
		let parent = null;
		for (const candidate of ordered) {
			if (candidate === child || !within(child.path, candidate.path)) continue;
			if (!parent || posix(candidate.path).length > posix(parent.path).length) parent = candidate;
		}
		if (!parent) continue;
		child.parentComponentId = parent.id;
		if (!child.coord && parent.coord) {
			child.coord = parent.coord;
			child.identityStatus = "probable";
			child.evidence.push({ ...(parent.evidence[0] || {}), relation: "submodule-of" });
		}
	}
}

function docRootFor(dir, ctx) {
	for (const suffix of ["web", "."]) {
		const docRoot = suffix === "." ? dir : join(dir, suffix);
		if (ctx.index.hasFile(join(docRoot, "core/lib/Drupal.php")) &&
			ctx.index.hasFile(join(docRoot, "core/core.services.yml"))) return docRoot;
	}
	return null;
}

function lockedCoreVersion(app, ctx) {
	const lock = join(app.root, "composer.lock");
	const dep = ctx.resolvedDeps.get("composer:drupal/core");
	return (dep?.occurrences || []).find(o => posix(path.relative(ctx.srcRoot, o.manifestPath)) === lock)?.version || null;
}

function extensionFromInfo(rel, app, ctx) {
	let info;
	try { info = yaml.load(ctx.readText(rel), { schema: yaml.JSON_SCHEMA }); }
	catch (error) { return { diagnostic: { code: "CMS_INFO_INVALID", applicationId: app.id, path: rel, message: error.message } }; }
	if (!info || typeof info !== "object" || !["module", "theme", "profile"].includes(info.type)) return null;
	const dir = path.posix.dirname(rel);
	const custom = /\/(modules|themes|profiles)\/custom\//.test(dir);
	let coord = null;
	const packageFile = join(dir, "composer.json");
	if (ctx.index.hasFile(packageFile)) {
		try { coord = JSON.parse(ctx.readText(packageFile)).name || null; } catch { /* no proven Composer identity */ }
	}
	if (!coord && !custom && typeof info.project === "string" && info.project) coord = `drupal/${info.project}`;
	const privatePackage = coord && !coord.toLowerCase().startsWith("drupal/");
	const version = typeof info.version === "string" || typeof info.version === "number" ? String(info.version) : null;
	return { component: { id: `${app.id}:${info.type}:${dir}:${path.posix.basename(rel).replace(/\.info\.yml$/, "")}`, applicationId: app.id,
		kind: info.type, path: dir, name: typeof info.name === "string" ? info.name : path.posix.basename(dir),
		machineName: path.posix.basename(rel).replace(/\.info\.yml$/, ""), coord,
		version, coreVersionRequirement: typeof info.core_version_requirement === "string" ? info.core_version_requirement : null,
		visibility: custom || privatePackage || ctx.isPrivatePath(dir) ? "private" : "unknown", catalogueStatus: "not-queried",
		identityStatus: coord ? "verified" : "unknown", activation: "unknown",
		evidence: [{ path: rel, field: "name" }, ...(version ? [{ path: rel, field: "version" }] : [])] } };
}

function legacyExtension(rel, app, ctx) {
	let content;
	try { content = ctx.readText(rel, 65536); }
	catch (error) { return { diagnostic: { code: "CMS_INFO_INVALID", applicationId: app.id, path: rel, message: error.message } }; }
	const fields = {};
	for (const line of content.split(/\r?\n/)) {
		const match = line.match(/^\s*([a-z_]+)\s*=\s*(.*?)\s*$/i);
		if (match) fields[match[1].toLowerCase()] = match[2].replace(/^['"]|['"]$/g, "");
	}
	if (!fields.name) return { diagnostic: { code: "CMS_INFO_INVALID", applicationId: app.id, path: rel,
		message: "legacy .info file carries no Drupal extension name field" } };
	const dir = path.posix.dirname(rel);
	const kind = /\/themes\//.test(dir) ? "theme" : /\/profiles\//.test(dir) ? "profile" : "module";
	const custom = /\/(modules|themes|profiles)\/custom\//.test(dir);
	return { component: { id: `${app.id}:${kind}:${dir}`, applicationId: app.id, kind, path: dir,
		name: fields.name || path.posix.basename(dir), machineName: path.posix.basename(rel, ".info"),
		version: fields.version || null, rawVersion: fields.version || null, normalizedVersion: null,
		coreVersionRequirement: fields.core || null,
		coord: !custom && fields.project ? `drupal/${fields.project}` : null,
		visibility: custom || ctx.isPrivatePath(dir) ? "private" : "unknown",
		identityStatus: custom ? "private" : fields.project ? "probable" : "unknown",
		activation: "unknown", evidence: [{ path: rel, field: "name" }, ...(fields.version ? [{ path: rel, field: "version" }] : [])] } };
}

function collectLegacy(app, ctx) {
	const versionFile = join(app.root, "includes/bootstrap.inc");
	let version = null;
	try { version = ctx.readPrefix(versionFile, 16384).match(/define\s*\(\s*['"]VERSION['"]\s*,\s*['"]([^'"\r\n]+)['"]\s*\)/)?.[1] || null; }
	catch { /* missing version is reported below */ }
	const components = [{ id: `${app.id}:core`, applicationId: app.id, kind: "core", path: app.root,
		name: "Drupal", coord: "drupal/core", version, rawVersion: version, normalizedVersion: version,
		visibility: "public", identityStatus: "verified", activation: "unknown", evidence: [{ path: versionFile, field: "VERSION" }] }];
	const diagnostics = [{ code: "CMS_UNSUPPORTED_BRANCH", applicationId: app.id,
		message: "Drupal 7 is past community security support; official security advisories no longer cover this branch" }];
	for (const dir of ctx.index.directories) {
		if (!within(dir, app.root) || !/(^|\/)(modules|themes|profiles)(\/|$)/.test(dir)) continue;
		for (const file of ctx.index.filesIn(dir).filter(name => name.endsWith(".info"))) {
			const entry = legacyExtension(join(dir, file), app, ctx);
			if (entry.component) components.push(entry.component);
			if (entry.diagnostic) diagnostics.push(entry.diagnostic);
		}
	}
	groupSubmodules(components);
	const unknown = components.filter(c => !c.version);
	diagnostics.push(...unknown.map(c => ({ code: "CMS_VERSION_UNKNOWN", applicationId: app.id, componentId: c.id,
		message: `version unavailable for ${c.kind} ${c.name}` })));
	return { components, diagnostics, coverage: [
		{ applicationId: app.id, capability: "inventory", execution: unknown.length ? "partial" : "completed",
			result: unknown.length ? "indeterminate" : "not-applicable", expected: components.length,
			executed: components.length - unknown.length, ...(unknown.length ? { diagnostic: "CMS_VERSION_UNKNOWN" } : {}) },
		{ applicationId: app.id, capability: "advisories", sourceId: "drupal-security-advisories",
			execution: "not-run", result: "indeterminate", expected: components.length, executed: 0, diagnostic: "CMS_UNSUPPORTED_BRANCH" },
	] };
}

module.exports = {
	id: "drupal", version: "0.1.0", apiVersion: 1, label: "Drupal",
	supportedLayouts: ["composer-web", "classic", "drupal7"], capabilities: { inventory: "experimental", advisories: "experimental" },
	requiredCodecs: [], providerIds: ["drupal-security-advisories"],
	discover(ctx) {
		if (ctx.scanContext === "component") {
			// A file name alone is not a marker: discovery reads and validates the metadata first.
			const probe = { id: "drupal:." };
			const files = ctx.index.filesIn(".").filter(name => name.endsWith(".info.yml") || name.endsWith(".info"));
			const candidates = [], diagnostics = [];
			let firstValid = null;
			for (const file of files) {
				const entry = file.endsWith(".info.yml") ? extensionFromInfo(file, probe, ctx) : legacyExtension(file, probe, ctx);
				if (entry?.component) {
					candidates.push(entry.component);
					if (!firstValid) firstValid = { file, component: entry.component };
				} else diagnostics.push({ code: "CMS_INFO_INVALID", path: file,
					message: `${file} does not carry valid Drupal extension metadata` });
			}
			if (!candidates.length) return { candidates: [], diagnostics };
			return [{ root: ".", layout: "component",
				evidence: [{ path: firstValid.file, field: firstValid.file.endsWith(".info.yml") ? "type" : "name" },
					...firstValid.component.evidence] }];
		}
		const modern = ctx.index.directories.filter(dir => ctx.index.hasFile(join(dir, "composer.json")))
			.map(dir => ({ dir, docRoot: docRootFor(dir, ctx) })).filter(x => x.docRoot)
			.map(({ dir, docRoot }) => ({ root: dir, layout: "composer", documentRoot: docRoot, evidence: [{ path: join(docRoot, "core/lib/Drupal.php") },
				{ path: join(dir, "composer.json"), field: "require.drupal/core" }] }));
		// Drupal 8+ also ships core/includes/bootstrap.inc and core/modules/system/system.module;
		// the only positive Drupal 7 evidence is the 7.x VERSION define in bootstrap.inc.
		const legacy = ctx.index.directories.filter(dir => {
			const bootstrap = join(dir, "includes/bootstrap.inc");
			if (!ctx.index.hasFile(bootstrap) || !ctx.index.hasFile(join(dir, "modules/system/system.module"))) return false;
			try { return /define\s*\(\s*['"]VERSION['"]\s*,\s*['"]7\./.test(ctx.readPrefix(bootstrap, 16384)); }
			catch { return false; }
		})
			.map(dir => ({ root: dir, layout: "drupal7", documentRoot: dir,
				evidence: [{ path: join(dir, "includes/bootstrap.inc"), field: "VERSION" }, { path: join(dir, "modules/system/system.module") }] }));
		return [...modern, ...legacy];
	},
	collect(app, ctx) {
		if (app.layout === "component") {
			const components = [], diagnostics = [];
			for (const file of ctx.index.filesIn(".").filter(name => name.endsWith(".info.yml") || name.endsWith(".info"))) {
				const entry = file.endsWith(".info.yml") ? extensionFromInfo(file, app, ctx) : legacyExtension(file, app, ctx);
				if (entry?.component) components.push(entry.component);
				if (entry?.diagnostic) diagnostics.push(entry.diagnostic);
			}
			if (!components.length) throw new Error("no valid standalone Drupal extension metadata");
			const unknown = components.filter(c => !c.version);
			return { components, diagnostics: [...diagnostics, ...unknown.map(c => ({ code: "CMS_VERSION_UNKNOWN",
				applicationId: app.id, componentId: c.id, message: `version unavailable for ${c.kind} ${c.name}` }))],
				coverage: [{ applicationId: app.id, capability: "inventory",
					execution: unknown.length || diagnostics.length ? "partial" : "completed",
					result: unknown.length || diagnostics.length ? "indeterminate" : "not-applicable",
					expected: components.length, executed: components.length - unknown.length,
					...(unknown.length || diagnostics.length ? { diagnostic: (diagnostics[0] || { code: "CMS_VERSION_UNKNOWN" }).code } : {}) }] };
		}
		if (app.layout === "drupal7") return collectLegacy(app, ctx);
		const docRoot = docRootFor(app.root, ctx);
		// The lock is the installed-version authority; the on-disk core marker is the
		// observed version of the tree, so a lockless source tree is still assessable.
		const coreFile = join(docRoot, "core/lib/Drupal.php");
		let observed = null;
		try { observed = ctx.readPrefix(coreFile, 16384).match(/const\s+VERSION\s*=\s*['"]([^'"\r\n]+)['"]/)?.[1] || null; }
		catch { /* no readable marker: the version stays unproven */ }
		const locked = lockedCoreVersion(app, ctx);
		const coreVersion = locked || observed;
		const versionStatus = locked && observed && locked !== observed ? "conflict" : locked ? "locked" : observed ? "observed" : null;
		const coreEvidence = locked
			? [{ path: coreFile }, ...(observed ? [{ path: coreFile, field: "VERSION" }] : []),
				{ path: join(app.root, "composer.lock"), field: "packages[name=drupal/core].version" }]
			: observed ? [{ path: coreFile, field: "VERSION" }] : [{ path: coreFile }];
		const components = [{ id: `${app.id}:core`, applicationId: app.id, kind: "core", path: docRoot,
			name: "Drupal", coord: "drupal/core", version: coreVersion, visibility: "public",
			...(versionStatus ? { versionStatus } : {}),
			identityStatus: "verified", activation: "unknown", evidence: coreEvidence }];
		const diagnostics = [];
		if (versionStatus === "conflict") diagnostics.push({ code: "CMS_VERSION_CONFLICT", applicationId: app.id,
			componentId: `${app.id}:core`, message: `composer.lock resolves drupal/core ${locked} but core/lib/Drupal.php declares ${observed}` });
		const roots = ["modules", "themes", "profiles"].flatMap(n => [join(docRoot, n), join(docRoot, `sites/all/${n}`)]);
		for (const dir of ctx.index.directories) {
			if (!roots.some(base => within(dir, base))) continue;
			for (const file of ctx.index.filesIn(dir).filter(name => name.endsWith(".info.yml"))) {
				const entry = extensionFromInfo(join(dir, file), app, ctx);
				if (entry?.component) components.push(entry.component);
				if (entry?.diagnostic) diagnostics.push(entry.diagnostic);
			}
		}
		groupSubmodules(components);
		for (const component of components) {
			if (component.kind === "core" || !component.coord || component.version) continue;
			const dep = ctx.resolvedDeps.get(`composer:${component.coord}`);
			const occurrence = (dep?.occurrences || []).find(o => posix(path.relative(ctx.srcRoot, o.manifestPath)) === join(app.root, "composer.lock"));
			if (occurrence) {
				component.version = occurrence.version;
				component.evidence.push({ path: join(app.root, "composer.lock"), field: `packages[name=${component.coord}].version` });
			}
		}
		const unknown = components.filter(c => !c.version);
		if (unknown.length) diagnostics.push(...unknown.map(c => ({ code: "CMS_VERSION_UNKNOWN", applicationId: app.id,
			componentId: c.id, message: `version unavailable for ${c.kind} ${c.name}` })));
		const conflicted = components.some(c => c.versionStatus === "conflict");
		const inventoryPartial = unknown.length || conflicted || diagnostics.some(d => d.code === "CMS_INFO_INVALID");
		return { components, diagnostics, coverage: [
			{ applicationId: app.id, capability: "inventory", execution: inventoryPartial ? "partial" : "completed",
				result: inventoryPartial ? "indeterminate" : "not-applicable",
				expected: components.length, executed: components.length - unknown.length,
				...(unknown.length ? { diagnostic: "CMS_VERSION_UNKNOWN" } : conflicted ? { diagnostic: "CMS_VERSION_CONFLICT" } : {}) },
		] };
	},
	async assess(app, components, ctx) {
		if (app.layout === "drupal7") return [];
		if (!ctx.drupalAdvisoriesPath && !ctx.liveDrupalAdvisoriesUrl) return { findings: [], coverage: [{ applicationId: app.id, capability: "advisories",
			sourceId: "drupal-security-advisories", execution: "not-run", result: "indeterminate",
			expected: components.length, executed: 0, diagnostic: "CMS_PROVIDER_UNCONFIGURED" }] };
		const key = ctx.drupalAdvisoriesPath
			? `drupal-advisories:${ctx.drupalAdvisoriesPath}` : `drupal-advisories:live:${ctx.liveDrupalAdvisoriesUrl}`;
		// Live source: query exactly the inventoried public drupal/* identities, never private ones.
		const packages = [...new Set((components || [])
			.filter(c => c.visibility !== "private" && typeof c.coord === "string" && c.coord.toLowerCase().startsWith("drupal/"))
			.map(c => c.coord.toLowerCase()))];
		let cached = ctx.snapshotCache.get(key);
		if (!cached && ctx.drupalAdvisoriesPath) {
			// Reuse the runner's single validated read when available (freshness and schema
			// were already checked before discovery); fall back to a direct read otherwise.
			const validated = ctx.validatedLocalSources?.get(ctx.drupalAdvisoriesPath);
			const stat = validated?.stat || fs.statSync(ctx.drupalAdvisoriesPath);
			if (!stat.isFile() || stat.size > 128 * 1024 * 1024) throw new Error("Drupal advisory snapshot must be a JSON file of at most 128 MiB");
			const bytes = validated?.bytes || fs.readFileSync(ctx.drupalAdvisoriesPath);
			const snapshot = validated?.snapshot || JSON.parse(bytes.toString("utf8"));
			const sourceSnapshot = localSourceSnapshot(ctx, ctx.drupalAdvisoriesPath, bytes, stat, snapshot);
			cached = { snapshot, sourceSnapshot };
		} else if (!cached) {
			const fetched = await fetchDrupalAdvisories(packages, { fetchImpl: ctx.fetchImpl || undefined,
				apiUrl: ctx.liveDrupalAdvisoriesUrl, now: ctx.now });
			if (ctx.advisoryCacheDir) writeSnapshotAtomically(path.join(ctx.advisoryCacheDir, "drupal-security-advisories.json"), fetched.snapshot);
			cached = { snapshot: fetched.snapshot, sourceSnapshot: fetched.sourceSnapshot, live: true };
		} else if (cached.live) {
			// Another instance may have already filled the cache without this instance's packages:
			// load the missing identities before evaluating, and merge only what was actually obtained.
			const already = new Set((cached.snapshot.queriedPackages || []).map(p => String(p).toLowerCase()));
			const missing = packages.filter(p => !already.has(p));
			if (missing.length) {
				const fetched = await fetchDrupalAdvisories(missing, { fetchImpl: ctx.fetchImpl || undefined,
					apiUrl: ctx.liveDrupalAdvisoriesUrl, now: ctx.now });
				cached = mergeDrupalSnapshots(cached, fetched);
				if (ctx.advisoryCacheDir) writeSnapshotAtomically(path.join(ctx.advisoryCacheDir, "drupal-security-advisories.json"), cached.snapshot);
			}
		}
		ctx.snapshotCache.set(key, cached);
		const assessed = assessDrupalAdvisories(cached.snapshot, components);
		return { findings: assessed.matches, coverage: assessed.coverage.map(check => ({ ...check, sourceSnapshot: cached.sourceSnapshot })),
			diagnostics: assessed.diagnostics };
	}, remediation() { return null; },
};
