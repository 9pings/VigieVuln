const fs = require("node:fs");
const path = require("node:path");
const { fetchGithubAdvisories, writeSnapshotAtomically } = require("../live-snapshot");
const { assessGithubAdvisories, typo3RangeGrammar } = require("../../providers/github/advisories");
const { join, within, readJson, composerOccurrences, composerComponent, composerCoverageDiagnostic, finishInventory, localSourceSnapshot } = require("./wave2-common");

const GITHUB_REPO = "TYPO3/typo3";
const SOURCE_ID = "github-typo3-advisories";

function legacyVersion(ctx, relative) {
	if (!ctx.index.hasFile(relative)) return null;
	try { return ctx.readPrefix(relative, 65536).match(/['"]version['"]\s*=>\s*['"]([^'"\r\n]+)['"]/)?.[1] || null; }
	catch { return null; }
}

function extensionAt(ctx, app, dir) {
	const emconf = join(dir, "ext_emconf.php");
	const composerFile = join(dir, "composer.json");
	const composer = ctx.index.hasFile(composerFile) ? readJson(ctx, composerFile) : null;
	const extra = composer?.extra?.["typo3/cms"];
	const declaredType = composer?.type === "typo3-cms-extension";
	const system = /(^|\/)typo3\/sysext\/[^/]+$/.test(dir);
	if (!ctx.index.hasFile(emconf) && !declaredType && !(system && composer?.type === "typo3-cms-framework")) return null;
	const key = typeof extra?.["extension-key"] === "string" ? extra["extension-key"] : dir.split("/").at(-1);
	const declared = typeof extra?.version === "string" ? extra.version : typeof composer?.version === "string" ? composer.version : null;
	const legacy = legacyVersion(ctx, emconf);
	return { id: `${app.id}:extension:${dir}`, applicationId: app.id,
		kind: system ? "framework-component" : "module", path: dir,
		name: key, machineName: key, coord: typeof composer?.name === "string" ? composer.name.toLowerCase() : null,
		version: declared || legacy, rawVersion: declared || legacy,
		versionStatus: declared || legacy ? "observed" : "unknown", visibility: ctx.isPrivatePath(dir) ? "private" : "unknown",
		identityStatus: composer?.name && (declaredType || (system && composer.type === "typo3-cms-framework")) ? "verified" : "unknown", activation: "unknown",
		evidence: [declared ? { path: composerFile, field: extra?.version ? "extra.typo3/cms.version" : "version" } :
			{ path: emconf, field: "version" }],
		...(declared && legacy && declared !== legacy ? { versionConflict: { composer: declared, extEmconf: legacy } } : {}) };
}

function isComposerSite(dir, ctx) {
	const file = join(dir, "composer.json");
	if (!ctx.index.hasFile(file)) return false;
	const root = readJson(ctx, file);
	if (!root?.require?.["typo3/cms-core"] && !root?.["require-dev"]?.["typo3/cms-core"]) return false;
	return ["public/index.php", "web/index.php", "typo3/index.php", "config/sites", "public/typo3", "web/typo3"]
		.some(marker => ctx.index.hasFile(join(dir, marker)) || ctx.index.directories.includes(join(dir, marker)));
}

function isClassicSite(dir, ctx) {
	if (!ctx.index.hasFile(join(dir, "typo3/sysext/core/ext_emconf.php"))) return false;
	return ctx.index.hasFile(join(dir, "typo3/index.php")) ||
		readJson(ctx, join(dir, "composer.json"))?.name === "typo3/cms";
}

module.exports = {
	id: "typo3", version: "0.1.0", apiVersion: 1, label: "TYPO3",
	supportedLayouts: ["composer", "classic", "source", "component"],
	capabilities: { inventory: "experimental", advisories: "experimental" }, requiredCodecs: [],
	providerIds: [SOURCE_ID],
	discover(ctx) {
		if (ctx.scanContext === "component") {
			return extensionAt(ctx, { id: "typo3:." }, ".")
				? [{ root: ".", layout: "component", componentKind: "module",
					evidence: [{ path: ctx.index.hasFile("composer.json") ? "composer.json" : "ext_emconf.php" }] }] : [];
		}
		return ctx.index.directories.filter(dir => isComposerSite(dir, ctx) || isClassicSite(dir, ctx))
			.map(dir => ({ root: dir, layout: isClassicSite(dir, ctx) && !ctx.index.hasFile(join(dir, "composer.lock"))
				? ctx.index.hasFile(join(dir, "typo3/index.php")) ? "classic" : "source" : "composer",
				evidence: isClassicSite(dir, ctx) ? [{ path: join(dir, "typo3/sysext/core/ext_emconf.php") },
					ctx.index.hasFile(join(dir, "typo3/index.php")) ? { path: join(dir, "typo3/index.php") } :
						{ path: join(dir, "composer.json"), field: "name" }] :
					[{ path: join(dir, "composer.json"), field: "require.typo3/cms-core" }] }));
	},
	collect(app, ctx) {
		if (app.layout === "component") return finishInventory(app, [extensionAt(ctx, app, ".")].filter(Boolean),
			[], undefined, { advisories: false });
		const components = [], diagnostics = [composerCoverageDiagnostic(app, ctx)].filter(Boolean);
		const entries = composerOccurrences(app, ctx);
		for (const entry of entries) {
			const kind = entry.coord === "typo3/cms-core" ? "core" : entry.coord.startsWith("typo3/cms-") ? "framework-component" :
				entry.occurrence.packageType === "typo3-cms-extension" ? "module" : "library";
			components.push(composerComponent(app, entry, kind));
		}
		if (!components.some(c => c.kind === "core")) {
			const file = join(app.root, "typo3/sysext/core/ext_emconf.php");
			const version = legacyVersion(ctx, file);
			components.push({ id: `${app.id}:core`, applicationId: app.id, kind: "core", path: app.root,
				name: "TYPO3", coord: "typo3/cms-core", version, rawVersion: version,
				versionStatus: version ? "observed" : "unknown", visibility: "public", identityStatus: "verified",
				activation: "unknown", evidence: [{ path: file, field: "version" }] });
		}
		for (const dir of ctx.index.directories) {
			if (!within(dir, app.root) || dir === app.root) continue;
			const relative = app.root === "." ? dir : dir.slice(app.root.length + 1);
			if (!/^typo3conf\/ext\/[^/]+$/.test(relative) && !/^packages\/[^/]+$/.test(relative) &&
				!/^typo3\/sysext\/(?!core$)[^/]+$/.test(relative)) continue;
			const extension = extensionAt(ctx, app, dir);
			if (!extension) continue;
			const locked = components.find(c => c.coord && c.coord === extension.coord);
			if (locked) {
				locked.path = dir;
				locked.evidence.push(...extension.evidence);
				if (extension.version && extension.version !== locked.version) diagnostics.push({ code: "CMS_VERSION_CONFLICT",
					applicationId: app.id, componentId: locked.id, path: dir,
					message: `TYPO3 extension ${extension.name} declares ${extension.version}, lock pins ${locked.version}` });
			} else components.push(extension);
			if (extension.versionConflict) diagnostics.push({ code: "CMS_VERSION_CONFLICT", applicationId: app.id,
				componentId: extension.id, path: dir, message: `TYPO3 extension ${extension.name} has conflicting Composer and ext_emconf versions` });
		}
		return finishInventory(app, components, diagnostics, undefined, { advisories: false });
	},
	// TYPO3 publishes its advisories as GitHub security advisories on the CMS monorepo,
	// attributed per composer package (typo3/cms-core, typo3/cms-<sysext>, …): the whole
	// repo feed is fetched once, then matched per inventoried coordinate.
	async assess(app, components, ctx) {
		if (!ctx.typo3AdvisoriesPath && !ctx.liveTypo3AdvisoriesUrl) return { findings: [], coverage: [{
			applicationId: app.id, capability: "advisories", sourceId: SOURCE_ID, execution: "not-run",
			result: "indeterminate", expected: (components || []).length, executed: 0, diagnostic: "CMS_PROVIDER_UNCONFIGURED" }] };
		const key = ctx.typo3AdvisoriesPath
			? `typo3-advisories:${ctx.typo3AdvisoriesPath}` : `typo3-advisories:live:${ctx.liveTypo3AdvisoriesUrl}`;
		let cached = ctx.snapshotCache.get(key);
		if (!cached && ctx.typo3AdvisoriesPath) {
			const validated = ctx.validatedLocalSources?.get(ctx.typo3AdvisoriesPath);
			const stat = validated?.stat || fs.statSync(ctx.typo3AdvisoriesPath);
			if (!stat.isFile() || stat.size > 128 * 1024 * 1024) throw new Error("TYPO3 advisory snapshot must be a JSON file of at most 128 MiB");
			const bytes = validated?.bytes || fs.readFileSync(ctx.typo3AdvisoriesPath);
			const snapshot = validated?.snapshot || JSON.parse(bytes.toString("utf8"));
			const sourceSnapshot = localSourceSnapshot(ctx, ctx.typo3AdvisoriesPath, bytes, stat, snapshot);
			cached = { snapshot, sourceSnapshot };
		} else if (!cached) {
			const fetched = await fetchGithubAdvisories(GITHUB_REPO, { fetchImpl: ctx.fetchImpl || undefined,
				endpoint: ctx.liveTypo3AdvisoriesUrl.startsWith("http") ? ctx.liveTypo3AdvisoriesUrl : null, now: ctx.now });
			if (ctx.advisoryCacheDir) writeSnapshotAtomically(path.join(ctx.advisoryCacheDir, "github-typo3-advisories.json"), fetched.snapshot);
			cached = { snapshot: fetched.snapshot, sourceSnapshot: fetched.sourceSnapshot, live: true };
		}
		ctx.snapshotCache.set(key, cached);
		const assessed = assessGithubAdvisories(cached.snapshot, components, { sourceId: SOURCE_ID, normalizeRange: typo3RangeGrammar });
		return { findings: assessed.matches, coverage: assessed.coverage.map(check => ({ ...check, sourceSnapshot: cached.sourceSnapshot })),
			diagnostics: assessed.diagnostics };
	},
	remediation() { return null; },
};
