const path = require("node:path");
const frameworkMap = require("../../../data/eol-composer-frameworks.json");

const FRAMEWORK_COMPONENTS = new Set(frameworkMap.symfony.components);
const join = (dir, file) => dir === "." ? file : `${dir}/${file}`;
const posix = value => value.split(path.sep).join("/");

function safeRecipeFiles(files) {
	return (Array.isArray(files) ? files : []).filter(file => typeof file === "string" && file.length <= 256 &&
		!path.posix.isAbsolute(file) && !file.split("/").includes(".."));
}

function readRecipes(app, ctx) {
	const rel = join(app.root, "symfony.lock");
	if (!ctx.index.hasFile(rel)) return { recipes: new Map(), coverage: { applicationId: app.id,
		capability: "recipes", execution: "not-applicable", result: "not-applicable" }, diagnostics: [] };
	try {
		const data = JSON.parse(ctx.readText(rel, 1024 * 1024));
		if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("expected a package-keyed object");
		const recipes = new Map();
		for (const [name, entry] of Object.entries(data)) {
			if (!name.includes("/") || !entry || typeof entry !== "object") continue;
			recipes.set(name.toLowerCase(), { version: typeof entry.recipe?.version === "string" ? entry.recipe.version : null,
				files: safeRecipeFiles(entry.files) });
		}
		return { recipes, coverage: { applicationId: app.id, capability: "recipes", execution: "completed",
			result: "not-applicable", expected: recipes.size, executed: recipes.size }, diagnostics: [] };
	} catch (error) {
		return { recipes: new Map(), coverage: { applicationId: app.id, capability: "recipes", execution: "failed",
			result: "indeterminate", diagnostic: "CMS_RECIPE_LOCK_INVALID" }, diagnostics: [{ code: "CMS_RECIPE_LOCK_INVALID",
			applicationId: app.id, path: rel, message: `symfony.lock could not be parsed: ${error.message}` }] };
	}
}

function isSymfonyRoot(dir, ctx) {
	if (!ctx.index.hasFile(join(dir, "composer.json"))) return false;
	const hasAppMarker = ctx.index.hasFile(join(dir, "bin/console")) ||
		ctx.index.hasFile(join(dir, "src/Kernel.php")) || ctx.index.hasFile(join(dir, "app/AppKernel.php"));
	if (!hasAppMarker) return false;
	const lock = join(dir, "composer.lock");
	for (const dep of ctx.resolvedDeps.values()) {
		if (dep.ecosystem !== "composer" || dep.coordKey !== "composer:symfony/framework-bundle") continue;
		if ((dep.occurrences || []).some(o => posix(path.relative(ctx.srcRoot, o.manifestPath)) === lock)) return true;
	}
	try {
		const root = JSON.parse(ctx.readText(join(dir, "composer.json")));
		return !!(root.require?.["symfony/framework-bundle"] || root["require-dev"]?.["symfony/framework-bundle"]);
	} catch { return false; }
}

module.exports = {
	id: "symfony", version: "0.1.0", apiVersion: 1, label: "Symfony",
	supportedLayouts: ["modern", "legacy"],
	capabilities: { inventory: "experimental", advisories: "experimental" },
	requiredCodecs: ["composer"], providerIds: ["osv-packagist"],
	discover(ctx) {
		return ctx.index.directories.filter(dir => isSymfonyRoot(dir, ctx)).map(dir => ({
			root: dir, evidence: [{ path: join(dir, "composer.json"), field: "require.symfony/framework-bundle" },
				{ path: ctx.index.hasFile(join(dir, "bin/console")) ? join(dir, "bin/console") :
					ctx.index.hasFile(join(dir, "src/Kernel.php")) ? join(dir, "src/Kernel.php") : join(dir, "app/AppKernel.php") }],
		}));
	},
	collect(app, ctx) {
		const lockPath = join(app.root, "composer.lock");
		const jsonPath = join(app.root, "composer.json");
		const recipeState = readRecipes(app, ctx);
		let symfonyRequireConstraint = null;
		try {
			const root = JSON.parse(ctx.readText(jsonPath, 1024 * 1024));
			if (typeof root.extra?.symfony?.require === "string") symfonyRequireConstraint = root.extra.symfony.require;
		} catch { /* framework inventory still uses the resolved lock */ }
		const components = [];
		for (const dep of ctx.resolvedDeps.values()) {
			if (dep.ecosystem !== "composer") continue;
			const coord = `${dep.namespace}/${dep.name}`.toLowerCase();
			for (const occurrence of dep.occurrences || []) {
				const rel = posix(path.relative(ctx.srcRoot, occurrence.manifestPath));
				if (rel !== lockPath && rel !== jsonPath) continue;
				const kind = coord === "symfony/framework-bundle" || coord === "symfony/symfony" ? "framework" :
					FRAMEWORK_COMPONENTS.has(coord) ? "framework-component" : coord.endsWith("-bundle") ? "bundle" : "library";
				components.push({ id: `${app.id}:${coord}@${occurrence.version}`, applicationId: app.id,
					kind, coord, version: occurrence.version, scope: occurrence.scope,
					...(kind === "framework" && symfonyRequireConstraint ? { symfonyRequireConstraint } : {}),
					managerRelation: occurrence.managerRelation || "unknown", visibility: "unknown",
					...(recipeState.recipes.has(coord) ? { recipe: recipeState.recipes.get(coord) } : {}),
					evidence: [{ path: rel, field: `packages[name=${coord}].version` }] });
			}
		}
		if (!components.some(c => c.kind === "framework")) {
			components.push({ id: `${app.id}:symfony/framework-bundle@unknown`, applicationId: app.id,
				kind: "framework", coord: "symfony/framework-bundle", version: null, visibility: "unknown",
				...(symfonyRequireConstraint ? { symfonyRequireConstraint } : {}),
				evidence: [{ path: jsonPath, field: "require.symfony/framework-bundle" }] });
		}
		const unknownVersion = components.some(c => c.kind === "framework" && !c.version);
		const installedNames = new Set(components.filter(c => c.version).map(c => c.coord));
		const orphanedRecipes = [...recipeState.recipes.keys()].filter(name => !installedNames.has(name));
		return { components, coverage: [
			{ applicationId: app.id, capability: "inventory", execution: unknownVersion ? "partial" : "completed",
				result: unknownVersion ? "indeterminate" : "not-applicable", expected: components.length,
				executed: components.filter(c => c.version).length, ...(unknownVersion ? { diagnostic: "CMS_VERSION_UNKNOWN" } : {}) },
			// Symfony publishes no machine-readable advisory feed of its own: the
			// inventoried components ARE Composer dependencies, so their advisory
			// evaluation is the report's own dependency lanes (OSV.dev, Packagist
			// security-advisories, NVD). The coverage says so instead of inventing a
			// CMS-style gap the scan could never fill.
			{ applicationId: app.id, capability: "advisories", execution: "completed",
				result: "not-applicable", sourceId: "dependency-lanes", expected: components.length,
				executed: components.length },
			recipeState.coverage,
		], diagnostics: [...recipeState.diagnostics,
			...orphanedRecipes.map(name => ({ code: "CMS_RECIPE_ORPHANED", applicationId: app.id, package: name,
				message: `symfony.lock recipe ${name} has no matching installed Composer package` })),
			...(unknownVersion ? [{ code: "CMS_VERSION_UNKNOWN", applicationId: app.id, path: jsonPath,
				message: "Symfony framework version is not resolved by Composer" }] : [])] };
	},
	assess() { return []; },
	remediation() { return null; },
};
