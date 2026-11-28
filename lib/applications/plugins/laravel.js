const path = require("node:path");
const join = (dir, file) => dir === "." ? file : `${dir}/${file}`;
const posix = value => value.split(path.sep).join("/");

function isLaravelRoot(dir, ctx) {
	if (!ctx.index.hasFile(join(dir, "composer.json")) || !ctx.index.hasFile(join(dir, "artisan")) ||
		!ctx.index.hasFile(join(dir, "bootstrap/app.php"))) return false;
	try {
		const root = JSON.parse(ctx.readText(join(dir, "composer.json"), 1024 * 1024));
		return !!(root.require?.["laravel/framework"] || root["require-dev"]?.["laravel/framework"]);
	} catch { return false; }
}

module.exports = {
	id: "laravel", version: "0.1.0", apiVersion: 1, label: "Laravel",
	supportedLayouts: ["artisan"], capabilities: { inventory: "experimental", advisories: "experimental" },
	requiredCodecs: ["composer"], providerIds: ["osv-packagist"],
	discover(ctx) {
		return ctx.index.directories.filter(dir => isLaravelRoot(dir, ctx)).map(dir => ({ root: dir,
			evidence: [{ path: join(dir, "composer.json"), field: "require.laravel/framework" },
				{ path: join(dir, "artisan") }, { path: join(dir, "bootstrap/app.php") }] }));
	},
	collect(app, ctx) {
		const lockPath = join(app.root, "composer.lock");
		const jsonPath = join(app.root, "composer.json");
		const components = [];
		for (const dep of ctx.resolvedDeps.values()) {
			if (dep.ecosystem !== "composer") continue;
			const coord = `${dep.namespace}/${dep.name}`.toLowerCase();
			for (const occurrence of dep.occurrences || []) {
				const rel = posix(path.relative(ctx.srcRoot, occurrence.manifestPath));
				if (rel !== lockPath && rel !== jsonPath) continue;
				components.push({ id: `${app.id}:${coord}@${occurrence.version}`, applicationId: app.id,
					kind: coord === "laravel/framework" ? "framework" : coord.startsWith("laravel/") || coord.startsWith("illuminate/") ? "framework-component" : "library",
					coord, version: occurrence.version, scope: occurrence.scope,
					managerRelation: occurrence.managerRelation || "unknown", visibility: "unknown",
					evidence: [{ path: rel, field: `packages[name=${coord}].version` }] });
			}
		}
		if (!components.some(c => c.kind === "framework")) components.push({ id: `${app.id}:laravel/framework@unknown`,
			applicationId: app.id, kind: "framework", coord: "laravel/framework", version: null, visibility: "unknown",
			evidence: [{ path: jsonPath, field: "require.laravel/framework" }] });
		const unknown = components.filter(c => !c.version);
		return { components, coverage: [
			{ applicationId: app.id, capability: "inventory", execution: unknown.length ? "partial" : "completed",
				result: unknown.length ? "indeterminate" : "not-applicable", expected: components.length,
				executed: components.length - unknown.length, ...(unknown.length ? { diagnostic: "CMS_VERSION_UNKNOWN" } : {}) },
			// Laravel publishes no machine-readable advisory feed of its own: the
			// inventoried components ARE Composer dependencies, so their advisory
			// evaluation is the report's own dependency lanes (OSV.dev, Packagist
			// security-advisories, NVD). The coverage says so instead of inventing a
			// CMS-style gap the scan could never fill.
			{ applicationId: app.id, capability: "advisories", execution: "completed",
				result: "not-applicable", sourceId: "dependency-lanes", expected: components.length,
				executed: components.length },
		], diagnostics: unknown.map(c => ({ code: "CMS_VERSION_UNKNOWN", applicationId: app.id, componentId: c.id,
			message: `version unavailable for ${c.coord}` })) };
	},
	assess() { return []; },
	remediation() { return null; },
};
