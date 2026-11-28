const { parseStringPromise } = require("xml2js");
const { join, within, readJson, composerOccurrences, composerComponent, composerCoverageDiagnostic, finishInventory } = require("./wave2-common");

const COMMUNITY = "magento/product-community-edition";
const ENTERPRISE = "magento/product-enterprise-edition";

async function moduleAt(ctx, app, dir) {
	const xml = join(dir, "etc/module.xml"), registration = join(dir, "registration.php");
	if (!ctx.index.hasFile(xml) || !ctx.index.hasFile(registration)) return null;
	let name;
	try {
		const parsed = await parseStringPromise(ctx.readText(xml, 65536), { explicitArray: false, trim: true, strict: true });
		name = parsed?.config?.module?.$?.name;
		const registered = ctx.readPrefix(registration, 8192)
			.match(/ComponentRegistrar::register\s*\(\s*ComponentRegistrar::MODULE\s*,\s*['"]([^'"\r\n]+)['"]/)?.[1];
		if (!name || registered !== name) return null;
	} catch { return null; }
	const composerFile = join(dir, "composer.json");
	const composer = ctx.index.hasFile(composerFile) ? readJson(ctx, composerFile) : null;
	const version = typeof composer?.version === "string" ? composer.version : null;
	return { id: `${app.id}:module:${dir}`, applicationId: app.id, kind: "module", path: dir,
		name, coord: typeof composer?.name === "string" ? composer.name.toLowerCase() : null,
		version, rawVersion: version, versionStatus: version ? "observed" : "unknown",
		visibility: ctx.isPrivatePath(dir) ? "private" : "unknown",
		identityStatus: composer?.name ? "verified" : "unknown", activation: "unknown",
		evidence: [{ path: xml, field: "config.module.name" }, { path: registration, field: "ComponentRegistrar::MODULE" },
			...(version ? [{ path: composerFile, field: "version" }] : [])] };
}

async function themeAt(ctx, app, dir) {
	const xml = join(dir, "theme.xml"), registration = join(dir, "registration.php");
	if (!ctx.index.hasFile(xml) || !ctx.index.hasFile(registration)) return null;
	let title;
	try {
		const parsed = await parseStringPromise(ctx.readText(xml, 65536), { explicitArray: false, trim: true, strict: true });
		title = parsed?.theme?.title;
		const registered = ctx.readPrefix(registration, 8192)
			.match(/ComponentRegistrar::register\s*\(\s*ComponentRegistrar::THEME\s*,\s*['"]([^'"\r\n]+)['"]/)?.[1];
		if (!title || !registered) return null;
	} catch { return null; }
	const composerFile = join(dir, "composer.json");
	const composer = ctx.index.hasFile(composerFile) ? readJson(ctx, composerFile) : null;
	const version = typeof composer?.version === "string" ? composer.version : null;
	return { id: `${app.id}:theme:${dir}`, applicationId: app.id, kind: "theme", path: dir,
		name: title, coord: typeof composer?.name === "string" ? composer.name.toLowerCase() : null,
		version, rawVersion: version, versionStatus: version ? "observed" : "unknown",
		visibility: ctx.isPrivatePath(dir) ? "private" : "unknown",
		identityStatus: composer?.name ? "verified" : "unknown", activation: "unknown",
		evidence: [{ path: xml, field: "theme.title" }, { path: registration, field: "ComponentRegistrar::THEME" },
			...(version ? [{ path: composerFile, field: "version" }] : [])] };
}

async function componentAt(ctx, app, dir) { return await moduleAt(ctx, app, dir) || themeAt(ctx, app, dir); }

function siteEdition(dir, ctx) {
	if (!ctx.index.hasFile(join(dir, "composer.json")) || !ctx.index.hasFile(join(dir, "bin/magento")) ||
		!ctx.index.hasFile(join(dir, "app/bootstrap.php"))) return null;
	const root = readJson(ctx, join(dir, "composer.json"));
	if (!root) return null;
	if (root.require?.[ENTERPRISE] || root.name === ENTERPRISE) return "adobe-commerce";
	if (root.require?.[COMMUNITY] || ["magento/magento2ce", "magento/project-community-edition"].includes(root.name)) return "open-source";
	return null;
}

module.exports = {
	id: "magento", version: "0.1.0", apiVersion: 1, label: "Magento / Adobe Commerce",
	supportedLayouts: ["composer", "source", "component"],
	capabilities: { inventory: "experimental", advisories: "experimental" }, requiredCodecs: [], providerIds: [],
	async discover(ctx) {
		if (ctx.scanContext === "component") {
			const component = await componentAt(ctx, { id: "magento:." }, ".");
			return component ? [{ root: ".", layout: "component", componentKind: component.kind,
				evidence: component.evidence }] : [];
		}
		return ctx.index.directories.map(dir => ({ dir, edition: siteEdition(dir, ctx) })).filter(x => x.edition)
			.map(({ dir, edition }) => ({ root: dir, layout: "composer", edition,
				evidence: [{ path: join(dir, "composer.json"), field: edition === "adobe-commerce" ? ENTERPRISE : COMMUNITY },
					{ path: join(dir, "bin/magento") }, { path: join(dir, "app/bootstrap.php") }] }));
	},
	async collect(app, ctx) {
		if (app.layout === "component") return finishInventory(app, [await componentAt(ctx, app, ".")].filter(Boolean), [], "application-advisories", { ctx });
		const components = [], diagnostics = [composerCoverageDiagnostic(app, ctx)].filter(Boolean);
		const entries = composerOccurrences(app, ctx);
		const products = entries.filter(entry => [COMMUNITY, ENTERPRISE].includes(entry.coord));
		const edition = products.some(entry => entry.coord === ENTERPRISE) ? "adobe-commerce" :
			products.some(entry => entry.coord === COMMUNITY) ? "open-source" :
			siteEdition(app.root, ctx);
		if (products.length > 1) diagnostics.push({ code: "CMS_VERSION_CONFLICT", applicationId: app.id,
			message: "multiple Magento/Adobe Commerce product packages are locked" });
		const product = products.find(entry => entry.coord === (edition === "adobe-commerce" ? ENTERPRISE : COMMUNITY));
		// The lock pin is the authority on a composer-installed site; a SOURCE
		// distribution ships no lock, but its root composer.json carries the exact
		// product version ("version": "2.4.7-p3") — observed, with the file as evidence.
		let observedVersion = null;
		let requiredProduct = null;
		if (!product) {
			try {
				const rootComposer = JSON.parse(ctx.readText(join(app.root, "composer.json"), 65536));
				observedVersion = typeof rootComposer?.version === "string" && rootComposer.version.trim() ? rootComposer.version.trim() : null;
				requiredProduct = [COMMUNITY, ENTERPRISE].find(name => rootComposer?.require && Object.keys(rootComposer.require).includes(name)) || null;
			} catch { /* no readable marker → the version stays unknown and the coverage says so */ }
		}
		if (observedVersion) {
			// A source distribution ships no lock BY CONSTRUCTION: the tree is the
			// product and its root composer.json carries the exact version — the
			// missing-lock alarm would misread it as an unresolved site install.
			const lockAlarm = diagnostics.findIndex(d => d.code === "CMS_LOCKFILE_MISSING");
			if (lockAlarm >= 0) diagnostics.splice(lockAlarm, 1);
		}
		const coreVersion = product?.occurrence.version || observedVersion || null;
		components.push({ id: `${app.id}:core`, applicationId: app.id, kind: "core", path: app.root,
			name: edition === "adobe-commerce" ? "Adobe Commerce" : "Magento Open Source", edition,
			coord: product?.coord || requiredProduct || null, version: coreVersion,
			rawVersion: coreVersion, versionStatus: product ? "locked" : observedVersion ? "observed" : "unknown",
			visibility: "public", identityStatus: (product || requiredProduct) ? "verified" : "probable", activation: "unknown",
			evidence: [product ? { path: product.relative, field: `packages[name=${product.coord}].version` } :
				observedVersion ? { path: join(app.root, "composer.json"), field: "version" } :
				{ path: join(app.root, "composer.json"), field: "name/require" }] });
		for (const dir of ctx.index.directories) {
			if (!within(dir, app.root) || dir === app.root) continue;
			const relative = app.root === "." ? dir : dir.slice(app.root.length + 1);
			if (!/^app\/code\/[^/]+\/[^/]+$/.test(relative) &&
				!/^app\/design\/(frontend|adminhtml)\/[^/]+\/[^/]+$/.test(relative)) continue;
			const component = await componentAt(ctx, app, dir);
			if (component) components.push(component);
		}
		for (const entry of entries) {
			if (entry === product) continue;
			const local = components.find(c => c.coord === entry.coord);
			if (local) {
				if (local.version && local.version !== entry.occurrence.version) diagnostics.push({ code: "CMS_VERSION_CONFLICT",
					applicationId: app.id, componentId: local.id, path: local.path,
					message: `${local.name} declares ${local.version}, lock pins ${entry.occurrence.version}` });
				local.rawVersion = local.version;
				local.version = entry.occurrence.version;
				local.versionStatus = "locked";
				local.evidence.push({ path: entry.relative, field: `packages[name=${entry.coord}].version` });
				continue;
			}
			const kind = entry.occurrence.packageType === "magento2-module" ? "module" :
				entry.occurrence.packageType === "magento2-theme" ? "theme" : "library";
			components.push(composerComponent(app, entry, kind));
		}
		return finishInventory(app, components, diagnostics, "application-advisories", { ctx });
	},
	assess() { return []; },
	remediation() { return null; },
};
