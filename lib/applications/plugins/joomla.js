const path = require("node:path");
const { parseStringPromise } = require("xml2js");
const { join, within, readJson, composerOccurrences, composerComponent, composerCoverageDiagnostic, finishInventory } = require("./wave2-common");

const TYPES = new Map([["component", "component"], ["module", "module"], ["plugin", "plugin"], ["template", "theme"]]);

async function manifest(ctx, relative) {
	try {
		const data = await parseStringPromise(ctx.readText(relative, 65536), { explicitArray: false, trim: true, strict: true });
		const root = data?.extension || data?.install;
		const type = root?.$?.type;
		if (!root || !type) return null;
		return { type, name: typeof root.name === "string" ? root.name : null,
			version: typeof root.version === "string" ? root.version.trim() : null };
	} catch { return null; }
}

function extensionKind(relative, docRoot) {
	const sub = path.posix.relative(docRoot, relative);
	if (/^(administrator\/)?components\/com_[^/]+$/.test(sub)) return "component";
	if (/^(administrator\/)?modules\/mod_[^/]+$/.test(sub)) return "module";
	if (/^plugins\/[^/]+\/[^/]+$/.test(sub)) return "plugin";
	if (/^(administrator\/)?templates\/[^/]+$/.test(sub)) return "theme";
	return null;
}

function codeVersion(ctx, relative) {
	try {
		const source = ctx.readPrefix(relative, 32768);
		const number = name => source.match(new RegExp(`\\bconst\\s+${name}\\s*=\\s*(\\d+)\\s*;`))?.[1];
		const major = number("MAJOR_VERSION"), minor = number("MINOR_VERSION"), patch = number("PATCH_VERSION");
		if ([major, minor, patch].some(value => value == null)) return null;
		const extra = source.match(/\bconst\s+EXTRA_VERSION\s*=\s*['"]([^'"\r\n]*)['"]\s*;/)?.[1] || "";
		return `${major}.${minor}.${patch}${extra ? `-${extra}` : ""}`;
	} catch { return null; }
}

async function extensionAt(ctx, app, dir, expectedKind) {
	for (const file of ctx.index.filesIn(dir).filter(name => name.endsWith(".xml") && name !== "joomla.xml")) {
		const relative = join(dir, file);
		const parsed = await manifest(ctx, relative);
		if (!parsed || TYPES.get(parsed.type) !== expectedKind || !parsed.name) continue;
		const packageJson = join(dir, "composer.json");
		const coord = ctx.index.hasFile(packageJson) ? readJson(ctx, packageJson)?.name || null : null;
		return { id: `${app.id}:${expectedKind}:${dir}`, applicationId: app.id, kind: expectedKind,
			path: dir, name: parsed.name, coord, version: parsed.version, rawVersion: parsed.version,
			versionStatus: parsed.version ? "observed" : "unknown", visibility: ctx.isPrivatePath(dir) ? "private" : "unknown",
			identityStatus: coord ? "verified" : "unknown", activation: "unknown",
			evidence: [{ path: relative, field: "extension.name" }, ...(parsed.version ? [{ path: relative, field: "extension.version" }] : [])] };
	}
	return null;
}

module.exports = {
	id: "joomla", version: "0.1.0", apiVersion: 1, label: "Joomla",
	supportedLayouts: ["site", "component"], capabilities: { inventory: "experimental", advisories: "experimental" },
	requiredCodecs: [], providerIds: [],
	async discover(ctx) {
		if (ctx.scanContext === "component") {
			for (const file of ctx.index.filesIn(".").filter(name => name.endsWith(".xml"))) {
				const parsed = await manifest(ctx, file);
				if (parsed?.name && TYPES.has(parsed.type)) return [{ root: ".", layout: "component",
					componentKind: TYPES.get(parsed.type), evidence: [{ path: file, field: "extension.type" }] }];
			}
			return [];
		}
		const candidates = [];
		for (const dir of ctx.index.directories) {
			const coreManifest = join(dir, "administrator/manifests/files/joomla.xml");
			const versionFile = join(dir, "libraries/src/Version.php");
			if (!ctx.index.hasFile(coreManifest) || !ctx.index.hasFile(versionFile)) continue;
			const parsed = await manifest(ctx, coreManifest);
			if (!parsed || !/joomla/i.test(parsed.name || "")) continue;
			candidates.push({ root: dir, documentRoot: dir, layout: "site",
				evidence: [{ path: coreManifest, field: "extension.name" }, { path: versionFile }] });
		}
		return candidates;
	},
	async collect(app, ctx) {
		const components = [], diagnostics = [composerCoverageDiagnostic(app, ctx)].filter(Boolean);
		if (app.layout === "component") {
			const component = await extensionAt(ctx, app, ".", app.componentKind);
			if (component) components.push(component);
			return finishInventory(app, components, [], "application-advisories", { ctx });
		}
		const coreManifest = join(app.root, "administrator/manifests/files/joomla.xml");
		const core = await manifest(ctx, coreManifest);
		const versionFile = join(app.root, "libraries/src/Version.php");
		const runtimeVersion = codeVersion(ctx, versionFile);
		if (runtimeVersion && core?.version && runtimeVersion !== core.version)
			diagnostics.push({ code: "CMS_VERSION_CONFLICT", applicationId: app.id, path: versionFile,
				message: `Joomla runtime code declares ${runtimeVersion}, package manifest declares ${core.version}` });
		const version = runtimeVersion || core?.version || null;
		components.push({ id: `${app.id}:core`, applicationId: app.id, kind: "core", path: app.root,
			name: "Joomla", coord: null, version, rawVersion: version,
			versionStatus: version ? "observed" : "unknown", visibility: "public",
			identityStatus: "verified", activation: "unknown", evidence: [{ path: coreManifest, field: "extension.version" },
				...(runtimeVersion ? [{ path: versionFile, field: "MAJOR/MINOR/PATCH/EXTRA_VERSION" }] : [])] });
		for (const dir of ctx.index.directories) {
			if (!within(dir, app.root) || dir === app.root) continue;
			const kind = extensionKind(dir, app.root);
			if (!kind) continue;
			const extension = await extensionAt(ctx, app, dir, kind);
			if (extension) components.push(extension);
		}
		for (const entry of composerOccurrences(app, ctx)) {
			if (components.some(c => c.coord === entry.coord)) continue;
			components.push(composerComponent(app, entry, "library"));
		}
		return finishInventory(app, components, diagnostics, "application-advisories", { ctx });
	},
	assess() { return []; },
	remediation() { return null; },
};
