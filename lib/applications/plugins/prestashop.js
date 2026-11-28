const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");
const { fetchGithubAdvisories, writeSnapshotAtomically } = require("../live-snapshot");
const { assessGithubAdvisories, prestashopRangeGrammar } = require("../../providers/github/advisories");
const { join, within, readJson, composerOccurrences, composerComponent, composerCoverageDiagnostic, finishInventory, localSourceSnapshot } = require("./wave2-common");

const GITHUB_REPO = "PrestaShop/PrestaShop";
const SOURCE_ID = "github-prestashop-advisories";

function literalVersion(ctx, relative, constant) {
	if (!ctx.index.hasFile(relative)) return null;
	try {
		const source = ctx.readPrefix(relative, 65536);
		return source.match(new RegExp(`\\bdefine\\s*\\(\\s*['\"]${constant}['\"]\\s*,\\s*['\"]([^'\"\\r\\n]+)['\"]`))?.[1] || null;
	} catch { return null; }
}

function moduleAt(ctx, app, dir) {
	const slug = dir.split("/").at(-1);
	const names = dir === "." ? ctx.index.filesIn(".").filter(name => name.endsWith(".php")) : [`${slug}.php`];
	let file, name, observedVersion;
	for (const candidate of names) {
		const relative = join(dir, candidate);
		if (!ctx.index.hasFile(relative)) continue;
		let source;
		try { source = ctx.readPrefix(relative, 65536); } catch { continue; }
		if (!/\bextends\s+\\?[A-Za-z_\\]*Module(?:Graph(?:Engine)?|Grid(?:Engine)?)?\b/i.test(source)) continue;
		const declared = source.match(/\$this->name\s*=\s*['"]([^'"\r\n]+)['"]\s*;/)?.[1];
		if (!declared || declared.toLowerCase() !== candidate.slice(0, -4).toLowerCase()) continue;
		file = relative; name = declared;
		observedVersion = source.match(/\$this->version\s*=\s*['"]([^'"\r\n]+)['"]\s*;/)?.[1] || null;
		break;
	}
	if (!file) return null;
	const packageJson = join(dir, "composer.json");
	const coord = ctx.index.hasFile(packageJson) ? readJson(ctx, packageJson)?.name || null : null;
	return { id: `${app.id}:module:${dir}`, applicationId: app.id, kind: "module", path: dir,
		name, coord, version: observedVersion, rawVersion: observedVersion,
		versionStatus: observedVersion ? "observed" : "unknown",
		visibility: ctx.isPrivatePath(dir) ? "private" : "unknown", identityStatus: coord ? "verified" : "unknown",
		activation: "unknown", evidence: [{ path: file, field: "$this->name" },
			...(observedVersion ? [{ path: file, field: "$this->version" }] : [])] };
}

function themeAt(ctx, app, dir) {
	const file = join(dir, "config/theme.yml");
	if (!ctx.index.hasFile(file)) return null;
	let data;
	try { data = yaml.load(ctx.readText(file, 65536), { schema: yaml.JSON_SCHEMA }); }
	catch { return null; }
	if (!data || typeof data !== "object" || typeof data.name !== "string" || !data.name.trim()) return null;
	const observedVersion = typeof data.version === "string" || typeof data.version === "number" ? String(data.version) : null;
	const packageJson = join(dir, "composer.json");
	const coord = ctx.index.hasFile(packageJson) ? readJson(ctx, packageJson)?.name || null : null;
	return { id: `${app.id}:theme:${dir}`, applicationId: app.id, kind: "theme", path: dir,
		name: data.name, coord, version: observedVersion, rawVersion: observedVersion,
		versionStatus: observedVersion ? "observed" : "unknown",
		visibility: ctx.isPrivatePath(dir) ? "private" : "unknown", identityStatus: coord ? "verified" : "unknown",
		activation: "unknown", evidence: [{ path: file, field: "name" },
			...(observedVersion ? [{ path: file, field: "version" }] : [])] };
}

function adminThemeAt(ctx, app, dir) {
	const admin = path.posix.dirname(path.posix.dirname(dir));
	if (!ctx.index.hasFile(join(admin, "index.php")) || !ctx.index.directories.includes(join(dir, "template"))) return null;
	for (const filename of ["package.json", "package-lock.json"]) {
		const file = join(dir, filename);
		if (!ctx.index.hasFile(file)) continue;
		const data = readJson(ctx, file);
		const metadata = data?.packages?.[""] || data;
		if (metadata?.name !== path.posix.basename(dir)) continue;
		const version = typeof metadata.version === "string" ? metadata.version : null;
		return { id:`${app.id}:theme:${dir}`, applicationId:app.id, kind:"theme", path:dir,
			name:metadata.name, version, versionStatus:version ? "observed" : "unknown",
			visibility:ctx.isPrivatePath(dir) ? "private" : "unknown", activation:"unknown",
			evidence:[{path:file,field:data?.packages?.[""] ? 'packages[""].name' : "name"},
				...(version ? [{path:file,field:data?.packages?.[""] ? 'packages[""].version' : "version"}] : [])] };
	}
	return null;
}

function componentAt(ctx, app) { return moduleAt(ctx, app, ".") || themeAt(ctx, app, "."); }

function distributionVersion(dir, ctx) {
	const file = join(dir, "src/Core/Version.php");
	if (!ctx.index.hasFile(file)) return null;
	let text;
	try { text = ctx.readPrefix(file, 16384); } catch { return null; }
	if (!/namespace\s+PrestaShop\\PrestaShop\\Core\s*;/.test(text)) return null;
	return text.match(/\bpublic\s+const\s+VERSION\s*=\s*['"]([0-9]+(?:\.[0-9]+){1,3}(?:[-+][\w.-]+)?)['"]/)?.[1] || null;
}

function isSite(dir, ctx) {
	if (!ctx.index.hasFile(join(dir, "config/config.inc.php"))) return false;
	const manifest = join(dir, "composer.json");
	if (ctx.index.hasFile(manifest) && readJson(ctx, manifest)?.name?.toLowerCase() === "prestashop/prestashop") return true;
	return ctx.index.hasFile(join(dir, "classes/Tools.php")) && (ctx.index.hasFile(join(dir, "config/settings.inc.php")) || !!distributionVersion(dir, ctx));
}

module.exports = {
	id: "prestashop", version: "0.1.0", apiVersion: 1, label: "PrestaShop",
	supportedLayouts: ["composer", "legacy", "component"],
	capabilities: { inventory: "experimental", advisories: "experimental" }, requiredCodecs: [],
	providerIds: [SOURCE_ID],
	discover(ctx) {
		if (ctx.scanContext === "component") {
			const component = componentAt(ctx, { id: "prestashop:." });
			return component ? [{ root: ".", layout: "component", componentKind: component.kind,
				evidence: component.evidence }] : [];
		}
		return ctx.index.directories.filter(dir => isSite(dir, ctx)).map(dir => {
			const script = "tmp/docker_run.sh";
			let template = false;
			if (ctx.scanContext === "installation" && dir === "tmp/data-ps/prestashop" && ctx.index.hasFile(script)) {
				try {
					template = /^\s*cp\s+(?:-[A-Za-z]+\s+)*\/tmp\/data-ps\/prestashop\/?\s+\/var\/www\/html\/?\s*$/m.test(ctx.readText(script, 65536));
				} catch { /* Keep the role unknown when the script cannot be read. */ }
			}
			return { root: dir,
			...(template ? {deploymentRole:"installation-template"} : {}),
			layout: ctx.index.hasFile(join(dir, "composer.json")) ? "composer" : "legacy",
			evidence: [{ path: join(dir, "config/config.inc.php") },
				{ path: ctx.index.hasFile(join(dir, "composer.json")) ? join(dir, "composer.json") : join(dir, "classes/Tools.php") }, ...(template ? [{path:script,field:"installation copy source"}] : [])] };
		});
	},
	collect(app, ctx) {
		if (app.layout === "component") return finishInventory(app, [componentAt(ctx, app)].filter(Boolean),
			[], undefined, { advisories: false });
		const components = [], diagnostics = [composerCoverageDiagnostic(app, ctx)].filter(Boolean);
		const installedFile = join(app.root, "config/settings.inc.php");
		const sourceFile = join(app.root, "install-dev/install_version.php");
		const installed = literalVersion(ctx, installedFile, "_PS_VERSION_");
		const source = literalVersion(ctx, sourceFile, "_PS_INSTALL_VERSION_");
		const release = distributionVersion(app.root, ctx);
		const version = installed || release || source;
		if (installed && source && installed !== source) diagnostics.push({ code: "CMS_VERSION_CONFLICT",
			applicationId: app.id, path: installedFile,
			message: `installed PrestaShop version ${installed} differs from source installer version ${source}` });
		components.push({ id: `${app.id}:core`, applicationId: app.id, kind: "core", path: app.root,
			name: "PrestaShop", coord: "prestashop/prestashop", version, rawVersion: version,
			versionStatus: installed || release ? "observed" : source ? "source-observed" : "unknown",
			visibility: "public", identityStatus: "verified", activation: "unknown",
			evidence: [{ path: installed ? installedFile : release ? join(app.root, "src/Core/Version.php") : source ? sourceFile : join(app.root, "composer.json"),
				field: installed ? "_PS_VERSION_" : release ? "Version::VERSION" : source ? "_PS_INSTALL_VERSION_" : "name" }] });
		for (const dir of ctx.index.directories) {
			if (!within(dir, app.root) || dir === app.root) continue;
			const relative = app.root === "." ? dir : dir.slice(app.root.length + 1);
			if (/^modules\/[^/]+$/.test(relative)) {
				const module = moduleAt(ctx, app, dir);
				if (module) components.push(module);
			} else if (/^(?:admin[^/]*\/)?themes\/[^/]+$/.test(relative)) {
				const theme = themeAt(ctx, app, dir) || (relative.startsWith("admin") && adminThemeAt(ctx, app, dir));
				if (theme) components.push(theme);
			}
		}
		const entries = composerOccurrences(app, ctx);
		for (const entry of entries) {
			const kind = entry.occurrence.packageType === "prestashop-module" ? "module" :
				entry.occurrence.packageType === "prestashop-theme" ? "theme" : "library";
			const locked = composerComponent(app, entry, kind);
			// Distribution builds can strip each module's composer.json. The official
			// installer places a typed prestashop/<slug> under modules/ or themes/.
			const slug = entry.coord.split("/")[1];
			const installDir = join(app.root,(kind === "theme" ? "themes/" : "modules/") + slug);
			const installed = components.find(c => c.coord?.toLowerCase() === entry.coord ||
				(kind !== "library" && entry.coord.startsWith("prestashop/") && c.kind === kind &&
				!c.coord && c.path === installDir && c.name?.toLowerCase() === slug));
			if (!installed) { components.push(locked); continue; }
			installed.coord = entry.coord;
			installed.managerRelation = locked.managerRelation;
			installed.evidence.push(...locked.evidence);
			if (installed.version && installed.version !== locked.version) {
				installed.versionConflict = {observed:installed.version,locked:locked.version};
				diagnostics.push({code:"CMS_VERSION_CONFLICT",applicationId:app.id,componentId:installed.id,
					path:installed.path,message:`Installed ${entry.coord} ${installed.version} differs from composer.lock ${locked.version}`});
			} else if (!installed.version) {
				installed.version = locked.version;
				installed.versionStatus = "locked";
			}
		}
		return finishInventory(app, components, diagnostics, undefined, { advisories: false });
	},
	// The publisher's machine feed is the GitHub advisory list of PrestaShop's own core
	// repository. Its 2020-era records carry no package identity; they are attributed to
	// the core coordinate here, and every range is evaluated with its patched bound.
	async assess(app, components, ctx) {
		if (!ctx.prestashopAdvisoriesPath && !ctx.livePrestashopAdvisoriesUrl) return { findings: [], coverage: [{
			applicationId: app.id, capability: "advisories", sourceId: SOURCE_ID, execution: "not-run",
			result: "indeterminate", expected: (components || []).length, executed: 0, diagnostic: "CMS_PROVIDER_UNCONFIGURED" }] };
		const key = ctx.prestashopAdvisoriesPath
			? `prestashop-advisories:${ctx.prestashopAdvisoriesPath}` : `prestashop-advisories:live:${ctx.livePrestashopAdvisoriesUrl}`;
		let cached = ctx.snapshotCache.get(key);
		if (!cached && ctx.prestashopAdvisoriesPath) {
			const validated = ctx.validatedLocalSources?.get(ctx.prestashopAdvisoriesPath);
			const stat = validated?.stat || fs.statSync(ctx.prestashopAdvisoriesPath);
			if (!stat.isFile() || stat.size > 128 * 1024 * 1024) throw new Error("PrestaShop advisory snapshot must be a JSON file of at most 128 MiB");
			const bytes = validated?.bytes || fs.readFileSync(ctx.prestashopAdvisoriesPath);
			const snapshot = validated?.snapshot || JSON.parse(bytes.toString("utf8"));
			const sourceSnapshot = localSourceSnapshot(ctx, ctx.prestashopAdvisoriesPath, bytes, stat, snapshot);
			cached = { snapshot, sourceSnapshot };
		} else if (!cached) {
			const fetched = await fetchGithubAdvisories(GITHUB_REPO, { fetchImpl: ctx.fetchImpl || undefined,
				endpoint: ctx.livePrestashopAdvisoriesUrl.startsWith("http") ? ctx.livePrestashopAdvisoriesUrl : null, now: ctx.now });
			if (ctx.advisoryCacheDir) writeSnapshotAtomically(path.join(ctx.advisoryCacheDir, "github-prestashop-advisories.json"), fetched.snapshot);
			cached = { snapshot: fetched.snapshot, sourceSnapshot: fetched.sourceSnapshot, live: true };
		}
		ctx.snapshotCache.set(key, cached);
		const assessed = assessGithubAdvisories(cached.snapshot, components,
			{ sourceId: SOURCE_ID, fallbackCoord: "prestashop/prestashop", normalizeRange: prestashopRangeGrammar });
		return { findings: assessed.matches, coverage: assessed.coverage.map(check => ({ ...check, sourceSnapshot: cached.sourceSnapshot })),
			diagnostics: assessed.diagnostics };
	},
	remediation() { return null; },
};
