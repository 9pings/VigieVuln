/**
 * lib/applications/plugins/spip.js — the SPIP application plugin.
 *
 * SPIP is a French-CMS staple with a layout no other product shares: the front
 * controller `spip.php` next to `ecrire/inc_version.php` (which carries
 * `$spip_version_branche`), the official dist plugins under `plugins-dist/`
 * (each with a `paquet.xml` prefix+version), user plugins under `plugins/`
 * (`paquet.xml`, or legacy `plugin.xml`), and skeletons in `squelettes/`.
 *
 * Detection is conjunctive (`spip.php` AND `ecrire/inc_version.php`) and the core
 * version is only reported when the version constant is actually readable in the
 * marker file — a bare file name never creates an application. The advisory lane is
 * NVD's `cpe:2.3:a:spip:spip` (see lib/providers/spip/advisories.js):
 * no publisher API exists. SPIP plugins have no advisory source at all — their rows
 * say so. The composer lock of a SPIP tree is scanned by the standard lanes like
 * any library tree; this plugin adds the instance view on top.
 */
const path = require("node:path");
const fs = require("node:fs");
const { SPIP_ADVISORIES_URL, fetchSpipAdvisories, assessSpipAdvisories } = require("../../providers/spip/advisories");
const { writeSnapshotAtomically } = require("../live-snapshot");
const { localSourceSnapshot } = require("./wave2-common");

/** Attributes of a `paquet.xml` (SPIP ≥3) or legacy `plugin.xml` root element. */
function readPluginMetadata(ctx, relPath, maxBytes = 65536) {
	let content;
	try { content = ctx.readText(relPath, maxBytes); }
	catch (error) { return { diagnostic: { code: "CMS_INFO_INVALID", path: relPath, message: error.message } }; }
	const head = content.slice(0, 4096);
	const attrs = {};
	const attrRe = /([a-z_]+)\s*=\s*"([^"]*)"/g;
	let match;
	while ((match = attrRe.exec(head))) attrs[match[1].toLowerCase()] = match[2];
	// paquet.xml carries identity as <paquet/> attributes; plugin.xml (legacy) as child elements.
	const tag = name => {
		const m = content.match(new RegExp(`<${name}[^>]*>([^<]*)</${name}>`));
		return m ? m[1].trim() : null;
	};
	const prefix = attrs.prefix || tag("prefix");
	const version = attrs.version || tag("version");
	if (!prefix) return { diagnostic: { code: "CMS_INFO_INVALID", path: relPath, message: "the plugin metadata carries no prefix" } };
	return { prefix, version: version || null, etat: attrs.etat || tag("etat") || null,
		compatibilite: attrs.compatibilite || tag("compatibilite") || null,
		nom: attrs.nom || tag("nom") };
}

module.exports = {
	id: "spip", version: "0.1.0", apiVersion: 1, label: "SPIP",
	supportedLayouts: ["classic"],
	capabilities: { inventory: "experimental", advisories: "experimental" },
	requiredCodecs: [], providerIds: ["spip-security-advisories"],
	discover(ctx) {
		// Conjunctive positive markers of a SPIP root: the front controller AND the
		// core version file that only ships inside `ecrire/`. A composer.json named
		// spip/spip never creates an application by itself.
		return ctx.index.directories
			.filter(dir => ctx.index.hasFile(path.join(dir, "ecrire/inc_version.php")) && ctx.index.hasFile(path.join(dir, "spip.php")))
			.map(dir => ({ root: dir, layout: "classic", documentRoot: dir,
				evidence: [{ path: path.join(dir, "spip.php") },
					{ path: path.join(dir, "ecrire/inc_version.php"), field: "spip_version_branche" }] }));
	},
	collect(app, ctx) {
		const versionFile = path.join(app.root, "ecrire/inc_version.php");
		let observed = null;
		try { observed = ctx.readPrefix(versionFile, 65536).match(/\$spip_version_branche\s*=\s*['"]([^'"]+)['"]/)?.[1] || null; }
		catch { /* unreadable marker: the version stays unproven and the coverage says so */ }
		const components = [{ id: `${app.id}:core`, applicationId: app.id, kind: "core", path: app.root,
			name: "SPIP", coord: "spip/spip", version: observed, rawVersion: observed, normalizedVersion: observed,
			visibility: "public", identityStatus: "verified", catalogueStatus: "not-queried", activation: "unknown",
			evidence: [{ path: versionFile, field: "spip_version_branche" }] }];
		const diagnostics = [];
		if (!components[0].version) diagnostics.push({ code: "CMS_VERSION_UNKNOWN", applicationId: app.id,
			componentId: components[0].id, message: "the SPIP version constant is not readable in ecrire/inc_version.php" });

		// Plugins: the official dist set (`plugins-dist/`, public) and user-installed ones
		// (`plugins/`, unknown — or private by declared path). Skeletons carry no version
		// metadata, so they are not inventoried as versioned components.
		for (const kind of ["plugins-dist", "plugins"]) {
			const rootRel = app.root === "." ? kind : `${app.root}/${kind}`;
			const dist = kind === "plugins-dist";
			for (const dir of ctx.index.directories) {
				if (path.posix.dirname(dir) !== rootRel) continue;
				const metadata = readPluginMetadata(ctx, path.posix.join(dir, "paquet.xml"));
				const plugin = metadata.diagnostic ? readPluginMetadata(ctx, path.posix.join(dir, "plugin.xml")) : metadata;
				const metadataFile = metadata.diagnostic ? "plugin.xml" : "paquet.xml";
				if (plugin?.diagnostic) { diagnostics.push({ code: plugin.diagnostic.code, applicationId: app.id,
					path: dir, message: plugin.diagnostic.message }); continue; }
				const visibility = ctx.isPrivatePath(dir) ? "private" : dist ? "public" : "unknown";
				components.push({ id: `${app.id}:plugin:${dir}`, applicationId: app.id, kind: "plugin",
					path: dir, name: plugin.nom || plugin.prefix, machineName: plugin.prefix, coord: null,
					version: plugin.version, rawVersion: plugin.version, normalizedVersion: plugin.version,
					coreVersionRequirement: plugin.compatibilite || null, visibility,
					identityStatus: dist ? "verified" : "unknown", catalogueStatus: "not-queried",
					activation: plugin.etat || "unknown",
					evidence: [{ path: path.posix.join(dir, metadataFile), field: "prefix" },
						...(plugin.version ? [{ path: path.posix.join(dir, metadataFile), field: "version" }] : [])] });
			}
		}

		const unknown = components.filter(c => !c.version);
		for (const c of unknown) if (c.kind !== "core") diagnostics.push({ code: "CMS_VERSION_UNKNOWN",
			applicationId: app.id, componentId: c.id, message: `version unavailable for ${c.kind} ${c.name}` });
		return { components, diagnostics, coverage: [
			{ applicationId: app.id, capability: "inventory",
				execution: unknown.length || diagnostics.length ? "partial" : "completed",
				result: unknown.length || diagnostics.length ? "indeterminate" : "not-applicable",
				expected: components.length, executed: components.length - unknown.length,
				...(unknown.length || diagnostics.length ? { diagnostic: (diagnostics[0] || { code: "CMS_VERSION_UNKNOWN" }).code } : {}) },
			// No lifecycle source covers SPIP (endoflife.date has no entry) — the row says
			// so instead of borrowing another product's verdict.
			{ applicationId: app.id, capability: "lifecycle", sourceId: "application-lifecycle",
				execution: "not-run", result: "indeterminate", expected: 1, executed: 0,
				diagnostic: "CMS_LIFECYCLE_NOT_QUALIFIED" },
		] };
	},
	async assess(app, components, ctx) {
		if (!ctx.spipAdvisoriesPath && !ctx.liveSpipAdvisoriesUrl) return { findings: [],
			coverage: (components || []).map(component => ({
				applicationId: component.applicationId, occurrenceId: component.id, capability: "advisories",
				sourceId: component.visibility === "private" ? "internal-advisories" : "spip-security-advisories",
				expected: 1, executed: 0, execution: "not-run", result: "indeterminate",
				diagnostic: "CMS_PROVIDER_UNCONFIGURED" })), diagnostics: [] };
		const key = ctx.spipAdvisoriesPath
			? `spip-advisories:${ctx.spipAdvisoriesPath}` : `spip-advisories:live:${ctx.liveSpipAdvisoriesUrl}`;
		let cached = ctx.snapshotCache.get(key);
		if (!cached && ctx.spipAdvisoriesPath) {
			// Reuse the runner's single validated read when available (freshness and schema
			// were already checked before discovery); fall back to a direct read otherwise.
			const validated = ctx.validatedLocalSources?.get(ctx.spipAdvisoriesPath);
			const stat = validated?.stat || fs.statSync(ctx.spipAdvisoriesPath);
			if (!stat.isFile() || stat.size > 128 * 1024 * 1024) throw new Error("SPIP advisory snapshot must be a JSON file of at most 128 MiB");
			const bytes = validated?.bytes || fs.readFileSync(ctx.spipAdvisoriesPath);
			const snapshot = validated?.snapshot || JSON.parse(bytes.toString("utf8"));
			const sourceSnapshot = localSourceSnapshot(ctx, ctx.spipAdvisoriesPath, bytes, stat, snapshot);
			cached = { snapshot, sourceSnapshot };
		} else if (!cached) {
			const fetched = await fetchSpipAdvisories({ fetchImpl: ctx.fetchImpl || undefined,
				...(ctx.liveSpipAdvisoriesUrl !== SPIP_ADVISORIES_URL ? { apiUrl: ctx.liveSpipAdvisoriesUrl } : {}),
				...(ctx.spipAdvisoriesApiKey ? { apiKey: ctx.spipAdvisoriesApiKey } : {}), now: ctx.now });
			if (ctx.advisoryCacheDir) writeSnapshotAtomically(path.join(ctx.advisoryCacheDir, "spip-security-advisories.json"), fetched.snapshot);
			cached = { snapshot: fetched.snapshot, sourceSnapshot: fetched.sourceSnapshot, live: true };
		}
		ctx.snapshotCache.set(key, cached);
		const assessed = assessSpipAdvisories(cached.snapshot, components);
		return { findings: assessed.matches, coverage: assessed.coverage
			.map(check => ({ ...check, sourceSnapshot: cached.sourceSnapshot })), diagnostics: assessed.diagnostics };
	},
	remediation() { return null; },
};
