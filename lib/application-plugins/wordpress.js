const path = require("node:path");
const fs = require("node:fs");
const { assessWordfenceFeed, indexFeed } = require("../application-providers/wordfence-v3");
const { assertFresh } = require("../advisory-freshness");
const { fetchWordfenceFeed, fetchWordpressChecksums, writeSnapshotAtomically } = require("../application-providers/live-snapshot");
const { validateChecksums, evaluateChecksums, DEFAULT_MAX_FILE_BYTES, WP_CHECKSUMS_API } = require("../application-providers/wp-checksums");
const { localSourceSnapshot } = require("./wave2-common");

const join = (dir, file) => dir === "." ? file : `${dir}/${file}`;
const directChild = (dir, parent) => path.posix.dirname(dir) === parent;
const DROP_INS = new Set(["advanced-cache.php", "db.php", "object-cache.php", "sunrise.php", "maintenance.php", "fatal-error-handler.php", "install.php"]);

function header(text, key) {
	const comment = String(text || "").match(/\/\*([\s\S]*?)\*\//)?.[1] || "";
	const line = comment.split(/\r?\n/).find(raw => new RegExp(`^\\s*\\*?\\s*${key}:`, "i").test(raw));
	return line ? line.replace(new RegExp(`^\\s*\\*?\\s*${key}:\\s*`, "i"), "").trim() : null;
}

function pluginAt(dir, ctx, app, kind = "plugin") {
	for (const name of ctx.index.filesIn(dir).filter(n => n.endsWith(".php"))) {
		const file = join(dir, name);
		let content;
		try { content = ctx.readPrefix(file); } catch { continue; }
		const displayName = header(content, "Plugin Name");
		if (!displayName) continue;
		const version = header(content, "Version");
		const privateComponent = ctx.isPrivatePath(dir) || !!header(content, "Update URI");
		const publicSlug = privateComponent ? null : ctx.publicSlugForPath(dir);
		let coord = null;
		const composerJson = join(dir, "composer.json");
		if (ctx.index.hasFile(composerJson)) {
			try { coord = JSON.parse(ctx.readText(composerJson)).name || null; } catch { /* identity stays local/unknown */ }
		}
		return { id: `${app.id}:${kind}:${dir}`, applicationId: app.id, kind, path: dir,
			name: displayName, slug: publicSlug || path.posix.basename(dir), coord, version: version || null,
			visibility: privateComponent ? "private" : publicSlug ? "public" : "unknown",
			catalogueStatus: publicSlug ? "user-declared" : "not-queried",
			identityStatus: publicSlug ? "asserted" : coord ? "verified" : "probable", activation: "unknown",
			evidence: [{ path: file, field: "Plugin Name" }, ...(version ? [{ path: file, field: "Version" }] : [])] };
	}
	return null;
}

function themeAt(dir, ctx, app) {
	const file = join(dir, "style.css");
	if (!ctx.index.hasFile(file)) return null;
	let content;
	try { content = ctx.readPrefix(file); } catch { return null; }
	const name = header(content, "Theme Name");
	if (!name) return null;
	const version = header(content, "Version");
	return { id: `${app.id}:theme:${dir}`, applicationId: app.id, kind: "theme", path: dir,
		name, slug: ctx.publicSlugForPath(dir) || path.posix.basename(dir), version: version || null, parentSlug: header(content, "Template"),
		visibility: ctx.isPrivatePath(dir) ? "private" : ctx.publicSlugForPath(dir) ? "public" : "unknown",
		catalogueStatus: ctx.publicSlugForPath(dir) ? "user-declared" : "not-queried",
		identityStatus: ctx.publicSlugForPath(dir) ? "asserted" : "probable", activation: "unknown", evidence: [{ path: file, field: "Theme Name" },
			...(version ? [{ path: file, field: "Version" }] : [])] };
}

module.exports = {
	id: "wordpress", version: "0.1.0", apiVersion: 1, label: "WordPress",
	supportedLayouts: ["classic", "bedrock"], capabilities: { inventory: "experimental", advisories: "experimental" },
	requiredCodecs: [], providerIds: ["wordfence-v3", "wordpress-checksums"],
	discover(ctx) {
		if (ctx.scanContext === "component") {
			const plugin = pluginAt(".", ctx, { id: "wordpress:." });
			const theme = themeAt(".", ctx, { id: "wordpress:." });
			if (!plugin && !theme) return [];
			const component = plugin || theme;
			return [{ root: ".", layout: "component", componentKind: component.kind, evidence: component.evidence }];
		}
		const bedrock = ctx.index.directories.filter(dir => ctx.index.hasFile(join(dir, "composer.json")) &&
			ctx.index.hasFile(join(dir, "web/wp/wp-includes/version.php")) &&
			ctx.index.hasFile(join(dir, "web/wp/wp-admin/index.php")) &&
			ctx.index.hasFile(join(dir, "web/wp/wp-load.php")))
			.map(dir => ({ root: dir, layout: "bedrock", documentRoot: join(dir, "web/wp"), contentRoot: join(dir, "web/app"),
				evidence: [{ path: join(dir, "composer.json") }, { path: join(dir, "web/wp/wp-includes/version.php"), field: "wp_version" }] }));
		const bedrockCoreRoots = new Set(bedrock.map(c => c.documentRoot));
		const classic = ctx.index.directories.filter(dir => !bedrockCoreRoots.has(dir) && ctx.index.hasFile(join(dir, "wp-includes/version.php")) &&
			ctx.index.hasFile(join(dir, "wp-admin/index.php")) && ctx.index.hasFile(join(dir, "wp-load.php")))
			.map(dir => ({ root: dir, layout: "classic", documentRoot: dir, contentRoot: join(dir, "wp-content"),
				evidence: [{ path: join(dir, "wp-includes/version.php"), field: "wp_version" },
					{ path: join(dir, "wp-load.php") }] }));
		return [...bedrock, ...classic];
	},
	collect(app, ctx) {
		if (app.layout === "component") {
			const component = app.componentKind === "theme" ? themeAt(".", ctx, app) : pluginAt(".", ctx, app);
			if (!component) throw new Error("standalone WordPress component header is unreadable");
			return { components: [component], coverage: [{ applicationId: app.id, capability: "inventory",
				execution: component.version ? "completed" : "partial", result: component.version ? "not-applicable" : "indeterminate",
				expected: 1, executed: component.version ? 1 : 0,
				...(!component.version ? { diagnostic: "CMS_VERSION_UNKNOWN" } : {}) }],
				diagnostics: component.version ? [] : [{ code: "CMS_VERSION_UNKNOWN", applicationId: app.id,
					componentId: component.id, message: `version unavailable for ${component.kind} ${component.name}` }] };
		}
		const docRoot = app.documentRoot || app.root;
		const contentRoot = app.contentRoot || join(app.root, "wp-content");
		const versionFile = join(docRoot, "wp-includes/version.php");
		let version = null;
		try { version = ctx.readPrefix(versionFile, 16384).match(/\$wp_version\s*=\s*['"]([^'"\r\n]+)['"]\s*;/)?.[1] || null; }
		catch { /* recorded below as unknown */ }
		const components = [{ id: `${app.id}:core`, applicationId: app.id, kind: "core", path: docRoot,
			name: "WordPress", version, visibility: "public", identityStatus: "verified", activation: "unknown",
			evidence: [{ path: versionFile, field: "wp_version" }] }];
		const pluginsBase = join(contentRoot, "plugins");
		const themesBase = join(contentRoot, "themes");
		const muBase = join(contentRoot, "mu-plugins");
		for (const dir of ctx.index.directories) {
			if (directChild(dir, pluginsBase)) {
				const plugin = pluginAt(dir, ctx, app);
				if (plugin) components.push(plugin);
			} else if (directChild(dir, themesBase)) {
				const theme = themeAt(dir, ctx, app);
				if (theme) components.push(theme);
			} else if (directChild(dir, muBase)) {
				const plugin = pluginAt(dir, ctx, app, "mu-plugin");
				if (plugin) components.push(plugin);
			}
		}
		for (const name of ctx.index.filesIn(muBase).filter(n => n.endsWith(".php"))) {
			const file = join(muBase, name);
			let text;
			try { text = ctx.readPrefix(file); } catch { continue; }
			const displayName = header(text, "Plugin Name") || name;
			components.push({ id: `${app.id}:mu-plugin:${file}`, applicationId: app.id, kind: "mu-plugin", path: file,
				name: displayName, version: header(text, "Version"), visibility: ctx.isPrivatePath(file) ? "private" : "unknown",
				catalogueStatus: "not-queried", activation: "must-use", evidence: [{ path: file }] });
		}
		for (const name of ctx.index.filesIn(contentRoot).filter(n => DROP_INS.has(n))) {
			const file = join(contentRoot, name);
			let text = "";
			try { text = ctx.readPrefix(file); } catch { /* version stays unknown */ }
			components.push({ id: `${app.id}:drop-in:${file}`, applicationId: app.id, kind: "drop-in", path: file,
				name: header(text, "Plugin Name") || name, version: header(text, "Version"),
				visibility: ctx.isPrivatePath(file) ? "private" : "unknown", activation: "conditional",
				evidence: [{ path: file }] });
		}
		const themes = components.filter(c => c.kind === "theme");
		const missingParents = themes.filter(c => c.parentSlug && !themes.some(parent => parent.slug === c.parentSlug));
		const missing = components.filter(c => !c.version);
		const diagnostics = [
			...missing.map(c => ({ code: "CMS_VERSION_UNKNOWN", applicationId: app.id, componentId: c.id,
				message: `version unavailable for ${c.kind} ${c.name}` })),
			...missingParents.map(c => ({ code: "CMS_PARENT_MISSING", applicationId: app.id, componentId: c.id,
				message: `parent theme ${c.parentSlug} is not present in the scanned tree` })),
		];
		return { components, coverage: [
			{ applicationId: app.id, capability: "inventory", execution: diagnostics.length ? "partial" : "completed",
				result: diagnostics.length ? "indeterminate" : "not-applicable", expected: components.length,
				executed: components.length - missing.length,
				...(diagnostics.length ? { diagnostic: diagnostics[0].code } : {}) },
		], diagnostics };
	},
	// The official checksums reference is pinned by version and locale; a reference for
	// another version can never produce a verdict, and missing core files (a common
	// hardening step) are not a divergence — modified and unexpected files are.
	async assessChecksums(app, components, ctx) {
		const core = (components || []).find(c => c.kind === "core");
		const base = { applicationId: app.id, capability: "integrity", sourceId: "wordpress-checksums" };
		const notRun = diagnostic => ({ coverage: [{ ...base, execution: "not-run", result: "indeterminate",
			expected: 1, executed: 0, diagnostic }], diagnostics: [] });
		let ctxSnapshotPath = null;
		if (!ctx.wpChecksumsPath && !ctx.liveWpChecksumsUrl) {
			// Cached-reference reuse: a reference a prior run (or the air-gap phase 2)
			// fetched is pinned by core version and locale, so the fallback resolves per
			// instance. Every mode — the lane state follows the cache, not online/offline;
			// an explicit --wp-checksums or live URL always wins.
			const cachedPath = ctx.advisoryCacheDir && core?.version
				? path.join(ctx.advisoryCacheDir, `wordpress-checksums-${core.version}-${ctx.wpChecksumsLocale || "en_US"}.json`) : null;
			if (!cachedPath || !fs.existsSync(cachedPath)) return notRun("CMS_PROVIDER_UNCONFIGURED");
			ctx.autoCachedSources?.add(cachedPath);
			ctxSnapshotPath = cachedPath;
		}
		if (!core || !core.version) return notRun("CMS_VERSION_UNKNOWN");
		const docRoot = app.documentRoot || app.root;
		const toScanRoot = relative => docRoot === "." ? relative : `${docRoot}/${relative}`;
		const docRootPrefix = docRoot === "." ? "" : `${docRoot}/`;
		const checksumsPath = ctx.wpChecksumsPath || ctxSnapshotPath;
		let cached;
		if (checksumsPath) {
			const key = `wp-checksums:${checksumsPath}`;
			cached = ctx.snapshotCache.get(key);
			if (!cached) {
				const validated = ctx.validatedLocalSources?.get(checksumsPath);
				const stat = validated?.stat || fs.statSync(checksumsPath);
				if (!stat.isFile() || stat.size > 128 * 1024 * 1024) throw new Error("WordPress checksums snapshot must be a JSON file of at most 128 MiB");
				const bytes = validated?.bytes || fs.readFileSync(checksumsPath);
				const snapshot = validated?.snapshot || JSON.parse(bytes.toString("utf8"));
				// The runner only validates explicitly configured paths; a per-instance
				// cached fallback enforces the same freshness bound itself.
				if (!validated && ctx.maxAdvisoryAgeMs) assertFresh(snapshot, "WordPress checksums", ctx.maxAdvisoryAgeMs, ctx.now || Date.now());
				const sourceSnapshot = localSourceSnapshot(ctx, checksumsPath, bytes, stat, snapshot);
				cached = { reference: validateChecksums(snapshot), sourceSnapshot };
				ctx.snapshotCache.set(key, cached);
			}
		} else {
			const key = `wp-checksums:live:${ctx.liveWpChecksumsUrl}:${core.version}:${ctx.wpChecksumsLocale}`;
			cached = ctx.snapshotCache.get(key);
			if (!cached) {
				const fetched = await fetchWordpressChecksums(core.version, ctx.wpChecksumsLocale,
					{ fetchImpl: ctx.fetchImpl || undefined, now: ctx.now,
						...(ctx.liveWpChecksumsUrl !== WP_CHECKSUMS_API ? { apiUrl: ctx.liveWpChecksumsUrl } : {}) });
				if (ctx.advisoryCacheDir) writeSnapshotAtomically(
					path.join(ctx.advisoryCacheDir, `wordpress-checksums-${core.version}-${ctx.wpChecksumsLocale}.json`), fetched.snapshot);
				cached = { reference: validateChecksums(fetched.snapshot), sourceSnapshot: fetched.sourceSnapshot };
				ctx.snapshotCache.set(key, cached);
			}
		}
		const reference = cached.reference;
		if (reference.version && reference.version !== core.version) {
			return { coverage: [{ ...base, execution: "not-run", result: "indeterminate", expected: 1, executed: 0,
				diagnostic: "CMS_CHECKSUMS_REFERENCE_MISMATCH", sourceSnapshot: cached.sourceSnapshot }],
				diagnostics: [{ code: "CMS_CHECKSUMS_REFERENCE_MISMATCH", applicationId: app.id,
					message: `checksums reference is for WordPress ${reference.version} but the tree declares ${core.version}` }] };
		}
		const verdict = evaluateChecksums(reference, {
			has: file => ctx.index.hasFile(toScanRoot(file)),
			read: file => { try { return ctx.readBytes(toScanRoot(file), DEFAULT_MAX_FILE_BYTES); } catch { return null; } },
			filesIn: dir => ctx.index.filesIn(toScanRoot(dir)),
			directories: ctx.index.directories
				.filter(dir => docRoot === "." || dir === docRoot || dir.startsWith(docRootPrefix))
				.map(dir => dir === docRoot ? "." : dir.slice(docRootPrefix.length)),
		});
		const uncertain = verdict.uncertain.length;
		return { coverage: [{ ...base, expected: verdict.expected, executed: verdict.checked,
			execution: uncertain ? "partial" : "completed",
			result: verdict.modified.length || verdict.extra.length ? "affected" : uncertain ? "indeterminate" : "no-match",
			...(uncertain ? { diagnostic: "CMS_FILE_UNREADABLE" } : {}), sourceSnapshot: cached.sourceSnapshot }],
			diagnostics: verdict.diagnostics.map(d => ({ ...d, applicationId: app.id })) };
	},
	async assess(app, components, ctx) {
		const integrity = await this.assessChecksums(app, components, ctx);
		if (!ctx.wordfenceFeedPath && !ctx.liveWordfenceUrl) return { findings: [], coverage: [
			{ applicationId: app.id, capability: "advisories",
			sourceId: "wordfence-v3", execution: "not-run", result: "indeterminate", expected: components.length,
			executed: 0, diagnostic: "CMS_PROVIDER_UNCONFIGURED" }, ...integrity.coverage],
			diagnostics: integrity.diagnostics };
		const projection = !ctx.wordfenceFeedPath && require("../providers").hasProxyRoute();
		const software = projection ? require("../application-providers/wordfence-projection").componentQueries(components) : null;
		const key = ctx.wordfenceFeedPath ? `wordfence-v3:${ctx.wordfenceFeedPath}` :
			`wordfence-v3:live:${ctx.liveWordfenceUrl}:${projection ? JSON.stringify(software) : "full"}`;
		let cached = ctx.snapshotCache.get(key);
		if (!cached && ctx.wordfenceFeedPath) {
			// Reuse the runner's single validated read when available (freshness and schema
			// were already checked before discovery); fall back to a direct read otherwise.
			const validated = ctx.validatedLocalSources?.get(ctx.wordfenceFeedPath);
			const stat = validated?.stat || fs.statSync(ctx.wordfenceFeedPath);
			if (!stat.isFile() || stat.size > 128 * 1024 * 1024) throw new Error("Wordfence feed must be a JSON file of at most 128 MiB");
			const bytes = validated?.bytes || fs.readFileSync(ctx.wordfenceFeedPath);
			const feed = validated?.snapshot || JSON.parse(bytes.toString("utf8"));
			const index = indexFeed(feed);
			const sourceSnapshot = localSourceSnapshot(ctx, ctx.wordfenceFeedPath, bytes, stat, feed);
			if (index.sourceSnapshot) Object.assign(sourceSnapshot, index.sourceSnapshot);
			cached = { index, sourceSnapshot };
		} else if (!cached) {
			const fetched = await fetchWordfenceFeed(ctx.liveWordfenceUrl, {
				fetchImpl: ctx.fetchImpl || undefined, now: ctx.now, apiKey: ctx.wordfenceApiKey, components,
			});
			if (ctx.advisoryCacheDir) {
				if (projection) require("../application-providers/wordfence-client").cacheProjection(ctx.advisoryCacheDir, fetched.snapshot);
				else writeSnapshotAtomically(path.join(ctx.advisoryCacheDir, "wordfence-v3.json"), fetched.snapshot);
			}
			cached = { index: indexFeed(fetched.snapshot), sourceSnapshot: fetched.sourceSnapshot };
		}
		ctx.snapshotCache.set(key, cached);
		const assessed = assessWordfenceFeed(cached.index, components);
		return { findings: assessed.matches, coverage: [...assessed.coverage
			.map(check => ({ ...check, sourceSnapshot: cached.sourceSnapshot })), ...integrity.coverage],
			diagnostics: [...assessed.diagnostics, ...integrity.diagnostics] };
	},
	remediation() { return null; },
};
