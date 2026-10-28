const fs = require("node:fs");
const path = require("node:path");
const { walkDirs } = require("../parallel-walk");
const { makeDirFilter } = require("../path-filter");
const { createCoverage } = require("../scan-coverage");
const { selectPlugins } = require("./select");

const DEFAULT_SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "vendor", "dist", "build", "out", "target"]);
const posix = p => p.split(path.sep).join("/");
const WORDFENCE_MAX_LOCAL_AGE_MS = 3600000;
function staleWordfenceSnapshot(meta, now, autoCached = false) {
	if (!autoCached && meta?.completeness !== "targeted") return false;
	const collectedAt = Date.parse(meta?.collectedAt);
	return meta?.stale === true || !Number.isFinite(collectedAt) || collectedAt > now + 60000 ||
		now - collectedAt > WORDFENCE_MAX_LOCAL_AGE_MS;
}
function privatePath(value) {
	if (typeof value !== "string" || !value || path.isAbsolute(value) || posix(value).split("/").includes(".."))
		throw new Error("private component path must stay relative to the scan root");
	return path.posix.normalize(posix(value));
}
function publicComponent(value) {
	const separator = typeof value === "string" ? value.lastIndexOf("=") : -1;
	if (separator < 1) throw new Error("public component must be <relative-path>=<catalogue-slug>");
	const relative = privatePath(value.slice(0, separator));
	const slug = value.slice(separator + 1).trim().toLowerCase();
	if (!/^[a-z0-9][a-z0-9._-]*$/.test(slug)) throw new Error("public component requires a valid catalogue slug");
	return [relative, slug];
}

async function indexApplicationTree(root, opts = {}) {
	const srcRoot = fs.realpathSync(path.resolve(root));
	const byDir = new Map();
	const skipped = [];
	const skipDir = makeDirFilter({
		srcRoot, defaultSkip: DEFAULT_SKIP, excludePath: opts.excludePath || [],
		useDefaults: opts.defaultExcludes !== false,
		onSkip(abs, reason) { skipped.push({ path: posix(path.relative(srcRoot, abs)), reason }); },
	});
	await walkDirs(srcRoot, { skipDir, onDir(abs, entries) {
		const rel = posix(path.relative(srcRoot, abs)) || ".";
		byDir.set(rel, new Set(entries.filter(e => e.isFile()).map(e => e.name)));
	} });
	return {
		srcRoot,
		skipped,
		directories: [...byDir.keys()].sort(),
		hasFile(relativePath) {
			const p = posix(relativePath).replace(/^\.\//, "");
			const dir = path.posix.dirname(p);
			return !!byDir.get(dir === "." ? "." : dir)?.has(path.posix.basename(p));
		},
		filesIn(relativeDir) { return [...(byDir.get(relativeDir || ".") || [])].sort(); },
	};
}

function checkedFile(root, relativePath) {
	if (typeof relativePath !== "string" || path.isAbsolute(relativePath)) throw new Error("application plugin read requires a relative path");
	const abs = path.resolve(root, relativePath);
	if (abs !== root && !abs.startsWith(root + path.sep)) throw new Error("application plugin read escaped scan root");
	const stat = fs.lstatSync(abs);
	if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("application plugin read requires a regular file");
	const real = fs.realpathSync(abs);
	if (!real.startsWith(root + path.sep)) throw new Error("application plugin read escaped scan root");
	return { abs, stat };
}

function boundedRead(root, relativePath, maxBytes = 65536) {
	const { abs, stat } = checkedFile(root, relativePath);
	if (stat.size > maxBytes) throw new Error(`application plugin file exceeds ${maxBytes} bytes`);
	return fs.readFileSync(abs, "utf8");
}

function boundedPrefix(root, relativePath, maxBytes = 8192) {
	const { abs } = checkedFile(root, relativePath);
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 65536) throw new Error("invalid application plugin prefix limit");
	const buffer = Buffer.alloc(maxBytes);
	const fd = fs.openSync(abs, "r");
	try { return buffer.subarray(0, fs.readSync(fd, buffer, 0, maxBytes, 0)).toString("utf8"); }
	finally { fs.closeSync(fd); }
}

function boundedBytes(root, relativePath, maxBytes) {
	const { abs, stat } = checkedFile(root, relativePath);
	if (stat.size > maxBytes) return null;
	return fs.readFileSync(abs);
}

async function runApplicationPlugins(root, opts = {}) {
	if (!["source", "installation", "component"].includes(opts.scanContext || "source"))
		throw new Error("scan context must be source, installation, or component");
	const plugins = selectPlugins(opts.plugins || [], opts.selection || "auto");
	const requiredProviderIds = new Set([...(opts.requiredProviderIds || []),
		...(opts.liveWordfenceUrl ? ["wordfence-v3"] : []),
		...(opts.liveDrupalAdvisoriesUrl ? ["drupal-security-advisories"] : []),
		...(opts.livePrestashopAdvisoriesUrl ? ["github-prestashop-advisories"] : []),
		...(opts.liveTypo3AdvisoriesUrl ? ["github-typo3-advisories"] : []),
		...(opts.liveSpipAdvisoriesUrl ? ["spip-security-advisories"] : []),
		...(opts.liveWpChecksumsUrl ? ["wordpress-checksums"] : [])]);
	for (const providerId of requiredProviderIds) if (!plugins.some(plugin => plugin.providerIds.includes(providerId)))
		throw new Error(`${providerId} source configured but its application plugin is not selected`);
	// Cached advisory-snapshot reuse: a snapshot the tool itself fetched and cached (in
	// ~/.fad-checker/advisory-snapshots/, carried between machines by --export-cache /
	// --import-cache, warmed by --import-anonymized or a prior live scan) is consumed
	// without its explicit flag. Hosted online Drupal lookups must reach the proxy instead
	// of letting an implicit snapshot bypass its freshness policy. Offline and direct
	// scans retain the local fallback. An explicit
	// flag or live URL always wins, the fallback only engages when the source's
	// application plugin is selected, and the file goes through the same validation
	// (schema, freshness) as an operator-supplied one.
	const selectedPluginIds = new Set(plugins.map(plugin => plugin.id));
	const hostedOnline = !opts.offline && require("../providers").hasHostedProxy();
	const wordfenceProxyOnline = !opts.offline && require("../providers").hasProxyRoute();
	const liveWordfenceUrl = opts.offline ? null : opts.liveWordfenceUrl || null;
	// Drupal's live operation is scoped to the inventoried public package identities.
	// Never refresh a bulk catalogue here, and never replace an operator-selected file.
	const liveDrupalAdvisoriesUrl = opts.offline ? null : (opts.liveDrupalAdvisoriesUrl ||
		(hostedOnline && !opts.drupalAdvisoriesPath && selectedPluginIds.has("drupal")
			? require("../application-providers/live-snapshot").DRUPAL_ADVISORIES_URL : null));
	const autoCachedSources = new Set();
	const withCachedFallback = (configured, liveUrl, pluginId, file) => {
		if (configured || liveUrl || !opts.advisoryCacheDir || !selectedPluginIds.has(pluginId)) return configured || null;
		const cached = path.join(opts.advisoryCacheDir, file);
		if (!fs.existsSync(cached)) return configured || null;
		autoCachedSources.add(cached);
		return cached;
	};
	const wordfenceFeedPath = withCachedFallback(opts.wordfenceFeedPath, liveWordfenceUrl, "wordpress",
		"wordfence-v3-targeted.json") || withCachedFallback(null, liveWordfenceUrl, "wordpress", "wordfence-v3.json");
	const drupalAdvisoriesPath = withCachedFallback(opts.drupalAdvisoriesPath, liveDrupalAdvisoriesUrl, "drupal", "drupal-security-advisories.json");
	const prestashopAdvisoriesPath = withCachedFallback(opts.prestashopAdvisoriesPath, opts.livePrestashopAdvisoriesUrl, "prestashop", "github-prestashop-advisories.json");
	const typo3AdvisoriesPath = withCachedFallback(opts.typo3AdvisoriesPath, opts.liveTypo3AdvisoriesUrl, "typo3", "github-typo3-advisories.json");
	const spipAdvisoriesPath = withCachedFallback(opts.spipAdvisoriesPath, opts.liveSpipAdvisoriesUrl, "spip", "spip-security-advisories.json");
	// A locally configured advisory source is validated once, before discovery: readability,
	// size limit, JSON decoding, provider schema and — when requested — freshness. An
	// unusable source fails the scan before any report is written, even when no instance
	// would ever reach the file, and the parsed snapshot is reused during assessment to
	// avoid divergent second reads.
	const validatedLocalSources = new Map();
	const validateLocalSource = (snapshotPath, label, validate) => {
		if (!snapshotPath || validatedLocalSources.has(snapshotPath)) return;
		const stat = fs.statSync(snapshotPath);
		if (!stat.isFile() || stat.size > 128 * 1024 * 1024)
			throw new Error(`${label} advisory snapshot must be a JSON file of at most 128 MiB`);
		const bytes = fs.readFileSync(snapshotPath);
		const snapshot = JSON.parse(bytes.toString("utf8"));
		validate(snapshot);
		// Give an expired cache a chance to revalidate before applying the strict
		// age gate. The assessed source is checked again before recording coverage.
		const revalidateWordfence = snapshotPath === wordfenceFeedPath && wordfenceProxyOnline &&
			staleWordfenceSnapshot(snapshot._fadSnapshot, opts.now || Date.now(), autoCachedSources.has(snapshotPath));
		if (opts.maxAdvisoryAgeMs && !revalidateWordfence) {
			const { assertFresh } = require("../advisory-freshness");
			assertFresh(snapshot, label, opts.maxAdvisoryAgeMs, opts.now || Date.now());
		}
		validatedLocalSources.set(snapshotPath, { stat, bytes, snapshot });
	};
	validateLocalSource(wordfenceFeedPath, "Wordfence", feed => require("../application-providers/wordfence-v3").indexFeed(feed));
	validateLocalSource(drupalAdvisoriesPath, "Drupal advisories", require("../application-providers/drupal-advisories").validateSnapshot);
	validateLocalSource(prestashopAdvisoriesPath, "PrestaShop advisories",
		feed => require("../application-providers/github-advisories").validateSnapshot(feed, { fallbackCoord: "prestashop/prestashop" }));
	validateLocalSource(typo3AdvisoriesPath, "TYPO3 advisories",
		feed => require("../application-providers/github-advisories").validateSnapshot(feed));
	validateLocalSource(spipAdvisoriesPath, "SPIP advisories",
		require("../application-providers/spip-advisories").validateSnapshot);
	validateLocalSource(opts.wpChecksumsPath, "WordPress checksums",
		require("../application-providers/wp-checksums").validateChecksums);
	const result = { applications: [], inventory: [], findings: [], coverage: [], diagnostics: [] };
	if (!plugins.length) return result;
	const index = await indexApplicationTree(root, opts);
	const journal = createCoverage();
	const privatePaths = new Set((opts.privateComponentPaths || []).map(privatePath));
	const publicSlugs = new Map((opts.publicComponents || []).map(publicComponent));
	for (const relative of publicSlugs.keys()) if (privatePaths.has(relative))
		throw new Error(`component cannot be both private and public: ${relative}`);
	const context = {
		srcRoot: index.srcRoot, index, resolvedDeps: opts.resolvedDeps || new Map(),
		activeCodecIds: opts.activeCodecIds || [],
		readText: (rel, maxBytes) => boundedRead(index.srcRoot, rel, maxBytes),
		readPrefix: (rel, maxBytes) => boundedPrefix(index.srcRoot, rel, maxBytes),
		readBytes: (rel, maxBytes) => boundedBytes(index.srcRoot, rel, maxBytes),
		isPrivatePath: rel => privatePaths.has(privatePath(rel)),
		publicSlugForPath: rel => publicSlugs.get(privatePath(rel)) || null,
		wordfenceFeedPath,
		drupalAdvisoriesPath,
		liveWordfenceUrl,
		wordfenceApiKey: opts.wordfenceApiKey || null,
		liveDrupalAdvisoriesUrl,
		prestashopAdvisoriesPath,
		livePrestashopAdvisoriesUrl: opts.livePrestashopAdvisoriesUrl || null,
		typo3AdvisoriesPath,
		liveTypo3AdvisoriesUrl: opts.liveTypo3AdvisoriesUrl || null,
		spipAdvisoriesPath,
		liveSpipAdvisoriesUrl: opts.liveSpipAdvisoriesUrl || null,
		spipAdvisoriesApiKey: opts.spipAdvisoriesApiKey || null,
		wpChecksumsPath: opts.wpChecksumsPath || null,
		liveWpChecksumsUrl: opts.liveWpChecksumsUrl || null,
		wpChecksumsLocale: opts.wpChecksumsLocale || "en_US",
		advisoryCacheDir: opts.advisoryCacheDir || null,
		offline: !!opts.offline,
		maxAdvisoryAgeMs: opts.maxAdvisoryAgeMs || null,
		autoCachedSources,
		fetchImpl: opts.fetchImpl || null,
		now: opts.now || Date.now(),
		scanContext: opts.scanContext || "source",
		snapshotCache: new Map(),
		validatedLocalSources,
	};
	async function assessApplication(plugin, app, components) {
		const local = validatedLocalSources.get(wordfenceFeedPath)?.snapshot;
		const localStale = staleWordfenceSnapshot(local?._fadSnapshot, context.now,
			autoCachedSources.has(wordfenceFeedPath));
		let assessed;
		let refreshError;
		let usedLocal = true;
		if (plugin.id === "wordpress" && wordfenceProxyOnline && localStale) {
			try {
				assessed = await plugin.assess(app, components, { ...context, wordfenceFeedPath: null,
					liveWordfenceUrl: require("../application-providers/wordfence-projection").SOURCE_URL });
				usedLocal = false;
			} catch (error) {
				if (requiredProviderIds.has("wordfence-v3") && !opts.reportProviderFailures) throw error;
				refreshError = error;
			}
		}
		if (!assessed) assessed = await plugin.assess(app, components, context);
		if (plugin.id !== "wordpress" || !assessed || Array.isArray(assessed)) return assessed;
		let stale = false;
		const coverage = (assessed.coverage || []).map(check => {
			if (check.sourceId !== "wordfence-v3" ||
				!((usedLocal && localStale) || staleWordfenceSnapshot(check.sourceSnapshot, context.now))) return check;
			stale = true;
			return { ...check, sourceSnapshot: { ...check.sourceSnapshot, stale: true },
				execution: check.execution === "completed" ? "partial" : check.execution,
				result: "indeterminate", diagnostic: check.diagnostic || "CMS_ADVISORY_STALE" };
		});
		return { ...assessed, coverage, diagnostics: [...(assessed.diagnostics || []),
			...(stale ? [{ code: "CMS_ADVISORY_STALE", applicationId: app.id,
				message: `Wordfence snapshot is stale; advisory coverage is indeterminate${refreshError
					? ` (targeted revalidation failed: ${refreshError.message})` : ""}` }] : [])] };
	}
	// discover returns candidates, and may add diagnostics (e.g. recognized-but-invalid input);
	// a bare candidate array stays the documented simple form.
	function discovered(plugin) {
		const value = plugin.discover(context);
		return Promise.resolve(value).then(out => Array.isArray(out)
			? { candidates: out, diagnostics: [] }
			: { candidates: out?.candidates || [], diagnostics: out?.diagnostics || [] });
	}
	const seen = new Set();
	for (const plugin of plugins) {
		let candidates;
		try {
			const discoveredOut = await discovered(plugin);
			candidates = discoveredOut.candidates;
			result.diagnostics.push(...discoveredOut.diagnostics);
		}
		catch (error) {
			result.diagnostics.push({ code: "CMS_PLUGIN_FAILED", pluginId: plugin.id, message: `discovery failed: ${error.message}` });
			continue;
		}
		for (const candidate of candidates || []) {
			const relativeRoot = posix(candidate.root || ".").replace(/^\.\//, "") || ".";
			const abs = path.resolve(index.srcRoot, relativeRoot);
			if (path.isAbsolute(candidate.root || "") || (abs !== index.srcRoot && !abs.startsWith(index.srcRoot + path.sep))) {
				result.diagnostics.push({ code: "CMS_UNSUPPORTED_LAYOUT", pluginId: plugin.id, path: relativeRoot, message: "candidate root escapes scan root" });
				continue;
			}
			const app = { id: `${plugin.id}:${relativeRoot}`, type: plugin.id, root: relativeRoot, pluginId: plugin.id,
				pluginVersion: plugin.version, scanContext: context.scanContext, evidence: candidate.evidence || [],
				...(candidate.layout ? { layout: candidate.layout } : {}),
				...(candidate.documentRoot ? { documentRoot: candidate.documentRoot } : {}),
				...(candidate.contentRoot ? { contentRoot: candidate.contentRoot } : {}) };
			if (candidate.componentKind) app.componentKind = candidate.componentKind;
			if (candidate.edition) app.edition = candidate.edition;
			if (seen.has(app.id)) continue;
			seen.add(app.id);
			result.applications.push(app);
			const missing = plugin.requiredCodecs.filter(id => !context.activeCodecIds.includes(id));
			if (missing.length) {
				result.diagnostics.push({ code: "CMS_CODEC_DISABLED", applicationId: app.id, message: `required codec disabled: ${missing.join(", ")}` });
				journal.record({ applicationId: app.id, capability: "inventory", execution: "not-run", result: "indeterminate", diagnostic: "CMS_CODEC_DISABLED" });
				continue;
			}
			let collected;
			try {
				collected = await plugin.collect(app, context) || {};
				result.inventory.push(...(collected.components || []));
				result.diagnostics.push(...(collected.diagnostics || []));
				for (const component of collected.components || []) if (component.visibility === "private") {
					result.diagnostics.push({ code: "CMS_PRIVATE_COMPONENT", applicationId: app.id, componentId: component.id,
						message: `${component.kind} ${component.name || component.coord || component.id} is private; public catalogues cannot establish its advisory coverage` });
				}
				for (const check of collected.coverage || []) journal.record(check);
			} catch (error) {
				result.diagnostics.push({ code: "CMS_PLUGIN_FAILED", applicationId: app.id, message: `inventory failed: ${error.message}` });
				journal.record({ applicationId: app.id, capability: "inventory", execution: "failed", result: "indeterminate", diagnostic: "CMS_PLUGIN_FAILED" });
				continue;
			}
			try {
				const assessed = await assessApplication(plugin, app, collected.components || []) || [];
				if (Array.isArray(assessed)) result.findings.push(...assessed);
				else {
					result.findings.push(...(assessed.findings || []));
					result.diagnostics.push(...(assessed.diagnostics || []));
					for (const check of assessed.coverage || []) {
						if (context.maxAdvisoryAgeMs && check.sourceSnapshot)
							require("../advisory-freshness").assertFresh(check.sourceSnapshot,
								check.sourceId || plugin.id, context.maxAdvisoryAgeMs, context.now);
						journal.record(check);
					}
				}
			} catch (error) {
				const required = plugin.providerIds.filter(id => requiredProviderIds.has(id));
				// A CLI scan must retain its inventory and write partial reports. Its explicit
				// coverage gate runs after export; library callers retain fail-fast semantics.
				if (required.length && (!opts.reportProviderFailures || context.maxAdvisoryAgeMs))
					throw new Error(`${plugin.id} advisory source failed: ${error.message}`);
				result.diagnostics.push({ code: "CMS_PLUGIN_FAILED", applicationId: app.id,
					sourceIds: required, message: `assessment failed: ${error.message}` });
				if (!journal.records.some(c => c.applicationId === app.id && c.capability === "advisories")) {
					for (const sourceId of required.length ? required : [null])
						journal.record({ applicationId: app.id, ...(sourceId ? { sourceId } : {}),
							capability: "advisories", execution: "failed", result: "indeterminate", diagnostic: "CMS_PLUGIN_FAILED" });
				}
			}
		}
	}
	for (const relative of privatePaths) if (!result.inventory.some(component => component.path && privatePath(component.path) === relative))
		result.diagnostics.push({ code: "CMS_PRIVATE_PATH_UNMATCHED", path: relative,
			message: `private component path ${relative} did not match an inventoried component` });
	for (const relative of publicSlugs.keys()) {
		const component = result.inventory.find(item => item.path && privatePath(item.path) === relative);
		if (!component) result.diagnostics.push({ code: "CMS_PUBLIC_PATH_UNMATCHED", path: relative,
			message: `public component path ${relative} did not match an inventoried component` });
		else if (component.visibility === "private") result.diagnostics.push({ code: "CMS_IDENTITY_CONFLICT", path: relative,
			componentId: component.id, applicationId: component.applicationId,
			message: `public catalogue declaration conflicts with private component evidence for ${relative}` });
	}
	if (context.scanContext === "component" && plugins.length && !result.applications.length)
		result.diagnostics.push({ code: "CMS_COMPONENT_NOT_RECOGNIZED",
			message: "component scan context recognized no supported application component in the scan root; " +
				"point --src at a plugin, theme, module or profile with valid metadata, or select the matching --app-plugins" });
	result.coverage = journal.records;
	return result;
}

module.exports = { indexApplicationTree, runApplicationPlugins };
