/**
 * lib/codecs/composer.codec.js — codec PHP/Composer.
 *
 * Vuln scanning is OSV (ecosystem "Packagist", wired in Plan A). This codec adds
 * collection (composer.lock, composer.json fallback), Packagist registry
 * (abandoned + outdated), and EOL via endoflife.date.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const { parseComposerLock, parseComposerJson, isConcrete } = require("./composer/parse");
const { readPlatformPhp } = require("./composer/platform");
const { versionRelationsFor } = require("./composer/relations");

const SKIP = new Set(["vendor", ".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "target"]);

function findComposerManifests(dir, skipDir = (child, name) => SKIP.has(name)) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const names = new Set(entries.filter(e => e.isFile()).map(e => e.name));
		if (names.has("composer.json") || names.has("composer.lock")) {
			groups.push({
				dir: cur,
				composerJson: names.has("composer.json") ? path.join(cur, "composer.json") : null,
				composerLock: names.has("composer.lock") ? path.join(cur, "composer.lock") : null,
			});
		}
		for (const e of entries) if (e.isDirectory() && !skipDir(path.join(cur, e.name), e.name)) stack.push(path.join(cur, e.name));
	}
	return groups.sort((a, b) => a.dir.localeCompare(b.dir));
}

function dirFilter(dir, opts) {
	return require("../path-filter").makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
}

module.exports = {
	id: "composer",
	label: "Composer",
	osvEcosystem: "Packagist",
	manifestNames: ["composer.json", "composer.lock"],

	detect(dir) { return findComposerManifests(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { ignoreTest, deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const parsedManifests = [];
		const platforms = [];
		const included = d => (!ignoreTest || !d.isDev) && (!deps2Exclude || !deps2Exclude.test(d.name));
		const add = (d, manifestPath, managerRelation = "unknown") => {
			const key = coordKeyFor("composer", d.vendor, d.pkg);
			const rec = makeDepRecord({ ecosystem: "composer", namespace: d.vendor, name: d.pkg,
				version: d.version, manifestPath, scope: d.scope, isDev: d.isDev });
			const packageLinks = links => Object.fromEntries(Object.entries(links || {}).filter(([name]) => name.includes("/")));
			const occurrence = {
				version: d.version, manifestPath, scope: d.scope, isDev: d.isDev, managerRelation,
				packageType: d.type || null,
				distHost: d.distHost || null,
				requires: packageLinks(d.require), replaces: packageLinks(d.replace), provides: packageLinks(d.provide),
				sourceReference: d.sourceReference || null, distReference: d.distReference || null,
				license: d.license || [],
			};
			const existing = out.get(key);
			if (!existing) {
				rec.versionScopes = d.version ? { [d.version]: [d.scope] } : {};
				rec.occurrences = [occurrence];
				out.set(key, rec);
				return;
			}
			if (!existing.manifestPaths.includes(manifestPath)) existing.manifestPaths.push(manifestPath);
			if (d.version) {
				if (!existing.versions.includes(d.version)) existing.versions.push(d.version);
				const paths = Object.hasOwn(existing.versionPaths, d.version)
					? existing.versionPaths[d.version] : (existing.versionPaths[d.version] = []);
				if (!paths.includes(manifestPath)) paths.push(manifestPath);
				const scopes = Object.hasOwn(existing.versionScopes, d.version)
					? existing.versionScopes[d.version] : (existing.versionScopes[d.version] = []);
				if (!scopes.includes(d.scope)) scopes.push(d.scope);
			}
			if (!existing.occurrences.some(o => o.version === occurrence.version && o.manifestPath === manifestPath && o.scope === d.scope)) {
				existing.occurrences.push(occurrence);
			}
			// The coordinate is production if any installation uses it in production.
			// Keep a production version as the representative for legacy consumers;
			// CVE/OSV matching uses every value in versions[].
			if (existing.isDev && !d.isDev) {
				existing.isDev = false;
				existing.scope = d.scope;
				existing.version = d.version;
			}
		};
		for (const g of findComposerManifests(dir, dirFilter(dir, opts))) {
			// The PHP platform requirement — a runtime verdict input, never a dep (see platform.js).
			const platform = readPlatformPhp(g.composerLock, g.composerJson);
			if (platform) platforms.push(platform);
			if (g.composerLock) {
				let rootDirect = null;
				if (g.composerJson) {
					parsedManifests.push(g.composerJson);
					try {
						rootDirect = new Set(parseComposerJson(g.composerJson).deps.map(d => d.name.toLowerCase()));
					} catch (e) {
						warnings.push({ type: "parse-error", manifestPath: g.composerJson, message: `composer.json parse failed: ${e.message}` });
					}
				}
				parsedManifests.push(g.composerLock);
				let parsed;
				try { parsed = parseComposerLock(g.composerLock); }
				catch (e) { warnings.push({ type: "parse-error", manifestPath: g.composerLock, message: `composer.lock parse failed: ${e.message}` }); continue; }
				const { deps } = parsed;
				for (const d of deps) if (included(d)) {
					add(d, g.composerLock, rootDirect === null ? "unknown" : rootDirect.has(d.name.toLowerCase()) ? "direct" : "transitive");
				}
			} else if (g.composerJson) {
				// No lockfile → best-effort: pinned exact versions only + warning.
				parsedManifests.push(g.composerJson);
				let parsed;
				try { parsed = parseComposerJson(g.composerJson); }
				catch (e) { warnings.push({ type: "parse-error", manifestPath: g.composerJson, message: `composer.json parse failed: ${e.message}` }); continue; }
				const { deps } = parsed;
				let pinned = 0, ranges = 0;
				for (const d of deps) {
					if (!included(d)) continue;
					if (isConcrete(d.version)) {
						add({ ...d, version: String(d.version).replace(/^v/, "") }, g.composerJson, "direct");
						pinned++;
					} else {
						ranges++;
					}
				}
				warnings.push({ type: "no-lockfile", manifestPath: g.composerJson, message: `composer.json without composer.lock — best-effort: ${pinned} pinned, ${ranges} range(s) skipped (run "composer install")` });
			}
		}
		for (const dep of out.values()) dep.versionRelations = versionRelationsFor(dep);
		return { deps: out, warnings, parsedManifests, _composer: { platforms } };
	},

	coordKey(d) { return coordKeyFor("composer", d.namespace || "", d.name); },
	formatCoord(d) { return d.namespace ? `${d.namespace}/${d.name}` : d.name; },
	osvPackageName(d) { return `${d.namespace || ""}/${d.name}`; },

	async checkRegistry(deps, opts = {}) {
		const { checkComposerRegistryDeps } = require("./composer/registry");
		return checkComposerRegistryDeps(deps, opts);
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	recipe: require("./recipes").composer,
	nativeScanners: [],
};
