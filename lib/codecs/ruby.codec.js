/**
 * lib/codecs/ruby.codec.js — codec Ruby (Bundler).
 *
 * Reads Gemfile.lock (authoritative resolved versions). Vuln recall via OSV
 * (ecosystem "RubyGems"); outdated + licenses via the RubyGems API.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const R = require("./ruby/parse");
const { mergeVersionEvidence } = require("./version-evidence");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "target", "vendor", "tmp"]);

function findGemfileLocks(dir, skipDir = (child, name) => SKIP.has(name)) {
	const found = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		for (const e of entries) {
			if (e.isFile() && e.name === "Gemfile.lock") found.push(path.join(cur, e.name));
			else if (e.isDirectory() && !skipDir(path.join(cur, e.name), e.name)) stack.push(path.join(cur, e.name));
		}
	}
	return found;
}

function dirFilter(dir, opts) {
	return require("../path-filter").makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
}

module.exports = {
	id: "ruby",
	label: "Ruby",
	osvEcosystem: "RubyGems",
	manifestNames: ["Gemfile.lock"],

	detect(dir) { return findGemfileLocks(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const parsedManifests = [];
		for (const fp of findGemfileLocks(dir, dirFilter(dir, opts))) {
			parsedManifests.push(fp);
			try {
				const { deps } = R.parseGemfileLockFile(fp);
				for (const d of deps) {
					if (deps2Exclude && deps2Exclude.test(d.name)) continue;
					const key = coordKeyFor("ruby", "", d.name);
					const record = makeDepRecord({ ecosystem: "ruby", namespace: "", name: d.name, version: d.version, manifestPath: fp, scope: d.scope, isDev: false });
					out.set(key, mergeVersionEvidence(out.get(key), record, d.managerRelations));
				}
			} catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `Gemfile.lock parse failed: ${e.message}` }); }
		}
		return { deps: out, warnings, parsedManifests };
	},

	coordKey(d) { return coordKeyFor("ruby", "", d.name); },
	formatCoord(d) { return d.name; },
	osvPackageName(d) { return d.name; },

	async checkRegistry(deps, opts = {}) {
		const { checkRubyRegistryDeps } = require("./ruby/registry");
		return checkRubyRegistryDeps(deps, opts);
	},
	resolveEolProduct() { return null; },
	recipe: require("./recipes").ruby,
	nativeScanners: [],
};
