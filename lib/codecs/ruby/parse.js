/**
 * lib/codecs/ruby/parse.js — parse Gemfile.lock.
 *
 * The GEM section's `specs:` block lists resolved gems at 4-space indent
 * (`name (version)`); their transitive requirements sit at 6-space indent and
 * are skipped (they reappear as their own 4-space spec entry).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { gemfileRelations } = require("./relations");

/** Parse Gemfile.lock text → { deps: [{ name, version, scope, isDev }] }. */
function parseGemfileLock(text) {
	const deps = [];
	const seen = new Set();
	const lines = String(text || "").split(/\r?\n/);
	let inSpecs = false;
	for (const raw of lines) {
		const trimmed = raw.trim();
		if (/^(GEM|GIT|PATH|PLATFORMS|DEPENDENCIES|BUNDLED WITH|CHECKSUMS)\b/.test(trimmed) && !raw.startsWith(" ")) {
			inSpecs = false;
		}
		if (trimmed === "specs:") { inSpecs = true; continue; }
		if (!inSpecs) continue;
		// Exactly 4 leading spaces = a resolved gem; 6+ = its dependency (skip).
		const m = raw.match(/^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)\s*$/);
		if (!m) continue;
		const name = m[1];
		// Version may carry a platform suffix ("1.2.3-x86_64-linux"); keep the version.
		const version = m[2].split(/[ -]/)[0];
		const key = `${name}@${version}`;
		if (seen.has(key)) continue;
		seen.add(key);
		deps.push({ name, version, scope: "compile", isDev: false });
	}
	const relations = gemfileRelations(text);
	for (const d of deps) d.managerRelations = [relations.get(`${d.name}@${d.version}`) || "unknown"];
	return { deps };
}

function parseGemfileLockFile(fp) { return parseGemfileLock(fs.readFileSync(fp, "utf8")); }

module.exports = { parseGemfileLock, parseGemfileLockFile };
