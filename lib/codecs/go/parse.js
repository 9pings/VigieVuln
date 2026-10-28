/**
 * lib/codecs/go/parse.js — parse go.mod (authoritative for selected versions on
 * Go ≥1.17, which lists the full pruned module graph) with go.sum as fallback.
 *
 * Versions are stored WITHOUT the leading "v" (OSV's Go ecosystem and our
 * version comparisons expect bare semver; the purl layer re-adds context).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { compareMavenVersions } = require("../../maven-version");

function stripV(v) { return String(v || "").replace(/^v/, ""); }

// "old [vX] => new vY" (module replace) or "old [vX] => ../dir" (directory
// replace — per spec a replacement WITHOUT a version must be a directory path).
function parseReplaceLine(s) {
	const m = s.match(/^(\S+)(?:\s+(v\S+))?\s+=>\s+(\S+)(?:\s+(v\S+))?$/);
	if (!m) return null;
	return { oldName: m[1], oldVer: m[2] ? stripV(m[2]) : null, newName: m[3], newVer: m[4] ? stripV(m[4]) : null };
}

/**
 * Parse go.mod → { module, goVersion, deps, dropped }.
 * `replace` directives are APPLIED: the effective build uses the replacement
 * module/version, so scanning the raw require line would miss a downgrade
 * (false negative) or flag an already-redirected module (false positive).
 * Directory replaces have no scannable version — the dep is dropped and
 * surfaced in `dropped` so the codec can emit a chapter-0 warning.
 */
function parseGoMod(text) {
	const out = { module: null, goVersion: null, deps: [], dropped: [] };
	const lines = String(text || "").split(/\r?\n/);
	let inRequire = false;
	let inReplace = false;
	let uncertainSyntax = false;
	const replaces = [];
	const addReq = (name, ver, indirect, reliable) => {
		if (!name || !ver) return;
		out.deps.push({ name, version: stripV(ver), scope: indirect ? "transitive" : "compile", isDev: false,
			managerRelations: [reliable ? (indirect ? "transitive" : "direct") : "unknown"] });
	};
	for (let raw of lines) {
		const noComment = raw.split("//")[0].trim();
		if (/\/\*|\*\/|^(?:<<<<<<<|=======|>>>>>>>)/.test(noComment)) uncertainSyntax = true;
		const comment = raw.includes("//") ? raw.slice(raw.indexOf("//") + 2).trim() : "";
		const indirect = /^indirect(?:\s|$)/.test(comment);
		const reliable = !comment.startsWith("indirect") || indirect;
		if (noComment.startsWith("module ")) { out.module = noComment.slice(7).trim(); continue; }
		if (noComment.startsWith("go ")) { out.goVersion = noComment.slice(3).trim(); continue; }
		if (noComment === "require (") { inRequire = true; continue; }
		if (noComment === "replace (") { inReplace = true; continue; }
		if ((inRequire || inReplace) && noComment === ")") { inRequire = inReplace = false; continue; }
		if (inReplace) {
			const r = parseReplaceLine(noComment);
			if (r) replaces.push(r);
			else if (noComment) uncertainSyntax = true;
			continue;
		}
		if (inRequire) {
			const m = noComment.match(/^(\S+)\s+(\S+)/);
			if (m) addReq(m[1], m[2], indirect, reliable && /^\S+\s+v[0-9][A-Za-z0-9.+-]*$/.test(noComment) && !/["`]/.test(m[1]));
			continue;
		}
		const single = noComment.match(/^require\s+(\S+)\s+(\S+)/);
		if (single) { addReq(single[1], single[2], indirect, reliable && /^require\s+\S+\s+v[0-9][A-Za-z0-9.+-]*$/.test(noComment) && !/["`]/.test(single[1])); continue; }
		const rep = noComment.startsWith("replace ") ? parseReplaceLine(noComment.slice(8).trim()) : null;
		if (rep) replaces.push(rep);
		else if (/^replace\b/.test(noComment)) uncertainSyntax = true;
	}
	// Apply replaces: versioned old matches that exact version only; versionless
	// old matches every version of the module.
	if (replaces.length) {
		const kept = [];
		for (const dep of out.deps) {
			const r = replaces.find(x => x.oldName === dep.name && (!x.oldVer || x.oldVer === dep.version));
			if (!r) { kept.push(dep); continue; }
			if (r.newVer) kept.push({ ...dep, name: r.newName, version: r.newVer, replaced: true, managerRelations: ["unknown"] });
			else out.dropped.push({ name: dep.name, version: dep.version, path: r.newName });
		}
		out.deps = kept;
	}
	// Dedupe by name@version (a replace can converge two requires onto one coord).
	// An unclosed block, exclude or malformed replacement requires resolution we do not perform.
	const ambiguous = uncertainSyntax || inRequire || inReplace || lines.some(line => /^\s*exclude\b/.test(line));
	if (ambiguous) for (const d of out.deps) d.managerRelations = ["unknown"];
	const seen = new Map();
	out.deps = out.deps.filter(d => {
		const k = `${d.name}@${d.version}`;
		if (seen.has(k)) {
			const prior = seen.get(k);
			prior.managerRelations = [...new Set([...prior.managerRelations, ...d.managerRelations])];
			return false;
		}
		seen.set(k, d);
		return true;
	});
	return out;
}

/** Parse go.sum → deps (fallback when go.mod has no require list). Highest version per module. */
function parseGoSum(text) {
	const byMod = new Map();
	for (const raw of String(text || "").split(/\r?\n/)) {
		const m = raw.trim().match(/^(\S+)\s+(v\S+?)(\/go\.mod)?\s+h1:/);
		if (!m) continue;
		// go.sum records two kinds of line per module:
		//   mod ver h1:…         the module ZIP was downloaded → it IS in the build
		//   mod ver/go.mod h1:…  only its go.mod was read, during minimal version selection
		// A module carrying only the second kind was weighed and rejected: it sits on no
		// classpath, and scanning it invents a dependency. Measured on prometheus v2.30.0
		// (go 1.14, so go.mod lists direct deps only and go.sum is our transitive source):
		// 187 modules have a zip hash, 391 have a go.mod hash alone — and taking all of
		// them put gin, echo AND go-restful in one report, three mutually exclusive web
		// frameworks. 70% of that project's Go production findings came from modules that
		// were never built.
		if (m[3]) continue;
		const name = m[1];
		const ver = stripV(m[2]);
		// Several versions can genuinely be downloaded in one graph; keep the highest.
		const prev = byMod.get(name);
		if (!prev || compareMavenVersions(ver, prev) > 0) byMod.set(name, ver);
	}
	return { deps: [...byMod.entries()].map(([name, version]) => ({ name, version, scope: "transitive", isDev: false })) };
}

function parseGoModFile(fp) { return parseGoMod(fs.readFileSync(fp, "utf8")); }
function parseGoSumFile(fp) { return parseGoSum(fs.readFileSync(fp, "utf8")); }

module.exports = { parseGoMod, parseGoSum, parseGoModFile, parseGoSumFile, stripV };
