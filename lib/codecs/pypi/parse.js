/**
 * lib/python/parse.js — parse Python manifests / lockfiles.
 *
 *   poetry.lock / uv.lock / pdm.lock — TOML, [[package]] name/version arrays.
 *   Pipfile.lock                     — JSON, { default:{}, develop:{} }, version "==x".
 *   pyproject.toml                   — TOML, PEP 621 [project] + poetry table (fallback).
 *   requirements.txt                 — text; only "==" pins are queryable (fallback).
 *                                      -r/-c includes are followed recursively;
 *                                      a -c constraint pin upgrades a range to scannable.
 *
 * All names are PEP 503 normalized (lowercase, runs of -_. → single -) so they
 * match OSV / PyPI / the resolved-deps key.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const TOML = require("smol-toml");

function pep503(name) { return String(name || "").toLowerCase().replace(/[-_.]+/g, "-"); }

function stripOp(v) { return String(v || "").replace(/^[=~!<>]+/, "").trim(); }
function isPinned(spec) { return /^==\s*\d[\w.\-+!]*$/.test(String(spec || "").trim()); }
function isConcrete(v) { return /^\d+(\.\d+)*([.\-+]\S+)?$/.test(String(v || "")); }

// Split a PEP 508 requirement string ("requests[extra]==2.31.0 ; marker") into
// { name, spec } — env markers (after ";") and extras ("[...]") are dropped.
function splitPep508(req) {
	const s = String(req || "").split(";")[0].trim();
	const m = s.match(/^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$/);
	if (!m) return { name: null, spec: "" };
	return { name: m[1], spec: m[3].trim() };
}

// poetry.lock / uv.lock / pdm.lock all use [[package]] name/version arrays.
function parseTomlPackages(filePath, type) {
	const data = TOML.parse(fs.readFileSync(filePath, "utf8"));
	const pkgs = Array.isArray(data.package) ? data.package : [];
	const deps = [];
	for (const p of pkgs) {
		if (!p.name || !p.version) continue;
		// uv.lock lists the project ITSELF as a package (source.virtual/editable = ".");
		// it is not a registry dep and its name could shadow a real PyPI package.
		if (p.source && (p.source.virtual != null || p.source.editable != null)) continue;
		// pdm/poetry≥1.5 use `groups`; classic poetry.lock (≤1.4) uses `category = "dev"`.
		const groups = Array.isArray(p.groups) ? p.groups : null;
		const isDev = groups
			? groups.every(g => g === "dev")
			: (p.category ? String(p.category).toLowerCase() === "dev" : false);
		deps.push({ name: pep503(p.name), version: String(p.version), scope: isDev ? "dev" : "prod", isDev });
	}
	return { manifestPath: filePath, manifestType: type, deps };
}
const parsePoetryLock = f => parseTomlPackages(f, "poetry.lock");
const parseUvLock = f => parseTomlPackages(f, "uv.lock");
const parsePdmLock = f => parseTomlPackages(f, "pdm.lock");

function parsePipfileLock(filePath) {
	const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	const push = (obj, scope) => {
		for (const [name, meta] of Object.entries(obj || {})) {
			const v = stripOp(meta.version);
			if (!v) continue;
			deps.push({ name: pep503(name), version: v, scope, isDev: scope === "dev" });
		}
	};
	push(json.default, "prod");
	push(json.develop, "dev");
	return { manifestPath: filePath, manifestType: "Pipfile.lock", deps };
}

// pyproject.toml — fallback when no lockfile. Reads PEP 621 [project] and the
// poetry tool table. Only exact pins are scannable (PEP 621 "==x"; poetry exact
// "x"); ranges (^/~/>=/wildcards) are counted in `skipped` like requirements.txt.
function parsePyprojectToml(filePath) {
	const data = TOML.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	let skipped = 0;
	const seen = new Set();
	const push = (rawName, version, scope) => {
		const name = pep503(rawName);
		if (!name || name === "python") return;
		const k = `${name}@${version}`;
		if (seen.has(k)) return; seen.add(k);
		deps.push({ name, version, scope, isDev: scope === "dev" });
	};
	// PEP 508 specs ("requests==2.31.0") — exact "==" pins only.
	const addSpec = (req, scope) => {
		const { name, spec } = splitPep508(req);
		if (!name) return;
		if (isPinned(spec)) push(name, stripOp(spec), scope);
		else skipped++;
	};
	// Poetry constraints ("^2.0" / "==4.2" / bare exact "4.2.0" / { version }).
	const addPoetry = (name, val, scope) => {
		if (pep503(name) === "python") return;            // the interpreter, not a dep
		const spec = typeof val === "string" ? val : (val && typeof val === "object" ? (val.version || "") : "");
		const s = String(spec || "").trim();
		if (isConcrete(s)) push(name, s, scope);          // poetry: bare version == exact
		else if (isPinned(s)) push(name, stripOp(s), scope);
		else skipped++;
	};

	// PEP 621 [project]
	const proj = data.project || {};
	for (const req of (Array.isArray(proj.dependencies) ? proj.dependencies : [])) addSpec(req, "prod");
	for (const [group, arr] of Object.entries(proj["optional-dependencies"] || {})) {
		const isDev = /^(dev|test|tests|lint|docs|typing|type|check)$/i.test(group);
		for (const req of (Array.isArray(arr) ? arr : [])) addSpec(req, isDev ? "dev" : "prod");
	}
	// Poetry [tool.poetry]
	const poetry = (data.tool && data.tool.poetry) || {};
	for (const [name, v] of Object.entries(poetry.dependencies || {})) addPoetry(name, v, "prod");
	for (const [name, v] of Object.entries(poetry["dev-dependencies"] || {})) addPoetry(name, v, "dev");
	for (const grp of Object.values(poetry.group || {})) {
		for (const [name, v] of Object.entries((grp && grp.dependencies) || {})) addPoetry(name, v, "dev");
	}
	return { manifestPath: filePath, manifestType: "pyproject.toml", deps, skipped };
}

// Walk a requirements.txt graph, following -r/--requirement (deps) and
// -c/--constraint (version pins) includes recursively. `kind` is "req" for the
// dependency graph and "constraint" for files reached via -c.
function collectReqGraph(filePath, seen, kind, acc, root) {
	const real = path.resolve(filePath);
	let resolved;
	try { resolved = fs.realpathSync(real); }
	catch { acc.missing.push(real); return; }
	const relative = path.relative(root, resolved);
	if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
		acc.missing.push(`${real} (outside scan root; ignored)`); return;
	}
	if (seen.has(resolved)) return;          // cycle / re-include guard
	seen.add(resolved);
	if (seen.size > 200) return;         // sanity bound
	let lines;
	try { lines = fs.readFileSync(resolved, "utf8").split(/\r?\n/); }
	catch { acc.missing.push(real); return; }
	const dir = path.dirname(real);
	for (const raw of lines) {
		let line = raw.replace(/(^|\s)#.*$/, "").trim();
		if (!line) continue;
		// pip-compile --generate-hashes writes "pkg==1.0 \" + indented "--hash=…"
		// continuation lines. The trailing backslash made isPinned() reject the
		// spec, silently skipping EVERY dep of a hash-pinned file.
		line = line.replace(/\\$/, "").trim();
		if (!line) continue;
		const rMatch = line.match(/^(?:-r|--requirement)[=\s]+(.+)$/);
		if (rMatch) { collectReqGraph(path.resolve(dir, rMatch[1].trim()), seen, kind, acc, root); continue; }
		const cMatch = line.match(/^(?:-c|--constraint)[=\s]+(.+)$/);
		if (cMatch) { collectReqGraph(path.resolve(dir, cMatch[1].trim()), seen, "constraint", acc, root); continue; }
		if (line.startsWith("-")) continue;              // -e ., --hash, other flags
		// Per-requirement options ("pkg==1.0 --hash=sha256:…") come after the spec.
		const { name, spec } = splitPep508(line.split(/\s+--/)[0].trim());
		if (!name) continue;
		const n = pep503(name);
		if (kind === "constraint") acc.constraints.set(n, spec);
		else acc.reqs.push({ name: n, spec });
	}
}

function parseRequirementsTxt(filePath, scanRoot = path.dirname(filePath)) {
	const acc = { reqs: [], constraints: new Map(), missing: [] };
	collectReqGraph(filePath, new Set(), "req", acc, fs.realpathSync(scanRoot));
	const deps = [];
	let skipped = 0;
	const seen = new Set();
	for (const r of acc.reqs) {
		let version = null;
		if (isPinned(r.spec)) version = stripOp(r.spec);
		else if (acc.constraints.has(r.name) && isPinned(acc.constraints.get(r.name))) {
			version = stripOp(acc.constraints.get(r.name));  // range pinned by -c constraint
		}
		if (!version) { skipped++; continue; }
		const k = `${r.name}@${version}`;
		if (seen.has(k)) continue; seen.add(k);
		deps.push({ name: r.name, version, scope: "prod", isDev: false });
	}
	return { manifestPath: filePath, manifestType: "requirements.txt", deps, skipped, missing: acc.missing };
}

module.exports = { pep503, isConcrete, splitPep508, parsePoetryLock, parseUvLock, parsePdmLock, parsePipfileLock, parsePyprojectToml, parseRequirementsTxt };
