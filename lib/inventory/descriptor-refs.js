/**
 * lib/inventory/descriptor-refs.js — WHERE, inside a descriptor, a dependency is declared.
 *
 * A finding's "defined in" names the module; an auditor who has to act on it needs the
 * file AND the line. `findDeclarations(file, dep)` re-reads the descriptor and returns
 * every line that declares this coordinate, with the declaration itself as a snippet.
 *
 * Deliberately strict: each descriptor kind has its own declaration shape (a pom
 * `<dependency>` block whose groupId AND artifactId match, a lockfile entry header, a
 * `requirements.txt` line that starts with the name…). A file whose kind is unknown, or
 * where no declaration matches, yields NO line rather than the first line that happens
 * to mention the name — a wrong line number is worse than none. A label is evidence
 * here, so an unreadable file never throws: it just has no line.
 */
const path = require("path");
const fs = require("fs");

const MAX_SNIPPET = 160;

function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function snippet(text) {
	const s = String(text).replace(/\s+/g, " ").trim();
	return s.length > MAX_SNIPPET ? s.slice(0, MAX_SNIPPET) + "…" : s;
}

/** 1-based line number of a character offset. */
function lineAt(text, offset) {
	let n = 1;
	for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
	return n;
}

/** Every line (1-based) whose content matches `re`. */
function grepLines(text, re) {
	const out = [];
	const lines = text.split(/\r?\n/);
	for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) out.push({ line: i + 1, text: snippet(lines[i]) });
	return out;
}

function depParts(dep) {
	const ns = dep.namespace || dep.groupId || "";
	const name = dep.name || dep.artifactId || "";
	return { ns, name };
}

/** pom.xml: a <dependency>/<parent>/<plugin> block whose groupId AND artifactId match. */
function pomDeclarations(text, { ns, name }) {
	const out = [];
	const blockRe = /<(dependency|parent|plugin|extension)>([\s\S]*?)<\/\1>/g;
	let m;
	while ((m = blockRe.exec(text))) {
		const body = m[2];
		const a = /<artifactId>\s*([^<]*?)\s*<\/artifactId>/.exec(body);
		if (!a || a[1] !== name) continue;
		const g = /<groupId>\s*([^<]*?)\s*<\/groupId>/.exec(body);
		const gid = g ? g[1] : "";
		// A ${project.groupId}-style group cannot be checked textually; a block with no
		// groupId at all is a plugin defaulting to org.apache.maven.plugins.
		if (ns && gid && gid !== ns && !/\$\{/.test(gid)) continue;
		if (ns && !gid && ns !== "org.apache.maven.plugins") continue;
		const aOffset = m.index + m[0].indexOf(a[0], m[1].length + 2);
		out.push({ line: lineAt(text, aOffset), text: snippet(m[0]) });
	}
	return out;
}

/** PEP 503 normalisation, so `Django`, `django_x` and `django-x` compare equal. */
function pep503(s) { return String(s).toLowerCase().replace(/[-_.]+/g, "-"); }

function pypiRequirementLines(text, name) {
	const want = pep503(name);
	const out = [];
	const lines = text.split(/\r?\n/);
	for (let i = 0; i < lines.length; i++) {
		const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[=<>~!;@]|$)/.exec(lines[i]);
		if (m && pep503(m[1]) === want) out.push({ line: i + 1, text: snippet(lines[i]) });
	}
	return out;
}

function tomlNameLines(text, name) {
	const want = pep503(name);
	const out = [];
	const lines = text.split(/\r?\n/);
	for (let i = 0; i < lines.length; i++) {
		const m = /^\s*name\s*=\s*"([^"]+)"/.exec(lines[i]);
		if (m && pep503(m[1]) === want) out.push({ line: i + 1, text: snippet(lines[i]) });
	}
	return out;
}

/**
 * Declarations of `dep` inside `text`, the content of descriptor `file`.
 * → [{ line, text }] (1-based line, trimmed declaration). Pure.
 */
function findInText(file, text, dep) {
	if (!text || !dep) return [];
	const base = path.basename(String(file)).toLowerCase();
	const { ns, name } = depParts(dep);
	if (!name) return [];
	const N = escapeRe(name);
	const eco = dep.ecosystem;

	if (base === "pom.xml" || base.endsWith(".pom")) return pomDeclarations(text, { ns, name });

	if (eco === "maven") {
		const GA = escapeRe(`${ns}:${name}`);
		if (base === "gradle.lockfile") return grepLines(text, new RegExp(`^${GA}:`));
		if (base.endsWith(".toml")) {
			return grepLines(text, new RegExp(`["']${GA}(?::|["'])|group\\s*=\\s*["']${escapeRe(ns)}["'].*name\\s*=\\s*["']${N}["']`));
		}
		if (/\.gradle(\.kts)?$/.test(base)) {
			return grepLines(text, new RegExp(`["']${GA}(?::|["'])|group\\s*[:=]\\s*["']${escapeRe(ns)}["'].*name\\s*[:=]\\s*["']${N}["']`));
		}
		return [];
	}

	if (eco === "npm") {
		if (base === "package.json") return grepLines(text, new RegExp(`^\\s*"${N}"\\s*:`));
		if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
			const v2 = grepLines(text, new RegExp(`^\\s*"(?:[^"]*/)?node_modules/${N}"\\s*:`));
			return v2.length ? v2 : grepLines(text, new RegExp(`^\\s*"${N}"\\s*:\\s*\\{`));
		}
		if (base === "yarn.lock") return grepLines(text, new RegExp(`^"?${N}@`));
		if (base === "pnpm-lock.yaml") return grepLines(text, new RegExp(`^\\s+['"]?/?${N}[@/(]`));
		return [];
	}

	if (eco === "composer") {
		const full = ns ? `${ns}/${name}` : name;
		const F = escapeRe(full);
		if (base === "composer.lock") return grepLines(text, new RegExp(`^\\s*"name"\\s*:\\s*"${F}"`, "i"));
		if (base === "composer.json") return grepLines(text, new RegExp(`^\\s*"${F}"\\s*:`, "i"));
		return [];
	}

	if (eco === "pypi") {
		if (/^requirements.*\.(txt|in)$/.test(base) || base.endsWith(".txt")) return pypiRequirementLines(text, name);
		if (base === "poetry.lock" || base === "uv.lock" || base === "pdm.lock") return tomlNameLines(text, name);
		if (base === "pipfile.lock") {
			const want = pep503(name);
			return grepLines(text, /^\s*"[^"]+"\s*:\s*\{/).filter(l => pep503(/"([^"]+)"/.exec(l.text)[1]) === want);
		}
		if (base === "pyproject.toml" || base === "pipfile") {
			const want = pep503(name);
			const out = [];
			const lines = text.split(/\r?\n/);
			for (let i = 0; i < lines.length; i++) {
				const m = /^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/.exec(lines[i]) || /^\s*"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*[=<>~!;"]/.exec(lines[i]);
				if (m && pep503(m[1]) === want && !/^\s*(name|version)\s*=/.test(lines[i])) out.push({ line: i + 1, text: snippet(lines[i]) });
			}
			return out;
		}
		return [];
	}

	if (eco === "nuget") {
		if (base === "packages.config") return grepLines(text, new RegExp(`\\bid\\s*=\\s*"${N}"`, "i"));
		if (base === "packages.lock.json") return grepLines(text, new RegExp(`^\\s*"${N}"\\s*:\\s*\\{`, "i"));
		if (/\.(cs|fs|vb)proj$/.test(base) || base.endsWith(".props") || base.endsWith(".targets")) {
			return grepLines(text, new RegExp(`<Package(?:Reference|Version)\\b[^>]*\\b(?:Include|Update)\\s*=\\s*"${N}"`, "i"));
		}
		return [];
	}

	if (eco === "go") {
		if (base === "go.mod") return grepLines(text, new RegExp(`(^|\\s)${N}\\s+v`));
		if (base === "go.sum") return grepLines(text, new RegExp(`^${N}\\s+v`));
		return [];
	}

	if (eco === "ruby") {
		if (base === "gemfile.lock") return grepLines(text, new RegExp(`^ {4}${N} \\(`));
		if (base === "gemfile") return grepLines(text, new RegExp(`^\\s*gem\\s+["']${N}["']`));
		return [];
	}
	return [];
}

/**
 * Same, reading the file. A per-call cache (`cache`, a Map) avoids re-reading one pom
 * for every finding it declares.
 */
function findDeclarations(file, dep, { readFile = p => fs.readFileSync(p, "utf8"), cache = null } = {}) {
	if (!file) return [];
	let text;
	if (cache && cache.has(file)) text = cache.get(file);
	else {
		try { text = readFile(file); } catch { text = null; }
		if (cache) cache.set(file, text);
	}
	if (text == null) return [];
	try { return findInText(file, text, dep); } catch { return []; }
}

module.exports = { findDeclarations, findInText };
