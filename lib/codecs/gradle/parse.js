/**
 * lib/codecs/gradle/parse.js — Gradle manifest parsers (lockfile-first, best-effort DSL).
 *
 *   gradle.lockfile            → authoritative `g:a:v=conf,conf` (resolved, transitives incl.)
 *   gradle.properties          → `key=value` (used to resolve `$var` versions)
 *   build.gradle / .kts        → best-effort regex over `dependencies { … }`:
 *                                string notation, map notation, version-catalog accessors
 *                                (`libs.foo.bar`), and `platform(...)` BOMs (surfaced
 *                                separately for the import-BOM backfill, NOT as a dep).
 *                                `constraints { }` entries and forces (`resolutionStrategy
 *                                .force`, `force = true`, `strictly`) are surfaced as
 *                                `constraints` — version pins, NOT deps — and `exclude(…)`
 *                                (per declaration and per configuration) as exclusionSets.
 *
 * A Gradle dependency IS a Maven coordinate, so the codec emits ecosystem "maven" records;
 * this module only turns the various Gradle surfaces into {group,name,version} tuples.
 * Versions that can't be resolved statically (programmatic constructs, missing var) come
 * back null — never assumed-vulnerable — and are listed in `unresolved` for a warning.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { resolveLibraryAccessor, findCatalogVersion, normKey } = require("./catalog");
const { compareMavenVersions } = require("../maven/version");

const COORD = "[A-Za-z0-9_.\\-]+";

// Function/keyword call sites that look like a configuration but are NOT external deps.
const DENY = new Set([
	"id", "kotlin", "version", "project", "exclude", "platform", "enforcedPlatform",
	"files", "fileTree", "gradleApi", "localGroovy", "because", "create", "named",
	"register", "maven", "url", "uri", "from", "into", "extendsFrom", "add", "plugin",
	"apply", "alias", "set", "property", "the", "get", "named", "dependencies",
	// Version constraints, not dependencies (see parseBuildScript step 2 / 5).
	"force", "strictly", "require", "prefer", "constraints",
]);

function isTestConfig(c) { return /test/i.test(String(c || "")); }

// Guard against non-coordinate string args that happen to contain a colon — e.g.
// jvmArgs("-Xshare:off"), systemProperty("a:b"). A real Maven groupId is reverse-DNS:
// it always starts with a letter (never "-" or a digit); an artifactId starts alphanumeric.
function looksLikeCoord(group, name) {
	return /^[A-Za-z][\w.\-]*$/.test(String(group || "")) && /^[A-Za-z0-9][\w.\-]*$/.test(String(name || ""));
}

function depScope(config) {
	const isDev = isTestConfig(config);
	return { scope: isDev ? "test" : "compile", isDev };
}

// Read the version expression that begins at s[i] (right after `g:a:` in a coord string).
// Handles a `${ … }` template (balanced braces — so a nested findVersion("x") with its own
// quotes/parens is captured whole), a bare `$var`, or a plain literal up to the closing quote.
function readVersionExpr(s, i) {
	if (s[i] === "$" && s[i + 1] === "{") {
		let depth = 0;
		for (let j = i + 1; j < s.length; j++) {
			if (s[j] === "{") depth++;
			else if (s[j] === "}" && --depth === 0) return s.slice(i, j + 1);
		}
		return s.slice(i);
	}
	if (s[i] === "$") { const m = s.slice(i).match(/^\$[\w.]+/); return m ? m[0] : null; }
	const m = s.slice(i).match(/^[^"'\s)]+/);
	return m ? m[0] : null;
}

/** Resolve a (possibly `$var` / catalog-backed) version expression → concrete string or null. */
function resolveVer(raw, ctx) {
	if (raw == null) return null;
	const v = String(raw).trim();
	if (!v) return null;
	if (v.includes("$")) {
		let m = v.match(/findVersion\(\s*["']([^"']+)["']\s*\)/);
		if (m) return findCatalogVersion(ctx.catalog, m[1]) || null;
		m = v.match(/libs\.versions\.([\w.]+?)(?:\.get\(\))?[\s}"')]*$/);
		if (m) { const r = findCatalogVersion(ctx.catalog, m[1]); if (r) return r; }
		m = v.match(/\$\{?([\w.]+)\}?/);
		if (m) {
			const k = m[1];
			if (ctx.ambiguousVars?.has(k)) return null;
			if (ctx.extVars?.has(k) && m[0] !== v) return null;
			if (ctx.localVars && ctx.localVars[k] != null) return ctx.localVars[k];
			if (ctx.properties && ctx.properties[k] != null) return ctx.properties[k];
		}
		return null;
	}
	const m = v.match(/[\w][\w.\-]*/);
	return m ? m[0] : null;
}

/** Parse the inner content of a `platform( … )` call → {group,name,version} or null. */
function parsePlatformCoord(content, ctx) {
	const c = String(content || "").trim();
	const head = c.match(new RegExp(`["']?\\s*(${COORD}):(${COORD}):`));
	if (head) {
		const tail = c.slice(c.indexOf(head[0]) + head[0].length);
		return { group: head[1], name: head[2], version: resolveVer(tail, ctx) || null };
	}
	const ga = c.match(new RegExp(`["']\\s*(${COORD}):(${COORD})\\s*["']`));
	if (ga) return { group: ga[1], name: ga[2], version: null };
	const lib = c.match(/libs\.([\w.]+)/);
	if (lib && ctx.catalog) {
		const e = resolveLibraryAccessor(ctx.catalog, lib[1]);
		if (e && e.group && e.name) return { group: e.group, name: e.name, version: e.version || null };
	}
	return null;
}

/** Parse a gradle.lockfile → { deps: [{group,name,version,scope,isDev,configurations}] }. */
function parseGradleLockfile(text) {
	const deps = [];
	for (const raw of String(text || "").split(/\r?\n/)) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		const eq = line.indexOf("=");
		if (eq < 0) continue;
		const coord = line.slice(0, eq).trim();
		if (coord === "empty") continue;
		const configurations = line.slice(eq + 1).split(",").map(s => s.trim()).filter(Boolean);
		const parts = coord.split(":");
		if (parts.length < 3 || !parts[0] || !parts[1] || !parts[2]) continue;
		const isDev = configurations.length > 0 && configurations.every(isTestConfig);
		deps.push({ group: parts[0], name: parts[1], version: parts[2], scope: isDev ? "test" : "compile", isDev, configurations });
	}
	return { deps };
}

/** Parse a gradle.properties → { key: value }. */
function parseGradleProperties(text) {
	const out = {};
	for (const raw of String(text || "").split(/\r?\n/)) {
		const line = raw.trim();
		if (!line || line.startsWith("#") || line.startsWith("!")) continue;
		const eq = line.indexOf("=");
		if (eq < 0) continue;
		const k = line.slice(0, eq).trim();
		if (k) out[k] = line.slice(eq + 1).trim();
	}
	return out;
}

// ---------------------------------------------------------------------------
// Build-script structure: comments, string literals and brace blocks.
//
// Whether a coordinate is a dependency, a version constraint or a force depends on the
// BLOCK it sits in (`constraints { }`, `resolutionStrategy { }`, `configurations.all { }`,
// the closure after a declaration), so the parser needs the block structure — and a brace
// inside a string ("${…}" templates) or a comment must not open or close one.
// ---------------------------------------------------------------------------

/**
 * One pass over the script → `clean` (comments blanked) and `mask` (comments AND string
 * literals blanked). Both keep every index and newline of the source, so a position found
 * in one is valid in the others. Kotlin/Groovy "${ … }" templates are followed (a nested
 * "quoted" argument inside one does not end the outer string).
 */
function lexScript(src) {
	const n = src.length;
	const clean = src.split("");
	const mask = src.split("");
	const blank = (arr, a, b) => { for (let k = a; k < b; k++) if (arr[k] !== "\n") arr[k] = " "; };
	const stack = []; // { kind: "str", q, start } | { kind: "tpl", depth }
	let outerStart = -1;
	let i = 0;
	while (i < n) {
		const top = stack[stack.length - 1];
		if (top && top.kind === "str") {
			if (src.startsWith(top.q, i)) {
				i += top.q.length;
				stack.pop();
				if (!stack.some(f => f.kind === "str")) { blank(mask, outerStart, i); outerStart = -1; }
				continue;
			}
			if (src[i] === "\\") { i += 2; continue; }
			if (top.q[0] === "\"" && src[i] === "$" && src[i + 1] === "{") { stack.push({ kind: "tpl", depth: 1 }); i += 2; continue; }
			if (src[i] === "\n" && top.q.length === 1) {
				// Unterminated one-line string: give up on it rather than swallow the file.
				stack.pop();
				if (!stack.some(f => f.kind === "str")) { blank(mask, outerStart, i); outerStart = -1; }
			}
			i++;
			continue;
		}
		if (src[i] === "/" && src[i + 1] === "/") {
			let e = src.indexOf("\n", i); if (e < 0) e = n;
			blank(clean, i, e); blank(mask, i, e); i = e; continue;
		}
		if (src[i] === "/" && src[i + 1] === "*") {
			let e = src.indexOf("*/", i + 2); e = e < 0 ? n : e + 2;
			blank(clean, i, e); blank(mask, i, e); i = e; continue;
		}
		const q = src.startsWith("\"\"\"", i) ? "\"\"\"" : src.startsWith("'''", i) ? "'''" : (src[i] === "\"" || src[i] === "'") ? src[i] : null;
		if (q) {
			if (!stack.some(f => f.kind === "str")) outerStart = i;
			stack.push({ kind: "str", q, start: i });
			i += q.length;
			continue;
		}
		if (top && top.kind === "tpl") {
			if (src[i] === "{") top.depth++;
			else if (src[i] === "}" && --top.depth === 0) stack.pop();
		}
		i++;
	}
	if (outerStart >= 0) blank(mask, outerStart, n);
	return { clean: clean.join(""), mask: mask.join("") };
}

/** Brace blocks of a lexed script → [{ open, close, header }], `header` = the text before `{`. */
function scriptBlocks(clean, mask) {
	const blocks = [];
	const stack = [];
	for (let i = 0; i < mask.length; i++) {
		if (mask[i] === "{") stack.push(i);
		else if (mask[i] === "}" && stack.length) blocks.push({ open: stack.pop(), close: i });
	}
	while (stack.length) blocks.push({ open: stack.pop(), close: mask.length });
	for (const b of blocks) {
		let s = b.open - 1;
		while (s >= 0 && !"{};\n".includes(mask[s])) s--;
		b.header = clean.slice(s + 1, b.open).trim();
	}
	blocks.sort((a, b) => a.open - b.open);
	return blocks;
}

/** Blocks enclosing `idx`, innermost first. */
function enclosingBlocks(blocks, idx) {
	return blocks.filter(b => b.open < idx && idx < b.close).sort((a, b) => b.open - a.open);
}

/** Index of the parenthesis closing the one at `open` (string-blind thanks to the mask). */
function closeParen(mask, open) {
	let depth = 0;
	for (let i = open; i < mask.length; i++) {
		if (mask[i] === "(") depth++;
		else if (mask[i] === ")" && --depth === 0) return i;
	}
	return mask.length;
}

/**
 * Arguments of a call whose name ends at `at`: `name(…)` (balanced) or the Groovy command
 * form `name a, b` (to the end of the line, continued while a line ends with a comma).
 * → { args, start, end } or null.
 */
function callArgs(clean, mask, at) {
	let i = at;
	while (i < clean.length && (clean[i] === " " || clean[i] === "\t")) i++;
	if (clean[i] === "(") {
		const close = closeParen(mask, i);
		return { args: clean.slice(i + 1, close), start: i, end: Math.min(close + 1, clean.length) };
	}
	let end = i;
	for (;;) {
		let e = clean.indexOf("\n", end); if (e < 0) e = clean.length;
		end = e;
		if (!/,\s*$/.test(clean.slice(i, e)) || e >= clean.length) break;
		end = e + 1;
	}
	return { args: clean.slice(i, end), start: i, end };
}

const GLOBAL_HEADER = /\b(?:allprojects|subprojects)\s*$/;
const CONSTRAINTS_HEADER = /\bconstraints\s*$/;

/**
 * One `exclude(…)` → "group:module" ("*" for the part left out), or null when the call
 * names neither (a file-pattern exclude of a `jar { }` / `sourceSets { }` block).
 * Accepts Kotlin named args (`group = "x"`), Groovy maps (`group: 'x'`), `mapOf("group" to
 * "x")` and Kotlin positional `exclude("x", "y")` (the ModuleDependency extension).
 */
function parseExcludeArgs(args) {
	const a = String(args || "");
	const named = k => {
		const m = a.match(new RegExp(`\\b${k}\\s*[:=]\\s*["']([^"']*)["']`)) || a.match(new RegExp(`["']${k}["']\\s*(?:to|:)\\s*["']([^"']*)["']`));
		return m ? m[1] : null;
	};
	let g = named("group");
	let m = named("module");
	if (g == null && m == null) {
		if (/\b\w+\s*[:=]/.test(a)) return null;
		const strs = [...a.matchAll(/["']([^"']*)["']/g)].map(x => x[1]);
		if (!strs.length || strs.length > 2) return null;
		[g, m] = [strs[0], strs[1] ?? null];
	}
	const ok = s => s == null || s === "" || /^[\w.\-]+$/.test(s);
	if (!ok(g) || !ok(m) || (!g && !m)) return null;
	return `${g || "*"}:${m || "*"}`;
}

// Gradle's configuration hierarchy, as far as excludes go: an exclude rule declared on a
// configuration is inherited by every configuration extending it, so one on
// `implementation` (or `api`, `runtimeOnly`, …) reaches runtimeClasspath AND
// testRuntimeClasspath — i.e. every declaration. `runtimeClasspath` itself is extended by
// nothing (production declarations only); the `test*` ones reach test declarations only.
const EXCLUDE_ALL_CONFS = new Set(["*", "implementation", "api", "runtimeOnly", "compile", "runtime"]);
const EXCLUDE_TEST_CONFS = new Set(["testImplementation", "testRuntimeOnly", "testRuntimeClasspath", "testCompile", "testRuntime"]);
function excludeAppliesTo(target, config) {
	if (EXCLUDE_ALL_CONFS.has(target)) return true;
	if (target === "runtimeClasspath") return !isTestConfig(config);
	if (EXCLUDE_TEST_CONFS.has(target)) return /^test/.test(String(config || ""));
	return target === config;
}

// The configuration an exclude outside any dependency closure is declared on, or null when
// it is not a configuration exclude at all. `all`/`configureEach` → "*".
const CONF_ACCESS = String.raw`configurations\s*(?:\.\s*(\w+)\s*\*?|\[\s*["'](\w+)["']\s*\]|\.\s*(?:getByName|named|maybeCreate|create|register)\s*(?:<[^>]*>)?\s*\(\s*["'](\w+)["']\s*\))(?:\s*\.\s*get\s*\(\s*\))?`;
function excludeTarget(clean, blocks, idx) {
	const norm = n => (n === "all" || n === "configureEach") ? "*" : n;
	const lineStart = clean.lastIndexOf("\n", idx - 1) + 1;
	const prefix = clean.slice(lineStart, idx);
	let m = prefix.match(new RegExp(`${CONF_ACCESS}\\s*\\.\\s*$`));
	if (m) return norm(m[1] || m[2] || m[3]);
	const [inner, parent] = enclosingBlocks(blocks, idx);
	if (!inner) return null;
	m = inner.header.match(new RegExp(`${CONF_ACCESS}\\s*$`));
	if (m) return norm(m[1] || m[2] || m[3]);
	if (parent && /\bconfigurations\s*$/.test(parent.header)) {
		m = inner.header.match(/^(?:(\w+)|(?:getByName|named|maybeCreate|create|register)\s*\(\s*["'](\w+)["']\s*\)|["'](\w+)["'])$/);
		if (m) return norm(m[1] || m[2] || m[3]);
	}
	return null;
}

/** `exclude` call sites in clean[from, to) → [{ index, exclusion }]. */
function findExcludes(clean, mask, from, to) {
	const out = [];
	const re = /\bexclude\b/g;
	re.lastIndex = from;
	let m;
	while ((m = re.exec(clean)) && m.index < to) {
		if (mask[m.index] === " ") continue; // inside a string literal
		const call = callArgs(clean, mask, m.index + m[0].length);
		const exclusion = call && parseExcludeArgs(call.args);
		if (exclusion) out.push({ index: m.index, exclusion });
	}
	return out;
}

// Spring Boot imports its matching BOM only when BOTH plugins are applied. Limit
// inference to a top-level plugins block: pluginManagement, apply false, comments
// and strings do not establish that either plugin runs in this project.
function springBootBom(clean, mask, blocks, ctx) {
	const applied = new Map();
	for (const block of blocks) {
		if (block.header !== "plugins" || enclosingBlocks(blocks, block.open).length) continue;
		const declarations = [...clean.slice(block.open + 1, block.close).matchAll(
			/\b(?:id\s*(?:\(\s*)?(["'])([^"']+)\1\s*\)?|alias\s*\(\s*libs\.plugins\.([\w.]+)\s*\))/g
		)].filter(m => mask[block.open + 1 + m.index] !== " ");
		for (let i = 0; i < declarations.length; i++) {
			const m = declarations[i];
			const start = block.open + 1 + m.index + m[0].length;
			const end = i + 1 < declarations.length ? block.open + 1 + declarations[i + 1].index : block.close;
			const suffix = clean.slice(start, end);
			if (/\bapply\s*(?:\(\s*)?false\b/.test(mask.slice(start, end))) continue;
			const plugin = m[3] && Object.entries(ctx.catalog?.plugins || {}).find(([alias]) => normKey(alias) === normKey(m[3]))?.[1];
			const id = m[2] || plugin?.id;
			const versionExpr = suffix.match(/^\s*\.?\s*version\s*(?:\(\s*)?(["'])(.*?)\1/s);
			let version = versionExpr ? versionExpr[2] : plugin?.version;
			// Only resolve a whole variable here; resolveVer's best-effort dependency
			// parsing would turn "4.${patch}" into just the value of patch.
			if (version?.includes("$")) version = /^\$(?:[\w.]+|\{[\w.]+\})$/.test(version) ? resolveVer(version, ctx) : null;
			if (id) applied.set(id, version || null);
		}
	}
	const version = applied.get("org.springframework.boot");
	// Unknown and dynamic versions cannot identify a concrete BOM safely.
	if (!applied.has("io.spring.dependency-management") || !version || !/^\d[\w.\-]*$/.test(version)) return null;
	return { group: "org.springframework.boot", name: "spring-boot-dependencies", version, inferred: true };
}

/**
 * Best-effort parse of a build.gradle / build.gradle.kts.
 * @param opts { catalog, properties, kotlin, extraExcludes } — catalog from
 *   parseVersionCatalog, properties from parseGradleProperties; `kotlin` is informational
 *   (the regexes accept both DSLs); `extraExcludes` [{target, exclusion}] are configuration
 *   excludes declared ELSEWHERE that reach this script (subprojects { } / convention plugin).
 * @returns {
 *   deps:        [{group,name,version,configuration,scope,isDev,exclusionSets}] — one per g:a,
 *                real DEPENDENCIES only; exclusionSets = one "g:a" list per declaration,
 *   constraints: [{group,name,version,kind:"constraint"|"force",configuration,global}] —
 *                version constraints (`constraints { }`), forces (`resolutionStrategy.force`,
 *                `force = true`, `strictly`), NOT dependencies,
 *   configExcludes: [{target, exclusion, global}],
 *   platformBoms, unresolved }
 */
function parseBuildScript(text, opts = {}) {
	const src = String(text || "");
	const ctx = { catalog: opts.catalog || null, properties: opts.properties || {}, localVars: {} };
	const { clean, mask } = lexScript(src);
	for (const m of clean.matchAll(/\b(?:val|def)\s+(\w+)\s*=\s*["']([^"']*)["']/g)) ctx.localVars[m[1]] = m[2];
	const blocks = scriptBlocks(clean, mask);
	if (!opts.kotlin) {
		// Recognize only literal assignments directly in a top-level Groovy ext
		// block. Any other assignment to the same name makes its value uncertain.
		const assignments = [...mask.matchAll(/\b([A-Za-z_]\w*)\s*(?:\*\*=|<<=|>>>=|>>=|\+=|-=|\*=|\/=|%=|&=|\|=|\^=|=(?!=))/g)];
		const extAssignments = assignments.filter(m => {
			const parents = enclosingBlocks(blocks, m.index);
			return parents.length === 1 && parents[0].header === "ext" && !/[\w.]/.test(mask[m.index - 1] || "");
		});
		// Indexed or method-based writes may compute the property name at runtime.
		const indirectWrite = /\b(?:ext|(?:project\s*\.\s*)?ext)\s*(?:\[|\.\s*(?:set|setProperty)\s*\()|\b(?:setProperty|setExtProperty)\s*\(/.test(mask);
		ctx.ambiguousVars = new Set();
		ctx.extVars = new Set();
		for (const m of extAssignments) {
			const name = m[1];
			const literal = clean.slice(m.index + m[0].length).match(/^[ \t]*(["'])(\d[\w.\-]*)\1(?=[ \t]*(?:;|\n|}|$))/);
			const mutated = new RegExp(`(?:\\b${name}\\s*(?:\\+\\+|--)|(?:\\+\\+|--)\\s*(?:[A-Za-z_]\\w*\\s*\\.\\s*)*${name}\\b)`).test(mask);
			if (!literal || indirectWrite || mutated || assignments.filter(a => a[1] === name).length !== 1 || !/^\w+\s*=$/.test(m[0])) {
				ctx.ambiguousVars.add(name);
				delete ctx.localVars[name];
			} else { ctx.localVars[name] = literal[2]; ctx.extVars.add(name); }
		}
	}
	const blockAt = new Map(blocks.map(b => [b.open, b]));
	const isGlobal = idx => enclosingBlocks(blocks, idx).some(b => GLOBAL_HEADER.test(b.header));

	const platformBoms = [];
	const unresolved = [];
	const constraints = [];
	const blankSpans = [];

	// 1. platform()/enforcedPlatform() — balanced-paren scan (handles nested ${...} templates
	//    with their own quotes/parens), then blank the span so the inner coord isn't re-read.
	const re = /(?:enforced)?[Pp]latform\s*\(/g;
	let pm;
	while ((pm = re.exec(clean))) {
		const open = clean.indexOf("(", pm.index + pm[0].length - 1);
		if (open < 0) continue;
		const end = closeParen(mask, open);
		if (end <= open || end >= clean.length) continue;
		const coord = parsePlatformCoord(clean.slice(open + 1, end), ctx);
		if (coord && coord.group && coord.name && !platformBoms.some(b => b.group === coord.group && b.name === coord.name)) platformBoms.push(coord);
		blankSpans.push([pm.index, end + 1]);
	}
	// Keep an explicit platform declaration authoritative when it names this BOM.
	const bootBom = springBootBom(clean, mask, blocks, ctx);
	if (bootBom && !platformBoms.some(b => b.group === bootBom.group && b.name === bootBom.name)) platformBoms.push(bootBom);

	// 2. force(…) / forcedModules = [ … ] — a FORCE is a version constraint that wins over
	//    every other requirement, not a dependency: it only applies if something brings the
	//    module in. `resolutionStrategy.force("io.netty:netty-handler:4.1.100.Final")` used
	//    to be read as a dependency of configuration "force".
	const pinCoords = (args, kind, idx) => {
		for (const cm of args.matchAll(new RegExp(`(["'])(${COORD}):(${COORD}):`, "g"))) {
			if (!looksLikeCoord(cm[2], cm[3])) continue;
			const version = resolveVer(readVersionExpr(args, cm.index + cm[0].length), ctx);
			if (version) constraints.push({ group: cm[2], name: cm[3], version, kind, configuration: null, global: isGlobal(idx) });
		}
		for (const lm of args.matchAll(/\blibs\.([\w.]+)/g)) {
			const lib = resolveLibraryAccessor(ctx.catalog, lm[1]);
			if (lib && lib.group && lib.name && lib.version) constraints.push({ group: lib.group, name: lib.name, version: lib.version, kind, configuration: null, global: isGlobal(idx) });
		}
	};
	for (const fm of clean.matchAll(/\bforce\b(?=\s*[("'])/g)) {
		if (mask[fm.index] === " ") continue;
		const call = callArgs(clean, mask, fm.index + fm[0].length);
		pinCoords(call.args, "force", fm.index);
		blankSpans.push([fm.index, call.end]);
	}
	for (const fm of clean.matchAll(/\bforcedModules\s*\+?=\s*\[/g)) {
		const open = fm.index + fm[0].length - 1;
		let depth = 0, end = clean.length;
		for (let i = open; i < mask.length; i++) {
			if (mask[i] === "[") depth++;
			else if (mask[i] === "]" && --depth === 0) { end = i + 1; break; }
		}
		pinCoords(clean.slice(open, end), "force", fm.index);
		blankSpans.push([fm.index, end]);
	}

	let work = clean;
	if (blankSpans.length) {
		const chars = work.split("");
		for (const [s, e] of blankSpans) for (let k = s; k < e && k < chars.length; k++) if (chars[k] !== "\n") chars[k] = " ";
		work = chars.join("");
	}

	// 3. Declarations, in three notations. Each keeps WHERE it ends, so the closure that may
	//    follow it (`{ exclude(…) }`, `{ isForce = true }`, `{ version { strictly(…) } }`) is
	//    read for that declaration only.
	const decls = [];
	const pushDecl = (group, name, versionRaw, config, index, end, versionResolved) => {
		if (!group || !name || !looksLikeCoord(group, name) || DENY.has(config)) return;
		decls.push({ group, name, versionRaw, versionResolved, config, index, end });
	};
	// map notation: conf group: 'x', name: 'y'[, version: 'z']
	for (const m of work.matchAll(/\b(\w+)\s*\(?\s*group:\s*(["'])([^"']+)\2\s*,\s*name:\s*(["'])([^"']+)\4(?:\s*,\s*version:\s*(["'])([^"']+)\6)?/g)) {
		pushDecl(m[3], m[5], m[7] || null, m[1], m.index, m.index + m[0].length);
	}
	// string notation: conf("g:a[:v]") | conf 'g:a[:v]'. We match only the opening
	// `conf("g:a` + optional `:` and then read the version expression manually, so a
	// version like `${libs.findVersion("x").get()}` (nested quotes) isn't truncated.
	const strRe = new RegExp(`\\b(\\w+)\\s*(?:\\(\\s*)?(["'])(${COORD}):(${COORD})(:?)`, "g");
	let sm;
	while ((sm = strRe.exec(work))) {
		const at = sm.index + sm[0].length;
		const versionRaw = sm[5] === ":" ? readVersionExpr(work, at) : null;
		pushDecl(sm[3], sm[4], versionRaw, sm[1], sm.index, at + (versionRaw ? versionRaw.length : 0));
	}
	// version-catalog accessor: conf(libs.foo.bar)
	for (const m of work.matchAll(/\b(\w+)\s*(?:\(\s*)?libs\.([\w.]+)/g)) {
		if (m[1] === "libs") continue;
		const accessor = m[2];
		if (/^(versions|findVersion|bundles|plugins)\b/.test(accessor)) continue;
		const lib = resolveLibraryAccessor(ctx.catalog, accessor);
		if (lib && lib.group && lib.name) pushDecl(lib.group, lib.name, lib.version, m[1], m.index, m.index + m[0].length, true);
	}

	// The closure right after a declaration: only quotes, `)`, further map entries
	// (`, classifier: 'x'`) or a comma may separate it from the notation — and no newline,
	// so the next statement's block is never mistaken for it.
	const closureRe = /^(?:[ \t]*,[ \t]*\w+[ \t]*:[ \t]*(["'])[^"'\n]*\1)*["' \t,]*\)?[ \t,]*\{/;
	const depClosures = [];
	for (const d of decls) {
		const m = work.slice(d.end).match(closureRe);
		const b = m && blockAt.get(d.end + m[0].length - 1);
		d.closure = b || null;
		if (b) depClosures.push(b);
	}
	const inDepClosure = idx => depClosures.some(b => b.open < idx && idx < b.close);

	// 4. Configuration-level excludes (outside any declaration closure).
	const configExcludes = [];
	for (const e of findExcludes(clean, mask, 0, clean.length)) {
		if (inDepClosure(e.index)) continue;
		const target = excludeTarget(clean, blocks, e.index);
		if (target) configExcludes.push({ target, exclusion: e.exclusion, global: isGlobal(e.index) });
	}
	const allConfigExcludes = configExcludes.concat(opts.extraExcludes || []);

	// 5. Classify each declaration: a version constraint, or a dependency (possibly forced).
	const byKey = new Map();
	const unresolvedSeen = new Set();
	for (const d of decls) {
		const body = d.closure ? clean.slice(d.closure.open + 1, d.closure.close) : "";
		const strict = (body.match(/\bstrictly\s*\(?\s*["']([^"'\[\]()]+)["']/) || [])[1] || null;
		const require = (body.match(/\b(?:require|prefer)\s*\(?\s*["']([^"'\[\]()]+)["']/) || [])[1] || null;
		const forced = /\b(?:isForce|force)\s*(?:=\s*true\b|\(\s*true\s*\)|true\b)/.test(body);
		const version = (d.versionResolved ? (d.versionRaw || null) : (resolveVer(d.versionRaw, ctx) || null)) || strict || require;
		const versionUnresolved = d.versionRaw != null && !d.versionResolved && /\$/.test(String(d.versionRaw)) && !version;

		// A `constraints { }` entry is a VERSION CONSTRAINT: Gradle applies it only when
		// something actually brings the module in (docs.gradle.org "Dependency constraints").
		if (enclosingBlocks(blocks, d.index).some(b => CONSTRAINTS_HEADER.test(b.header))) {
			if (version) constraints.push({ group: d.group, name: d.name, version, kind: strict ? "force" : "constraint", configuration: d.config, global: isGlobal(d.index) });
			continue;
		}
		if (versionUnresolved && !unresolvedSeen.has(`${d.group}:${d.name}`)) {
			unresolvedSeen.add(`${d.group}:${d.name}`);
			unresolved.push({ group: d.group, name: d.name, raw: String(d.versionRaw), reason: "unresolved-variable" });
		}
		// `force = true` / `strictly(…)` on a declaration: still a dependency, AND its version
		// wins over every other requirement for that module.
		if (version && (forced || strict)) constraints.push({ group: d.group, name: d.name, version: strict || version, kind: "force", configuration: d.config, global: isGlobal(d.index) });

		const exclusions = [];
		const addEx = x => { if (!exclusions.includes(x)) exclusions.push(x); };
		if (d.closure) for (const e of findExcludes(clean, mask, d.closure.open, d.closure.close)) addEx(e.exclusion);
		for (const e of allConfigExcludes) if (excludeAppliesTo(e.target, d.config)) addEx(e.exclusion);

		const key = `${d.group}:${d.name}`;
		const scope = depScope(d.config);
		const existing = byKey.get(key);
		if (!existing) {
			byKey.set(key, { group: d.group, name: d.name, version, configuration: d.config, configurations: [d.config], ...scope, exclusionSets: [exclusions], gradleDeclarations: [{ configuration: d.config, exclusions }] });
			continue;
		}
		existing.exclusionSets.push(exclusions);
		existing.gradleDeclarations.push({ configuration: d.config, exclusions });
		if (!existing.configurations.includes(d.config)) existing.configurations.push(d.config);
		// The WIDEST scope wins (a production declaration beats a test one, whatever the
		// order): `testImplementation` listed above `implementation` used to file the dep as
		// test-only — out of the production count and the CI gate. The version follows the
		// widest-scope declarations: a test-only version is not on the production classpath.
		if (existing.isDev && !scope.isDev) {
			Object.assign(existing, { configuration: d.config, ...scope, version: version || existing.version });
		} else if (existing.isDev === scope.isDev && version && (!existing.version || compareMavenVersions(version, existing.version) > 0)) {
			existing.version = version; // same classpath → Gradle's conflict resolution takes the highest
		}
	}
	return { deps: [...byKey.values()], constraints, configExcludes, platformBoms, unresolved };
}

module.exports = { parseGradleLockfile, parseGradleProperties, parseBuildScript, parseExcludeArgs, excludeAppliesTo, resolveVer, depScope, isTestConfig };
