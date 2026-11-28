/**
 * lib/inventory/module-names.js — the display name of one of the SCANNED PROJECT's OWN descriptors.
 *
 * This is about the modules being audited (a reactor's poms, a monorepo's package.json
 * files), never about the dependencies they pull in. It exists so the report can say
 * "acme-gateway has 14 critical/high" instead of pointing at a path the reader has to
 * decode, and so a module with no declared name still gets a stable label: its path
 * relative to the scan root.
 *
 * Pure given `readFile`. Every extractor is best-effort — an unreadable or malformed
 * descriptor yields null and the caller falls back to the path. A label is cosmetic;
 * failing to read one must never interrupt a scan.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");

/** Lockfiles carry no project name — borrow it from the manifest beside them. */
const SIBLING_MANIFEST = {
	"gradle.lockfile": "build.gradle",
	"package-lock.json": "package.json",
	"yarn.lock": "package.json",
	"pnpm-lock.yaml": "package.json",
	"composer.lock": "composer.json",
	"poetry.lock": "pyproject.toml",
	"uv.lock": "pyproject.toml",
	"pdm.lock": "pyproject.toml",
	"Pipfile.lock": "Pipfile",
};

/**
 * The project's own artifactId. A pom's `<parent>` block declares an artifactId too, and
 * it is the one that appears FIRST — taking it would label every module of a Spring Boot
 * reactor "spring-boot-starter-parent". Drop the parent block, then read.
 */
function mavenArtifactId(xml) {
	const body = String(xml).replace(/<parent\b[\s\S]*?<\/parent>/gi, "");
	const m = /<artifactId>\s*([^<\s][^<]*?)\s*<\/artifactId>/i.exec(body);
	return m ? m[1] : null;
}

function jsonName(text) {
	try {
		const n = JSON.parse(text)?.name;
		return typeof n === "string" && n.trim() ? n.trim() : null;
	} catch { return null; }
}

/**
 * .NET: the project name IS the file name — MyApp.csproj is project MyApp, which is how
 * every solution file, build log and NuGet package refers to it. AssemblyName / PackageId
 * override it when the project renames its output.
 */
function dotnetProjectName(text, file) {
	const m = /<(?:AssemblyName|PackageId)>\s*([^<\s][^<]*?)\s*<\//i.exec(String(text));
	if (m) return m[1];
	return path.basename(file).replace(/\.(cs|fs|vb)proj$/i, "") || null;
}

/**
 * Gradle: the root project is named by settings.gradle(.kts); a subproject with no settings
 * file of its own is named after its DIRECTORY, which is Gradle's own default, not a guess.
 */
function gradleProjectName(file, readFile, readDir) {
	const dir = path.dirname(file);
	let names = [];
	try { names = readDir(dir) || []; } catch { names = []; }
	for (const settings of names.filter(n => /^settings\.gradle(\.kts)?$/i.test(n))) {
		let text = null;
		try { text = readFile(path.join(dir, settings)); } catch { /* unreadable */ }
		const m = text && /rootProject\.name\s*=\s*["']([^"']+)["']/.exec(text);
		if (m) return m[1];
	}
	const base = path.basename(dir);
	return base && base !== "." && base !== "/" ? base : null;
}

/** Ruby: Gemfile.lock names nothing; a .gemspec beside it does. */
function gemspecName(file, readFile, readDir) {
	const dir = path.dirname(file);
	let names = [];
	try { names = readDir(dir) || []; } catch { return null; }
	for (const spec of names.filter(n => n.endsWith(".gemspec"))) {
		let text = null;
		try { text = readFile(path.join(dir, spec)); } catch { continue; }
		const m = /\.name\s*=\s*["']([^"']+)["']/.exec(text || "");
		if (m) return m[1];
	}
	return null;
}

/** NuGet lock/config files sit beside the project file that names them. */
function dotnetSiblingName(file, readFile, readDir) {
	const dir = path.dirname(file);
	let names = [];
	try { names = readDir(dir) || []; } catch { return null; }
	const proj = names.find(n => /\.(cs|fs|vb)proj$/i.test(n));
	if (!proj) return null;
	const full = path.join(dir, proj);
	let text = null;
	try { text = readFile(full); } catch { return path.basename(proj).replace(/\.(cs|fs|vb)proj$/i, ""); }
	return dotnetProjectName(text, full);
}

function goModule(text) {
	const m = /^\s*module\s+(\S+)/m.exec(String(text));
	return m ? m[1] : null;
}

/** `[project] name` (PEP 621) or `[tool.poetry] name`, without pulling in a TOML parser. */
function pyprojectName(text) {
	const s = String(text);
	for (const section of ["project", "tool.poetry"]) {
		const head = new RegExp(`^\\s*\\[${section.replace(".", "\\.")}\\]\\s*$`, "m").exec(s);
		if (!head) continue;
		const rest = s.slice(head.index + head[0].length);
		const body = rest.split(/^\s*\[/m)[0];
		const m = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(body);
		if (m) return m[1];
	}
	return null;
}

/**
 * Display name for one descriptor, or null when it declares none.
 * @param {string} file absolute descriptor path
 */
function moduleNameFor(file, { readFile = p => fs.readFileSync(p, "utf8"), readDir = d => fs.readdirSync(d) } = {}) {
	if (!file) return null;
	const base = path.basename(file);
	const read = p => { try { return readFile(p); } catch { return null; } };
	const io = { readFile, readDir };

	// Gradle's build script has no name field; resolve it from settings/directory instead of
	// recursing into SIBLING_MANIFEST, which would loop for gradle.lockfile.
	if (/^build\.gradle(\.kts)?$/i.test(base)) return gradleProjectName(file, readFile, readDir);
	if (base === "gradle.lockfile") return gradleProjectName(file, readFile, readDir);
	if (base === "Gemfile.lock") return gemspecName(file, readFile, readDir);
	if (base === "packages.config" || base === "packages.lock.json") return dotnetSiblingName(file, readFile, readDir);

	const sibling = SIBLING_MANIFEST[base];
	if (sibling) return moduleNameFor(path.join(path.dirname(file), sibling), io);

	if (/\.(cs|fs|vb)proj$/i.test(base)) {
		const text = read(file);
		return text == null ? base.replace(/\.(cs|fs|vb)proj$/i, "") : dotnetProjectName(text, file);
	}

	const text = read(file);
	if (text == null) return null;
	if (base === "pom.xml") return mavenArtifactId(text);
	if (base === "package.json" || base === "composer.json") return jsonName(text);
	if (base === "go.mod") return goModule(text);
	if (base === "pyproject.toml") return pyprojectName(text);
	// requirements*.txt, Pipfile, *.gemspec-less trees … carry no project name at all;
	// inventing one from the directory would be a guess. The caller uses the path.
	return null;
}

/**
 * Label every parsed descriptor: its declared name, else its path relative to the scan root.
 * @param {Array<{path:string}>} parsedManifests
 * @returns {Map<string,string>} absolute path → label
 */
function resolveModuleNames(parsedManifests, { srcRoot = "", readFile, readDir } = {}) {
	const out = new Map();
	for (const entry of parsedManifests || []) {
		const file = entry && entry.path;
		if (!file || out.has(file)) continue;
		let rel = file;
		try { const r = path.relative(srcRoot, file); if (r && !r.startsWith("..")) rel = r; } catch { /* keep absolute */ }
		const io = {};
		if (readFile) io.readFile = readFile;
		if (readDir) io.readDir = readDir;
		out.set(file, moduleNameFor(file, io) || rel);
	}
	return out;
}

module.exports = { moduleNameFor, resolveModuleNames, mavenArtifactId, pyprojectName, dotnetProjectName, gradleProjectName };
