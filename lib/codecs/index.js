/**
 * lib/codecs/index.js — registre des codecs.
 *
 * getCodec(id)      → le codec, ou null
 * allCodecs()       → tous les codecs enregistrés, dans l'ordre report stable
 * detectCodecs(dir) → les codecs dont detect() est vrai sur ce répertoire
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { assertCodecShape } = require("./codec.interface");
const maven = require("./maven.codec");
const gradle = require("./gradle.codec");
const npm = require("./npm.codec");
const yarn = require("./yarn.codec");
const composer = require("./composer.codec");
const pypi = require("./pypi.codec");
const nuget = require("./nuget.codec");
const go = require("./go.codec");
const ruby = require("./ruby.codec");
const binary = require("./binary.codec");

// Ordre stable pour le report (maven, npm, yarn, puis les nouveaux écosystèmes).
// "binary" (committed native libs, no manifest) reste en dernier.
const ORDER = ["maven", "gradle", "npm", "yarn", "nuget", "composer", "pypi", "go", "ruby", "binary"];

const REGISTRY = new Map();
for (const c of [maven, gradle, npm, yarn, composer, pypi, nuget, go, ruby, binary]) {
	assertCodecShape(c);
	REGISTRY.set(c.id, c);
}

function getCodec(id) { return REGISTRY.get(id) || null; }

function allCodecs() {
	return [...REGISTRY.values()].sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id));
}

// Dirs skipped during detection. Starts from the INTERSECTION of every codec's own
// skip set (a dir skipped here only if ALL codecs skip it → detection never misses a
// manifest a codec would have found) plus well-known dependency/cache/tooling dirs
// that are NEVER a project root (all dot-dirs or vendored-dep caches), so detection
// can prune them safely. NOTE: "build" / "vendor" / "bin" / "obj" are deliberately
// NOT here — maven keeps build/ for BOMs and several codecs scan vendor/.
const DETECT_SKIP = new Set([
	"node_modules", ".git", ".idea", ".vscode", "target", "dist", "out",   // intersection
	".svn", ".hg", ".gradle", ".mvn", ".cache", ".m2", "bower_components",  // never a project root
	"jspm_packages", "__pycache__", ".venv", ".tox", ".mypy_cache", "coverage", ".next", ".nuxt",
]);

const DETECT_CONCURRENCY = 48;

// yarn est détecté via le même arbre JS que npm ; on ne le renvoie pas en
// doublon de détection (npm.collect ramasse déjà yarn.lock).
//
// ONE shared walk instead of one full-tree walk per codec: we descend the tree once
// and, per file, test it against each codec's manifestNames (supporting "*.ext"
// globs). Short-circuits as soon as every codec has matched. readdir runs with bounded
// concurrency — on a high-latency filesystem (WSL/9p, network mounts) the walk is
// latency-bound, so issuing many readdirs at once is far faster than a serial walk.
async function detectCodecs(dir, opts = {}) {
	const { makeDirFilter } = require("../inventory/path-filter");
	const skipDir = makeDirFilter({ srcRoot: dir, defaultSkip: DETECT_SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
	const codecs = allCodecs().filter(c => c.id !== "yarn");
	const matchers = codecs.map(c => {
		const exact = new Set();
		const exts = [];
		for (const n of c.manifestNames || []) {
			if (n.startsWith("*.")) exts.push(n.slice(1)); // "*.csproj" → ".csproj"
			else exact.add(n);
		}
		return { codec: c, exact, exts, found: false };
	});
	let remaining = matchers.length;
	const queue = [dir];
	let active = 0;

	await new Promise(resolve => {
		let settled = false;
		const finish = () => { if (!settled) { settled = true; resolve(); } };
		const pump = () => {
			if (settled) return;
			if (remaining === 0) return finish();
			if (queue.length === 0 && active === 0) return finish();
			while (active < DETECT_CONCURRENCY && queue.length && remaining > 0) {
				const cur = queue.pop();
				active++;
				fs.promises.readdir(cur, { withFileTypes: true }).then(async entries => {
					for (const e of entries) {
						if (e.isDirectory()) {
							const child = path.join(cur, e.name);
							if (!skipDir(child, e.name)) queue.push(child);
							continue;
						}
						if (!e.isFile()) continue;
						const name = e.name;
						for (const m of matchers) {
							if (m.found) continue;
							if (m.exact.has(name) || m.exts.some(ext => name.endsWith(ext)) || (m.codec.detectFile && await m.codec.detectFile(path.join(cur, name)))) { if (!m.found) { m.found = true; remaining--; } }
						}
					}
				}).catch(() => { /* unreadable dir → skip */ }).finally(() => { active--; pump(); });
			}
		};
		pump();
	});
	return matchers.filter(m => m.found).map(m => m.codec);
}

module.exports = { getCodec, allCodecs, detectCodecs, ORDER };
