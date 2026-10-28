/**
 * lib/retire.js — wrap retire.js (the CLI) to find vulnerable
 * vendored JavaScript libraries living in the source tree as
 * unmanaged .js / .min.js files (no package-lock to back them).
 *
 * retire ships its own signature DB updated weekly; we just shell
 * out to it and normalise the output to vigievuln match shape so the
 * report can render it like any other CVE source.
 *
 * Cache: ~/.fad-checker/retire-cache/<md5(src)>.json, 24 h TTL.
 * Hosted online scans revalidate signatures via the proxy and bypass cached findings.
 *
 * The CLI is expected at node_modules/.bin/retire (declared in
 * package.json deps). When bundled with bun, we also try `retire`
 * on PATH as a fallback.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileP = promisify(execFile);

const RETIRE_CACHE_DIR = path.join(require("./cache-directory").getCacheDir(), "retire-cache");
const RETIRE_CACHE_TTL_MS = 24 * 3600 * 1000;

// retire's own signature DB. By default retire caches it in /tmp/.retire-cache
// (outside ~/.fad-checker/, with a 1h TTL → a network refetch on expiry). For the
// air-gapped offline workflow we instead keep a stable local copy INSIDE ~/.fad-checker/
// so `--export-cache` carries it, and feed it to retire via `--jsrepo <file>`
// (loaded from file, never the network — no TTL).
const RETIRE_SIG_DIR = path.join(require("./cache-directory").getCacheDir(), "retire-signatures");
const RETIRE_SIG_FILE = path.join(RETIRE_SIG_DIR, "jsrepository-v5.json");
const RETIRE_REPO_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v5.json";

// retire always emits ABSOLUTE file paths (it resolves --jspath). Make them
// relative to the scan root robustly — resolving BOTH sides so it works whether
// the caller passed -s as a relative ("./proj") or absolute path. The old
// `file.startsWith(srcDir)` guard silently left paths absolute for a relative -s.
function relToSrc(srcDir, file) {
	if (!file) return file;
	if (!srcDir) return file;
	try {
		const rel = path.relative(path.resolve(srcDir), path.resolve(file));
		return rel && !rel.startsWith("..") ? rel : file;
	} catch { return file; }
}

function cacheKey(srcDir) {
	return crypto.createHash("md5").update(path.resolve(srcDir)).digest("hex") + ".json";
}

// Cache schema version. Bumped to 2 when retire started running with `--verbose`
// (so the cached body carries the FULL vendored-JS inventory, not just vulnerable
// hits). A cached entry without `_schema >= 2` was written by a pre-verbose build
// (e.g. 1.0.6) and its body holds vuln-only data — trusting it would silently empty
// the inventory chapter (1D) on an offline re-run. We treat such an entry as a
// cache MISS so the normal path re-scans (online, or offline with local signatures)
// and the offline report reproduces the online one.
const RETIRE_CACHE_SCHEMA = 2;

function readCache(srcDir) {
	const p = path.join(RETIRE_CACHE_DIR, cacheKey(srcDir));
	if (!fs.existsSync(p)) return null;
	try {
		const data = JSON.parse(fs.readFileSync(p, "utf8"));
		if (!(data._schema >= RETIRE_CACHE_SCHEMA)) return null; // legacy / pre-verbose → re-scan
		if (Date.now() - data._fetchedAt < RETIRE_CACHE_TTL_MS) return data.body;
	} catch { /* ignore */ }
	return null;
}

function writeCache(srcDir, body) {
	fs.mkdirSync(RETIRE_CACHE_DIR, { recursive: true });
	fs.writeFileSync(path.join(RETIRE_CACHE_DIR, cacheKey(srcDir)),
		JSON.stringify({ _schema: RETIRE_CACHE_SCHEMA, _fetchedAt: Date.now(), body }));
}

function findRetireBin() {
	const local = path.join(__dirname, "..", "node_modules", ".bin", "retire");
	if (fs.existsSync(local)) return local;
	return "retire"; // fall back to PATH
}

// Decide HOW to launch retire. The compiled (bun) binary has no node_modules to
// spawn the retire CLI from and the air-gapped box has no `retire` on PATH — so it
// re-execs ITSELF with __FAD_RETIRE__ set, and the entry point (vigievuln.js)
// hands off to the statically-bundled retire CLI. Pure for testability.
//   - running under bun (compiled binary)       → self-invoke this executable.
//   - else localBin present (node dev)           → run it directly.
//   - else                                       → `retire` on PATH (last resort).
//
// bun is checked FIRST because `localBin` is resolved from `__dirname`, which in the
// compiled binary still points at the directory it was BUILT in. Wherever that path also
// exists at run time — the developer who built it running it on the same machine, a shared
// or mounted checkout — the binary found a `#!/usr/bin/env node` script and died with
// "env: 'node': No such file or directory" with node absent, taking the whole vendored-JS
// chapter with it. On a box that never held the checkout the path is simply missing and the
// old order happened to work, which is why a container did not show this. Either way a
// compiled binary has no business preferring an external script over the retire CLI it
// bundles: the order now depends on what the binary IS, not on what is on disk beside it.
function chooseRetireLauncher({ localBin, isBun, execPath }) {
	if (isBun) return { cmd: execPath, env: { __FAD_RETIRE__: "1" } };
	if (localBin) return { cmd: localBin, env: null };
	return { cmd: "retire", env: null };
}

function findRetireLauncher() {
	// npm installs a .cmd shim on Windows; execFile cannot run it without a shell.
	// Invoke the package's JS entry with the current Node executable instead.
	if (process.platform === 'win32' && !(process.versions && process.versions.bun)) {
		const script = path.join(__dirname, '..', 'node_modules', 'retire', 'lib', 'cli.js');
		if (fs.existsSync(script)) return {cmd:process.execPath, env:null, args:[script]};
	}
	const local = path.join(__dirname, "..", "node_modules", ".bin", "retire");
	return chooseRetireLauncher({
		localBin: fs.existsSync(local) ? local : null,
		isBun: !!(process.versions && process.versions.bun),
		execPath: process.execPath,
	});
}

/**
 * Fetch retire's signature DB to a stable file inside ~/.fad-checker/ so it can
 * be bundled by --export-cache and reused offline via --jsrepo. Network call —
 * online only. Returns { ok, path } | { ok:false, error }. Never throws.
 */
async function warmRetireSignatures(opts = {}) {
	const { verbose, force, offline } = opts;
	const present = fs.existsSync(RETIRE_SIG_FILE);
	if (offline) return present ? { ok: true, path: RETIRE_SIG_FILE, cached: true }
		: { ok: false, error: "offline: no local retire signatures" };
	const hostedOnline = require("./providers").hasHostedProxy();
	if (!force && !hostedOnline && present) {
		if (verbose) console.log(`retire: signatures already present (${RETIRE_SIG_FILE})`);
		return { ok: true, path: RETIRE_SIG_FILE, cached: true };
	}
	try {
		const res = await require("./providers").getResource("retire", "signatures", {},
			{ ...(opts.fetcher ? { fetcher: opts.fetcher } : {}), signal: AbortSignal.timeout(60000) });
		if (!res.ok) throw new Error(`HTTP ${res.status}`);
		const text = await res.text();
		const repo = JSON.parse(text);
		if (!repo || typeof repo !== "object" || Array.isArray(repo)) throw new Error("invalid retire signatures");
		fs.mkdirSync(RETIRE_SIG_DIR, { recursive: true });
		// Failed/truncated refreshes must leave the offline snapshot intact.
		const temp = `${RETIRE_SIG_FILE}.${crypto.randomBytes(8).toString("hex")}.tmp`;
		try { fs.writeFileSync(temp, text); fs.renameSync(temp, RETIRE_SIG_FILE); }
		finally { try { fs.unlinkSync(temp); } catch { /* renamed or not created */ } }
		if (verbose) console.log(`retire: signatures warmed → ${RETIRE_SIG_FILE}`);
		return { ok: true, path: RETIRE_SIG_FILE };
	} catch (e) {
		if (verbose) console.warn(`retire: signature warm failed — ${e.message}`);
		return { ok: false, error: e.message };
	}
}

// Hosted online: always consult the proxy (including its stale/source-health signal).
// Offline: only report local availability, even with --force and a configured proxy.
async function ensureSignatures({ verbose, offline, fetcher } = {}) {
	if (offline) return fs.existsSync(RETIRE_SIG_FILE);
	if (!require("./providers").hasHostedProxy() && fs.existsSync(RETIRE_SIG_FILE)) return true;
	const r = await warmRetireSignatures({ verbose, fetcher });
	return !!r.ok;
}

// Directories retire never needs to walk. Mirrors the per-walker default SKIP sets
// the codecs use (lib/path-filter.js / npm parse.js): package stores, build output,
// IDE/VCS metadata. Matched by BASENAME at any depth (see buildRetireIgnorePatterns).
const DEFAULT_RETIRE_SKIP_DIRS = [
	"node_modules", "bower_components", "jspm_packages",
	".git", ".idea", ".vscode", ".gradle", ".mvn",
	"target", "dist", "build", "build-output", "out", "coverage", ".next", ".nuxt",
];

/**
 * Build the lines for a retire ignorefile, mirroring the rest of the scan's
 * exclude policy (lib/path-filter.js#makeDirFilter) so retire skips the SAME dirs
 * every codec walker prunes.
 *
 * Why an ignorefile and not `--ignore`: retire `path.resolve()`s every `--ignore`
 * entry against ITS OWN cwd (cli.js), so a bare "node_modules" becomes
 * `<cwd>/node_modules` and silently misses `<srcDir>/…/node_modules` whenever fad
 * runs from a different directory than `-s` — and it can never express "this dir
 * at ANY depth". An ignorefile line prefixed with `@` is kept VERBATIM (no resolve)
 * and used as a substring regex, which is the only retire mechanism that can.
 *
 * Two layers, exactly like makeDirFilter:
 *   - default skip dirs → `@/<name>/` : segment-bounded substring → matches the dir
 *     at ANY depth (the bug: a deeply-nested node_modules), and the surrounding
 *     slashes keep lookalike files (`node_modules_shim.js`) from being clipped.
 *     Dropped entirely when defaultExcludes === false (--no-default-excludes).
 *   - user --exclude-path globs → `@<absSrcDir>/<glob>/` : ANCHORED to the scan
 *     root (not any-depth), retire expands `*`→[^/]* and `**`→.* itself.
 *
 * retire walks with POSIX-style paths (its own matchers use `/`), so we emit `/`.
 */
function buildRetireIgnorePatterns({ srcDir, excludePath = [], defaultExcludes = true, sep = path.sep } = {}) {
	const lines = [];
	// retire compiles each line into a REGEX and tests it against the file path AND
	// path.resolve(file) — both of which use BACKSLASHES on Windows. A forward-slash
	// pattern therefore never matches there, and every exclusion (including the defaults
	// that keep retire out of node_modules) is silently inert. A character class like
	// [\\/] is not an option: retire escapes `[` and `]` before compiling. So emit the
	// POSIX form plus, on Windows, the native-separator twin — retire's `.some()` means
	// either one matching is enough, and on POSIX the twin is identical and deduped away.
	const push = line => { if (!lines.includes(line)) lines.push(line); };
	const emit = body => {
		push(`@${body}`);
		if (sep === "\\") push(`@${body.split("/").join("\\")}`);
	};

	if (defaultExcludes !== false) {
		for (const d of DEFAULT_RETIRE_SKIP_DIRS) emit(`/${d}/`);
	}
	// Separator-agnostic on INPUT (path.resolve yields backslashes on Windows); `sep`
	// only decides what we emit.
	const root = srcDir ? path.resolve(srcDir).replace(/\\/g, "/").replace(/\/+$/, "") : "";
	for (const g of excludePath || []) {
		// Normalise like compileGlobs: strip a leading ./ or /, a trailing /, and a
		// trailing /** (the dir's whole subtree is already covered by the segment).
		const base = String(g || "").trim().replace(/^\.?\/+/, "").replace(/\/+$/, "").replace(/\/\*\*$/, "");
		if (!base) continue;
		emit(root ? `${root}/${base}/` : `/${base}/`);
	}
	return lines;
}

// Pure: build the retire CLI argv. `ignoreFile` (a path-anchored ignorefile, see
// buildRetireIgnorePatterns) is passed when there's anything to exclude. `jsRepo`
// (a local signature file) is added when available so retire loads signatures from
// disk instead of the network.
function buildRetireArgs({ srcDir, outPath, ignoreFile, jsRepo }) {
	const args = [
		// --verbose makes retire list EVERY identified library, not just the
		// vulnerable ones (its own wording: "by default only vulnerable files are
		// shown"). We need the full set for the vendored-JS inventory chapter;
		// vulnerable findings are still flagged in each result's `vulnerabilities`.
		"--verbose",
		"--outputformat", "json",
		"--outputpath", outPath,
		"--jspath", srcDir,
	];
	if (ignoreFile) { args.push("--ignorefile", ignoreFile); }
	if (jsRepo) { args.push("--jsrepo", jsRepo); }
	return args;
}

const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, none: 1 };

// Pick the human-meaningful line out of retire's stderr for a failure message.
// retire dumps a multi-line stack trace; the useful part is the first non-empty,
// non-stack-frame line (preferring an ENOENT / "no such file" / permission line).
function retireFailureReason(stderr, fallback) {
	const lines = String(stderr || "")
		.split("\n")
		.map(l => l.trim())
		.filter(l => l && !/^at\s/.test(l));
	if (!lines.length) return fallback;
	const hot = lines.find(l => /ENOENT|no such file|permission denied|EACCES/i.test(l));
	return hot || lines[0];
}

/**
 * Extract the full inventory of identified vendored JS libraries (vulnerable or
 * not) from retire's --verbose output. Each entry: the standalone library, where
 * it lives, how retire identified it, and whether it carries known vulns.
 * This is a governance/cyber-hygiene signal: third-party code no package manager
 * governs (unknown provenance, integrity, patch story) — the JS twin of the
 * native-binary inventory (chapter 1C).
 */
function extractVendoredInventory(raw, srcDir) {
	const out = [];
	if (!raw) return out;
	const files = Array.isArray(raw) ? raw : (raw.data || []);
	for (const f of files) {
		const file = f.file;
		const relFile = relToSrc(srcDir, file);
		for (const res of f.results || []) {
			if (!res.component) continue;
			const vulns = res.vulnerabilities || [];
			let maxSeverity = null;
			for (const v of vulns) {
				const s = (v.severity || "").toLowerCase();
				if (!maxSeverity || (SEV_RANK[s] || 0) > (SEV_RANK[maxSeverity] || 0)) maxSeverity = s;
			}
			out.push({
				component: res.component,
				version: res.version || null,
				file: relFile || null,
				detection: res.detection || null,
				vulnerable: vulns.length > 0,
				vulnCount: vulns.length,
				maxSeverity: maxSeverity ? maxSeverity.toUpperCase() : null,
			});
		}
	}
	// Vulnerable first (by severity), then by component/version/file for stability.
	out.sort((a, b) =>
		(SEV_RANK[(b.maxSeverity || "").toLowerCase()] || 0) - (SEV_RANK[(a.maxSeverity || "").toLowerCase()] || 0)
		|| String(a.component).localeCompare(String(b.component))
		|| String(a.version).localeCompare(String(b.version))
		|| String(a.file).localeCompare(String(b.file)));
	return out;
}

/**
 * Run retire.js against `srcDir`. Returns the parsed JSON output (an array
 * of file-level findings) or null if retire is unavailable.
 *
 * `--outputformat json` is the structured form; a generated `--ignorefile`
 * prunes the same dirs the rest of the scan skips (default SKIP set at any depth
 * + the user's --exclude-path globs, anchored to the scan root) so retire never
 * walks node_modules/target/… or anything the auditor excluded.
 */
async function runRetire(srcDir, opts = {}) {
	const { verbose, force, offline, excludePath, defaultExcludes } = opts;
	// Optional diagnostics collector: callers (scanWithRetireFull) read diag.error to
	// surface a genuine SCAN FAILURE (retire crashed / produced no parseable output)
	// as a report warning — instead of letting it masquerade as "no vendored JS found".
	const diag = opts.diag || {};
	// No source tree (e.g. --import-anonymized) → nothing to scan for vendored JS.
	if (!srcDir) { if (verbose) console.warn("retire: no source dir — skipped"); return null; }
	try { if (!fs.statSync(srcDir).isDirectory()) throw new Error('not a directory'); }
	catch { diag.error = 'retire.js scan failed: source directory is unavailable'; return null; }
	const hostedOnline = !offline && require("./providers").hasHostedProxy();
	// A result's scan time cannot prove that the signatures it used are still current.
	if (!force && !hostedOnline) {
		const cached = readCache(srcDir);
		if (cached) {
			if (verbose) console.log("retire: using cached results (<24h)");
			return cached;
		}
	}

	// No findings cache → we must scan. We need a signature DB. Offline, we can
	// only proceed if a local signature file was previously warmed (and bundled
	// via --export-cache / --import-cache); otherwise honor --offline and skip.
	const haveSig = await ensureSignatures({ verbose, offline, fetcher: opts.fetcher });
	if (hostedOnline && !haveSig) {
		diag.error = "retire.js signatures could not be refreshed through the hosted proxy; scan skipped (no direct fallback)";
		return null;
	}
	if (offline && !haveSig) {
		if (verbose) console.warn("retire: --offline, no findings cache and no local signatures — skipped");
		return null;
	}

	const launcher = findRetireLauncher();

	// retire.js refuses to write to /dev/stdout, so we use a real temp file
	// and read it back. Falls back to stdout if --outputpath is rejected.
	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigievuln-retire-'));
	const tmpOut = path.join(tmpDir, 'output.json');

	// Pruning policy, written to a temp ignorefile so retire honors it for the tree
	// it ACTUALLY walks (anchored to srcDir, not retire's cwd — the nested
	// node_modules bug) and respects the same --exclude-path the codecs do.
	const ignorePatterns = buildRetireIgnorePatterns({ srcDir, excludePath, defaultExcludes });
	// retire treats a `.json` ignorefile as the structured descriptor form; keep a
	// plain-text extension so the `@`-prefixed regex lines are read as such.
	const tmpIgnore = ignorePatterns.length ? path.join(tmpDir, 'ignore.txt') : null;
	try { if (tmpIgnore) fs.writeFileSync(tmpIgnore, ignorePatterns.join("\n") + "\n", { mode: 0o600, flag: 'wx' }); }
	catch (error) { fs.rmSync(tmpDir, { recursive: true, force: true }); throw error; }
	const cleanup = () => {
		try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
	};

	const args = buildRetireArgs({ srcDir, outPath: tmpOut, ignoreFile: tmpIgnore, jsRepo: haveSig ? RETIRE_SIG_FILE : null });
	if (verbose) console.log(`retire: scanning ${srcDir}…${haveSig ? " (local signatures)" : ""}`);

	let execErr = null;
	try {
		// retire.js exits with code 13 when it finds vulnerabilities — that's
		// expected. Catch and ignore the non-zero exit; the JSON file is still
		// produced.
		await execFileP(launcher.cmd, [...(launcher.args || []), ...args], {
			maxBuffer: 1024 * 1024 * 64,
			env: launcher.env ? { ...process.env, ...launcher.env } : process.env,
		});
	} catch (err) {
		execErr = err;
		// exit code 13 (or anything where a non-empty output file exists) is OK.
		// A missing OR empty (0-byte) output file means retire crashed mid-walk
		// (e.g. ENOENT on the source path, an unreadable file) — a real failure.
		let size = -1;
		try { size = fs.statSync(tmpOut).size; } catch { /* missing */ }
		if (size <= 0) {
			const reason = retireFailureReason(err.stderr, err.message);
			diag.error = `retire.js scan failed: ${reason}`;
			if (verbose) console.warn(`retire: failed to run — ${reason}`);
			cleanup();
			return null;
		}
	}

	let parsed;
	try {
		const body = fs.readFileSync(tmpOut, "utf8");
		parsed = JSON.parse(body);
	} catch (err) {
		const reason = retireFailureReason(execErr && execErr.stderr, err.message);
		diag.error = `retire.js scan failed: ${reason}`;
		if (verbose) console.warn(`retire: could not parse output — ${err.message}`);
		return null;
	} finally {
		cleanup();
	}
	writeCache(srcDir, parsed);
	return parsed;
}

/**
 * Normalise a retire.js result tree to vigievuln match shape.
 *
 * retire output (jsonsimple-ish):
 *   {
 *     data: [
 *       {
 *         file: "/abs/path/jquery-1.4.4.min.js",
 *         results: [
 *           {
 *             component: "jquery",
 *             version:   "1.4.4",
 *             vulnerabilities: [
 *               {
 *                 severity: "high",
 *                 identifiers: { CVE: ["CVE-…"], summary: "…", issue?: "…" },
 *                 info:      ["https://…"],
 *                 below?:    "1.6.3",
 *                 atOrAbove?: "1.4.0",
 *               },
 *             ],
 *           },
 *         ],
 *       },
 *     ],
 *   }
 */
function normaliseRetireResults(raw, srcDir) {
	const out = [];
	if (!raw) return out;
	const files = Array.isArray(raw) ? raw : (raw.data || []);
	for (const f of files) {
		const file = f.file;
		const relFile = relToSrc(srcDir, file);
		for (const res of f.results || []) {
			const component = res.component;
			const version = res.version;
			for (const v of res.vulnerabilities || []) {
				const ids = v.identifiers || {};
				const cveIds = Array.isArray(ids.CVE) && ids.CVE.length ? ids.CVE : [ids.issue || ids.summary || `RETIRE-${component}-${version}`];
				const severity = (v.severity || "medium").toUpperCase();
				const description = ids.summary || v.info?.[0] || "";
				const refs = (v.info || []).map(u => ({ type: "WEB", url: u }));
				for (const cveId of cveIds) {
					out.push({
						dep: {
							groupId: "",
							artifactId: component,
							version,
							scope: "vendored",
							ecosystem: "npm",
							ecosystemType: "retire",
							pomPaths: file ? [file] : [],
							manifestPaths: file ? [file] : [],
							vendoredFile: relFile,
						},
						cve: {
							id: cveId,
							severity,
							score: null,
							description,
							fixVersion: v.below || null,
							osvRefs: refs,
						},
						source: "retire",
						confidence: "exact",
					});
				}
			}
		}
	}
	return out;
}

/**
 * Public entry point. Returns an array of match objects or [] if retire
 * couldn't run or found nothing.
 */
async function scanWithRetire(srcDir, opts = {}) {
	const raw = await runRetire(srcDir, opts);
	if (!raw) return [];
	return normaliseRetireResults(raw, srcDir);
}

/**
 * Like scanWithRetire but returns BOTH the vulnerable matches (chapter "Vendored
 * JS") and the full identified-library inventory (chapter "Unmanaged / vendored
 * JavaScript"). One retire run feeds both.
 */
async function scanWithRetireFull(srcDir, opts = {}) {
	const diag = {};
	const raw = await runRetire(srcDir, { ...opts, diag });
	if (!raw) return { matches: [], inventory: [], error: diag.error || null };
	return {
		matches: normaliseRetireResults(raw, srcDir),
		inventory: extractVendoredInventory(raw, srcDir),
		error: null,
	};
}

module.exports = {
	scanWithRetire,
	scanWithRetireFull,
	extractVendoredInventory,
	runRetire,
	normaliseRetireResults,
	findRetireBin,
	findRetireLauncher,
	chooseRetireLauncher,
	warmRetireSignatures,
	ensureSignatures,
	buildRetireArgs,
	buildRetireIgnorePatterns,
	DEFAULT_RETIRE_SKIP_DIRS,
	retireFailureReason,
	readCache,
	writeCache,
	cacheKey,
	RETIRE_CACHE_SCHEMA,
	RETIRE_CACHE_DIR,
	RETIRE_SIG_DIR,
	RETIRE_SIG_FILE,
	RETIRE_REPO_URL,
};
