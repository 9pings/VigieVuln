/**
 * lib/cache-archive.js — export / import the entire ~/.fad-checker/ directory.
 *
 * Use case:
 *   - Move the warmed-up CVE/OSV/NVD/POM caches between machines
 *   - Snapshot the index before a scheduled refresh
 *   - Share a known-good cache with a teammate
 *
 * Format:
 *   .tar.gz   — preferred when tar is available (Linux, macOS, Windows 10+)
 *   .zip      — fallback for Windows-only envs without tar
 *
 * The format is selected from the file extension. Tar uses native `tar`
 * binary (zero new deps).
 *
 * Import MERGES by default (`--replace` restores the old wholesale swap). The
 * air-gapped workflow ships a cache into an enclave that is already warm and holds
 * its own config.json — which `--export-cache` deliberately never bundles. Replacing
 * threw both away silently, and `--offline` on the resulting cold cache reports
 * 0 CVE / 0 EOL, which reads exactly like a clean project.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFile, spawn } = require("child_process");
const { promisify } = require("util");
const execFileP = promisify(execFile);

const FAD_CACHE_DIR = require("./cache-directory").getCacheDir({homeDir:os.homedir()});

/**
 * Files inside ~/.fad-checker/ that hold secrets and should NOT be shipped by default.
 * Override by passing `includeConfig: true`.
 */
const SENSITIVE_FILES = ["config.json"];

/**
 * Never taken from an archive on a merging import. `config.json` is machine-local
 * (NVD key, private registry credentials) and is excluded from the export by default,
 * so an import that touched it could only ever lose the target's own.
 */
const NEVER_IMPORT = ["config.json"];

/**
 * Directories whose files only make sense together: the CVE index and the meta.json
 * that names the release it was built from. Merged per-file they could end up
 * describing two different builds, so the freshest side wins as a block.
 */
const ATOMIC_DIRS = ["cve-data"];

function readJson(file) {
	try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return null; }
}

/** Freshness of a cache file: its own stamp when it carries one, else the mtime. */
function stampOf(file, json) {
	const declared = json?._fadSnapshot?.collectedAt ?? json?.collectedAt ?? json?.generatedAt;
	// A declared but invalid snapshot date must not acquire freshness from a copy's mtime.
	if (declared != null) {
		const stamp = typeof declared === "string" ? Date.parse(declared) : NaN;
		return Number.isFinite(stamp) ? stamp : 0;
	}
	const s = json?.meta?.fetchedAt ?? json?._fetchedAt ?? json?.fetchedAt;
	if (typeof s === "number" && s > 0) return s;
	try { return fs.statSync(file).mtimeMs; } catch { return 0; }
}

/**
 * An accumulating per-key cache — `{ meta|_fetchedAt, entries: {…} }`, the shape of
 * version/maven-exists/npm-registry/eol/epss/packagist/pypi/nuget/go-proxy/rubygems/
 * hash-id. Those merge key by key. Anything else (kev's full `body.byId` catalogue, an
 * OSV/NVD/POM cache entry, an OSV DB index) is a self-contained blob: newest wins.
 */
const isEntryMap = j => !!j && typeof j === "object" && !!j.entries
	&& typeof j.entries === "object" && !Array.isArray(j.entries);

/** copyFileSync + keep the source mtime, so the next import still compares correctly. */
function copyPreservingTime(src, dst) {
	fs.mkdirSync(path.dirname(dst), { recursive: true });
	fs.copyFileSync(src, dst);
	const st = fs.statSync(src);
	try { fs.utimesSync(dst, st.atime, st.mtime); } catch { /* best effort */ }
}

/**
 * Union of two entry maps. The fresher side wins on a key collision; the merged map
 * is stamped with the OLDER of the two — a union is only as fresh as its stalest half,
 * and antedating it would let a TTL check treat stale entries as just-fetched.
 */
function mergeEntryMaps(srcFile, dstFile, srcJson, dstJson) {
	const srcStamp = stampOf(srcFile, srcJson), dstStamp = stampOf(dstFile, dstJson);
	const srcWins = srcStamp > dstStamp;
	const winner = srcWins ? srcJson : dstJson;
	const out = { ...winner };
	out.entries = srcWins
		? { ...dstJson.entries, ...srcJson.entries }
		: { ...srcJson.entries, ...dstJson.entries };
	const older = Math.min(srcStamp, dstStamp);
	if (out.meta && typeof out.meta === "object" && typeof out.meta.fetchedAt === "number") out.meta = { ...out.meta, fetchedAt: older };
	if (typeof out._fetchedAt === "number") out._fetchedAt = older;
	if (typeof out.fetchedAt === "number") out.fetchedAt = older;
	fs.writeFileSync(dstFile, JSON.stringify(out));
}

/** Newest mtime anywhere under `dir` — the freshness of an atomic directory. */
function newestMtime(dir) {
	let newest = 0;
	for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
		const p = path.join(dir, ent.name);
		if (ent.isDirectory()) newest = Math.max(newest, newestMtime(p));
		else if (ent.isFile()) newest = Math.max(newest, stampOf(p, readJson(p)));
	}
	return newest;
}

function copyTree(srcDir, dstDir) {
	fs.mkdirSync(dstDir, { recursive: true });
	for (const ent of fs.readdirSync(srcDir, { withFileTypes: true })) {
		const s = path.join(srcDir, ent.name), d = path.join(dstDir, ent.name);
		if (ent.isDirectory()) copyTree(s, d);
		else if (ent.isFile()) copyPreservingTime(s, d);
	}
}

function mergeFile(srcFile, dstFile, rel, stats) {
	if (!fs.existsSync(dstFile)) { copyPreservingTime(srcFile, dstFile); stats.added++; return; }
	const srcJson = readJson(srcFile), dstJson = readJson(dstFile);
	if (isEntryMap(srcJson) && isEntryMap(dstJson)) {
		mergeEntryMaps(srcFile, dstFile, srcJson, dstJson);
		stats.merged++;
		return;
	}
	if (stampOf(srcFile, srcJson) > stampOf(dstFile, dstJson)) { copyPreservingTime(srcFile, dstFile); stats.updated++; }
	else stats.kept++;
}

function mergeResourceStore(srcDir, dstDir, stats) {
	const { createCacheStore } = require("./proxy-cache");
	const incoming = createCacheStore(srcDir), target = createCacheStore(dstDir);
	for (const file of fs.readdirSync(incoming.entriesDir)) {
		if (!/^[a-f0-9]{64}\.json$/.test(file)) continue;
		const meta = readJson(path.join(incoming.entriesDir, file));
		if (typeof meta?.url !== "string") continue;
		const source = incoming.get(meta.url);
		if (!source || !Number.isFinite(source.fetchedAt)) continue;
		const current = target.get(meta.url);
		if (current && current.fetchedAt >= source.fetchedAt) { stats.kept++; continue; }
		const tmp = path.join(target.entriesDir, ".tmp-import-" + require("node:crypto").randomBytes(8).toString("hex"));
		try {
			fs.copyFileSync(source.bodyPath, tmp);
			const { bodyPath, bodyFile, ...metadata } = source;
			target.commit(meta.url, tmp, metadata);
			stats[current ? "updated" : "added"]++;
		} finally { fs.rmSync(tmp, { force: true }); }
	}
}

function mergeTree(srcDir, dstDir, stats, rel = "") {
	fs.mkdirSync(dstDir, { recursive: true });
	for (const ent of fs.readdirSync(srcDir, { withFileTypes: true })) {
		const relPath = rel ? `${rel}/${ent.name}` : ent.name;
		const s = path.join(srcDir, ent.name), d = path.join(dstDir, ent.name);
		if (NEVER_IMPORT.includes(relPath)) { stats.skipped.push(relPath); continue; }
		if (ent.isDirectory()) {
			if (relPath === "resource-cache") { mergeResourceStore(s, d, stats); continue; }
			if (ATOMIC_DIRS.includes(relPath)) {
				if (!fs.existsSync(d)) { copyTree(s, d); stats.added++; }
				else if (newestMtime(s) > newestMtime(d)) { fs.rmSync(d, { recursive: true, force: true }); copyTree(s, d); stats.updated++; }
				else stats.kept++;
				continue;
			}
			mergeTree(s, d, stats, relPath);
		} else if (ent.isFile()) {
			mergeFile(s, d, relPath, stats);
		}
		// symlinks and specials in a cache archive are not ours to reproduce — skipped
	}
}

/**
 * Node opens the archive and sets cwd: tar never has to parse a Windows drive/UNC
 * path (GNU tar treats ':' in -f as a remote host). '-' works with GNU and BSD tar.
 * Inherited file descriptors also keep large cache archives out of JS memory.
 */
async function runTar(args, archive, cwd, writing, verbose) {
	if (verbose) console.log(`📦 tar ${args.join(" ")} (cwd: ${cwd}, archive: ${archive})`);
	const fd = fs.openSync(archive, writing ? "w" : "r");
	try {
		await new Promise((resolve, reject) => {
			const child = spawn("tar", args, {
				cwd,
				stdio: writing ? ["ignore", fd, "pipe"] : [fd, "ignore", "pipe"],
			});
			let stderr = "";
			child.stderr.setEncoding("utf8");
			child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-64 * 1024); });
			child.on("error", reject);
			child.on("close", (code, signal) => {
				if (code === 0) resolve();
				else reject(new Error(`tar failed (${signal || code}): ${stderr.trim()}`));
			});
		});
	} finally {
		fs.closeSync(fd);
	}
}

async function exportCache(destFile, opts = {}) {
	const { verbose, includeConfig } = opts;
	if (!fs.existsSync(FAD_CACHE_DIR)) throw new Error(`no ~/.vigie-vuln/ directory to export`);
	const abs = path.resolve(destFile);
	fs.mkdirSync(path.dirname(abs), { recursive: true });

	const excludes = includeConfig ? [] : SENSITIVE_FILES.map(f => `${path.basename(FAD_CACHE_DIR)}/${f}`);
	if (excludes.length && verbose) console.log(`   excluding (use --include-config to keep): ${excludes.join(", ")}`);

	const ext = abs.toLowerCase();
	if (ext.endsWith(".tar.gz") || ext.endsWith(".tgz")) {
		const args = ["-czf", "-"];
		for (const e of excludes) args.push(`--exclude=${e}`);
		args.push(path.basename(FAD_CACHE_DIR));
		await runTar(args, abs, path.dirname(FAD_CACHE_DIR), true, verbose);
	} else if (ext.endsWith(".zip")) {
		if (process.platform === "win32") {
			if (verbose) console.log(`📦 Compress-Archive -Path ${FAD_CACHE_DIR}\\* -DestinationPath ${abs}`);
			// Powershell Compress-Archive doesn't have a clean exclude flag — manual copy
			await execFileP("powershell", ["-NoProfile", "-Command",
				`$src='${FAD_CACHE_DIR}'; $dst='${abs}'; ${includeConfig ? `Compress-Archive -Path "$src\\*" -DestinationPath $dst -Force` : `$tmp=Join-Path $env:TEMP "vigievuln-stage-$(Get-Random)"; Copy-Item $src $tmp -Recurse; ${SENSITIVE_FILES.map(f => `Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $tmp '${f}')`).join("; ")}; Compress-Archive -Path "$tmp\\*" -DestinationPath $dst -Force; Remove-Item $tmp -Recurse -Force`}`]);
		} else {
			const args = ["-r", "-q", abs, path.basename(FAD_CACHE_DIR)];
			for (const e of excludes) { args.push("-x"); args.push(e); }
			if (verbose) console.log(`📦 zip ${args.join(" ")}`);
			await execFileP("zip", args, { cwd: path.dirname(FAD_CACHE_DIR), maxBuffer: 1024 * 1024 * 32 });
		}
	} else {
		throw new Error(`unknown archive extension on ${destFile} (expected .tar.gz, .tgz, or .zip)`);
	}

	const size = fs.statSync(abs).size;
	return { path: abs, size, excluded: excludes };
}

/** Unpack an archive into `destParent`, which ends up holding a `.fad-checker/`. */
async function extractTo(abs, destParent, verbose) {
	fs.mkdirSync(destParent, { recursive: true });
	const ext = abs.toLowerCase();
	if (ext.endsWith(".tar.gz") || ext.endsWith(".tgz")) {
		// --no-same-owner: tar restores the archived uid/gid when it runs as root. Real root
		// can chown to anything, so plain Docker is fine; MAPPED root cannot — a rootless
		// container, a userns-remapped daemon, anything under `unshare -r` — and there the
		// chown fails, tar aborts having written NOTHING, and the air-gapped run that
		// follows finds no cache and reports a clean project. Ownership inside the archive
		// is meaningless here (it is the importer's own cache) and the flag is already the
		// default for a non-root user, so this costs nothing on the paths that worked.
		const args = ["-xzf", "-", "--no-same-owner"];
		await runTar(args, abs, destParent, false, verbose);
	} else if (ext.endsWith(".zip")) {
		if (process.platform === "win32") {
			if (verbose) console.log(`📦 Expand-Archive -Path ${abs} -DestinationPath ${destParent}`);
			await execFileP("powershell", ["-NoProfile", "-Command",
				`Expand-Archive -Path '${abs}' -DestinationPath '${destParent}' -Force`]);
		} else {
			if (verbose) console.log(`📦 unzip ${abs} -d ${destParent}`);
			await execFileP("unzip", ["-o", "-q", abs, "-d", destParent], { maxBuffer: 1024 * 1024 * 32 });
		}
	} else {
		throw new Error(`unknown archive extension on ${abs} (expected .tar.gz, .tgz, or .zip)`);
	}
}

/**
 * Restore ~/.fad-checker/ from an archive.
 *
 * Default: MERGE — union with whatever the target already has, so an enclave never
 * loses the cache it warmed itself, nor its config.json.
 *   opts.replace  wholesale swap, previous dir kept as .fad-checker.bak-<ts>
 *   opts.force    wholesale swap with no backup (implies replace)
 */
async function importCache(srcFile, opts = {}) {
	const { verbose, force } = opts;
	const replace = !!(opts.replace || force);
	const abs = path.resolve(srcFile);
	if (!fs.existsSync(abs)) throw new Error(`archive not found: ${abs}`);

	// Merge: unpack beside the cache (same filesystem), reconcile, drop the staging dir.
	fs.mkdirSync(path.dirname(FAD_CACHE_DIR), { recursive: true });
	const staging = fs.mkdtempSync(`${FAD_CACHE_DIR}.import-`);
	const stats = { added: 0, updated: 0, merged: 0, kept: 0, skipped: [] };
	try {
		await extractTo(abs, staging, verbose);
		// Never promote links or special files into a live cache, including in
		// replace mode. A later cache write could otherwise escape the cache root.
		const inspect = dir => {
			for (const entry of fs.readdirSync(dir)) {
				const file = path.join(dir, entry), st = fs.lstatSync(file);
				if (st.isSymbolicLink() || (!st.isDirectory() && (!st.isFile() || st.nlink !== 1)))
					throw new Error("archive contains links or special files");
				if (st.isDirectory()) inspect(file);
			}
		};
		inspect(staging);
		const modern = path.join(staging, path.basename(FAD_CACHE_DIR));
		const legacy = path.join(staging, '.fad-checker');
		// Windows Compress-Archive historically emitted the cache contents at
		// the ZIP root, whereas tar and Unix ZIP preserve the directory name.
		const flatWindowsZip = process.platform === 'win32' && abs.toLowerCase().endsWith('.zip');
		const incoming = fs.existsSync(modern) ? modern : fs.existsSync(legacy) ? legacy : flatWindowsZip ? staging : legacy;
		if (!fs.existsSync(incoming) || !fs.lstatSync(incoming).isDirectory()) {
			throw new Error(`archive holds no .vigie-vuln/ or .fad-checker/ directory — was it built with vigievuln --export-cache?`);
		}
		if (replace) {
			// Configuration contains machine-local credentials and is never
			// accepted from an imported archive, even for a replacement.
			for (const name of NEVER_IMPORT) {
				const src = path.join(FAD_CACHE_DIR, name), dst = path.join(incoming, name);
				fs.rmSync(dst, { force: true });
				if (fs.existsSync(src)) {
					const st = fs.lstatSync(src);
					if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1) throw new Error('unsafe local cache configuration');
					fs.copyFileSync(src, dst, fs.constants.COPYFILE_EXCL);
					try { fs.chmodSync(dst, 0o600); } catch { /* platform does not support chmod */ }
				}
			}
			if (fs.existsSync(FAD_CACHE_DIR) && !force) {
				const backup = `${FAD_CACHE_DIR}.bak-${Date.now()}`;
				fs.renameSync(FAD_CACHE_DIR, backup);
				if (verbose) console.log(`💾 existing ~/.vigie-vuln/ moved to ${backup}`);
			} else if (force && fs.existsSync(FAD_CACHE_DIR)) {
				fs.rmSync(FAD_CACHE_DIR, {recursive:true, force:true});
			}
			fs.renameSync(incoming, FAD_CACHE_DIR);
			return {dir:FAD_CACHE_DIR, mode:'replace'};
		}
		fs.mkdirSync(FAD_CACHE_DIR, { recursive: true });
		mergeTree(incoming, FAD_CACHE_DIR, stats);
	} finally {
		fs.rmSync(staging, { recursive: true, force: true });
	}
	return { dir: FAD_CACHE_DIR, mode: "merge", stats };
}

module.exports = { exportCache, importCache, FAD_CACHE_DIR, mergeResourceStore };
