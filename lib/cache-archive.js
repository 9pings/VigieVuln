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
const ATOMIC_DIRS = ["cve-data", "gcve-data", ...["maven", "npm", "pypi", "composer", "nuget", "go", "ruby"].map(e => `osv-db/records/${e}`)];

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

// Seed metadata and its records must be validated and compared as a pair. A
// forged file mtime must not replace a newer working snapshot, and a corrupt
// download must never destroy the last usable copy.
function osvSeedInfo(dir, name) {
	try {
		const expected = {maven:'Maven',npm:'npm',pypi:'PyPI',composer:'Packagist',nuget:'NuGet',go:'Go',ruby:'RubyGems'}[name];
		const metaFile = path.join(dir,'meta.json'), records = path.join(dir,'records.jsonl');
		for (const file of [metaFile,records]) { const st=fs.lstatSync(file); if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1) return null; }
		const meta=readJson(metaFile);
		if (!expected || meta?._schema !== 1 || meta.ecosystem !== expected || typeof meta.complete !== 'boolean' || !Number.isSafeInteger(meta._builtAt) || meta._builtAt <= 0 || meta._builtAt > Date.now()+300000 ||
			!Number.isSafeInteger(meta.recordCount) || meta.recordCount < 0 || !/^[a-f0-9]{64}$/.test(meta.sha256)) return null;
		const hash=require('crypto').createHash('sha256'), fd=fs.openSync(records,'r');
		try { const buf=Buffer.allocUnsafe(128*1024); for(let n;(n=fs.readSync(fd,buf,0,buf.length,null))>0;) hash.update(buf.subarray(0,n)); }
		finally { fs.closeSync(fd); }
		return hash.digest('hex') === meta.sha256 ? meta : null;
	} catch { return null; }
}

function mergeOsvSeed(src, dst, rel, stats) {
	const incoming=osvSeedInfo(src,path.basename(rel)), current=osvSeedInfo(dst,path.basename(rel));
	if (!incoming) { stats.skipped.push(rel + ': invalid OSV seed'); return; }
	if (current?.complete && !incoming.complete) { stats.skipped.push(rel + ': incomplete OSV seed'); return; }
	if (current && current._builtAt >= incoming._builtAt) { stats.kept++; return; }
	const suffix=require('crypto').randomBytes(8).toString('hex');
	const staged=`${dst}.stage-${suffix}`, backup=`${dst}.backup-${suffix}`;
	let moved=false;
	try {
		copyTree(src,staged);
		if (!osvSeedInfo(staged,path.basename(rel))) throw new Error('OSV seed changed during import');
		if (fs.existsSync(dst)) { fs.renameSync(dst,backup); moved=true; }
		try { fs.renameSync(staged,dst); } catch (error) { if(moved)fs.renameSync(backup,dst); moved=false; throw error; }
		if (moved) fs.rmSync(backup,{recursive:true,force:true});
		stats[current ? 'updated' : 'added']++;
	} finally { fs.rmSync(staged,{recursive:true,force:true}); }
}

function gcveSeedInfo(dir) {
	try {
		const file=path.join(dir,'index.json'), st=fs.lstatSync(file);
		if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1) return null;
		const index=require('./gcve-index').readGcveIndex(file);
		const at=Date.parse(index._fadSnapshot?.collectedAt);
		if (!index.directory?.verified || !Number.isFinite(at) || at <= 0 || at > Date.now()+300000) return null;
		return {at,complete:index.coverage.every(c=>c.complete === true)};
	} catch { return null; }
}

function mergeGcveSeed(src,dst,stats) {
	const incoming=gcveSeedInfo(src),current=gcveSeedInfo(dst);
	if (!incoming) {stats.skipped.push('gcve-data: invalid index');return;}
	if (current && (current.at >= incoming.at || (current.complete && !incoming.complete))) {stats.kept++;return;}
	const suffix=require('crypto').randomBytes(8).toString('hex'), staged=`${dst}.stage-${suffix}`,backup=`${dst}.backup-${suffix}`;
	let moved=false;
	try {
		copyTree(src,staged);
		if (!gcveSeedInfo(staged)) throw Error('GCVE seed changed during import');
		if (fs.existsSync(dst)) {fs.renameSync(dst,backup);moved=true;}
		try {fs.renameSync(staged,dst);} catch (error) {if(moved)fs.renameSync(backup,dst);moved=false;throw error;}
		if(moved)fs.rmSync(backup,{recursive:true,force:true});
		stats[current?'updated':'added']++;
	} finally {fs.rmSync(staged,{recursive:true,force:true});}
}

function mergeFile(srcFile, dstFile, rel, stats) {
	if (!fs.existsSync(dstFile)) { copyPreservingTime(srcFile, dstFile); stats.added++; return; }
	const srcJson = readJson(srcFile), dstJson = readJson(dstFile);
	if (isEntryMap(srcJson) && isEntryMap(dstJson)) {
		// Legacy Maven false values do not prove absence and must never override a
		// confirmed hit, even if their containing cache file is more recent.
		if (rel === "maven-exists-cache.json") {
			const { discardUnverifiedEntries } = require("./maven-presence");
			discardUnverifiedEntries(srcJson);
			discardUnverifiedEntries(dstJson);
		}
		mergeEntryMaps(srcFile, dstFile, srcJson, dstJson);
		stats.merged++;
		return;
	}
	if (stampOf(srcFile, srcJson) > stampOf(dstFile, dstJson)) { copyPreservingTime(srcFile, dstFile); stats.updated++; }
	else stats.kept++;
}

// Compact generations are immutable and identified by their manifest hash.
// Never merge individual shards by mtime: a newer local shard may be corrupt.
function mergeNvdBulk(src, dst, stats) {
	const {validateGeneration}=require('./nvd-bulk');
	fs.mkdirSync(dst,{recursive:true});
	for (const name of fs.readdirSync(src)) {
		const source=path.join(src,name), target=path.join(dst,name);
		if (fs.existsSync(target)) {
			try {validateGeneration(target);stats.kept++;continue;} catch { /* preserve and repair below */ }
		}
		const parent=path.dirname(dst), stage=fs.mkdtempSync(path.join(parent,'.nvd-stage-'));
		const staged=path.join(stage,name), backup=fs.mkdtempSync(path.join(parent,'.nvd-backup-'));
		const saved=path.join(backup,name); let moved=false;
		try {
			copyTree(source,staged);validateGeneration(staged);
			if (fs.existsSync(target)) {fs.renameSync(target,saved);moved=true;}
			try {fs.renameSync(staged,target);} catch (error) {if(moved)fs.renameSync(saved,target);moved=false;throw error;}
			stats[moved?'updated':'added']++;
		} finally {
			fs.rmSync(stage,{recursive:true,force:true});
			if (!moved) fs.rmSync(backup,{recursive:true,force:true});
		}
	}
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

// 1.1.3 used a Maven-only per-package projection with no schema field. Keep
// it in its own namespace: it contains neither complete native records nor
// withdrawal evidence. Do not convert the unpublished schema-2 indexes.
function readLegacyMavenIndex(file) {
 const index = readJson(file);
 if (!index || index._schema != null || index.ecosystem !== 'Maven' ||
     !Number.isSafeInteger(index._builtAt) || index._builtAt <= 0 || index._builtAt > Date.now() + 300000 ||
     !index.byPackage || typeof index.byPackage !== 'object' || Array.isArray(index.byPackage)) return null;
 const records = new Map(), invalid = new Set();
 for (const [name, entries] of Object.entries(index.byPackage)) {
  if (!Array.isArray(entries)) throw new Error('invalid legacy Maven OSV index');
  for (const document of entries) {
   if (!document || typeof document.id !== 'string' || !Array.isArray(document.affected)) throw new Error('invalid legacy Maven OSV advisory');
   if (document.affected.some(a=>a?.package?.ecosystem !== 'Maven' || String(a?.package?.name || '').toLowerCase() !== name.toLowerCase())) throw new Error('invalid legacy Maven OSV package');
   const {affected, ...rest}=document, previous=records.get(document.id), signature=JSON.stringify(rest);
   if (previous && previous.signature !== signature) {invalid.add(document.id);continue;}
   if (!previous) records.set(document.id,{signature,document:{...rest,affected:[...affected]}});
   else previous.document.affected.push(...affected);
  }
 }
 for (const id of invalid) records.delete(id);
 return {builtAt:index._builtAt, documents:[...records.values()].map(r=>r.document), conflicting:invalid.size};
}

async function importLegacyMavenIndex(cacheDir, file = path.join(cacheDir,'osv-db','maven-index.json')) {
 const legacy = readLegacyMavenIndex(file);
 if (!legacy) throw new Error('unrecognized or experimental Maven OSV index');
 const store = require('./advisory-store').openAdvisoryStore({cacheDir});
 await store.importRecords(legacy.documents, {source:'osv-legacy-maven', fetchedAt:legacy.builtAt, provenance:{transport:'legacy',format:'vigievuln-1.1.3'}, coverages:[{source:'osv-legacy-maven',ecosystem:'Maven',fetchedAt:legacy.builtAt,complete:false,provenance:{transport:'legacy'}}]});
 return {count:legacy.documents.length,conflicting:legacy.conflicting};
}

// Validate and stream a complete native OSV seed. importRecords stages the entire
// iterable and verifies each record before publishing it to the journal.
function readNativeSeed(dir) {
 const meta = readJson(path.join(dir, 'meta.json'));
 const validEcos = new Set(['Maven','npm','PyPI','Packagist','NuGet','Go','RubyGems']);
 if (!meta || meta._schema !== 1 || meta.source !== 'osv' || meta.complete !== true ||
     !Number.isSafeInteger(meta._builtAt) || meta._builtAt <= 0 || meta._builtAt > Date.now() + 300000 ||
     !Number.isSafeInteger(meta.recordCount) || meta.recordCount < 0 || !/^[a-f0-9]{64}$/.test(meta.sha256) ||
     !Array.isArray(meta.ecosystems) || !meta.ecosystems.length || meta.ecosystems.some(e => !validEcos.has(e)) || new Set(meta.ecosystems).size !== meta.ecosystems.length)
  throw new Error('invalid native OSV seed metadata');
 const file = path.join(dir, 'osv.jsonl');
 if (!fs.statSync(file).isFile()) throw new Error('missing native OSV seed records');
 return {meta, file};
}
async function* nativeSeedRecords({meta,file}, onProgress) {
 const hash = require('node:crypto').createHash('sha256');
 const stream = fs.createReadStream(file); stream.on('data', chunk => hash.update(chunk));
 const lines = require('./line-stream').readTextLines(stream);
 let count = 0;
 try {
  for await (const line of lines) {
   if (!line || Buffer.byteLength(line) > 16 * 1024 * 1024) throw new Error('invalid or oversized native OSV seed record');
   const document = JSON.parse(line);
   if (!document || typeof document.id !== 'string' || (!Array.isArray(document.affected) && !(document.withdrawn && document.affected == null))) throw new Error('invalid native OSV seed record');
   count++; if (count % 1000 === 0) onProgress?.({phase:'index-osv',count,total:meta.recordCount}); yield document;
  }
 } finally { stream.destroy(); }
 if (count !== meta.recordCount || hash.digest('hex') !== meta.sha256) throw new Error('native OSV seed checksum or count mismatch');
 onProgress?.({phase:'index-build',count});
}

function readCveSeed(dir) {
 const meta=readJson(path.join(dir,'cveproject-meta.json'));
 if (!meta || meta._schema!==1 || meta.source!=='cveproject' || meta.complete!==false ||
     !Number.isSafeInteger(meta._builtAt) || meta._builtAt<=0 || meta._builtAt>Date.now()+300000 ||
     !Number.isSafeInteger(meta.recordCount) || meta.recordCount<0 || !/^[a-f0-9]{64}$/.test(meta.sha256)) throw new Error('invalid CVEProject seed metadata');
 const file=path.join(dir,'cveproject.jsonl');if(!fs.statSync(file).isFile())throw new Error('missing CVEProject seed records');
 return {meta,file};
}
async function* cveSeedEnvelopes({meta,file}, onProgress) {
 const hash=require('node:crypto').createHash('sha256'), stream=fs.createReadStream(file);
 stream.on('data',chunk=>hash.update(chunk));
 const lines=require('./line-stream').readTextLines(stream);let count=0;
 try {for await (const line of lines) {
  if(!line || Buffer.byteLength(line)>16*1024*1024)throw new Error('invalid or oversized CVEProject seed record');
  count++;if(count % 1000 === 0)onProgress?.({phase:'index-cve',count,total:meta.recordCount});yield require('./native-advisories').cveEnvelope(JSON.parse(line),{fetchedAt:meta._builtAt,provenance:{transport:'seed'}});
 }} finally {stream.destroy();}
 if(count!==meta.recordCount || hash.digest('hex')!==meta.sha256)throw new Error('CVEProject seed checksum or count mismatch');
 onProgress?.({phase:'index-build',count});
}

function mergeTree(srcDir, dstDir, stats, rel = "") {
	fs.mkdirSync(dstDir, { recursive: true });
	for (const ent of fs.readdirSync(srcDir, { withFileTypes: true })) {
		const relPath = rel ? `${rel}/${ent.name}` : ent.name;
		const s = path.join(srcDir, ent.name), d = path.join(dstDir, ent.name);
		if (NEVER_IMPORT.includes(relPath)) { stats.skipped.push(relPath); continue; }
		if (ent.isDirectory()) {
			if (relPath === "advisory-store") continue; // journal is merged separately; indexes are derived
			if (relPath === "resource-cache") { mergeResourceStore(s, d, stats); continue; }
			if (relPath === "nvd-cache/_bulk") { mergeNvdBulk(s,d,stats); continue; }
			if (relPath === "gcve-data") { mergeGcveSeed(s,d,stats); continue; }
			if (relPath === "osv-db/records") { stats.skipped.push("osv-db/records: obsolete partitioned OSV seed cannot be imported; obtain a current bundle"); continue; }
			if (ATOMIC_DIRS.includes(relPath)) {
				if (!fs.existsSync(d)) { copyTree(s, d); stats.added++; }
				else if (newestMtime(s) > newestMtime(d)) { fs.rmSync(d, { recursive: true, force: true }); copyTree(s, d); stats.updated++; }
				else stats.kept++;
				continue;
			}
			mergeTree(s, d, stats, relPath);
		} else if (ent.isFile()) {
			if (/^package-versions\/[a-f0-9]{2}$/.test(rel)) {
				const incoming=require('./package-versions').readRecord(s);
				if (!incoming) { stats.skipped.push(relPath + ': invalid package observation'); continue; }
				// Its name includes the body hash: a conflict becomes another file,
				// not a replacement. Preserve valid existing observations on collision.
				if (fs.existsSync(d) && require('./package-versions').readRecord(d)) {stats.kept++;continue;}
				copyPreservingTime(s,d);stats.added++;continue;
			}
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
	const sourceDir = opts.sourceDir || FAD_CACHE_DIR;
	const origin = opts.proxyOrigin ? require("./proxy-scope").proxyOrigin(opts.proxyOrigin) : null;
	if (!fs.existsSync(sourceDir)) throw new Error(`no ~/.vigie-vuln/ directory to export`);
	const abs = path.resolve(destFile);
	fs.mkdirSync(path.dirname(abs), { recursive: true });

	const excludes = includeConfig ? [] : SENSITIVE_FILES.map(f => `${path.basename(sourceDir)}/${f}`);
	if (excludes.length && verbose) console.log(`   excluding (use --include-config to keep): ${excludes.join(", ")}`);

	const ext = abs.toLowerCase();
	const markerDir = origin ? fs.mkdtempSync(path.join(os.tmpdir(), "vigievuln-archive-")) : null;
	const markerName = ".vigievuln-archive-origin.json";
	if (markerDir) fs.writeFileSync(path.join(markerDir, markerName), JSON.stringify({ version: 1, origin }), { mode: 0o600 });
	try {
	if (ext.endsWith(".tar.gz") || ext.endsWith(".tgz")) {
		const args = ["-czf", "-"];
		for (const e of excludes) args.push(`--exclude=${e}`);
		args.push(path.basename(sourceDir));
		if (markerDir) args.push("-C", markerDir, markerName);
		await runTar(args, abs, path.dirname(sourceDir), true, verbose);
	} else if (ext.endsWith(".zip")) {
		if (process.platform === "win32") {
			if (origin) throw new Error("Proxy-scoped ZIP export is unavailable on Windows; use tar.gz.");
			if (verbose) console.log(`📦 Compress-Archive -Path ${sourceDir}\\* -DestinationPath ${abs}`);
			// Powershell Compress-Archive doesn't have a clean exclude flag — manual copy
			await execFileP("powershell", ["-NoProfile", "-Command",
				`$src='${sourceDir}'; $dst='${abs}'; ${includeConfig ? `Compress-Archive -Path "$src\\*" -DestinationPath $dst -Force` : `$tmp=Join-Path $env:TEMP "vigievuln-stage-$(Get-Random)"; Copy-Item $src $tmp -Recurse; ${SENSITIVE_FILES.map(f => `Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $tmp '${f}')`).join("; ")}; Compress-Archive -Path "$tmp\\*" -DestinationPath $dst -Force; Remove-Item $tmp -Recurse -Force`}`]);
		} else {
			const args = ["-r", "-q", abs, path.basename(sourceDir)];
			for (const e of excludes) { args.push("-x"); args.push(e); }
			if (verbose) console.log(`📦 zip ${args.join(" ")}`);
			await execFileP("zip", args, { cwd: path.dirname(sourceDir), maxBuffer: 1024 * 1024 * 32 });
			if (markerDir) await execFileP("zip", ["-q", abs, markerName], { cwd: markerDir });
		}
	} else {
		throw new Error(`unknown archive extension on ${destFile} (expected .tar.gz, .tgz, or .zip)`);
	}

	} finally { if (markerDir) fs.rmSync(markerDir, { recursive: true, force: true }); }
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

// Inspect only tar member names and, when necessary, the legacy Maven index.
// A server seed containing hundreds of thousands of old NVD files must not be
// expanded merely to discover its OSV partition is unusable. On ambiguity we
// fall back to the normal validated import, preserving published 1.1.x caches.
async function preflightSetupSeed(abs, onProgress) {
	if (!/\.(?:tar\.gz|tgz)$/i.test(abs)) return;
	const found={old:false,native:false,journal:false,details:false,index:null};
	const fd=fs.openSync(abs,'r');
	try {
		await new Promise((resolve,reject)=>{
			const child=spawn('tar',['-tzf','-'],{stdio:[fd,'pipe','pipe']});
			let stderr='', count=0;
			child.stderr.setEncoding('utf8');child.stderr.on('data',chunk=>{stderr=(stderr+chunk).slice(-4096)});
			const lines=require('node:readline').createInterface({input:child.stdout,crlfDelay:Infinity});
			lines.on('line',name=>{
				count++; if(count % 10000===0)onProgress?.({phase:'validating',count});
				const clean=name.replace(/^\.\//,'');
				if (!/^(?:\.vigie-vuln|\.fad-checker)\//.test(clean)) return;
				const rel=clean.slice(clean.indexOf('/')+1);
				if (rel.startsWith('osv-db/records/')) found.old=true;
				if (rel==='advisory-store/seed/osv.jsonl') found.native=true;
				if (rel==='advisory-store/events.jsonl') found.journal=true;
				if (/^osv-cache\/vuln_.+\.json$/.test(rel)) found.details=true;
				if (rel==='osv-db/maven-index.json') found.index=name;
			});
			child.on('error',reject);child.on('close',(code,signal)=>code===0?resolve():reject(new Error(`tar inspection failed (${signal || code}): ${stderr.trim()}`)));
		});
	} finally {fs.closeSync(fd);}
	if ((!found.old && !found.index) || found.native || found.journal || found.details) return;
	let oldIndex = !found.index;
	if (found.index) {
		const source=fs.openSync(abs,'r');
		try {
			const output=await new Promise((resolve,reject)=>{
				const child=spawn('tar',['-xOzf','-',found.index],{stdio:[source,'pipe','pipe']});
				const chunks=[];let size=0, tooLarge=false;
				child.stdout.on('data',chunk=>{size+=chunk.length;if(size>64*1024*1024){tooLarge=true;child.kill();}else chunks.push(chunk)});
				child.stderr.resume();child.on('error',reject);child.on('close',code=>resolve(!tooLarge && code===0?Buffer.concat(chunks).toString('utf8'):null));
			});
			if (output !== null) { try { oldIndex=JSON.parse(output)?._schema === 2; } catch { /* preserve ambiguous archives */ } }
		} finally {fs.closeSync(source);}
	}
	if (oldIndex) throw new Error('This server bundle uses an obsolete OSV seed format and contains no usable OSV advisories. Update the server and regenerate its bundle; setup was not saved.');
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
	const targetDir = opts.targetDir || FAD_CACHE_DIR;
	const replace = !!(opts.replace || force);
	const abs = path.resolve(srcFile);
	if (!fs.existsSync(abs)) throw new Error(`archive not found: ${abs}`);
	if (opts.requireUsableSeed) { opts.onProgress?.({phase:'validating'}); await preflightSetupSeed(abs,opts.onProgress); }

	// Merge: unpack beside the cache (same filesystem), reconcile, drop the staging dir.
	fs.mkdirSync(path.dirname(targetDir), { recursive: true });
	const staging = fs.mkdtempSync(`${targetDir}.import-`);
	const stats = { added: 0, updated: 0, merged: 0, kept: 0, skipped: [] };
	try {
		opts.onProgress?.({phase:'extracting'});
		await extractTo(abs, staging, verbose);
		opts.onProgress?.({phase:'validating'});
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
		if (opts.proxyOrigin) {
			const origin = require("./proxy-scope").proxyOrigin(opts.proxyOrigin);
			const marker = readJson(path.join(staging, ".vigievuln-archive-origin.json"));
			if (!marker || marker.version !== 1 || marker.origin !== origin) throw new Error("Archive proxy origin missing or does not match the active proxy scope.");
		}
		const modern = path.join(staging, '.vigie-vuln');
		const legacyDir = path.join(staging, '.fad-checker');
		// Windows Compress-Archive historically emitted the cache contents at
		// the ZIP root, whereas tar and Unix ZIP preserve the directory name.
		const flatWindowsZip = process.platform === 'win32' && abs.toLowerCase().endsWith('.zip');
		const incoming = fs.existsSync(modern) ? modern : fs.existsSync(legacyDir) ? legacyDir : flatWindowsZip ? staging : legacyDir;
		if (!fs.existsSync(incoming) || !fs.lstatSync(incoming).isDirectory()) {
			throw new Error(`archive holds no .vigie-vuln/ or .fad-checker/ directory — was it built with vigievuln --export-cache?`);
		}
		// A corrupt compact NVD generation must not be merged beside valid local
		// observations or cause any other part of this archive to be committed.
		if (fs.existsSync(path.join(incoming,'nvd-cache','_bulk')))
			require('./nvd-bulk').validateAll(path.join(incoming,'nvd-cache'));
		const storeDir = path.join(incoming, 'advisory-store');
		const journal = path.join(storeDir, 'events.jsonl');
		const seedDir = path.join(storeDir, 'seed');
		const hasJournal = fs.existsSync(journal), hasSeedDir = fs.existsSync(seedDir);
		const hasSeed = hasSeedDir && (fs.existsSync(path.join(seedDir,'meta.json')) || fs.existsSync(path.join(seedDir,'osv.jsonl')));
		const hasCveSeed = hasSeedDir && (fs.existsSync(path.join(seedDir,'cveproject-meta.json')) || fs.existsSync(path.join(seedDir,'cveproject.jsonl')));
		if (fs.existsSync(storeDir) && !hasJournal && !hasSeed && !hasCveSeed) throw new Error('archive advisory store has no journal or native seed');
		let usableJournalOsv = false;
		if (hasJournal) for (const item of require('./advisory-store').journalTransactions(journal)) {
			if (item.transaction.records.some(r => r.source === 'osv' && !r.document.withdrawn && r.document.affected?.some(a => a.package?.ecosystem && a.package?.name))) usableJournalOsv = true;
		}
		const seed = hasSeed ? readNativeSeed(seedDir) : null;
		const cveSeed = hasCveSeed ? readCveSeed(seedDir) : null;
		const gcveDir = path.join(incoming,'gcve-data');
		const gcve = fs.existsSync(gcveDir) && gcveSeedInfo(gcveDir) ? require('./gcve-index').readGcveIndex(path.join(gcveDir,'index.json')) : null;
		const legacyFile = path.join(incoming,'osv-db','maven-index.json');
		let legacy = null;
		if (fs.existsSync(legacyFile)) {
			try { legacy = readLegacyMavenIndex(legacyFile); } catch { /* warn below */ }
			if (!legacy && !seed) stats.skipped.push('osv-db/maven-index.json: unrecognized or experimental index; no legacy advisories imported');
			else if (legacy) stats.skipped.push(`Maven OSV legacy index is partial and cannot verify withdrawn advisories${legacy.conflicting ? `; ${legacy.conflicting} conflicting advisory IDs skipped` : ''}`);
		}
		// An unpublished, partitioned 1.2 seed cannot be interpreted by the
		// native store. Fail setup before modifying the destination if the bundle
		// otherwise contains no usable OSV advisories. Ordinary cache imports still
		// salvage their compatible entries and report the skipped old partition.
		const obsoleteOsv = opts.requireUsableSeed && (fs.existsSync(path.join(incoming,'osv-db','records')) || readJson(legacyFile)?._schema === 2);
		if (opts.requireUsableSeed && obsoleteOsv &&
		    !(seed?.meta.recordCount > 0) && !usableJournalOsv && !(legacy?.documents?.length > 0)) {
			let usableDetails = false;
			const dir = path.join(incoming,'osv-cache');
			if (fs.existsSync(dir)) for (const name of fs.readdirSync(dir)) {
				if (!/^vuln_.+\.json$/.test(name)) continue;
				try {
					const file=path.join(dir,name), st=fs.lstatSync(file);
					if (!st.isFile() || st.isSymbolicLink() || st.size>16*1024*1024) continue;
					const cached=JSON.parse(fs.readFileSync(file,'utf8'));
					require('./advisory-store').validateRecord({source:'osv',document:cached.body,fetchedAt:cached._fetchedAt});
					if (!cached.body.withdrawn && cached.body.affected?.some(a=>a.package?.ecosystem && a.package?.name)) { usableDetails=true; break; }
				} catch { /* malformed historical entry */ }
			}
			if (!usableDetails) throw new Error('This server bundle uses an obsolete OSV seed format and contains no usable OSV advisories. Update the server and regenerate its bundle; setup was not saved.');
		}

		// Validate seed completely in a temporary store before any target mutation.
		const prepared = path.join(staging, 'prepared-store');
		if (hasSeed || hasCveSeed || legacy || gcve || (replace && hasJournal)) {
			const store = require('./advisory-store').openAdvisoryStore({cacheDir:prepared});
			if (seed) { opts.onProgress?.({phase:'index-osv',count:0,total:seed.meta.recordCount}); await store.importRecords(nativeSeedRecords(seed,opts.onProgress), {source:'osv', fetchedAt:seed.meta._builtAt, provenance:{transport:'seed'}, coverages:seed.meta.ecosystems.map(ecosystem => ({source:'osv', ecosystem, fetchedAt:seed.meta._builtAt, complete:true, provenance:{transport:'seed'}, sha256:seed.meta.sha256, recordCount:seed.meta.recordCount}))}); }
			if (cveSeed) { opts.onProgress?.({phase:'index-cve',count:0,total:cveSeed.meta.recordCount}); await store.importEnvelopes(cveSeedEnvelopes(cveSeed,opts.onProgress),{coverages:[{source:'cveproject',ecosystem:'*',fetchedAt:cveSeed.meta._builtAt,complete:false,provenance:{transport:'seed'}}]}); }
			if (legacy) await importLegacyMavenIndex(prepared, legacyFile);
			if (gcve) { opts.onProgress?.({phase:'index-gcve'}); await require('./native-advisories').importGcveIndex(store,gcve,{provenance:{transport:'seed'}}); }
			if (hasJournal) store.mergeJournal(journal);
			if (!fs.existsSync(store.journal)) fs.writeFileSync(store.journal, '', {mode:0o600});
		}
		if (replace) {
			if (fs.existsSync(path.join(incoming, 'osv-db', 'records'))) {
				stats.skipped.push('osv-db/records: obsolete partitioned OSV seed cannot be imported; obtain a current bundle');
				fs.rmSync(path.join(incoming, 'osv-db', 'records'), {recursive:true,force:true});
			}
			fs.rmSync(storeDir, {recursive:true, force:true});
			if (hasSeed || hasCveSeed || hasJournal || legacy || gcve) fs.renameSync(path.join(prepared, 'advisory-store'), storeDir);
		}
		const containsLegacyOsv = fs.existsSync(path.join(incoming,'osv-cache'));
		if (replace) {
			// Configuration contains machine-local credentials and is never
			// accepted from an imported archive, even for a replacement.
			for (const name of NEVER_IMPORT) {
				const src = path.join(targetDir, name), dst = path.join(incoming, name);
				fs.rmSync(dst, { force: true });
				if (fs.existsSync(src)) {
					const st = fs.lstatSync(src);
					if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1) throw new Error('unsafe local cache configuration');
					fs.copyFileSync(src, dst, fs.constants.COPYFILE_EXCL);
					try { fs.chmodSync(dst, 0o600); } catch { /* platform does not support chmod */ }
				}
			}
			if (fs.existsSync(targetDir) && !force) {
				const backup = `${targetDir}.bak-${Date.now()}`;
				fs.renameSync(targetDir, backup);
				if (verbose) console.log(`💾 existing ~/.vigie-vuln/ moved to ${backup}`);
			} else if (force && fs.existsSync(targetDir)) {
				fs.rmSync(targetDir, {recursive:true, force:true});
			}
			fs.renameSync(incoming, targetDir);
			if (containsLegacyOsv) require('./osv-legacy').importLegacyOsvDetails(require('./advisory-store').openAdvisoryStore({cacheDir:targetDir}),{cacheDir:targetDir,force:true});
			return {dir:targetDir, mode:'replace', stats};
		}
		fs.mkdirSync(targetDir, { recursive: true });
		opts.onProgress?.({phase:'merging'});
		if (hasSeed || hasCveSeed || hasJournal || legacy || gcve) {
			const store = require('./advisory-store').openAdvisoryStore({cacheDir:targetDir});
			if (hasSeed || hasCveSeed || legacy || gcve) store.mergeJournal(path.join(prepared,'advisory-store','events.jsonl'));
			else store.mergeJournal(journal);
			stats.merged++;
		}
		mergeTree(incoming, targetDir, stats);
		if (containsLegacyOsv) require('./osv-legacy').importLegacyOsvDetails(require('./advisory-store').openAdvisoryStore({cacheDir:targetDir}),{cacheDir:targetDir,force:true});
	} finally {
		fs.rmSync(staging, { recursive: true, force: true });
	}
	return { dir: targetDir, mode: "merge", stats };
}

module.exports = { exportCache, importCache, FAD_CACHE_DIR, mergeResourceStore, readLegacyMavenIndex, importLegacyMavenIndex };
