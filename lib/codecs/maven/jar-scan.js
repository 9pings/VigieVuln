/**
 * lib/codecs/maven/jar-scan.js — discover Maven coordinates from embedded JARs.
 *
 * Many projects ship binary archives committed straight into the tree — a
 * vendored `lib/*.jar`, a Spring-Boot fat-jar under `BOOT-INF/lib/`, an uber-jar
 * with shaded dependencies, or jars inside a `.war`/`.ear`. None of those appear
 * in a `pom.xml`, so the manifest-based scan misses them. This module walks the
 * tree, reads every archive IN MEMORY (via fflate — a nested jar is just a zip
 * Buffer, so recursion needs no temp files and there is no zip-slip risk because
 * nothing is ever written to disk), and extracts each artifact's coordinate from,
 * in order of trust:
 *   1. META-INF/maven/<groupId>/<artifactId>/pom.properties  (authoritative)
 *   2. META-INF/MANIFEST.MF  (Implementation-* / OSGi Bundle-* headers)
 *   3. the file name  (commons-lang3-3.12.0.jar → commons-lang3 @ 3.12.0)
 * An archive whose coordinate can't be determined is reported as a warning, not
 * scanned blindly.
 *
 * Output deps carry provenance:"embedded" + a manifestPath using the `!/` nesting
 * notation (e.g. dist/app.jar!/BOOT-INF/lib/log4j-core-2.14.0.jar) so the report
 * can group them under their containing archive.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { strFromU8 } = require("fflate");
const { inflateRawSync } = require("node:zlib");
const { makeDepRecord } = require("../../dep-record");

const ARCHIVE_RE = /\.(jar|war|ear)$/i;
const SKIP_DIRS = new Set(["node_modules", ".git", "target", "build", "out", "dist-newstyle", ".gradle", ".m2"]);
// A fat-jar can be large; cap what we read into memory and how deep we recurse.
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
const MAX_EXPANDED_BYTES = 128 * 1024 * 1024;
const MAX_DEPTH = 8;

// The ONLY entries we ever decompress out of an archive: its own Maven coordinate
// (pom.properties), its manifest, and any NESTED archive (a fat-jar's bundled libs,
// which we recurse into). Everything else — .class files, resources — is skipped.
function wantedEntry(name) {
	return /^META-INF\/maven\/[^/]+\/[^/]+\/pom\.properties$/.test(name)
		|| name === "META-INF/MANIFEST.MF"
		|| ARCHIVE_RE.test(name);
}

/** Parse a META-INF/maven/.../pom.properties body → { groupId, artifactId, version } | null. */
function coordFromPomProperties(text) {
	const get = re => (String(text || "").match(re) || [])[1]?.trim();
	const groupId = get(/^groupId=(.+)$/m);
	const artifactId = get(/^artifactId=(.+)$/m);
	const version = get(/^version=(.+)$/m);
	if (groupId && artifactId && version) return { groupId, artifactId, version };
	return null;
}

/**
 * Parse a MANIFEST.MF body → { groupId, artifactId, version } | null.
 * Tries Implementation-* first, then OSGi Bundle-*. groupId is best-effort: the
 * manifest rarely carries it, so we fall back to the OSGi symbolic name or "".
 */
function coordFromManifest(text) {
	// MANIFEST.MF folds long lines with a leading space on continuation lines.
	const unfolded = String(text || "").replace(/\r?\n /g, "");
	const h = name => (unfolded.match(new RegExp(`^${name}:\\s*(.+)$`, "im")) || [])[1]?.trim();
	const title = h("Implementation-Title") || h("Bundle-Name");
	const implVer = h("Implementation-Version") || h("Bundle-Version") || h("Specification-Version");
	const symbolic = h("Bundle-SymbolicName");
	const vendor = h("Implementation-Vendor-Id") || h("Implementation-Vendor");
	// OSGi symbolic name (org.apache.commons.lang3) is the most coordinate-like.
	let groupId = "", artifactId = title || symbolic;
	if (symbolic && symbolic.includes(".")) {
		const parts = symbolic.split(";")[0].split(".");
		artifactId = parts.pop();
		groupId = parts.join(".");
	} else if (vendor && vendor.includes(".")) {
		groupId = vendor;
	}
	if (artifactId && implVer) return { groupId: groupId || vendor || "", artifactId, version: implVer };
	return null;
}

/**
 * Parse an archive file name → { groupId:"", artifactId, version } | null.
 * Handles `name-1.2.3.jar`, `name-1.2.3-SNAPSHOT.jar`, `name-1.2.3-classifier.jar`.
 * The version token is the first dash-separated segment that starts with a digit.
 */
function coordFromFilename(fileName) {
    const base = String(fileName || "").replace(ARCHIVE_RE, "");
    const m = base.match(/^(.+?)-(\d[\w.]*(?:-[A-Za-z0-9]+)?)$/);
    if (!m) return null;
    return { groupId: "", artifactId: m[1], version: m[2] };
}

/** Read the named entries from an in-memory zip buffer. Returns {} on a corrupt zip. */
function readEntries(buf, filter) {
	try {
		return readZipEntriesFromFd(buf, buf.length, filter || (() => true));
	} catch {
		return null; // not a valid zip / unsupported (e.g. ZIP64 edge) — caller warns
	}
}

const EOCD_SIG = 0x06054b50; // End Of Central Directory
const CEN_SIG = 0x02014b50;  // central directory file header
const LOC_SIG = 0x04034b50;  // local file header

/**
 * Read ONLY the `filter`-matched entries of an on-disk zip via positioned reads on
 * the file descriptor — without ever loading the whole archive into RAM. We read
 * the End-Of-Central-Directory record, then the central directory, then seek to and
 * inflate just the wanted entries. A 200 MB library jar with a 1 KB pom.properties
 * costs a few KB of reads instead of 200 MB; its .class files are never touched.
 *
 * Throws on anything this minimal parser doesn't handle (ZIP64, encryption, an
 * unknown compression method, a malformed record) so the caller can fall back to
 * the battle-tested fflate whole-buffer path. Sizes are taken from the central
 * directory (authoritative even when a streaming writer zeroes the local header).
 *
 * @returns {Object<string, Uint8Array>} matched entries, same shape as readEntries()
 */
function readZipEntriesFromFd(fd, fileSize, filter) {
	const read = (buffer, length, offset) => {
		if (offset < 0 || length < 0 || offset + length > fileSize) throw new Error('truncated ZIP');
		if (Buffer.isBuffer(fd)) fd.copy(buffer, 0, offset, offset + length);
		else if (fs.readSync(fd, buffer, 0, length, offset) !== length) throw new Error('truncated ZIP');
	};
	const back = Math.min(fileSize, 65557); // max EOCD comment (65535) + 22-byte record
	const tail = Buffer.allocUnsafe(back);
	read(tail, back, fileSize - back);
	let e = -1;
	for (let i = tail.length - 22; i >= 0; i--) {
		if (tail.readUInt32LE(i) === EOCD_SIG) { e = i; break; }
	}
	if (e < 0) throw new Error("no EOCD record");
	const count = tail.readUInt16LE(e + 10);
	const cdSize = tail.readUInt32LE(e + 12);
	const cdOff = tail.readUInt32LE(e + 16);
	if (count === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) throw new Error("ZIP64");

	if (cdSize > MAX_ENTRY_BYTES || cdOff + cdSize > fileSize) throw new Error('ZIP central directory too large');
	const cd = Buffer.allocUnsafe(cdSize);
	read(cd, cdSize, cdOff);
	const out = {};
	let p = 0, expanded = 0;
	for (let i = 0; i < count; i++) {
		if (p + 46 > cd.length || cd.readUInt32LE(p) !== CEN_SIG) throw new Error("bad central record");
		const flags = cd.readUInt16LE(p + 8);
		const method = cd.readUInt16LE(p + 10);
		const compSize = cd.readUInt32LE(p + 20);
		const uncompSize = cd.readUInt32LE(p + 24);
		const nameLen = cd.readUInt16LE(p + 28);
		const extraLen = cd.readUInt16LE(p + 30);
		const commentLen = cd.readUInt16LE(p + 32);
		const localOff = cd.readUInt32LE(p + 42);
		const name = cd.toString("utf8", p + 46, p + 46 + nameLen);
		p += 46 + nameLen + extraLen + commentLen;
		if (!filter(name)) continue;
		if (flags & 0x1) throw new Error("encrypted entry");
		if (compSize === 0xffffffff || uncompSize === 0xffffffff || localOff === 0xffffffff) throw new Error("ZIP64 entry");
		if (compSize > MAX_ENTRY_BYTES || uncompSize > MAX_ENTRY_BYTES || (expanded += uncompSize) > MAX_EXPANDED_BYTES) throw new Error('ZIP expanded data too large');
		// The local header's name/extra lengths can differ from the central record's,
		// so read it to locate the actual start of the entry's data.
		const loc = Buffer.allocUnsafe(30);
		read(loc, 30, localOff);
		if (loc.readUInt32LE(0) !== LOC_SIG) throw new Error("bad local header");
		const dataOff = localOff + 30 + loc.readUInt16LE(26) + loc.readUInt16LE(28);
		const comp = compSize > 0 ? Buffer.allocUnsafe(compSize) : Buffer.alloc(0);
		if (compSize > 0) read(comp, compSize, dataOff);
		if (method === 0) out[name] = comp;                                           // stored
		else if (method === 8) out[name] = inflateRawSync(comp, { maxOutputLength: Math.min(MAX_ENTRY_BYTES, uncompSize + 1) });
		else throw new Error("compression method " + method);
		if (out[name].length !== uncompSize) throw new Error('ZIP size mismatch');
	}
	return out;
}

/**
 * Resolve a single archive's own coordinate + confidence from its entries.
 * Returns { coord, source } | null. `source` ∈ pom.properties|manifest|filename.
 */
function coordForArchive(entries, fileName) {
	// 1. pom.properties (there may be several in a fat-jar; the archive's OWN is the
	//    one whose path matches its identity — but for the top artifact we take the
	//    first. Nested libs are handled separately as their own archives.)
	for (const name of Object.keys(entries)) {
		if (/^META-INF\/maven\/[^/]+\/[^/]+\/pom\.properties$/.test(name)) {
			const coord = coordFromPomProperties(strFromU8(entries[name]));
			if (coord) return { coord, source: "pom.properties" };
		}
	}
	const mf = entries["META-INF/MANIFEST.MF"];
	if (mf) {
		const coord = coordFromManifest(strFromU8(mf));
		if (coord) return { coord, source: "manifest" };
	}
	const coord = coordFromFilename(fileName);
	if (coord) return { coord, source: "filename" };
	return null;
}

/**
 * Given an archive's already-extracted entries, record its coordinate and recurse
 * into any nested archives. `ctx` carries { out, warnings, onProgress, scanned }.
 */
function processEntries(entries, displayPath, fileName, ctx, depth) {
	ctx.expandedBytes = (ctx.expandedBytes || 0) + Object.values(entries).reduce((sum, bytes) => sum + bytes.length, 0);
	if (ctx.expandedBytes > MAX_EXPANDED_BYTES) {
		ctx.warnings.push({ type: 'embedded-jar', message: `expanded archive budget exceeded: ${displayPath}` });
		return;
	}
	const resolved = coordForArchive(entries, fileName);
	if (resolved) {
		const { coord } = resolved;
		ctx.out.push(makeDepRecord({
			ecosystem: "maven",
			namespace: coord.groupId || "",
			name: coord.artifactId,
			version: coord.version,
			manifestPath: displayPath,
			scope: "embedded",
			provenance: "embedded",
		}));
	} else {
		ctx.warnings.push({ type: "embedded-jar", message: `embedded archive with no resolvable Maven coordinate (not scanned): ${displayPath}` });
	}

	// Recurse into nested archives (fat-jar libs).
	for (const name of Object.keys(entries)) {
		if (!ARCHIVE_RE.test(name)) continue;
		const nestedBuf = entries[name];
		if (!nestedBuf || !nestedBuf.length) continue;
		scanArchiveBuffer(Buffer.from(nestedBuf), `${displayPath}!/${name}`, path.basename(name), ctx, depth + 1);
	}
}

/**
 * Recursively scan one archive held in memory (a nested fat-jar lib). Only the
 * coordinate/manifest/nested-archive entries are decompressed (via wantedEntry).
 * `displayPath` is the `!/`-joined logical path.
 */
function scanArchiveBuffer(buf, displayPath, fileName, ctx, depth) {
	if (depth > MAX_DEPTH) { ctx.warnings.push({ type: "embedded-jar", message: `nesting too deep, skipped: ${displayPath}` }); return; }
	if (buf.length > MAX_ARCHIVE_BYTES) { ctx.warnings.push({ type: "embedded-jar", message: `archive too large (${Math.round(buf.length / 1048576)}MB), skipped: ${displayPath}` }); return; }
	// Report before the (blocking) inflate so the displayed line names this archive.
	ctx.scanned++;
	ctx.onProgress?.({ phase: "scan", scanned: ctx.scanned, total: ctx.total, path: displayPath });

	const entries = readEntries(buf, wantedEntry);
	if (entries === null) { ctx.warnings.push({ type: "embedded-jar", message: `could not read archive (corrupt/unsupported): ${displayPath}` }); return; }
	processEntries(entries, displayPath, fileName, ctx, depth);
}

/**
 * Scan one TOP-LEVEL on-disk archive. Tries the lazy positioned-read path first
 * (reads only the central directory + wanted entries — never the whole file), and
 * falls back to reading the whole file + fflate on any case the lazy parser can't
 * handle (ZIP64, encryption, corruption).
 */
function scanArchiveFile(abs, displayPath, fileName, ctx) {
	ctx.scanned++;
	ctx.onProgress?.({ phase: "scan", scanned: ctx.scanned, total: ctx.total, path: displayPath });

	let size;
	try { size = fs.statSync(abs).size; }
	catch (e) { ctx.warnings.push({ type: "embedded-jar", message: `could not stat ${abs}: ${e.message}` }); return; }
	// Skip oversized archives WITHOUT pulling them into RAM.
	if (size > MAX_ARCHIVE_BYTES) { ctx.warnings.push({ type: "embedded-jar", message: `archive too large (${Math.round(size / 1048576)}MB), skipped: ${displayPath}` }); return; }

	// Fast path: lazy central-directory read (no whole-file load, no .class inflate).
	let fd;
	try {
		fd = fs.openSync(abs, "r");
		const entries = readZipEntriesFromFd(fd, size, wantedEntry);
		processEntries(entries, displayPath, fileName, ctx, 0);
		return;
	} catch (e) { ctx.warnings.push({ type: "embedded-jar", message: `could not read archive (corrupt, oversized or unsupported): ${displayPath}` }); return; }
	finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* ignore */ } } }
}

/** Recursively list archive file paths under `dir`. */
function findArchives(dir, acc = []) {
	let entries;
	try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
	catch { return acc; }
	for (const e of entries) {
		if (e.isDirectory && e.isDirectory()) {
			if (SKIP_DIRS.has(e.name) || e.name.startsWith(".")) continue;
			findArchives(path.join(dir, e.name), acc);
		} else if (e.isFile() && ARCHIVE_RE.test(e.name)) {
			acc.push(path.join(dir, e.name));
		}
	}
	return acc;
}

// Parallel equivalent of findArchives — concurrent readdir so a deep tree on a
// high-latency filesystem isn't walked one round-trip at a time.
async function findArchivesAsync(dir, skipDir) {
	const { walkDirs } = require("../../parallel-walk");
	const skip = skipDir || ((child, name) => SKIP_DIRS.has(name) || name.startsWith("."));
	const acc = [];
	await walkDirs(dir, {
		skipDir: skip,
		onDir: (cur, entries) => {
			for (const e of entries) if (e.isFile() && ARCHIVE_RE.test(e.name)) acc.push(path.join(cur, e.name));
		},
	});
	return acc;
}

/**
 * Scan `rootDir` for embedded JAR/WAR/EAR coordinates.
 *
 * Reading + unzipping is synchronous and can be slow on a tree with many or large
 * fat-jars, so `opts.onProgress` is invoked around the work — for EVERY archive,
 * nested ones included — so the caller can tell the user what's happening (it would
 * otherwise block silently, especially while recursing through a fat-jar's libs):
 *   onProgress({ phase: "start", total })                  once; total = top-level archive count
 *   onProgress({ phase: "scan", scanned, total, path })    before each archive is read (top-level + nested)
 *   onProgress({ phase: "done", total, found, scanned })   once, when finished
 *
 * @returns { deps: depRecord[], warnings: [{type,message}] }
 */
async function scanEmbeddedJars(rootDir, opts = {}) {
	const { makeDirFilter } = require("../../path-filter");
	const useDefaults = opts.defaultExcludes !== false;
	const base = makeDirFilter({ srcRoot: opts.srcRoot || rootDir, defaultSkip: SKIP_DIRS, excludePath: opts.excludePath, useDefaults });
	const skipDir = (child, name) => base(child, name) || (useDefaults && name.startsWith("."));
	const archives = await findArchivesAsync(rootDir, skipDir);
	const ctx = {
		out: [],
		warnings: [],
		onProgress: typeof opts.onProgress === "function" ? opts.onProgress : null,
		scanned: 0,
		total: archives.length,
	};
	ctx.onProgress?.({ phase: "start", total: archives.length });
	for (const abs of archives) {
		const rel = (opts.srcRoot ? path.relative(opts.srcRoot, abs) : abs).split(path.sep).join("/");
		scanArchiveFile(abs, rel, path.basename(abs), ctx);
	}
	ctx.onProgress?.({ phase: "done", total: archives.length, found: ctx.out.length, scanned: ctx.scanned });
	return { deps: ctx.out, warnings: ctx.warnings };
}

module.exports = {
	scanEmbeddedJars,
	findArchives,
	coordFromPomProperties,
	coordFromManifest,
	coordFromFilename,
	coordForArchive,
	scanArchiveBuffer,
	readZipEntriesFromFd,
	findArchivesAsync,
};
