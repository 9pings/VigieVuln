/**
 * lib/codecs/binary/scan.js — walk a source tree for committed NATIVE binaries
 * (.dll/.exe/.so/.dylib) and hash each. Dependency archives (.jar/.war/.ear) are
 * owned by the Maven codec's jar-scan.js, not here.
 *
 * ELF magic is recognized regardless of filename; PE and Mach-O also require
 * an appropriate extension. Other data and spoofed extensions are rejected.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { sniffKind, extKind } = require("./sniff");

// Same skip set the other codecs use; never a place vendored binaries we own live.
const SKIP = new Set([
	".git", ".idea", ".vscode", "node_modules", "dist", "build", "out",
	"target", "vendor", "testdata", ".svn", ".hg", ".gradle", ".cache",
]);

const MAGIC_BYTES = 8;   // enough for every signature we sniff

// Bound both memory and work: large files are explicitly unassessed, never
// silently dropped or loaded into a multi-gigabyte Buffer.
const MAX_FILE_BYTES = 512 * 1024 * 1024;
const HASH_CHUNK_BYTES = 1024 * 1024;

function inspectFile(fp, kind, detectOnly, opts = {}) {
	let fd;
	try {
		fd = fs.openSync(fp, "r");
		const before = fs.fstatSync(fd);
		if (!before.isFile()) throw Error("not a regular file");
		const magic = Buffer.alloc(MAGIC_BYTES);
		const n = fs.readSync(fd, magic, 0, magic.length, 0);
		const actual = sniffKind(magic.subarray(0, n));
		if (!actual || (actual !== "elf" && actual !== kind)) return null;
		kind = actual;
		if (detectOnly) return { kind };
		const limit = opts.maxFileBytes ?? MAX_FILE_BYTES;
		if (before.size > limit) throw Error(`file size ${before.size} exceeds binary scan limit ${limit} bytes`);
		const sha1 = crypto.createHash("sha1"), sha256 = crypto.createHash("sha256");
		const chunk = Buffer.alloc(Math.min(HASH_CHUNK_BYTES, before.size));
		let offset = 0;
		while (offset < before.size) {
			const count = fs.readSync(fd, chunk, 0, Math.min(chunk.length, before.size - offset), offset);
			if (!count) throw Error("file changed or unexpected EOF while hashing");
			sha1.update(chunk.subarray(0, count)); sha256.update(chunk.subarray(0, count));
			offset += count;
		}
		const metadata = require("./metadata").extractMetadata(kind, fd, before.size, opts);
		const after = fs.fstatSync(fd);
		if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs)
			throw Error("file changed during binary scan");
		return { kind, size: offset, sha1: sha1.digest("hex"), sha256: sha256.digest("hex"), metadata };
	} finally { if (fd !== undefined) fs.closeSync(fd); }
}

/** Walk `dir`, return [{ path, kind, size, sha1, sha256, declaredName }]. */
function scanBinaries(dir, opts = {}) {
	const { onProgress, onWarning } = opts;
	const warn = (fp, error) => onWarning?.({ type: "dependency-coverage", reason: "binary-scan-error", ecosystem: "binary", manifestPath: fp,
		message: `binary scan incomplete for ${fp}: ${error.message}` });
	const { makeDirFilter } = require("../../path-filter");
	const skipDir = makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
	const out = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch (error) { warn(cur, error); continue; }
		for (const e of entries) {
			const fp = path.join(cur, e.name);
			if (e.isDirectory()) { if (!skipDir(fp, e.name)) stack.push(fp); continue; }
			if (!e.isFile()) continue;
			const ext = extKind(e.name);
			try {
				const h = inspectFile(fp, ext, opts.detectOnly, opts);
				if (!h) continue;
				if (onProgress) onProgress(fp);
				out.push({ path: fp, ...h, declaredName: e.name });
				if (opts.detectOnly) return out;
			} catch (error) { warn(fp, error); }
		}
	}
	return out;
}

module.exports = { scanBinaries, MAX_FILE_BYTES };
