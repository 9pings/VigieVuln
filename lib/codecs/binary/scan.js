/**
 * lib/codecs/binary/scan.js — walk a source tree for committed NATIVE binaries
 * (.dll/.exe/.so/.dylib) and hash each. Dependency archives (.jar/.war/.ear) are
 * owned by the Maven codec's jar-scan.js, not here.
 *
 * Selection requires BOTH an allowlisted extension AND a confirming magic byte
 * (sniff.js), so images/fonts/assets — even with a spoofed extension — are never
 * hashed or reported.
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

function hashFile(fp, kind) {
	const buf = fs.readFileSync(fp);
	return {
		size: buf.length,
		sha1: crypto.createHash("sha1").update(buf).digest("hex"),
		sha256: crypto.createHash("sha256").update(buf).digest("hex"),
		metadata: kind === "pe" ? require("./pe-metadata").extractPeMetadata(buf) : null,
	};
}

function readMagic(fp) {
	let fd;
	try {
		fd = fs.openSync(fp, "r");
		const buf = Buffer.alloc(MAGIC_BYTES);
		const n = fs.readSync(fd, buf, 0, MAGIC_BYTES, 0);
		return buf.subarray(0, n);
	} catch { return Buffer.alloc(0); }
	finally { if (fd !== undefined) try { fs.closeSync(fd); } catch { /* ignore */ } }
}

/** Walk `dir`, return [{ path, kind, size, sha1, sha256, declaredName }]. */
function scanBinaries(dir, opts = {}) {
	const { onProgress } = opts;
	const { makeDirFilter } = require("../../path-filter");
	const skipDir = makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
	const out = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		for (const e of entries) {
			const fp = path.join(cur, e.name);
			if (e.isDirectory()) { if (!skipDir(fp, e.name)) stack.push(fp); continue; }
			if (!e.isFile()) continue;
			const ext = extKind(e.name);
			if (!ext) continue;                          // not an allowlisted extension
			if (sniffKind(readMagic(fp)) !== ext) continue;  // magic must confirm the extension
			if (onProgress) onProgress(fp);
			const h = hashFile(fp, ext);
			out.push({ path: fp, kind: ext, size: h.size, sha1: h.sha1, sha256: h.sha256, metadata: h.metadata, declaredName: e.name });
		}
	}
	return out;
}

module.exports = { scanBinaries };
