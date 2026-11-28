/**
 * lib/reports/integrity.js — tamper-evidence for the report deliverable.
 *
 * An audit handed to a client should be verifiable as unaltered. This writes a
 * standard `sha256sum`-format manifest (`<hex>␠␠<relative-path>`) over every artifact
 * produced by a run, verifiable offline with `sha256sum -c SHA256SUMS`. Checksums
 * (not signatures) keep the CLI zero-config; signing the manifest with the auditor's
 * own key is then a trivial external step.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/** SHA-256 of a file's bytes, as lowercase hex. */
function sha256OfFile(filePath) {
	const buf = fs.readFileSync(filePath);
	return crypto.createHash("sha256").update(buf).digest("hex");
}

function relName(file, baseDir) {
	if (!baseDir) return path.basename(file);
	const rel = path.relative(baseDir, file);
	return rel && !rel.startsWith("..") ? rel : path.basename(file);
}

/**
 * Build a sha256sum-format manifest over `files` (existing ones only), sorted by
 * relative name for a deterministic, diffable output.
 */
function buildChecksumManifest(files, { baseDir } = {}) {
	const rows = [];
	for (const f of files || []) {
		if (!f) continue;
		let hex;
		try { hex = sha256OfFile(f); } catch { continue; } // missing/unreadable → skip
		rows.push({ name: relName(f, baseDir), hex });
	}
	rows.sort((a, b) => a.name.localeCompare(b.name));
	return rows.map(r => `${r.hex}  ${r.name}`).join("\n") + (rows.length ? "\n" : "");
}

/** Write the manifest to `manifestPath`; returns the manifest text. */
function writeChecksums(files, manifestPath, { baseDir } = {}) {
	const text = buildChecksumManifest(files, { baseDir: baseDir || path.dirname(manifestPath) });
	fs.writeFileSync(manifestPath, text);
	return text;
}

module.exports = { sha256OfFile, buildChecksumManifest, writeChecksums };
