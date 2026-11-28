/**
 * lib/certs/scan.js — walk a source tree for committed crypto material.
 *
 * Reuses the shared prune policy (lib/inventory/path-filter) so the cert scan honours the
 * same --exclude-path / --no-default-excludes rules as every other walker. Each
 * candidate file (sniff.js) is read, hashed (sha256), and handed to analyze.js;
 * the resulting items are returned flat. Pure I/O wrapper — no network, ever.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { isCandidate } = require("./sniff");
const { analyzeBuffer } = require("./analyze");

// Same default-skip set the other file walkers use.
const SKIP = new Set([
	".git", ".idea", ".vscode", "node_modules", "dist", "build", "out",
	"target", "vendor", "testdata", ".svn", ".hg", ".gradle", ".cache",
]);

const MAX_FILE = 8 * 1024 * 1024;   // crypto material is small; skip anything huge

function inspectCertificateFile(file, name, evidencePath, { now = Date.now(), expiryDays = 90, onProgress } = {}) {
	const stat = fs.lstatSync(file);
	if (!stat.isFile() || stat.size === 0 || stat.size > MAX_FILE) return [];
	const buf = fs.readFileSync(file);
	onProgress?.(file);
	const items = analyzeBuffer({name, path:evidencePath, buf, now, expiryDays});
	if (items.length) {
		const sha256 = crypto.createHash("sha256").update(buf).digest("hex");
		for (const item of items) item.sha256 = sha256;
	}
	return items;
}

/**
 * Walk `dir`, return a flat array of cert/key/keystore items (analyze.js shape),
 * each stamped with `sha256` of the file.
 * @param {string} dir
 * @param {{srcRoot?, excludePath?, defaultExcludes?, now?, expiryDays?, onProgress?}} opts
 */
function scanCertificates(dir, opts = {}) {
	if (!dir) return [];
	const { makeDirFilter } = require("../inventory/path-filter");
	const skipDir = makeDirFilter({
		srcRoot: opts.srcRoot || dir, defaultSkip: SKIP,
		excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false,
	});
	const now = opts.now || Date.now();
	const expiryDays = opts.expiryDays != null ? opts.expiryDays : 90;
	const out = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		for (const e of entries) {
			const fp = path.join(cur, e.name);
			if (e.isDirectory()) { if (!skipDir(fp, e.name)) stack.push(fp); continue; }
			if (!e.isFile()) continue;
			if (!isCandidate(e.name)) continue;
			try { out.push(...inspectCertificateFile(fp, e.name, fp, { now, expiryDays, onProgress:opts.onProgress })); } catch { continue; }
		}
	}
	// Worst severity first, then path — matches the report's priority-led ordering.
	const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
	out.sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0) || String(a.path).localeCompare(String(b.path)));
	return out;
}

module.exports = { scanCertificates, inspectCertificateFile, SKIP };
