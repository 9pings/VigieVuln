/**
 * lib/codecs/binary.codec.js — codec for committed NATIVE binaries
 * (.dll/.exe/.so/.dylib) that no package manager governs.
 *
 * Plan 1 scope: discover + hash only. The records carry no resolved coordinate
 * (just a filename); Plan 2's hash-id service fills `identity`, Plan 3 builds the
 * unmanaged inventory + report. Until then the records are `provenance:"binary"`
 * and the CVE/OSV/EOL/outdated stages skip them (no coordinate to query).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { makeDepRecord } = require("../dep-record");
const { scanBinaries } = require("./binary/scan");

module.exports = {
	id: "binary",
	label: "Binaries",
	osvEcosystem: null,                                   // no OSV ecosystem until identified
	manifestNames: ["*.dll", "*.exe", "*.so", "*.dylib"], // lets detectCodecs include us in auto mode

	detect(dir) {
		try { return scanBinaries(dir, { onProgress: null }).length > 0; }
		catch { return false; }
	},

	async collect(dir, opts = {}) {
		const out = new Map();
		const warnings = [];
		let records;
		try { records = scanBinaries(dir, { onProgress: opts.onBinaryProgress, srcRoot: opts.srcRoot || dir, excludePath: opts.excludePath, defaultExcludes: opts.defaultExcludes }); }
		catch (e) { return { deps: out, warnings: [{ type: "scan-error", message: `binary scan failed: ${e.message}` }] }; }
		for (const r of records) {
			const record = makeDepRecord({
				ecosystem: "binary",
				name: r.declaredName,
				version: null,
				manifestPath: r.path,
				provenance: "binary",
				hashes: { sha1: r.sha1, sha256: r.sha256 },
				declaredName: r.declaredName,
			});
			if (r.metadata) record.binaryMetadata = r.metadata;
			out.set(`binary:${r.path}`, record);
		}
		return { deps: out, warnings };
	},

	coordKey(d) { return `binary:${d.manifestPaths?.[0] || d.name}`; },
	formatCoord(d) { return d.declaredName || d.name; },
	osvPackageName() { return null; },
	async checkRegistry() { return { deprecated: [], outdated: [], licensed: [] }; },
	resolveEolProduct() { return null; },
	recipe: require("./recipes").binary,
	nativeScanners: [],
};
