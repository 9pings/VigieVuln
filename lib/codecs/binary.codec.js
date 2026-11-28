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
const { makeDepRecord } = require("../inventory/dep-record");
const { scanBinaries } = require("./binary/scan");

module.exports = {
	id: "binary",
	label: "Binaries",
	osvEcosystem: null,                                   // no OSV ecosystem until identified
	manifestNames: ["*.dll", "*.exe", "*.so", "*.dylib"],
	async detectFile(fp) {
		const fs = require("fs"); let handle;
		try { handle = await fs.promises.open(fp, "r"); const b = Buffer.alloc(4); const { bytesRead } = await handle.read(b, 0, 4, 0); return require("./binary/sniff").sniffKind(b.subarray(0, bytesRead)) === "elf"; } catch { return false; } finally { if (handle) await handle.close(); }
	}, // lets detectCodecs include us in auto mode

	detect(dir) {
		try {
			let incomplete = false;
			return scanBinaries(dir, { detectOnly: true, onWarning: () => { incomplete = true; } }).length > 0 || incomplete;
		}
		catch { return false; }
	},

	async collect(dir, opts = {}) {
		const out = new Map();
		const warnings = [];
		let records;
		try { records = scanBinaries(dir, { ...opts, onProgress: opts.onBinaryProgress, onWarning: warning => warnings.push(warning), srcRoot: opts.srcRoot || dir, excludePath: opts.excludePath, defaultExcludes: opts.defaultExcludes }); }
		catch (e) { return { deps: out, warnings: [{ type: "dependency-coverage", reason: "binary-scan-error", ecosystem: "binary", manifestPath: dir, message: `binary scan failed: ${e.message}` }] }; }
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
			const goVersion = /^go(\d+)\.(\d+)(?:\.(\d+))?$/.exec(r.metadata?.go?.version || "");
			if (goVersion) {
				const version = `v${goVersion[1]}.${goVersion[2]}.${goVersion[3] || "0"}`;
				const dep = makeDepRecord({ ecosystem: "go", name: "stdlib", version, manifestPath: r.path, provenance: "binary-module", scope: "transitive" });
				dep.coordKey = `binary-module:${r.path}:stdlib@${version}`;
				dep.binaryEvidence = { binaryPath: r.path, source: "go-buildinfo", runtimeVersion: r.metadata.go.version, symbolReachability: "unknown" };
				out.set(dep.coordKey, dep);
			}
			for (const module of r.metadata?.go?.modules || []) {
				const selected = module.replace || module;
				if (!selected.path || !/^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/.test(selected.version || "")) continue;
				const dep = makeDepRecord({ ecosystem: "go", name: selected.path, version: selected.version, manifestPath: r.path, provenance: "binary-module", scope: "transitive" });
				dep.coordKey = `binary-module:${r.path}:${selected.path}@${selected.version}`;
				dep.binaryEvidence = { binaryPath: r.path, source: "go-buildinfo", original: module };
				out.set(dep.coordKey, dep);
			}
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
