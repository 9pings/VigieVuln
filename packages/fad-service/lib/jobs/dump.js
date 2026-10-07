/**
 * Daily public dump build (opt-in: dumps.daily). Writes into <dumps.dir>/public, signs it
 * when a signing key is configured, keeps the newest dumps.keep builds.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("node:fs");
const path = require("node:path");
const { buildDump, pruneDumps } = require("../dumps/build");

async function run({ assets, options = {} }) {
	const d = options.dumps || {};
	const dir = path.join(d.dir, "public");
	const m = await buildDump({ db: assets.db, assets, dir, kind: "public", includePackages: !!d.publicIncludesPackages,
		signingKeyPem: d.signingKeyFile ? fs.readFileSync(d.signingKeyFile, "utf8") : null, baseUrl: options.baseUrl || null,
		trackers: d.trackers || [], instance: options.instance || {}, version: options.version || "0", sources: options.sources ? options.sources() : [] });
	const pruned = pruneDumps(dir, d.keep || 7);
	return `${m.id}: ${(m.payload.bytes / 1048576).toFixed(1)} MB, ${m.counts.asset} assets${pruned.length ? `, ${pruned.length} old build(s) removed` : ""}`;
}

module.exports = { run };
