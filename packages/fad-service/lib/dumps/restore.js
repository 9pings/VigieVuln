/**
 * Restore a dump into a fad-service database: merge by key, the fresher record wins, so a
 * delta applies on top of a full build and replaying a build twice changes nothing.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { fad } = require("../fad");

const BATCH = 1000;

/**
 * opts: { assets, store, manifestPath, publicKeyPem } → { manifest, counts }.
 * `store` (the resource store) receives "resource" lines.
 */
async function restoreDump({ assets, store, manifestPath, publicKeyPem = null }) {
	const { openDump, readLines } = fad("dump-format");
	const { manifest, payloadPath } = await openDump(manifestPath, { publicKeyPem });
	const db = assets.db;
	const counts = { asset: 0, assetKept: 0, signal: 0, nvd: 0, links: 0, resource: 0, resourceKept: 0 };
	const sigCols = ["kev", "epss_score", "epss_percentile", "epss_date", "euvd_id", "euvd_exploited_since", "certfr"];
	const putSignal = db.prepare(`INSERT INTO cve_signals (cve, ${sigCols.join(", ")}, updated_at) VALUES (?, ${sigCols.map(() => "?").join(", ")}, ?)
		ON CONFLICT(cve) DO UPDATE SET ${sigCols.map(c => `${c} = excluded.${c}`).join(", ")}, updated_at = excluded.updated_at
		WHERE excluded.updated_at > cve_signals.updated_at`);
	const putNvd = db.prepare(`INSERT INTO cve_nvd (cve, last_modified, data, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(cve) DO UPDATE SET last_modified = excluded.last_modified, data = excluded.data, updated_at = excluded.updated_at
		WHERE COALESCE(excluded.updated_at, 0) >= COALESCE(cve_nvd.updated_at, 0)`);
	let batch = [];
	const flush = () => {
		if (!batch.length) return;
		const rows = batch; batch = [];
		assets.transaction(() => {
			for (const l of rows) {
				if (l.t === "asset") { if (assets.importAsset(l)) counts.asset++; else counts.assetKept++; }
				else if (l.t === "signal") { putSignal.run(l.cve, ...sigCols.map(c => l[c] ?? null), l.updated_at); counts.signal++; }
				else if (l.t === "nvd") { putNvd.run(l.cve, l.lastModified, JSON.stringify(l.data), l.updatedAt || 0); counts.nvd++; }
				else if (l.t === "links") {
					assets.linkAdvisory(l.advisory, l.cves || []);
					if ((l.packages || []).length) assets.linkAdvisoryPackages(l.advisory, l.packages);
					counts.links++;
				}
			}
		});
	};
	for await (const line of readLines(payloadPath)) {
		if (line.t === "resource") {
			if (!store) continue;
			const cur = await store.get(line.key);
			if (cur && cur.fetchedAt >= line.meta.fetchedAt) { counts.resourceKept++; continue; }
			const body = Buffer.from(line.body, "base64");
			await store.put(line.key, body, { ...line.meta, bytes: body.length });
			counts.resource++;
			continue;
		}
		batch.push(line);
		if (batch.length >= BATCH) flush();
	}
	flush();
	return { manifest, counts };
}

module.exports = { restoreDump };
