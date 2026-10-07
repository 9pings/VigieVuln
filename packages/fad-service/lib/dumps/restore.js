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
	const counts = { asset: 0, assetKept: 0, signal: 0, nvd: 0, links: 0, resource: 0, resourceKept: 0 };
	let batch = [];
	const flush = async () => {
		if (!batch.length) return;
		const rows = batch; batch = [];
		const of = type => rows.filter(l => l.t === type);
		await assets.transaction(async t => {
			const assetRows = of("asset").map(l => ({ ...l, aliases: l.aliases ? String(l.aliases).split(" ").filter(Boolean) : [], published: !!l.published }));
			const written = await t.upsertMany(assetRows, { onlyNewer: true });
			counts.asset += written; counts.assetKept += assetRows.length - written;
			counts.signal += of("signal").length; await t.importSignals(of("signal"));
			counts.nvd += of("nvd").length; await t.importNvd(of("nvd"));
			const links = of("links").map(l => ({ advisory: l.advisory, cves: l.cves || [], packages: (l.packages || []).length ? l.packages : null }));
			counts.links += links.length; await t.linkMany(links);
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
		if (batch.length >= BATCH) await flush();
	}
	await flush();
	return { manifest, counts };
}

module.exports = { restoreDump };
