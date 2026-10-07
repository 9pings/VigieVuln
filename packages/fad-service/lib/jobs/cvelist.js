/**
 * cvelistV5 mirror. CVEProject publishes, in every hourly GitHub release:
 *   - `<day>_all_CVEs_at_midnight.zip.zip`  the whole list at 00:00 UTC (~620 MB, nested zip)
 *   - `<day>_delta_CVEs_at_<HH>00Z.zip`     every record changed since that midnight
 *
 * So: when the baseline day changes (first run, or a missed day), stream the baseline,
 * then apply the current delta; otherwise apply the delta of a new release only. Nothing is
 * written to disk — the zip is decompressed as it downloads (lib/zip-stream.js).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { Readable } = require("node:stream");
const { fad } = require("../fad");
const { parseCveRecord, headlineCvss } = require("../cve-record");
const { forEachJsonInZip } = require("../zip-stream");

const BATCH = 500;

function githubHeaders() {
	const h = { "user-agent": "fad-service", accept: "application/vnd.github+json" };
	if (process.env.FAD_SERVICE_GITHUB_TOKEN) h.authorization = `Bearer ${process.env.FAD_SERVICE_GITHUB_TOKEN}`;
	return h;
}

/** The release's baseline and delta assets → { tag, day, baseline, delta } (urls + names). */
function pickAssets(release) {
	const assets = Array.isArray(release?.assets) ? release.assets : [];
	const baseline = assets.find(a => /_all_CVEs_at_midnight\.zip(\.zip)?$/i.test(a.name));
	const delta = assets.find(a => /_delta_CVEs_at_\d{4}Z\.zip$/i.test(a.name));
	const day = baseline ? baseline.name.slice(0, 10) : null;
	return { tag: release?.tag_name || null, day, baseline, delta };
}

/** The asset written for one CVE record. */
function cveAsset(rec) {
	const { gcveId } = fad("gcve");
	const head = headlineCvss(rec.cvss);
	const title = rec.title || (rec.description ? rec.description.slice(0, 140) : rec.id);
	return {
		type: "cve", key: rec.id, title,
		summary: rec.description ? rec.description.slice(0, 1200) : null,
		aliases: [gcveId(rec.id)].filter(Boolean),
		data: { ...rec, severity: head?.severity || null, score: head?.score ?? null },
		sources: [{ name: "CVE List (CVEProject cvelistV5)", licence: "CVE Program Terms of Use", url: `https://www.cve.org/CVERecord?id=${rec.id}` }],
	};
}

async function importZip({ url, fetcher, assets, log, label }) {
	const res = await fetcher(url, { headers: { "user-agent": "fad-service" }, redirect: "follow" });
	if (!res.ok || !res.body) throw new Error(`${label} HTTP ${res.status}`);
	let pending = [], seen = 0, kept = 0;
	const flush = async () => {
		if (!pending.length) return;
		const rows = pending; pending = [];
		await assets.transaction(t => t.upsertMany(rows.map(cveAsset)));
	};
	await forEachJsonInZip(Readable.fromWeb(res.body), (name, json) => {
		seen++;
		const rec = parseCveRecord(json);
		if (!rec) return;
		kept++;
		pending.push(rec);
		if (log && seen % 50000 === 0) log(`cvelist ${label}: ${seen} records`);
	}, { afterChunk: () => pending.length >= BATCH ? flush() : null });
	await flush();
	return kept;
}

async function run({ assets, fetcher, log, state, setState }) {
	const { getProvider } = fad("providers");
	const releaseUrl = getProvider("github").build("cve-release", {}).url;
	const r = await fetcher(releaseUrl, { headers: githubHeaders() });
	if (!r.ok) throw new Error(`GitHub releases HTTP ${r.status}`);
	const { tag, day, baseline, delta } = pickAssets(await r.json());
	if (!tag || !baseline) throw new Error("no cvelistV5 baseline asset on the latest release");
	if (state.tag === tag) return `up to date (${tag})`;
	const parts = [];
	if (state.day !== day) {
		const n = await importZip({ url: baseline.browser_download_url, fetcher, assets, log, label: "baseline" });
		parts.push(`baseline ${day}: ${n} CVEs`);
		await setState({ ...state, day, tag: null });
	}
	if (delta) {
		const n = await importZip({ url: delta.browser_download_url, fetcher, assets, log, label: "delta" });
		parts.push(`delta ${tag}: ${n} CVEs`);
	}
	await setState({ day, tag });
	return parts.join(" · ");
}

module.exports = { run, pickAssets, cveAsset };
