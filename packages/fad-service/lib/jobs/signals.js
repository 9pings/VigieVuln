/**
 * Per-CVE signals mirrored in bulk: CISA KEV, EPSS, ENISA EUVD. Each job writes only its
 * own columns of `cve_signals`, so they refresh independently of the CVE records.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const zlib = require("node:zlib");
const { fad } = require("../fad");

const UA = { "user-agent": "fad-service" };

async function kev({ assets, fetcher }) {
	const url = fad("providers").getProvider("kev").build("catalog").url;
	const r = await fetcher(url, { headers: UA });
	if (!r.ok) throw new Error(`KEV HTTP ${r.status}`);
	const { byId } = fad("kev").indexKevCatalog(await r.json());
	const rows = Object.entries(byId);
	if (!rows.length) throw new Error("empty KEV catalogue — refusing to clear it");
	assets.setSignal("kev", rows);
	return `${rows.length} known-exploited CVEs`;
}

/** Pure: the EPSS daily CSV (gunzipped) → { date, rows: [[cve, score, percentile]] }. */
function parseEpssCsv(text) {
	let date = null;
	const rows = [];
	for (const line of String(text).split(/\r?\n/)) {
		if (line.startsWith("#")) { date = (/score_date:([0-9-]{10})/.exec(line) || [])[1] || date; continue; }
		const [cve, epss, pct] = line.split(",");
		if (!/^CVE-\d{4}-\d{4,}$/.test(cve || "")) continue;
		const s = Number(epss), p = Number(pct);
		if (Number.isFinite(s) && Number.isFinite(p)) rows.push([cve, s, p]);
	}
	return { date, rows };
}

async function epss({ assets, fetcher }) {
	const url = fad("providers").getProvider("epss").build("current-csv").url;
	const r = await fetcher(url, { headers: UA });
	if (!r.ok) throw new Error(`EPSS HTTP ${r.status}`);
	const text = zlib.gunzipSync(Buffer.from(await r.arrayBuffer())).toString("utf8");
	const { date, rows } = parseEpssCsv(text);
	if (!rows.length) throw new Error("empty EPSS file — refusing to clear it");
	assets.setEpss(rows, date);
	return `${rows.length} scores (${date || "undated"})`;
}

async function euvd({ assets, fetcher }) {
	const { byCve, exploited } = await fad("euvd").fetchSnapshot({ fetcher });
	const cves = new Set([...Object.keys(byCve), ...Object.keys(exploited)]);
	if (!cves.size) throw new Error("empty EUVD snapshot — refusing to clear it");
	assets.setEuvd([...cves].map(cve => [cve, byCve[cve] || null,
		Object.prototype.hasOwnProperty.call(exploited, cve) ? exploited[cve] : null]));
	return `${Object.keys(byCve).length} EUVD ids · ${Object.keys(exploited).length} exploited`;
}

module.exports = { kev, epss, euvd, parseEpssCsv };
