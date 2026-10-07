/**
 * NVD enrichment, mirrored from fkie-cad/nvd-json-data-feeds (a daily mirror of the NVD
 * API 2.0, same JSON) — the NVD API's terms do not let one key serve a fleet, the mirror
 * needs none. One xz file per year with a `.meta` carrying its sha256: a year is
 * re-imported only when its sha256 changed, streamed (lib/xz.js + lib/json-stream.js),
 * never parsed whole.
 *
 * Kept per CVE, apart from the CVE List record: NVD's CVSS (with its source and type),
 * vulnStatus, CWE, reference tags and the CPE configurations — through fad's own
 * extractFromNvdRecord, so the service and the CLI read NVD the same way.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { Readable } = require("node:stream");
const { fad } = require("../fad");
const { xzDecompress } = require("../xz");
const { forEachArrayItem } = require("../json-stream");

const RELEASE = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest";
const BATCH = 500;

const UA = () => {
	const h = { "user-agent": "fad-service", accept: "application/vnd.github+json" };
	if (process.env.FAD_SERVICE_GITHUB_TOKEN) h.authorization = `Bearer ${process.env.FAD_SERVICE_GITHUB_TOKEN}`;
	return h;
};

/** Pure: a `.meta` file → { sha256, lastModified }. */
function parseMeta(text) {
	const out = {};
	for (const line of String(text).split(/\r?\n/)) {
		const i = line.indexOf(":");
		if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
	}
	return { sha256: out.sha256 || null, lastModified: out.lastModifiedDate || null };
}

/** Pure: an NVD 2.0 CVE item → the row kept (every CVSS metric, not only the best). */
function nvdRow(item) {
	const base = fad("nvd").extractFromNvdRecord(item);
	if (!base?.id) return null;
	const metrics = [];
	for (const [key, list] of Object.entries(item.metrics || {})) {
		for (const m of Array.isArray(list) ? list : []) {
			const c = m?.cvssData;
			if (!c || c.baseScore == null) continue;
			metrics.push({ version: String(c.version || key.replace(/^cvssMetricV(\d)(\d)?$/, (x, a, b) => b ? `${a}.${b}` : a)),
				score: Number(c.baseScore), severity: String(c.baseSeverity || m.baseSeverity || "").toUpperCase() || null,
				vector: c.vectorString || null, source: m.source || null, type: m.type || null });
		}
	}
	return {
		id: base.id, vulnStatus: item.vulnStatus || null, lastModified: base.modified, published: base.published,
		metrics, cwes: base.cwes, references: base.references.slice(0, 200), configurations: base.configurations,
	};
}

async function importYear({ asset, fetcher, assets }) {
	const res = await fetcher(asset.browser_download_url, { headers: { "user-agent": "fad-service" }, redirect: "follow" });
	if (!res.ok || !res.body) throw new Error(`${asset.name} HTTP ${res.status}`);
	let pending = [];
	const flush = async () => { if (pending.length) { const rows = pending; pending = []; await assets.setNvd(rows); } };
	const n = await forEachArrayItem(xzDecompress(Readable.fromWeb(res.body)), "cve_items", item => {
		const row = nvdRow(item);
		if (row) pending.push(row);
	}, { afterChunk: () => pending.length >= BATCH ? flush() : null });
	await flush();
	return n;
}

async function run({ assets, fetcher, state, setState, log }) {
	const r = await fetcher(RELEASE, { headers: UA() });
	if (!r.ok) throw new Error(`fkie releases HTTP ${r.status}`);
	const rel = await r.json();
	const files = (rel.assets || []).filter(a => /^CVE-\d{4}\.json\.xz$/.test(a.name));
	if (!files.length) throw new Error("no yearly feed on the latest fkie release");
	const metas = Object.fromEntries((rel.assets || []).filter(a => /^CVE-\d{4}\.meta$/.test(a.name)).map(a => [a.name.slice(0, 8), a]));
	const seen = { ...(state.sha || {}) };
	let years = 0, items = 0;
	for (const asset of files) {
		const year = asset.name.slice(0, 8);
		let sha = null;
		if (metas[year]) {
			const m = await fetcher(metas[year].browser_download_url, { headers: { "user-agent": "fad-service" }, redirect: "follow" });
			if (m.ok) sha = parseMeta(await m.text()).sha256;
		}
		if (sha && seen[year] === sha) continue;
		const n = await importYear({ asset, fetcher, assets });
		items += n; years++;
		if (sha) { seen[year] = sha; await setState({ ...state, sha: seen, release: rel.tag_name }); }
		if (log) log(`nvd ${year}: ${n} records`);
	}
	await setState({ ...state, sha: seen, release: rel.tag_name });
	return years ? `${years} year file(s) re-imported, ${items} records (${rel.tag_name})` : `up to date (${rel.tag_name})`;
}

module.exports = { run, parseMeta, nvdRow };
