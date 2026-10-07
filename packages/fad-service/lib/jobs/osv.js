/**
 * OSV.dev mirror for the ecosystems fad scans. Per ecosystem: the first run streams
 * `<eco>/all.zip`; later runs read `<eco>/modified_id.csv` (newest first) and fetch only
 * the records modified since the last run — or stream all.zip again when too many did.
 * Each record becomes an advisory asset (`osv:<id>`, its own page) linked to the CVEs it
 * aliases. A record keeps the licence of the database it comes from.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { Readable } = require("node:stream");
const { forEachJsonInZip } = require("../zip-stream");
const { packageOfOsv } = require("../registry/purl");

const BASE = "https://osv-vulnerabilities.storage.googleapis.com";
const ECOSYSTEMS = ["Maven", "npm", "PyPI", "Packagist", "NuGet", "Go", "RubyGems"];
const BATCH = 500;
const MAX_INCREMENTAL = 5000;
const UA = { "user-agent": "fad-service" };

/** The licence of an OSV record, by the database its id belongs to (osv.dev/data). */
function osvLicence(id) {
	const p = String(id).split("-")[0];
	return {
		GHSA: "CC-BY 4.0 — GitHub Advisory Database", PYSEC: "CC-BY 4.0 — PyPA Advisory Database",
		GO: "CC-BY 4.0 — Go Vulnerability Database", MAL: "Apache-2.0 — OpenSSF Malicious Packages",
		RUSTSEC: "CC0 1.0 — RustSec", RSEC: "CC-BY 4.0 — RConsortium",
	}[p] || "See osv.dev/data for this database's licence";
}

const cap = (arr, n) => (Array.isArray(arr) ? arr : []).slice(0, n);

/** Pure: an OSV record → the advisory asset. */
function osvAsset(v) {
	if (!v?.id) return null;
	const affected = cap(v.affected, 100).map(a => ({
		ecosystem: a?.package?.ecosystem || null, name: a?.package?.name || null, purl: a?.package?.purl || null,
		ranges: cap(a?.ranges, 10).map(r => ({ type: r?.type || null, events: cap(r?.events, 40) })),
		versions: cap(a?.versions, 200),
	}));
	const cves = [...new Set([v.id, ...(v.aliases || [])].filter(x => /^CVE-\d{4}-\d{4,}$/.test(x)))];
	const packages = [...new Set(affected.map(a => a.name).filter(Boolean))];
	const packageKeys = [...new Set(affected.map(a => packageOfOsv({ ecosystem: a.ecosystem, name: a.name })).filter(Boolean))];
	const url = `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`;
	const title = String(v.summary || "").trim() || String(v.details || "").split("\n").find(l => l.trim())?.replace(/^#+\s*/, "").slice(0, 160) || v.id;
	return {
		asset: {
			type: "advisory", key: `osv:${v.id}`, title,
			summary: `${packages.join(" ")} ${String(v.details || "").slice(0, 1000)}`.trim(),
			aliases: [v.id, ...cap(v.aliases, 50), ...packages],
			data: { source: "osv", id: v.id, summary: v.summary || null, details: String(v.details || "").slice(0, 20000),
				aliases: cap(v.aliases, 50), related: cap(v.related, 50), published: v.published || null, modified: v.modified || null,
				withdrawn: v.withdrawn || null, severity: cap(v.severity, 5), affected,
				references: cap(v.references, 100).filter(r => /^https?:\/\//i.test(r?.url || "")).map(r => ({ type: r.type || null, url: r.url })), url },
			sources: [{ name: "OSV.dev", licence: osvLicence(v.id), url }],
		},
		cves,
		packages: packageKeys,
	};
}

function store(assets, records) {
	assets.transaction(() => {
		for (const v of records) {
			const out = osvAsset(v);
			if (!out) continue;
			assets.upsert(out.asset);
			assets.linkAdvisory(out.asset.key, out.cves);
			assets.linkAdvisoryPackages(out.asset.key, out.packages);
		}
	});
}

async function importAll(eco, { fetcher, assets }) {
	const res = await fetcher(`${BASE}/${encodeURIComponent(eco)}/all.zip`, { headers: UA });
	if (!res.ok || !res.body) throw new Error(`OSV ${eco} all.zip HTTP ${res.status}`);
	let pending = [], n = 0;
	await forEachJsonInZip(Readable.fromWeb(res.body), (name, v) => {
		pending.push(v); n++;
		if (pending.length >= BATCH) { store(assets, pending); pending = []; }
	});
	store(assets, pending);
	return n;
}

/** Pure: modified_id.csv (newest first) → ids modified strictly after `since`, or null when too many. */
function modifiedSince(csv, since, max = MAX_INCREMENTAL) {
	const ids = [];
	for (const line of String(csv).split(/\r?\n/)) {
		const [ts, id] = line.split(",");
		if (!ts || !id) continue;
		if (ts <= since) break;
		ids.push(id.trim());
		if (ids.length > max) return null;
	}
	return ids;
}

async function importChanged(eco, ids, { fetcher, assets }) {
	const records = [];
	let next = 0;
	const worker = async () => {
		while (next < ids.length) {
			const id = ids[next++];
			const r = await fetcher(`${BASE}/${encodeURIComponent(eco)}/${encodeURIComponent(id)}.json`, { headers: UA });
			if (r.ok) records.push(await r.json());
			else if (r.status !== 404) throw new Error(`OSV ${eco}/${id} HTTP ${r.status}`);
		}
	};
	await Promise.all(Array.from({ length: 8 }, worker));
	for (let i = 0; i < records.length; i += BATCH) store(assets, records.slice(i, i + BATCH));
	return records.length;
}

/** Advisories imported before package links existed get them from their stored record. */
function relinkPackages(assets) {
	let n = 0, batch = [];
	const flush = () => { assets.transaction(() => { for (const [k, p] of batch) assets.linkAdvisoryPackages(k, p); }); batch = []; };
	for (const { key, data } of assets.iteratePrefix("advisory", "osv:")) {
		const pk = [...new Set((data.affected || []).map(a => packageOfOsv({ ecosystem: a.ecosystem, name: a.name })).filter(Boolean))];
		if (pk.length) { batch.push([key, pk]); n++; }
		if (batch.length >= BATCH) flush();
	}
	if (batch.length) flush();
	return n;
}

async function run({ assets, fetcher, state, setState, log, ecosystems = ECOSYSTEMS }) {
	const marks = { ...(state.since || {}) };
	const parts = [];
	if (!assets.advisoryPackageLinks() && Object.keys(marks).length) parts.push(`relinked ${relinkPackages(assets)} advisories to packages`);
	for (const eco of ecosystems) {
		const started = new Date().toISOString();
		let n, how;
		const since = marks[eco];
		let ids = null;
		if (since) {
			const r = await fetcher(`${BASE}/${encodeURIComponent(eco)}/modified_id.csv`, { headers: UA });
			if (!r.ok) throw new Error(`OSV ${eco} modified_id.csv HTTP ${r.status}`);
			ids = modifiedSince(await r.text(), since);
		}
		if (ids) { n = await importChanged(eco, ids, { fetcher, assets }); how = "changed"; }
		else { n = await importAll(eco, { fetcher, assets }); how = "all"; }
		marks[eco] = started;
		setState({ ...state, since: marks });
		parts.push(`${eco} ${n} ${how}`);
		if (log) log(`osv ${eco}: ${n} records (${how})`);
	}
	return parts.join(" · ");
}

module.exports = { run, osvAsset, osvLicence, modifiedSince, relinkPackages, ECOSYSTEMS };
