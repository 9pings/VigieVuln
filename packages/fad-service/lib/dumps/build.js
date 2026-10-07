/**
 * Build a dump (spec §8, format: fad-checker lib/dump-format.js).
 *
 * Three kinds, by who may receive them:
 *   public   PUBLISHED vulnerability data: CVEs, advisories, signals, NVD, links. Registry
 *            projections stay out unless includePackages (their bulk redistribution is
 *            not cleared for every registry — spec §11). Listed on /dumps, torrent.
 *   private  public + published package pages + the /v1/resource cache entries a relay
 *            needs, minus anything tied to an unpublished package or fetched with a
 *            client's own credentials. For client-token holders (/dumps/private/…).
 *   full     everything, unpublished included — replication between YOUR instances and
 *            backups. Never served over HTTP.
 * `since` (ms) makes a delta: only what changed after it.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const { once } = require("node:events");
const { fad } = require("../fad");
const { packageOfRequest } = require("../registry/purl");

const KINDS = ["public", "private", "full"];

function stamp(d = new Date()) { return d.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z"); }

/** Is a /v1/resource cache entry fit for a private (client) build? */
function resourceShareable(key, isPublishedPackage) {
	let parsed;
	try { parsed = JSON.parse(key); } catch { return false; }
	const [provider, type, params, scope] = Array.isArray(parsed) ? parsed : [];
	if (scope) return false;                                    // fetched with someone's credentials
	const pkg = packageOfRequest({ provider, type, params });
	return !pkg || isPublishedPackage(pkg);                     // a registry entry only for a public package
}

/**
 * opts: { db, assets, dir, kind, since (ms|null), includePackages, signingKeyPem, baseUrl,
 *         trackers, instance: { name, baseUrl }, version, sources (job status) }
 * → manifest (also written to <dir>/<id>.manifest.json)
 */
async function buildDump(opts) {
	const { db, dir, kind = "public", since = null, includePackages = false, signingKeyPem = null,
		baseUrl = null, trackers = [], instance = {}, version = "0", sources = [] } = opts;
	if (!KINDS.includes(kind)) throw new Error(`dump kind must be one of ${KINDS.join(", ")}`);
	const { FORMAT, sha256File, signManifest, encodeLine } = fad("dump-format");
	fs.mkdirSync(dir, { recursive: true });
	const id = `fad-${kind}-${stamp()}${since ? "-delta" : ""}`;
	const payloadName = `${id}.jsonl.gz`;
	const payloadPath = path.join(dir, payloadName);
	const tmp = payloadPath + ".part";
	const gz = zlib.createGzip({ level: 6 });
	const out = fs.createWriteStream(tmp);
	gz.pipe(out);
	const counts = { asset: 0, signal: 0, nvd: 0, links: 0, resource: 0 };
	const write = async obj => { if (!gz.write(encodeLine(obj))) await once(gz, "drain"); };
	const sinceMs = since || 0;
	const publishedOnly = kind !== "full";
	const typeOk = t => kind === "full" || t === "cve" || t === "advisory" || (t === "package" && (kind === "private" || includePackages));

	// Assets, and the CVE/package links of each advisory written.
	const assetRows = db.prepare(`SELECT type, key, title, summary, aliases, data, sources, published, updated_at FROM assets
		WHERE updated_at > ? ${publishedOnly ? "AND published = 1" : ""}`);
	const cveLinks = db.prepare("SELECT cve FROM advisory_cve WHERE advisory = ?");
	const pkgLinks = db.prepare("SELECT package FROM advisory_package WHERE advisory = ?");
	for (const r of assetRows.iterate(sinceMs)) {
		if (!typeOk(r.type)) continue;
		await write({ t: "asset", type: r.type, key: r.key, title: r.title, summary: r.summary, aliases: r.aliases,
			data: JSON.parse(r.data), sources: JSON.parse(r.sources), published: r.published, updatedAt: r.updated_at });
		counts.asset++;
		if (r.type === "advisory") {
			await write({ t: "links", advisory: r.key, cves: cveLinks.all(r.key).map(x => x.cve),
				packages: kind === "public" && !includePackages ? [] : pkgLinks.all(r.key).map(x => x.package) });
			counts.links++;
		}
	}
	for (const r of db.prepare("SELECT * FROM cve_signals WHERE updated_at > ?").iterate(sinceMs)) {
		await write({ t: "signal", ...r });
		counts.signal++;
	}
	for (const r of db.prepare("SELECT cve, last_modified, data, updated_at FROM cve_nvd WHERE COALESCE(updated_at, 0) > ? OR ? = 0").iterate(sinceMs, sinceMs)) {
		await write({ t: "nvd", cve: r.cve, lastModified: r.last_modified, updatedAt: r.updated_at || 0, data: JSON.parse(r.data) });
		counts.nvd++;
	}
	if (kind !== "public") {
		const published = db.prepare("SELECT 1 FROM assets WHERE type = 'package' AND key = ? AND published = 1");
		const isPub = key => !!published.get(key);
		for (const r of db.prepare("SELECT key, fetched_at, ttl_ms, content_type, response_headers, bytes, body FROM resources WHERE fetched_at > ?").iterate(sinceMs)) {
			if (kind === "private" && !resourceShareable(r.key, isPub)) continue;
			await write({ t: "resource", key: r.key, meta: { fetchedAt: r.fetched_at, ttlMs: r.ttl_ms, contentType: r.content_type,
				responseHeaders: r.response_headers ? JSON.parse(r.response_headers) : {} }, body: Buffer.from(r.body).toString("base64") });
			counts.resource++;
		}
	}
	gz.end();
	await once(out, "close");
	fs.renameSync(tmp, payloadPath);

	const manifest = {
		format: FORMAT, id, kind, delta: !!since, since: since ? new Date(since).toISOString() : null, createdAt: new Date().toISOString(),
		service: { name: "fad-service", version }, instance: { name: instance.name || null, baseUrl: instance.baseUrl || null },
		counts, sources,
		payload: { file: payloadName, bytes: fs.statSync(payloadPath).size, sha256: await sha256File(payloadPath), compression: "gzip", lines: "jsonl" },
		licences: "Each record keeps its source and licence (`sources` on assets). See /legal on the issuing instance.",
	};
	if (kind === "public" && baseUrl) {
		const { makeTorrent } = require("./torrent");
		const t = await makeTorrent(payloadPath, { name: payloadName, webSeed: `${baseUrl.replace(/\/$/, "")}/dumps/files/${payloadName}`, trackers,
			comment: `${instance.name || "fad-service"} — ${id}` });
		fs.writeFileSync(path.join(dir, `${id}.torrent`), t.torrent);
		manifest.torrent = { file: `${id}.torrent`, infoHash: t.infoHash, magnet: t.magnet };
	}
	const bytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n");
	fs.writeFileSync(path.join(dir, `${id}.manifest.json`), bytes);
	if (signingKeyPem) fs.writeFileSync(path.join(dir, `${id}.manifest.sig`), signManifest(bytes, signingKeyPem) + "\n");
	return manifest;
}

/** Keep the newest `keep` builds of a directory (all their files). → removed ids. */
function pruneDumps(dir, keep = 7) {
	if (!fs.existsSync(dir)) return [];
	const ids = [...new Set(fs.readdirSync(dir).map(f => /^(fad-[a-z]+-\d{8}T\d{6}Z(?:-delta)?)\./.exec(f)?.[1]).filter(Boolean))].sort();
	const drop = ids.slice(0, Math.max(0, ids.length - keep));
	for (const id of drop) for (const f of fs.readdirSync(dir)) if (f.startsWith(id + ".")) fs.rmSync(path.join(dir, f));
	return drop;
}

/** The builds of a directory, newest first → [manifest]. */
function listDumps(dir) {
	if (!fs.existsSync(dir)) return [];
	return fs.readdirSync(dir).filter(f => f.endsWith(".manifest.json")).sort().reverse().map(f => {
		try { return JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")); } catch { return null; }
	}).filter(Boolean);
}

module.exports = { buildDump, pruneDumps, listDumps, resourceShareable, KINDS };
