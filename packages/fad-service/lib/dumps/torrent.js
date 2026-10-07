/**
 * A BitTorrent v1 metainfo for one payload file, with the HTTPS download as a web seed
 * (BEP 19), so the file downloads with no peer online and the swarm takes load off the
 * instance when many relays fetch the same build. No dependency: bencode + SHA-1 pieces.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("node:fs");
const crypto = require("node:crypto");

function bencode(v) {
	if (Buffer.isBuffer(v)) return Buffer.concat([Buffer.from(`${v.length}:`), v]);
	if (typeof v === "string") return bencode(Buffer.from(v, "utf8"));
	if (Number.isInteger(v)) return Buffer.from(`i${v}e`);
	if (Array.isArray(v)) return Buffer.concat([Buffer.from("l"), ...v.map(bencode), Buffer.from("e")]);
	if (v && typeof v === "object") {
		const keys = Object.keys(v).filter(k => v[k] !== undefined).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
		return Buffer.concat([Buffer.from("d"), ...keys.flatMap(k => [bencode(k), bencode(v[k])]), Buffer.from("e")]);
	}
	throw new Error(`cannot bencode ${typeof v}`);
}

/** Piece length: ~1500 pieces, between 256 KiB and 16 MiB. */
function pieceLengthFor(size) {
	let p = 256 * 1024;
	while (p < 16 * 1024 * 1024 && size / p > 1500) p *= 2;
	return p;
}

async function pieces(file, pieceLength) {
	const out = [];
	let buf = Buffer.alloc(0);
	for await (const chunk of fs.createReadStream(file, { highWaterMark: 1024 * 1024 })) {
		buf = Buffer.concat([buf, chunk]);
		while (buf.length >= pieceLength) {
			out.push(crypto.createHash("sha1").update(buf.subarray(0, pieceLength)).digest());
			buf = buf.subarray(pieceLength);
		}
	}
	if (buf.length) out.push(crypto.createHash("sha1").update(buf).digest());
	return Buffer.concat(out);
}

/**
 * → { torrent: Buffer, infoHash: hex, magnet }.
 * webSeed: the HTTPS URL of the file; trackers: optional announce URLs.
 */
async function makeTorrent(file, { name, webSeed, trackers = [], comment }) {
	const length = fs.statSync(file).size;
	const pieceLength = pieceLengthFor(length);
	const info = { length, name, "piece length": pieceLength, pieces: await pieces(file, pieceLength) };
	const infoHash = crypto.createHash("sha1").update(bencode(info)).digest("hex");
	const meta = { info, "url-list": webSeed ? [webSeed] : undefined, "creation date": Math.floor(Date.now() / 1000),
		"created by": "fad-service", comment: comment || undefined,
		...(trackers.length ? { announce: trackers[0], "announce-list": trackers.map(t => [t]) } : {}) };
	const q = [`xt=urn:btih:${infoHash}`, `dn=${encodeURIComponent(name)}`, `xl=${length}`,
		...(webSeed ? [`ws=${encodeURIComponent(webSeed)}`] : []), ...trackers.map(t => `tr=${encodeURIComponent(t)}`)];
	return { torrent: bencode(meta), infoHash, magnet: `magnet:?${q.join("&")}` };
}

module.exports = { makeTorrent, bencode, pieceLengthFor };
