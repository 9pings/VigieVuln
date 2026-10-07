/**
 * lib/dump-format.js — the fad-service dump format, shared by the service (writes and
 * restores dumps) and by `fad-checker serve-cache --seed` (seeds a relay from one).
 *
 * A dump is two files:
 *   <id>.manifest.json   small, signed: what is inside, how fresh, sha256 of the payload
 *   <id>.jsonl.gz        the payload: one JSON object per line, gzip
 * plus <id>.manifest.sig (Ed25519 signature of the manifest bytes, base64) and, for a
 * public build, <id>.torrent.
 *
 * Payload lines: { t: "asset" | "signal" | "nvd" | "advisory_cve" | "advisory_package" |
 * "resource", … }. A "resource" line carries a /v1/resource cache entry: { key, meta,
 * body: base64 } — the only kind a relay needs. JSON Lines, not a database file: it streams,
 * it needs no SQLite on the reading side (the fad binary runs on bun), and any tool can
 * read it.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const crypto = require("crypto");
const zlib = require("zlib");

const FORMAT = "fad-dump/1";

/** sha256 (hex) of a file, streamed. */
function sha256File(file) {
	return new Promise((resolve, reject) => {
		const h = crypto.createHash("sha256");
		fs.createReadStream(file).on("data", d => h.update(d)).on("error", reject).on("end", () => resolve(h.digest("hex")));
	});
}

/** Sign the manifest bytes with an Ed25519 private key (PEM) → base64. */
function signManifest(bytes, privateKeyPem) {
	return crypto.sign(null, Buffer.from(bytes), crypto.createPrivateKey(privateKeyPem)).toString("base64");
}

/** → true when `sigB64` is a valid signature of `bytes` by the public key (PEM). */
function verifyManifest(bytes, sigB64, publicKeyPem) {
	try { return crypto.verify(null, Buffer.from(bytes), crypto.createPublicKey(publicKeyPem), Buffer.from(String(sigB64).trim(), "base64")); }
	catch { return false; }
}

/** Fingerprint of a public key (sha256 of its DER), to print and compare out of band. */
function keyFingerprint(publicKeyPem) {
	const der = crypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
	return crypto.createHash("sha256").update(der).digest("hex").match(/.{1,4}/g).slice(0, 8).join(":");
}

/**
 * Open a dump from its manifest path and check it: format, optional signature (when a
 * trusted public key is given — refused when the signature is missing or wrong), payload
 * sha256. → { manifest, payloadPath }.
 */
async function openDump(manifestPath, { publicKeyPem = null } = {}) {
	const bytes = fs.readFileSync(manifestPath);
	const manifest = JSON.parse(bytes.toString("utf8"));
	if (manifest.format !== FORMAT) throw new Error(`not a ${FORMAT} manifest`);
	if (publicKeyPem) {
		const sigPath = manifestPath.replace(/\.json$/, ".sig");
		if (!fs.existsSync(sigPath)) throw new Error("the dump is not signed");
		if (!verifyManifest(bytes, fs.readFileSync(sigPath, "utf8"), publicKeyPem)) throw new Error("bad signature: the dump does not come from the trusted key");
	}
	const payloadPath = require("path").join(require("path").dirname(manifestPath), manifest.payload.file);
	const sha = await sha256File(payloadPath);
	if (sha !== manifest.payload.sha256) throw new Error("payload sha256 mismatch: corrupted or tampered");
	return { manifest, payloadPath };
}

/**
 * Async iterator over the payload's lines, parsed. Split on "\n" ONLY: readline also breaks
 * on U+2028 / U+2029, which JSON leaves unescaped inside strings — a CVE description
 * holding one would cut its line in two.
 */
async function* readLines(payloadPath) {
	const { StringDecoder } = require("string_decoder");
	const decoder = new StringDecoder("utf8");
	let rest = "";
	for await (const chunk of fs.createReadStream(payloadPath).pipe(zlib.createGunzip())) {
		const text = rest + decoder.write(chunk);
		const lines = text.split("\n");
		rest = lines.pop();
		for (const line of lines) if (line) yield JSON.parse(line);
	}
	rest += decoder.end();
	if (rest) yield JSON.parse(rest);
}

/** One payload line: JSON with U+2028/U+2029 escaped, so any line reader is safe. */
const encodeLine = obj => JSON.stringify(obj).replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029") + "\n";

/**
 * Seed a resource store (lib/resource-cache/fs-store.js interface: put) from a dump's
 * "resource" lines. A cached entry fresher than the dump's is kept. → { imported, kept }.
 */
async function seedResourceStore(store, payloadPath) {
	let imported = 0, kept = 0;
	for await (const line of readLines(payloadPath)) {
		if (line.t !== "resource") continue;
		const current = await store.get(line.key);
		if (current && current.fetchedAt >= line.meta.fetchedAt) { kept++; continue; }
		const body = Buffer.from(line.body, "base64");
		await store.put(line.key, body, { ...line.meta, bytes: body.length });
		imported++;
	}
	return { imported, kept };
}

module.exports = { FORMAT, sha256File, signManifest, verifyManifest, keyFingerprint, openDump, readLines, encodeLine, seedResourceStore };
