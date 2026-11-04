/**
 * lib/certs/analyze.js — classify committed crypto material and derive findings.
 *
 * Pure: takes a file's bytes + name (+ a `now` for testability) and returns a flat
 * list of items. One file can yield several items (a .pem bundling a cert chain and
 * a private key produces one item per certificate plus one for the key).
 *
 * Each item is one of four kinds:
 *   - "certificate" — an X.509 cert (PEM or DER), fully parsed via the built-in
 *     crypto.X509Certificate (NO external library, works air-gapped).
 *   - "private-key" / "public-key" — key material, ALWAYS labelled with its
 *     visibility (the headline ask): PEM (PKCS#1/PKCS#8/SEC1), OpenSSH (every
 *     algorithm), PuTTY (.ppk), PGP, and one-line SSH public keys.
 *   - "keystore" — a Java keystore / PKCS#12 (content is password-protected, so we
 *     inventory + hash it rather than decrypt).
 *
 * Findings (item.issues[]): cert-expired, cert-expiring, cert-weak-key,
 * cert-weak-signature, cert-self-signed, private-key-committed,
 * public-key-committed, keystore-committed. No network, no decryption.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const crypto = require("crypto");

const DAY = 86_400_000;
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function worstSeverity(issues) {
	let s = "info";
	for (const i of issues) if ((SEV_RANK[i.severity] || 0) > SEV_RANK[s]) s = i.severity;
	return s;
}

// ---- PEM block handling --------------------------------------------------

const PEM_BLOCK_RE = /-----BEGIN ([A-Z0-9 ]+?)-----\r?\n([\s\S]*?)-----END \1-----/g;

function pemBlocks(text) {
	const out = [];
	let m;
	PEM_BLOCK_RE.lastIndex = 0;
	while ((m = PEM_BLOCK_RE.exec(text)) !== null) {
		out.push({ label: m[1].trim(), body: m[2], full: m[0] });
	}
	return out;
}

// ---- SSH public-key line + OpenSSH private-key blob ----------------------

const SSH_PUB_RE = /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-[a-z0-9-]+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+[A-Za-z0-9+/=]+/;

// Map an SSH key-type token to a human algorithm label.
function sshAlgo(type) {
	if (type === "ssh-rsa") return "RSA";
	if (type === "ssh-dss") return "DSA";
	if (type === "ssh-ed25519") return "Ed25519";
	if (type === "sk-ssh-ed25519@openssh.com") return "Ed25519-SK";
	if (type === "sk-ecdsa-sha2-nistp256@openssh.com") return "ECDSA-SK";
	if (type && type.startsWith("ecdsa-sha2-")) return "ECDSA (" + type.slice("ecdsa-sha2-".length) + ")";
	return type || null;
}

// Parse an OpenSSH private-key blob → { algorithm, encrypted }. Format:
// "openssh-key-v1\0" cipher kdf kdfopts uint32(numkeys) sshstring(pubkey) ...
function parseOpensshPrivate(body) {
	try {
		const buf = Buffer.from(body.replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
		const MAGIC = "openssh-key-v1\0";
		if (buf.subarray(0, MAGIC.length).toString("latin1") !== MAGIC) return null;
		let off = MAGIC.length;
		const readStr = () => {
			if (off + 4 > buf.length) throw new Error("truncated SSH string");
			const len = buf.readUInt32BE(off); off += 4;
			if (len > buf.length - off) throw new Error("truncated SSH string");
			const s = buf.subarray(off, off + len); off += len; return s;
		};
		const cipher = readStr().toString("latin1");
		const kdf = readStr().toString("latin1");
		readStr();                 // kdf options
		if (!cipher || !kdf || (cipher === "none") !== (kdf === "none")) return null;
		if (buf.readUInt32BE(off) !== 1) return null;
		off += 4;                  // supported OpenSSH files contain one key
		const pub = readStr();     // first public-key blob
		const tlen = pub.readUInt32BE(0);
		if (!tlen || tlen > pub.length - 4) return null;
		const keyType = pub.subarray(4, 4 + tlen).toString("latin1");
		if (!readStr().length || off !== buf.length) return null; // private section
		return { algorithm: sshAlgo(keyType), encrypted: cipher !== "none" };
	} catch { return null; }
}

// ---- weak signature-algorithm detection (X.509 AlgorithmIdentifier) -------

// Signature-algorithm OIDs we consider weak, as their DER value bytes.
const WEAK_SIG_OIDS = [
	{ name: "MD2withRSA", bytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02] },
	{ name: "MD5withRSA", bytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04] },
	{ name: "SHA1withRSA", bytes: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05] },
	{ name: "ECDSAwithSHA1", bytes: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01] },
	{ name: "DSAwithSHA1", bytes: [0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03] },
];

function detectWeakSig(raw) {
	if (!raw || !raw.length) return null;
	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }.
	// Never search extensions, names, public keys or signature bytes for an OID.
	const tlv = (offset, limit) => {
		if (offset + 2 > limit) throw new Error("truncated DER");
		const tag = raw[offset++];
		let length = raw[offset++];
		if (length & 0x80) {
			const octets = length & 0x7f;
			if (!octets || octets > 4 || offset + octets > limit || raw[offset] === 0) throw new Error("invalid DER length");
			length = 0;
			for (let i = 0; i < octets; i++) length = length * 256 + raw[offset++];
			if (length < 128) throw new Error("noncanonical DER length");
		}
		if (length > limit - offset) throw new Error("truncated DER value");
		return { tag, start: offset, end: offset + length };
	};
	try {
		const cert = tlv(0, raw.length);
		if (cert.tag !== 0x30 || cert.end !== raw.length) return null;
		const tbs = tlv(cert.start, cert.end);
		if (tbs.tag !== 0x30) return null;
		const algorithm = tlv(tbs.end, cert.end);
		if (algorithm.tag !== 0x30) return null;
		const signature = tlv(algorithm.end, cert.end);
		if (signature.tag !== 0x03 || signature.end !== cert.end) return null;
		const oid = tlv(algorithm.start, algorithm.end);
		if (oid.tag !== 0x06) return null;
		const value = raw.subarray(oid.start, oid.end);
		return WEAK_SIG_OIDS.find(item => value.equals(Buffer.from(item.bytes)))?.name || null;
	} catch { return null; }
}

// EC curves below the ~128-bit security floor (i.e. < 256-bit field).
const WEAK_CURVES = new Set(["prime192v1", "secp192r1", "secp192k1", "secp224r1", "secp224k1", "prime239v1"]);

function cnOf(dn) {
	if (!dn) return null;
	const m = /(?:^|\n)CN=([^\n]+)/.exec(dn);
	return m ? m[1].trim() : dn.split("\n")[0].trim();
}

// ---- certificate item ----------------------------------------------------

function certItem({ path, file, x509, now, expiryDays }) {
	const issues = [];
	const notAfterMs = Date.parse(x509.validTo);
	const notBeforeMs = Date.parse(x509.validFrom);
	const daysUntilExpiry = Number.isFinite(notAfterMs) ? Math.floor((notAfterMs - now) / DAY) : null;

	let algorithm = null, bits = null;
	try {
		const pk = x509.publicKey;
		algorithm = (pk.asymmetricKeyType || "").toUpperCase() || null;
		const d = pk.asymmetricKeyDetails || {};
		if (d.modulusLength) bits = d.modulusLength;
		else if (d.namedCurve) bits = d.namedCurve;
		if (algorithm === "RSA" && bits && bits < 2048)
			issues.push({ type: "cert-weak-key", severity: "high", message: `RSA ${bits}-bit key (below 2048-bit minimum)` });
		if ((algorithm === "EC" || algorithm === "ECDSA") && typeof bits === "string" && WEAK_CURVES.has(bits))
			issues.push({ type: "cert-weak-key", severity: "high", message: `weak EC curve ${bits}` });
	} catch { /* publicKey unreadable — leave algorithm null */ }

	if (Number.isFinite(notAfterMs)) {
		if (notAfterMs < now)
			issues.push({ type: "cert-expired", severity: "high", message: `expired on ${x509.validTo} (${-daysUntilExpiry} days ago)` });
		else if (daysUntilExpiry <= expiryDays)
			issues.push({ type: "cert-expiring", severity: "medium", message: `expires in ${daysUntilExpiry} days (${x509.validTo})` });
	}

	const weakSig = detectWeakSig(x509.raw);
	if (weakSig)
		issues.push({ type: "cert-weak-signature", severity: "high", message: `weak signature algorithm ${weakSig}` });

	const selfSigned = x509.subject === x509.issuer;
	if (selfSigned)
		issues.push({ type: "cert-self-signed", severity: "low", message: "self-signed certificate" });

	return {
		path, file, kind: "certificate", format: "x509",
		algorithm, bits, keyVisibility: null,
		subject: cnOf(x509.subject), issuer: cnOf(x509.issuer),
		serialNumber: x509.serialNumber || null,
		notBefore: Number.isFinite(notBeforeMs) ? new Date(notBeforeMs).toISOString() : null,
		notAfter: Number.isFinite(notAfterMs) ? new Date(notAfterMs).toISOString() : null,
		daysUntilExpiry, selfSigned, ca: !!x509.ca,
		signatureAlgorithm: weakSig || null,
		fingerprint256: x509.fingerprint256 || null,
		issues, severity: worstSeverity(issues),
	};
}

function tryX509(buf) {
	try { return new crypto.X509Certificate(buf); } catch { return null; }
}

// ---- key items -----------------------------------------------------------

function privateKeyItem({ path, file, format, algorithm, encrypted }) {
	const enc = encrypted === true ? " (encrypted)" : encrypted === false ? " (UNENCRYPTED)" : " (encryption unknown)";
	const issues = [{
		type: "private-key-committed", severity: "critical",
		message: `committed ${algorithm || ""} private key${enc} [${format}]`.replace(/\s+/g, " ").trim(),
	}];
	return {
		path, file, kind: "private-key", format, algorithm: algorithm || null,
		keyVisibility: "private", encrypted: typeof encrypted === "boolean" ? encrypted : null,
		issues, severity: "critical",
	};
}

function publicKeyItem({ path, file, format, algorithm, count }) {
	const issues = [{
		type: "public-key-committed", severity: "low",
		message: `committed ${algorithm || ""} public key${count > 1 ? ` (${count} keys)` : ""} [${format}]`.replace(/\s+/g, " ").trim(),
	}];
	return {
		path, file, kind: "public-key", format, algorithm: algorithm || null,
		keyVisibility: "public", count: count || 1,
		issues, severity: "low",
	};
}

// Classify one PEM private-key block → { algorithm, encrypted }.
function pemPrivateInfo(block) {
	if (block.label === "OPENSSH PRIVATE KEY") {
		const r = parseOpensshPrivate(block.body);
		return { algorithm: r?.algorithm || null, encrypted: r ? r.encrypted : null, format: "openssh" };
	}
	const encrypted = /ENCRYPTED/.test(block.label) || /Proc-Type:\s*4,ENCRYPTED/.test(block.body);
	let algorithm = null;
	if (/^RSA /.test(block.label)) algorithm = "RSA";
	else if (/^EC /.test(block.label)) algorithm = "EC";
	else if (/^DSA /.test(block.label)) algorithm = "DSA";
	if (!encrypted && !algorithm) {
		try {
			const k = crypto.createPrivateKey({ key: block.full });
			algorithm = (k.asymmetricKeyType || "").toUpperCase() || null;
		} catch { /* unparseable → leave null */ }
	}
	return { algorithm, encrypted, format: "pem" };
}

function pemPublicAlgo(block) {
	try {
		const k = crypto.createPublicKey({ key: block.full });
		return (k.asymmetricKeyType || "").toUpperCase() || null;
	} catch { return /^RSA /.test(block.label) ? "RSA" : null; }
}

// ---- top-level dispatch --------------------------------------------------

/**
 * Analyze one candidate file. Returns an array of items (possibly empty).
 * @param {{name, path, buf, now?, expiryDays?}} args
 */
function analyzeBuffer({ name, path, buf, now = Date.now(), expiryDays = 90 } = {}) {
	if (!buf || !buf.length) return [];
	const items = [];
	// latin1 keeps binary bytes 1:1 while still letting us substring-match ASCII headers.
	const text = buf.subarray(0, Math.min(buf.length, 8 * 1024 * 1024)).toString("latin1");

	// 1. PEM container — may hold certs AND keys; emit one item per block of interest.
	if (text.includes("-----BEGIN ")) {
		for (const block of pemBlocks(text)) {
			const L = block.label;
			if (/CERTIFICATE$/.test(L) && L !== "CERTIFICATE REQUEST" && L !== "NEW CERTIFICATE REQUEST") {
				const x = tryX509(block.full);
				if (x) items.push(certItem({ path, file: name, x509: x, now, expiryDays }));
			} else if (/PRIVATE KEY$/.test(L)) {
				const info = pemPrivateInfo(block);
				items.push(privateKeyItem({ path, file: name, ...info }));
			} else if (L === "PGP PRIVATE KEY BLOCK") {
				items.push(privateKeyItem({ path, file: name, format: "pgp", algorithm: "PGP", encrypted: null }));
			} else if (/PUBLIC KEY$/.test(L)) {
				items.push(publicKeyItem({ path, file: name, format: "pem", algorithm: pemPublicAlgo(block) }));
			} else if (L === "PGP PUBLIC KEY BLOCK") {
				items.push(publicKeyItem({ path, file: name, format: "pgp", algorithm: "PGP" }));
			}
		}
		if (items.length) return items;
	}

	// 2. PuTTY private key (.ppk).
	if (/^PuTTY-User-Key-File-\d+:\s*(\S+)/m.test(text)) {
		const algo = /^PuTTY-User-Key-File-\d+:\s*(\S+)/m.exec(text)[1];
		const cipher = /^Encryption:\s*(\S+)/m.exec(text)?.[1];
		const encrypted = cipher ? cipher !== "none" : null;
		items.push(privateKeyItem({ path, file: name, format: "putty", algorithm: sshAlgo(algo) || algo, encrypted }));
		return items;
	}

	// 3. One-line SSH public keys (authorized_keys / known_hosts / *.pub).
	const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean).filter(l => !l.startsWith("#"));
	const pubLines = lines.filter(l => {
		// known_hosts lines are "<host> <type> <b64>"; strip a leading host token.
		const t = l.replace(/^\S+\s+/, "");
		return SSH_PUB_RE.test(l) || SSH_PUB_RE.test(t);
	});
	if (pubLines.length) {
		const first = pubLines[0];
		const m = SSH_PUB_RE.exec(first) || SSH_PUB_RE.exec(first.replace(/^\S+\s+/, ""));
		items.push(publicKeyItem({ path, file: name, format: "ssh", algorithm: sshAlgo(m ? m[1] : null), count: pubLines.length }));
		return items;
	}

	// 4. Binary: DER certificate, else Java keystore / PKCS#12.
	const x = tryX509(buf);
	if (x) { items.push(certItem({ path, file: name, x509: x, now, expiryDays })); return items; }

	const ks = keystoreFormat(buf, name);
	if (ks) {
		items.push({
			path, file: name, kind: "keystore", format: ks, algorithm: null, keyVisibility: null,
			issues: [{ type: "keystore-committed", severity: "medium", message: `committed ${ks.toUpperCase()} keystore (encrypted contents not inspected)` }],
			severity: "medium",
		});
	}
	return items;
}

// Java keystore magic + PKCS#12 by extension (DER SEQUENCE is ambiguous by magic).
function keystoreFormat(buf, name) {
	if (buf && buf.length >= 4) {
		if (buf[0] === 0xfe && buf[1] === 0xed && buf[2] === 0xfe && buf[3] === 0xed) return "jks";
		if (buf[0] === 0xce && buf[1] === 0xce && buf[2] === 0xce && buf[3] === 0xce) return "jceks";
	}
	if (/\.(p12|pfx)$/i.test(name)) return "pkcs12";
	if (/\.(jks|keystore)$/i.test(name)) return "jks";
	return null;
}

module.exports = {
	analyzeBuffer, worstSeverity,
	// exported for unit tests:
	pemBlocks, detectWeakSig, sshAlgo, parseOpensshPrivate, keystoreFormat, SSH_PUB_RE,
};
