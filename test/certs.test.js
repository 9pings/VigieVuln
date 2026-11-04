/**
 * test/certs.test.js — certificate / key-material scanner.
 *
 * Fixtures (test/fixtures/certs/) are real artifacts generated with openssl +
 * ssh-keygen: CA + CA-signed leaf, expired, RSA-1024, SHA1-signed, self-signed,
 * DER, standalone/encrypted/SSH private keys, public keys (PEM + every SSH type),
 * authorized_keys, known_hosts, and a JKS keystore.
 */
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { scanCertificates } = require("../lib/certs/scan");
const { analyzeBuffer, detectWeakSig, sshAlgo, parseOpensshPrivate, keystoreFormat } = require("../lib/certs/analyze");
const { isCandidate } = require("../lib/certs/sniff");

const FX = path.join(__dirname, "fixtures", "certs");
const buf = f => fs.readFileSync(path.join(FX, f));

// scan once; index items by basename for the assertions below
const items = scanCertificates(FX);
const byFile = name => items.filter(i => i.file === name);
const one = name => { const r = byFile(name); assert.equal(r.length >= 1, true, `expected an item for ${name}`); return r[0]; };
const hasIssue = (it, type) => it.issues.some(i => i.type === type);

// ---- candidacy gate ----
test("isCandidate accepts certs, keys, keystores and conventional SSH names", () => {
	for (const n of ["a.pem", "b.crt", "c.der", "k.key", "x.pub", "s.p12", "t.jks", "u.ppk", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts"])
		assert.equal(isCandidate(n), true, n);
	for (const n of ["a.js", "b.txt", "c.so", "d.png"])
		assert.equal(isCandidate(n), false, n);
});

// ---- certificates ----
test("CA-signed leaf parses clean (no findings)", () => {
	const it = one("valid-leaf.crt");
	assert.equal(it.kind, "certificate");
	assert.equal(it.algorithm, "RSA");
	assert.equal(it.bits, 2048);
	assert.equal(it.selfSigned, false);
	assert.equal(it.issues.length, 0);
});

test("DER certificate is parsed", () => {
	const it = one("server.der");
	assert.equal(it.kind, "certificate");
	assert.equal(it.algorithm, "RSA");
});

test("expired certificate → cert-expired (high)", () => {
	const it = one("expired.crt");
	assert.equal(hasIssue(it, "cert-expired"), true);
	assert.equal(it.daysUntilExpiry < 0, true);
});

test("RSA-1024 certificate → cert-weak-key", () => {
	const it = one("weak-rsa-1024.crt");
	assert.equal(it.bits, 1024);
	assert.equal(hasIssue(it, "cert-weak-key"), true);
});

test("SHA1-signed certificate → cert-weak-signature", () => {
	const it = one("sha1.crt");
	assert.equal(hasIssue(it, "cert-weak-signature"), true);
});

test("self-signed certificate → cert-self-signed (low)", () => {
	const it = one("selfsigned.crt");
	assert.equal(it.selfSigned, true);
	assert.equal(hasIssue(it, "cert-self-signed"), true);
});

test("cert-expiring fires within the window (now-injected)", () => {
	const x = new (require("crypto").X509Certificate)(buf("valid-leaf.crt"));
	const notAfter = Date.parse(x.validTo);
	const soon = analyzeBuffer({ name: "valid-leaf.crt", path: "/p", buf: buf("valid-leaf.crt"), now: notAfter - 10 * 86400000, expiryDays: 90 });
	assert.equal(soon[0].issues.some(i => i.type === "cert-expiring"), true);
	const far = analyzeBuffer({ name: "valid-leaf.crt", path: "/p", buf: buf("valid-leaf.crt"), now: notAfter - 365 * 86400000, expiryDays: 90 });
	assert.equal(far[0].issues.some(i => i.type === "cert-expiring"), false);
});

// ---- private keys (visibility = private) ----
test("standalone PEM private key → critical, visibility private", () => {
	const it = one("private-key.pem");
	assert.equal(it.kind, "private-key");
	assert.equal(it.keyVisibility, "private");
	assert.equal(it.algorithm, "RSA");
	assert.equal(it.encrypted, false);
	assert.equal(it.severity, "critical");
	assert.equal(hasIssue(it, "private-key-committed"), true);
});

test("encrypted PEM private key → critical + encrypted flag", () => {
	const it = one("encrypted-key.pem");
	assert.equal(it.kind, "private-key");
	assert.equal(it.encrypted, true);
	assert.equal(it.severity, "critical");
});

test("OpenSSH private key → critical, algorithm + visibility private", () => {
	const it = one("id_ed25519");
	assert.equal(it.kind, "private-key");
	assert.equal(it.keyVisibility, "private");
	assert.equal(it.format, "openssh");
	assert.equal(it.algorithm, "Ed25519");
});

// ---- public keys (visibility = public) ----
test("standalone PEM public key → public, low", () => {
	const it = one("public-key.pem");
	assert.equal(it.kind, "public-key");
	assert.equal(it.keyVisibility, "public");
	assert.equal(it.severity, "low");
});

test("SSH public key (.pub) → public, ssh format", () => {
	const it = one("id_ed25519.pub");
	assert.equal(it.kind, "public-key");
	assert.equal(it.keyVisibility, "public");
	assert.equal(it.format, "ssh");
	assert.equal(it.algorithm, "Ed25519");
});

test("authorized_keys + known_hosts detected as SSH public keys", () => {
	assert.equal(one("authorized_keys").kind, "public-key");
	const kh = one("known_hosts");
	assert.equal(kh.kind, "public-key");
	assert.equal(kh.algorithm, "RSA");   // host token stripped, ssh-rsa recognised
});

// ---- keystore ----
test("JKS keystore detected by magic → medium", () => {
	const it = one("truststore.jks");
	assert.equal(it.kind, "keystore");
	assert.equal(it.format, "jks");
	assert.equal(hasIssue(it, "keystore-committed"), true);
});

// ---- pure helpers ----
test("detectWeakSig flags SHA1, ignores SHA256", () => {
	assert.equal(detectWeakSig(new (require("crypto").X509Certificate)(buf("sha1.crt")).raw), "SHA1withRSA");
	assert.equal(detectWeakSig(new (require("crypto").X509Certificate)(buf("valid-leaf.crt")).raw), null);
});

test("sshAlgo maps every SSH key type", () => {
	assert.equal(sshAlgo("ssh-rsa"), "RSA");
	assert.equal(sshAlgo("ssh-ed25519"), "Ed25519");
	assert.equal(sshAlgo("ssh-dss"), "DSA");
	assert.equal(sshAlgo("sk-ssh-ed25519@openssh.com"), "Ed25519-SK");
	assert.match(sshAlgo("ecdsa-sha2-nistp256"), /ECDSA/);
});

test("parseOpensshPrivate reads algorithm + encryption state", () => {
	const body = buf("id_ed25519").toString("latin1").match(/-----BEGIN OPENSSH PRIVATE KEY-----\r?\n([\s\S]*?)-----END/)[1];
	const r = parseOpensshPrivate(body);
	assert.equal(r.algorithm, "Ed25519");
	assert.equal(r.encrypted, false);
});

test("keystoreFormat: magic and extension", () => {
	assert.equal(keystoreFormat(Buffer.from([0xfe, 0xed, 0xfe, 0xed]), "x.bin"), "jks");
	assert.equal(keystoreFormat(Buffer.from([0xce, 0xce, 0xce, 0xce]), "x.bin"), "jceks");
	assert.equal(keystoreFormat(Buffer.alloc(8), "store.p12"), "pkcs12");
	assert.equal(keystoreFormat(Buffer.alloc(8), "x.txt"), null);
});

// ---- walk integration ----
test("scan finds a representative mix and rejects non-candidates", () => {
	const kinds = new Set(items.map(i => i.kind));
	for (const k of ["certificate", "private-key", "public-key", "keystore"]) assert.equal(kinds.has(k), true, `missing ${k}`);
	assert.equal(items.every(i => /^[0-9a-f]{64}$/.test(i.sha256)), true);
	// worst-severity-first ordering
	const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
	for (let i = 1; i < items.length; i++) assert.equal(RANK[items[i - 1].severity] >= RANK[items[i].severity], true);
});

test('weak signature detection reads only the certificate signature algorithm, not arbitrary DER bytes', () => {
	const crypto = require('node:crypto');
	const raw = Buffer.from(new crypto.X509Certificate(buf('valid-leaf.crt')).raw);
	// Signature bytes may contain any byte sequence. This changes the signature
	// value, not its declared algorithm, and must never be labelled SHA1.
	const sha1Oid = Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]);
	sha1Oid.copy(raw, raw.length - sha1Oid.length);
	assert.equal(detectWeakSig(raw), null);
	const item = analyzeBuffer({ name: 'oid-in-signature.der', path: '/p', buf: raw })[0];
	assert.equal(item.kind, 'certificate');
	assert.equal(hasIssue(item, 'cert-weak-signature'), false);
	for (const malformed of [sha1Oid, Buffer.from([0x30, 0x80]), Buffer.from([0x30, 0x84, 255, 255, 255, 255]), raw.subarray(0, raw.length - 1)])
		assert.equal(detectWeakSig(malformed), null);
});

test('unknown OpenSSH and PGP encryption is reported as unknown, never asserted encrypted or plaintext', () => {
	for (const [label, body] of [['OPENSSH PRIVATE KEY', 'aW52YWxpZA=='], ['PGP PRIVATE KEY BLOCK', 'aW52YWxpZA==']]) {
		const item = analyzeBuffer({ name: 'key.pem', path: '/p', buf: Buffer.from(`-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`) })[0];
		assert.equal(item.kind, 'private-key');
		assert.equal(item.encrypted, null);
		assert.equal(item.severity, 'critical');
		assert.match(item.issues[0].message, /encryption unknown/);
		assert.doesNotMatch(item.issues[0].message, /\(encrypted\)|UNENCRYPTED/);
	}
});

test('OpenSSH header parsing rejects truncated length-prefixed data instead of guessing plaintext', () => {
	const body = buf('id_ed25519').toString('latin1').match(/-----BEGIN OPENSSH PRIVATE KEY-----\r?\n([\s\S]*?)-----END/)[1];
	const raw = Buffer.from(body.replace(/\s/g, ''), 'base64');
	for (const end of [15, 19, 23, raw.length - 1]) assert.equal(parseOpensshPrivate(raw.subarray(0, end).toString('base64')), null);
	const invalidLength = Buffer.from(raw); invalidLength.writeUInt32BE(0xffffffff, 15);
	assert.equal(parseOpensshPrivate(invalidLength.toString('base64')), null);
	assert.equal(parseOpensshPrivate(body).encrypted, false);
});

test('PuTTY key without an Encryption header retains unknown encryption', () => {
	const item = analyzeBuffer({ name: 'key.ppk', path: '/p', buf: Buffer.from('PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\nAAAA\n') })[0];
	assert.equal(item.encrypted, null);
	assert.equal(item.severity, 'critical');
});
