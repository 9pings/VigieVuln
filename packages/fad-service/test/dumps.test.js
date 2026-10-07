// fad-service milestone 5: dumps — what each kind contains (privacy), signature and
// integrity, restore (idempotent, deltas), seeding a serve-cache relay, torrent, HTTP.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

let sqlite = true;
try { require("node:sqlite"); } catch { sqlite = false; }
const opts = { skip: !sqlite && "node:sqlite unavailable" };
const BIN = path.join(__dirname, "..", "bin", "fad-service.js");
const FAD = path.join(__dirname, "..", "..", "..", "lib");
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-dump-"));

function fixtureDb(file = ":memory:") {
	const { openDatabase, createSqliteStore } = require("../lib/sqlite-store");
	const { createAssetStore } = require("../lib/assets");
	const db = openDatabase(file);
	const assets = createAssetStore(db), store = createSqliteStore({ db });
	assets.upsert({ type: "cve", key: "CVE-2021-44228", title: "Log4Shell", summary: "log4j jndi", aliases: ["GCVE-0-2021-44228"],
		data: { id: "CVE-2021-44228" }, sources: [{ name: "CVE List", licence: "ToU", url: "https://www.cve.org/" }] });
	assets.upsert({ type: "advisory", key: "osv:GHSA-jfh8-c2jp-5v3q", title: "RCE in log4j", data: { id: "GHSA-jfh8-c2jp-5v3q", affected: [] }, sources: [] });
	assets.transaction(() => { assets.linkAdvisory("osv:GHSA-jfh8-c2jp-5v3q", ["CVE-2021-44228"]); assets.linkAdvisoryPackages("osv:GHSA-jfh8-c2jp-5v3q", ["pkg:maven/org.apache.logging.log4j/log4j-core"]); });
	assets.setSignal("kev", [["CVE-2021-44228", { dateAdded: "2021-12-10" }]]);
	assets.setNvd([{ id: "CVE-2021-44228", vulnStatus: "Analyzed", metrics: [] }]);
	assets.upsert({ type: "package", key: "pkg:npm/left-pad", title: "left-pad", data: { name: "left-pad", type: "npm" }, sources: [], published: true });
	assets.upsert({ type: "package", key: "pkg:npm/@acme/secret-stack", title: "@acme/secret-stack", data: { name: "@acme/secret-stack" }, sources: [], published: false });
	const put = (key, body) => store.put(key, Buffer.from(body), { fetchedAt: Date.now(), ttlMs: 86400000, contentType: "application/json", bytes: Buffer.byteLength(body) });
	put(JSON.stringify(["npm", "package", { name: "left-pad" }, ""]), '{"name":"left-pad"}');
	put(JSON.stringify(["npm", "package", { name: "@acme/secret-stack" }, ""]), '{"name":"@acme/secret-stack"}');
	put(JSON.stringify(["nvd", "cve", { id: "CVE-2021-44228" }, ""]), '{"vulnerabilities":[]}');
	put(JSON.stringify(["nvd", "cve", { id: "CVE-2021-44228" }, "client-credential-hash"]), '{"keyed":true}');
	return { db, assets, store };
}

async function linesOf(payload) {
	return zlib.gunzipSync(fs.readFileSync(payload)).toString().trim().split("\n").map(l => JSON.parse(l));
}

function keys(dir) {
	const out = execFileSync(process.execPath, [BIN, "keygen", "--out", dir], { encoding: "utf8" });
	assert.match(out, /fingerprint [0-9a-f]{4}(:[0-9a-f]{4}){7}/);
	assert.equal((fs.statSync(path.join(dir, "dump-signing.key")).mode & 0o777).toString(8), "600");
	assert.throws(() => execFileSync(process.execPath, [BIN, "keygen", "--out", dir], { stdio: "pipe" }), "never overwrites a key");
	return { priv: fs.readFileSync(path.join(dir, "dump-signing.key"), "utf8"), pubFile: path.join(dir, "dump-signing.pub.pem") };
}

test("dump kinds: public = published vulnerability data only; private adds what a relay needs; full = everything", opts, async () => {
	const { buildDump } = require("../lib/dumps/build");
	const { db, assets } = fixtureDb();
	const dir = tmp();
	try {
		const build = kind => buildDump({ db, assets, dir: path.join(dir, kind), kind });
		const pub = await build("public"), priv = await build("private"), full = await build("full");
		const L = async m => linesOf(path.join(dir, m.kind, m.payload.file));
		const p = await L(pub), q = await L(priv), f = await L(full);
		assert.deepEqual(p.filter(l => l.t === "asset").map(l => l.key).sort(), ["CVE-2021-44228", "osv:GHSA-jfh8-c2jp-5v3q"]);
		assert.ok(!p.some(l => l.t === "resource"), "no cache entries in a public build");
		assert.deepEqual(p.find(l => l.t === "links").packages, [], "no package links either");
		assert.ok(p.some(l => l.t === "signal" && l.cve === "CVE-2021-44228") && p.some(l => l.t === "nvd"));

		const privText = JSON.stringify(q);
		assert.ok(q.some(l => l.t === "asset" && l.key === "pkg:npm/left-pad"));
		assert.ok(!privText.includes("secret-stack"), "an unpublished package never leaves — neither its page nor its cache entry");
		assert.ok(!privText.includes("keyed"), "an entry fetched with a client's credentials never leaves");
		assert.equal(q.filter(l => l.t === "resource").length, 2, "left-pad + the NVD entry");

		assert.ok(JSON.stringify(f).includes("secret-stack"), "full = replication between your own instances");
		assert.equal(f.filter(l => l.t === "resource").length, 4);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("signature and integrity: verified, tampering detected, wrong key refused", opts, async () => {
	const { buildDump } = require("../lib/dumps/build");
	const { openDump } = require(path.join(FAD, "dump-format.js"));
	const { db, assets } = fixtureDb();
	const dir = tmp(), kd = tmp();
	try {
		const { priv, pubFile } = keys(kd);
		const m = await buildDump({ db, assets, dir, kind: "public", signingKeyPem: priv });
		const manifest = path.join(dir, `${m.id}.manifest.json`);
		const pem = fs.readFileSync(pubFile, "utf8");
		assert.equal((await openDump(manifest, { publicKeyPem: pem })).manifest.id, m.id);
		assert.match(execFileSync(process.execPath, [BIN, "verify", manifest, "--trust-key", pubFile], { encoding: "utf8" }), /^OK fad-public-/);

		const other = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
		await assert.rejects(openDump(manifest, { publicKeyPem: other }), /bad signature/);
		const original = fs.readFileSync(manifest);
		fs.writeFileSync(manifest, original.toString().replace('"public"', '"full"'));
		await assert.rejects(openDump(manifest, { publicKeyPem: pem }), /bad signature/, "a modified manifest");
		fs.writeFileSync(manifest, original);
		fs.appendFileSync(path.join(dir, m.payload.file), "x");
		await assert.rejects(openDump(manifest, { publicKeyPem: pem }), /sha256 mismatch/, "a modified payload");
	} finally { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(kd, { recursive: true, force: true }); }
});

test("restore: search and links work on the copy; replaying is a no-op; a delta applies on top", opts, async () => {
	const { buildDump } = require("../lib/dumps/build");
	const { restoreDump } = require("../lib/dumps/restore");
	const src = fixtureDb();
	const dir = tmp();
	try {
		const m = await buildDump({ db: src.db, assets: src.assets, dir, kind: "full" });
		const empty = (() => { const { openDatabase, createSqliteStore } = require("../lib/sqlite-store"); const { createAssetStore } = require("../lib/assets");
			const db = openDatabase(":memory:"); return { db, assets: createAssetStore(db), store: createSqliteStore({ db }) }; })();
		const r1 = await restoreDump({ assets: empty.assets, store: empty.store, manifestPath: path.join(dir, `${m.id}.manifest.json`) });
		assert.equal(r1.counts.asset, 4);
		assert.equal(empty.assets.search("GCVE-0-2021-44228")[0].key, "CVE-2021-44228", "aliases survive a dump");
		assert.deepEqual(empty.assets.advisoriesForCve("CVE-2021-44228").map(a => a.key), ["osv:GHSA-jfh8-c2jp-5v3q"]);
		assert.equal(empty.assets.signals("CVE-2021-44228").kev.dateAdded, "2021-12-10");
		assert.equal(empty.assets.nvd("CVE-2021-44228").vulnStatus, "Analyzed");
		assert.equal(empty.store.size(), 4);
		const r2 = await restoreDump({ assets: empty.assets, store: empty.store, manifestPath: path.join(dir, `${m.id}.manifest.json`) });
		assert.equal(r2.counts.asset, 0); assert.equal(r2.counts.assetKept, 4); assert.equal(r2.counts.resource, 0);

		const since = Date.now();
		await new Promise(ok => setTimeout(ok, 5));
		src.assets.upsert({ type: "cve", key: "CVE-2021-44228", title: "Log4Shell (updated)", summary: "log4j", data: { id: "CVE-2021-44228", v: 2 }, sources: [] });
		const d = await buildDump({ db: src.db, assets: src.assets, dir, kind: "full", since });
		assert.equal(d.delta, true);
		assert.equal(d.counts.asset, 1, "only what changed");
		await restoreDump({ assets: empty.assets, store: empty.store, manifestPath: path.join(dir, `${d.id}.manifest.json`) });
		assert.equal(empty.assets.get("cve", "CVE-2021-44228").title, "Log4Shell (updated)");
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("relay: fad-checker serve-cache --seed fills its store from a private build and answers without upstream", opts, async () => {
	const { buildDump } = require("../lib/dumps/build");
	const { createCacheStore, startProxyCacheServer } = require(path.join(FAD, "proxy-cache.js"));
	const { openDump, seedResourceStore } = require(path.join(FAD, "dump-format.js"));
	const { db, assets } = fixtureDb();
	const dir = tmp(), storeDir = tmp();
	try {
		const m = await buildDump({ db, assets, dir, kind: "private" });
		const { payloadPath } = await openDump(path.join(dir, `${m.id}.manifest.json`));
		assert.deepEqual(await seedResourceStore(createCacheStore(storeDir), payloadPath), { imported: 2, kept: 0 });
		const running = await startProxyCacheServer({ port: 0, store: createCacheStore(storeDir), fetcher: () => { throw new Error("must not fetch"); } });
		try {
			const r = await fetch(`${running.url}/v1/resource`, { method: "POST", body: JSON.stringify({ provider: "npm", type: "package", params: { name: "left-pad" } }) });
			assert.equal(r.headers.get("x-fad-proxy"), "hit");
			assert.equal((await r.json()).name, "left-pad");
		} finally { await new Promise(ok => running.server.close(ok)); }
	} finally { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(storeDir, { recursive: true, force: true }); }
});

/** Minimal bencode decoder, enough to read back what we wrote. */
function bdecode(buf, i = 0) {
	const c = String.fromCharCode(buf[i]);
	if (c === "i") { const e = buf.indexOf(0x65, i); return [Number(buf.slice(i + 1, e)), e + 1]; }
	if (c === "l" || c === "d") {
		const out = c === "l" ? [] : {}; i++;
		while (buf[i] !== 0x65) {
			if (c === "l") { const [v, n] = bdecode(buf, i); out.push(v); i = n; }
			else { const [k, n] = bdecode(buf, i); const [v, n2] = bdecode(buf, n); out[k.toString()] = v; i = n2; }
		}
		return [out, i + 1];
	}
	const colon = buf.indexOf(0x3a, i), len = Number(buf.slice(i, colon));
	return [buf.slice(colon + 1, colon + 1 + len), colon + 1 + len];
}

test("torrent: web seed on the HTTPS file, pieces match the payload, magnet carries the info-hash", opts, async () => {
	const { buildDump } = require("../lib/dumps/build");
	const { bencode } = require("../lib/dumps/torrent");
	const { db, assets } = fixtureDb();
	const dir = tmp();
	try {
		const m = await buildDump({ db, assets, dir, kind: "public", baseUrl: "https://vuln.example.fr", trackers: ["udp://tracker.example:1337"] });
		const [t] = bdecode(fs.readFileSync(path.join(dir, m.torrent.file)));
		const payload = fs.readFileSync(path.join(dir, m.payload.file));
		assert.equal(t.info.length, payload.length);
		assert.equal(t["url-list"][0].toString(), `https://vuln.example.fr/dumps/files/${m.payload.file}`);
		const pl = t.info["piece length"];
		assert.deepEqual(t.info.pieces.subarray(0, 20), crypto.createHash("sha1").update(payload.subarray(0, pl)).digest());
		assert.equal(crypto.createHash("sha1").update(bencode(t.info)).digest("hex"), m.torrent.infoHash);
		assert.match(m.torrent.magnet, new RegExp(`^magnet:\\?xt=urn:btih:${m.torrent.infoHash}&dn=.*&ws=https%3A%2F%2Fvuln\\.example\\.fr`));
		assert.match(m.torrent.magnet, /tr=udp%3A%2F%2Ftracker\.example%3A1337/);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("HTTP: /dumps lists public builds, files support Range, private builds need a token, no path escapes", opts, async () => {
	const { buildDump } = require("../lib/dumps/build");
	const { createServiceServer } = require("../lib/server");
	const { createTokenStore } = require("../lib/tokens");
	const { db, assets, store } = fixtureDb();
	const dumpsDir = tmp(), kd = tmp();
	try {
		const { priv } = keys(kd);
		const pub = await buildDump({ db, assets, dir: path.join(dumpsDir, "public"), kind: "public", signingKeyPem: priv });
		const prv = await buildDump({ db, assets, dir: path.join(dumpsDir, "private"), kind: "private", signingKeyPem: priv });
		const tokens = createTokenStore(db);
		const client = tokens.add({ role: "client" }).token;
		const server = createServiceServer({ store, tokens, assets, dumps: { dir: dumpsDir, signingKeyFile: path.join(kd, "dump-signing.key") } });
		await new Promise(ok => server.listen(0, "127.0.0.1", ok));
		const base = `http://127.0.0.1:${server.address().port}`;
		try {
			const page = await (await fetch(`${base}/dumps?lang=en`)).text();
			assert.match(page, new RegExp(pub.id));
			assert.ok(!page.includes(prv.id), "private builds are not listed");
			assert.match(page, /signing-key\.pem/);
			assert.match(await (await fetch(`${base}/dumps/signing-key.pem`)).text(), /BEGIN PUBLIC KEY/);
			assert.equal((await (await fetch(`${base}/dumps/latest.json`)).json()).id, pub.id);
			const part = await fetch(`${base}/dumps/files/${pub.payload.file}`, { headers: { range: "bytes=0-9" } });
			assert.equal(part.status, 206);
			assert.equal(part.headers.get("content-range"), `bytes 0-9/${pub.payload.bytes}`);
			assert.equal((await part.arrayBuffer()).byteLength, 10);
			assert.equal((await fetch(`${base}/dumps/files/${prv.payload.file}`)).status, 404, "a private file is not public");
			assert.equal((await fetch(`${base}/dumps/private/${prv.payload.file}`)).status, 401);
			assert.equal((await fetch(`${base}/dumps/private/${prv.payload.file}`, { headers: { authorization: `Bearer ${client}` } })).status, 200);
			for (const evil of ["..%2F..%2Fetc%2Fpasswd", "fad-public-20260101T000000Z.jsonl.gz%2F..%2F..%2Fx", "..", "x.manifest.json"])
				assert.equal((await fetch(`${base}/dumps/files/${evil}`)).status, 404, evil);
		} finally { await new Promise(ok => server.close(ok)); }
	} finally { fs.rmSync(dumpsDir, { recursive: true, force: true }); fs.rmSync(kd, { recursive: true, force: true }); }
});

test("CLI: fad-checker serve-cache --seed … --trust-key … --seed-only", opts, async () => {
	const { buildDump } = require("../lib/dumps/build");
	const { db, assets } = fixtureDb();
	const dir = tmp(), kd = tmp(), storeDir = tmp();
	try {
		const { priv, pubFile } = keys(kd);
		const m = await buildDump({ db, assets, dir, kind: "private", signingKeyPem: priv });
		const out = execFileSync(process.execPath, [path.join(FAD, "..", "fad-checker.js"), "serve-cache", "--cache-dir", storeDir,
			"--seed", path.join(dir, `${m.id}.manifest.json`), "--trust-key", pubFile, "--seed-only"], { encoding: "utf8", env: { ...process.env, FORCE_COLOR: "0" } });
		assert.match(out, /signature ok/);
		assert.match(out, /2 entries imported/);
		const bad = crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
		fs.writeFileSync(path.join(kd, "other.pem"), bad);
		assert.throws(() => execFileSync(process.execPath, [path.join(FAD, "..", "fad-checker.js"), "serve-cache", "--cache-dir", storeDir,
			"--seed", path.join(dir, `${m.id}.manifest.json`), "--trust-key", path.join(kd, "other.pem"), "--seed-only"], { stdio: "pipe" }), "a build from another key is refused");
	} finally { for (const d of [dir, kd, storeDir]) fs.rmSync(d, { recursive: true, force: true }); }
});

test("payload lines survive U+2028 / U+2029 inside data (readline would split them)", opts, async () => {
	const { buildDump } = require("../lib/dumps/build");
	const { openDump, readLines } = require(path.join(FAD, "dump-format.js"));
	const { db, assets } = fixtureDb();
	assets.upsert({ type: "cve", key: "CVE-2024-2028", title: "line separator", summary: "para graph", data: { id: "CVE-2024-2028", description: "a b" }, sources: [] });
	const dir = tmp();
	try {
		const m = await buildDump({ db, assets, dir, kind: "public" });
		const { payloadPath } = await openDump(path.join(dir, `${m.id}.manifest.json`));
		const got = [];
		for await (const l of readLines(payloadPath)) if (l.key === "CVE-2024-2028") got.push(l);
		assert.equal(got[0].data.description, "a b");
		assert.ok(!zlib.gunzipSync(fs.readFileSync(payloadPath)).toString().includes(" "), "escaped on disk");
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
