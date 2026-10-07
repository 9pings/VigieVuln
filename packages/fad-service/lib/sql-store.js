/**
 * The resource store of the engine (interface: fad-checker lib/resource-cache/fs-store.js)
 * on the service database — SQLite or PostgreSQL, through lib/db.js.
 *
 * - A row is replaced atomically and get() returns its body with its metadata, so a reader
 *   never pairs one generation's metadata with another's body.
 * - Bodies live in the row (BLOB / BYTEA), up to maxEntryBytes; above it the engine streams
 *   the answer once from the spool file and does not keep it (store.maxEntryBytes).
 * - No ownership lock: several processes and hosts share the database.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { Readable } = require("node:stream");

const TRANSIENT_KEEP_MS = 30 * 1000;
const DEFAULT_MAX_ENTRY_BYTES = 64 * 1024 * 1024;

const SCHEMA = `CREATE TABLE IF NOT EXISTS resources (
	key TEXT PRIMARY KEY,
	fetched_at {INT} NOT NULL,
	ttl_ms {INT} NOT NULL,
	content_type TEXT,
	response_headers TEXT,
	bytes {INT} NOT NULL,
	body {BLOB} NOT NULL
)`;

async function createSqlStore({ driver, spoolDir = os.tmpdir(), maxEntryBytes = DEFAULT_MAX_ENTRY_BYTES }) {
	await driver.exec(driver.ddl(SCHEMA));
	const store = {
		kind: driver.dialect === "pg" ? "postgresql" : "sqlite",
		driver,
		maxEntryBytes,
		async get(key) {
			const row = await driver.get("SELECT fetched_at, ttl_ms, content_type, response_headers, bytes, body FROM resources WHERE key = ?", [String(key)]);
			if (!row) return null;
			const body = Buffer.from(row.body);
			if (body.length !== Number(row.bytes)) return null;
			return { key, fetchedAt: Number(row.fetched_at), ttlMs: Number(row.ttl_ms), contentType: row.content_type,
				responseHeaders: row.response_headers ? JSON.parse(row.response_headers) : {}, bytes: Number(row.bytes), body };
		},
		acquire() { return () => {}; },
		openBody(entry) { return entry.body ? Readable.from([entry.body]) : fs.createReadStream(entry.filePath); },
		readBody(entry) { return entry.body || fs.readFileSync(entry.filePath); },
		async put(key, buffer, meta) {
			const body = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
			await driver.run(`INSERT INTO resources (key, fetched_at, ttl_ms, content_type, response_headers, bytes, body) VALUES (?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (key) DO UPDATE SET fetched_at = excluded.fetched_at, ttl_ms = excluded.ttl_ms, content_type = excluded.content_type,
					response_headers = excluded.response_headers, bytes = excluded.bytes, body = excluded.body`,
			[String(key), meta.fetchedAt, meta.ttlMs, meta.contentType || null, meta.responseHeaders ? JSON.stringify(meta.responseHeaders) : null, body.length, body]);
		},
		createWriter() {
			const tmp = path.join(spoolDir, `fad-service-${process.pid}-${crypto.randomBytes(6).toString("hex")}.part`);
			const drop = () => fs.rmSync(tmp, { force: true });
			return {
				account() {},
				sink() { return fs.createWriteStream(tmp); },
				bytes() { return fs.statSync(tmp).size; },
				read() { return fs.readFileSync(tmp); },
				async commit(key, meta) { try { await store.put(key, fs.readFileSync(tmp), meta); } finally { drop(); } },
				detach(meta) {
					const timer = setTimeout(drop, TRANSIENT_KEEP_MS);
					timer.unref?.();
					return { ...meta, filePath: tmp };
				},
				abort: drop,
			};
		},
		async purge(key) { return (await driver.run("DELETE FROM resources WHERE key = ?", [String(key)])).changes > 0; },
		async size() { return Number((await driver.get("SELECT COUNT(*) AS n FROM resources")).n); },
		async bodyBytes() { return Number((await driver.get("SELECT COALESCE(SUM(bytes), 0) AS b FROM resources")).b); },
		async clear() { const n = await store.size(); await driver.run("DELETE FROM resources"); return n; },
	};
	return store;
}

module.exports = { createSqlStore, DEFAULT_MAX_ENTRY_BYTES };
