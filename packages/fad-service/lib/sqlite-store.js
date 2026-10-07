/**
 * The SQLite resource store: the resource-engine interface (fad-checker
 * lib/resource-cache/fs-store.js documents it) on one database file, through Node's
 * built-in node:sqlite — no dependency.
 *
 * - WAL journal + busy timeout: several processes on ONE host (`--workers N`) share the
 *   file; SQLite serialises writers. Several hosts need the PostgreSQL store.
 * - A row is replaced atomically, and get() returns its body with its metadata, so a
 *   reader can never pair one generation's metadata with another's body.
 * - Bodies live in the row. That suits metadata (POMs, projections, advisories, a few
 *   MB at most); the separate body store of the spec comes with the PostgreSQL mode.
 * - A body above the engine's cache limit is never stored: it is spooled to a temp file
 *   and served once from there (detach), like the directory store does.
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

function openDatabase(file) {
	const { DatabaseSync } = require("node:sqlite");
	if (file !== ":memory:") fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
	const db = new DatabaseSync(file);
	db.exec("PRAGMA busy_timeout = 5000");
	if (file !== ":memory:") db.exec("PRAGMA journal_mode = WAL");
	db.exec("PRAGMA synchronous = NORMAL");
	return db;
}

// Bodies live in rows: above this a body is streamed to the client once and not kept
// (the engine honours store.maxEntryBytes) — e.g. the 620 MB cvelistV5 archive.
const DEFAULT_MAX_ENTRY_BYTES = 64 * 1024 * 1024;

function createSqliteStore({ db, file = null, spoolDir = os.tmpdir(), maxEntryBytes = DEFAULT_MAX_ENTRY_BYTES } = {}) {
	db = db || openDatabase(file || ":memory:");
	db.exec(`CREATE TABLE IF NOT EXISTS resources (
		key TEXT PRIMARY KEY,
		fetched_at INTEGER NOT NULL,
		ttl_ms INTEGER NOT NULL,
		content_type TEXT,
		response_headers TEXT,
		bytes INTEGER NOT NULL,
		body BLOB NOT NULL
	)`);
	const q = {
		get: db.prepare("SELECT fetched_at, ttl_ms, content_type, response_headers, bytes, body FROM resources WHERE key = ?"),
		put: db.prepare(`INSERT INTO resources (key, fetched_at, ttl_ms, content_type, response_headers, bytes, body)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET fetched_at = excluded.fetched_at, ttl_ms = excluded.ttl_ms,
				content_type = excluded.content_type, response_headers = excluded.response_headers,
				bytes = excluded.bytes, body = excluded.body`),
		purge: db.prepare("DELETE FROM resources WHERE key = ?"),
		count: db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b FROM resources"),
		clear: db.prepare("DELETE FROM resources"),
	};

	const store = {
		kind: "sqlite",
		db,
		maxEntryBytes,
		get(key) {
			const row = q.get.get(String(key));
			if (!row) return null;
			const body = Buffer.from(row.body);
			if (body.length !== row.bytes) return null;
			return { key, fetchedAt: row.fetched_at, ttlMs: row.ttl_ms, contentType: row.content_type,
				responseHeaders: row.response_headers ? JSON.parse(row.response_headers) : {}, bytes: row.bytes, body };
		},
		acquire() { return () => {}; },
		openBody(entry) { return entry.body ? Readable.from([entry.body]) : fs.createReadStream(entry.filePath); },
		readBody(entry) { return entry.body || fs.readFileSync(entry.filePath); },
		put(key, buffer, meta) {
			const body = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
			q.put.run(String(key), meta.fetchedAt, meta.ttlMs, meta.contentType || null,
				meta.responseHeaders ? JSON.stringify(meta.responseHeaders) : null, body.length, body);
		},
		createWriter() {
			const tmp = path.join(spoolDir, `fad-service-${process.pid}-${crypto.randomBytes(6).toString("hex")}.part`);
			const drop = () => fs.rmSync(tmp, { force: true });
			return {
				account() {},
				sink() { return fs.createWriteStream(tmp); },
				bytes() { return fs.statSync(tmp).size; },
				read() { return fs.readFileSync(tmp); },
				commit(key, meta) { try { store.put(key, fs.readFileSync(tmp), meta); } finally { drop(); } },
				detach(meta) {
					const timer = setTimeout(drop, TRANSIENT_KEEP_MS);
					timer.unref?.();
					return { ...meta, filePath: tmp };
				},
				abort: drop,
			};
		},
		purge(key) { return q.purge.run(String(key)).changes > 0; },
		size() { return Number(q.count.get().n); },
		bodyBytes() { return Number(q.count.get().b); },
		clear() { const n = store.size(); q.clear.run(); return n; },
		close() { db.close(); },
	};
	return store;
}

module.exports = { createSqliteStore, openDatabase };
