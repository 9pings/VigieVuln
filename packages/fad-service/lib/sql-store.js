/**
 * The resource store of the engine (interface: fad-checker lib/resource-cache/fs-store.js)
 * on the service database — SQLite or PostgreSQL, through lib/db.js.
 *
 * Memory is bounded on purpose (a public instance serves many concurrent readers):
 * - get() returns METADATA only; the body is loaded when it is streamed, and only if the
 *   row still holds the same generation (fetched_at + bytes) — a reader never pairs one
 *   generation's metadata with another's body;
 * - bodies being served share a byte budget (maxBodyBytesInFlight): past it, a reader
 *   waits for one to finish — N concurrent hits on a 64 MB entry no longer mean N × 64 MB;
 * - bodies above maxEntryBytes are never stored (the engine streams them once from a spool
 *   file), and spool files share a quota (maxSpoolBytes): past it, the fetch is refused.
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
const DEFAULT_MAX_BODY_BYTES_IN_FLIGHT = 256 * 1024 * 1024;
const DEFAULT_MAX_SPOOL_BYTES = 2 * 1024 * 1024 * 1024;

const SCHEMA = `CREATE TABLE IF NOT EXISTS resources (
	key TEXT PRIMARY KEY,
	fetched_at {INT} NOT NULL,
	ttl_ms {INT} NOT NULL,
	content_type TEXT,
	response_headers TEXT,
	bytes {INT} NOT NULL,
	body {BLOB} NOT NULL
)`;

/** A byte budget shared by concurrent readers; one request larger than it passes alone. */
function byteSemaphore(limit) {
	let used = 0;
	const waiting = [];
	const pump = () => {
		while (waiting.length) {
			const next = waiting[0];
			if (used > 0 && used + next.n > limit) return;
			waiting.shift();
			used += next.n;
			next.go();
		}
	};
	return {
		acquire(n) { return new Promise(go => { waiting.push({ n, go }); pump(); }); },
		release(n) { used = Math.max(0, used - n); pump(); },
		get used() { return used; },
	};
}

async function createSqlStore({ driver, spoolDir = os.tmpdir(), maxEntryBytes = DEFAULT_MAX_ENTRY_BYTES,
	maxBodyBytesInFlight = DEFAULT_MAX_BODY_BYTES_IN_FLIGHT, maxSpoolBytes = DEFAULT_MAX_SPOOL_BYTES }) {
	await driver.exec(driver.ddl(SCHEMA));
	const budget = byteSemaphore(maxBodyBytesInFlight);
	let spoolBytes = 0;

	/** The body of exactly this generation, or null when the row changed meanwhile. */
	const loadBody = async entry => {
		const row = await driver.get("SELECT body FROM resources WHERE key = ? AND fetched_at = ? AND bytes = ?",
			[String(entry.key), entry.fetchedAt, entry.bytes]);
		return row ? Buffer.from(row.body) : null;
	};

	const store = {
		kind: driver.dialect === "pg" ? "postgresql" : "sqlite",
		driver,
		maxEntryBytes,
		budget,
		spoolBytes: () => spoolBytes,
		async get(key) {
			const row = await driver.get("SELECT fetched_at, ttl_ms, content_type, response_headers, bytes FROM resources WHERE key = ?", [String(key)]);
			if (!row) return null;
			return { key: String(key), fetchedAt: Number(row.fetched_at), ttlMs: Number(row.ttl_ms), contentType: row.content_type,
				responseHeaders: row.response_headers ? JSON.parse(row.response_headers) : {}, bytes: Number(row.bytes) };
		},
		acquire() { return () => {}; },
		/** Stream one body: waits for the byte budget, loads it, releases when the stream ends. */
		openBody(entry) {
			if (entry.filePath) return fs.createReadStream(entry.filePath);
			let started = false, held = 0;
			const release = () => { if (held) { budget.release(held); held = 0; } };
			const stream = new Readable({
				async read() {
					if (started) return;
					started = true;
					try {
						await budget.acquire(entry.bytes);
						held = entry.bytes;
						const body = entry.body || await loadBody(entry);
						if (!body) throw new Error("resource replaced while being served");
						this.push(body);
						this.push(null);
					} catch (e) { release(); this.destroy(e); }
				},
				destroy(err, cb) { release(); cb(err); },
			});
			stream.on("end", release);
			return stream;
		},
		async readBody(entry) {
			if (entry.body) return entry.body;
			if (entry.filePath) return fs.readFileSync(entry.filePath);
			const body = await loadBody(entry);
			if (!body) throw new Error("resource replaced while being read");
			return body;
		},
		async put(key, buffer, meta) {
			const body = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
			await driver.run(`INSERT INTO resources (key, fetched_at, ttl_ms, content_type, response_headers, bytes, body) VALUES (?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (key) DO UPDATE SET fetched_at = excluded.fetched_at, ttl_ms = excluded.ttl_ms, content_type = excluded.content_type,
					response_headers = excluded.response_headers, bytes = excluded.bytes, body = excluded.body`,
			[String(key), meta.fetchedAt, meta.ttlMs, meta.contentType || null, meta.responseHeaders ? JSON.stringify(meta.responseHeaders) : null, body.length, body]);
		},
		createWriter() {
			const tmp = path.join(spoolDir, `fad-service-${process.pid}-${crypto.randomBytes(6).toString("hex")}.part`);
			let accounted = 0, dropped = false;
			const drop = () => {
				if (dropped) return;
				dropped = true;
				fs.rmSync(tmp, { force: true });
				spoolBytes -= accounted; accounted = 0;
			};
			return {
				account(n) {
					if (spoolBytes + n > maxSpoolBytes) throw new Error("spool quota exceeded — retry later");
					spoolBytes += n; accounted += n;
				},
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

module.exports = { createSqlStore, byteSemaphore, DEFAULT_MAX_ENTRY_BYTES };
