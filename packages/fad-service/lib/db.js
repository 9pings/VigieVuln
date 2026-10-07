/**
 * The database driver: one async API over SQLite (node:sqlite, one host) and PostgreSQL
 * (pg, any number of instances). Everything in the service goes through it.
 *
 *   openDb("fad-service.db" | ":memory:" | "postgres://…") → driver
 *   driver.dialect                 "sqlite" | "pg"
 *   driver.exec(sql)               DDL / multi-statement, no parameters
 *   driver.get(sql, params)        → first row | null
 *   driver.all(sql, params)        → rows
 *   driver.run(sql, params)        → { changes, lastId }   (lastId: SQLite rowid, or a RETURNING id)
 *   driver.iterate(sql, params)    → async iterator of rows (PostgreSQL: a server-side cursor)
 *   driver.transaction(async tx => …)  tx has the same API; committed or rolled back
 *   driver.ddl(text)               schema text with {INT} {REAL} {BLOB} {ID} placeholders → dialect DDL
 *   driver.close()
 *
 * SQL is written once with `?` placeholders (rewritten to $1… for PostgreSQL) and the
 * syntax both accept (ON CONFLICT … DO UPDATE/NOTHING, COALESCE, CASE). Where the two
 * genuinely differ — full-text search, maintenance, migrations — the caller branches on
 * `dialect`. Integers that hold millisecond timestamps are BIGINT on PostgreSQL; numeric
 * results come back as JS numbers on both.
 *
 * SQLite note: its calls are synchronous; a transaction whose body only awaits driver
 * calls therefore runs within one macrotask — no other request can interleave its writes.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("node:fs");
const path = require("node:path");

const DDL = {
	sqlite: { "{INT}": "INTEGER", "{REAL}": "REAL", "{BLOB}": "BLOB", "{ID}": "INTEGER PRIMARY KEY AUTOINCREMENT" },
	pg: { "{INT}": "BIGINT", "{REAL}": "DOUBLE PRECISION", "{BLOB}": "BYTEA", "{ID}": "BIGSERIAL PRIMARY KEY" },
};
const ddlFor = dialect => text => text.replace(/\{INT\}|\{REAL\}|\{BLOB\}|\{ID\}/g, t => DDL[dialect][t]);

/** `?` → `$1, $2…` (no `?` appears inside our SQL string literals). */
function toPg(sql) { let i = 0; return sql.replace(/\?/g, () => `$${++i}`); }

/** Numeric strings PostgreSQL returns for BIGINT / COUNT / SUM → numbers. */
function normaliseRow(row) {
	if (!row) return row;
	for (const k of Object.keys(row)) {
		const v = row[k];
		if (typeof v === "bigint") row[k] = Number(v);
	}
	return row;
}

function sqliteDriver(file) {
	const { DatabaseSync } = require("node:sqlite");
	if (file !== ":memory:") fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
	const db = new DatabaseSync(file);
	db.exec("PRAGMA busy_timeout = 5000");
	if (file !== ":memory:") db.exec("PRAGMA journal_mode = WAL");
	db.exec("PRAGMA synchronous = NORMAL");
	const cache = new Map();
	const stmt = sql => { let s = cache.get(sql); if (!s) { s = db.prepare(sql); cache.set(sql, s); } return s; };
	let depth = 0;
	const api = {
		dialect: "sqlite", raw: db, file,
		ddl: ddlFor("sqlite"),
		async exec(sql) { db.exec(sql); },
		async get(sql, p = []) { return normaliseRow(stmt(sql).get(...p)) || null; },
		async all(sql, p = []) { return stmt(sql).all(...p).map(normaliseRow); },
		async run(sql, p = []) { const r = stmt(sql).run(...p); return { changes: Number(r.changes), lastId: Number(r.lastInsertRowid) }; },
		async *iterate(sql, p = []) { for (const r of db.prepare(sql).iterate(...p)) yield normaliseRow(r); },
		async transaction(fn) {
			if (depth) return fn(api);                      // nested: part of the outer one
			depth++;
			db.exec("BEGIN IMMEDIATE");
			try { const r = await fn(api); db.exec("COMMIT"); return r; }
			catch (e) { try { db.exec("ROLLBACK"); } catch { /* already rolled back */ } throw e; }
			finally { depth--; }
		},
		async close() { db.close(); },
	};
	return api;
}

function pgDriver(url, { max = 10 } = {}) {
	const { Pool, types } = require("pg");
	types.setTypeParser(20, v => Number(v));       // BIGINT → number (timestamps, counts)
	types.setTypeParser(1700, v => Number(v));     // NUMERIC (SUM) → number
	const pool = new Pool({ connectionString: url, max, application_name: "fad-service" });
	const on = client => {
		const q = (sql, p = []) => client.query(toPg(sql), p);
		const api = {
			dialect: "pg", ddl: ddlFor("pg"),
			async exec(sql) { await client.query(sql); },
			async get(sql, p) { return normaliseRow((await q(sql, p)).rows[0]) || null; },
			async all(sql, p) { return (await q(sql, p)).rows.map(normaliseRow); },
			async run(sql, p) {
				const r = await q(sql, p);
				return { changes: r.rowCount ?? 0, lastId: r.rows?.[0]?.id != null ? Number(r.rows[0].id) : null };
			},
			async *iterate(sql, p = []) {
				// A cursor needs a transaction of its own on one connection.
				const c = client === pool ? await pool.connect() : client;
				const name = `c_${Math.random().toString(36).slice(2)}`;
				const own = c !== client;
				try {
					if (own) await c.query("BEGIN");
					await c.query(`DECLARE ${name} NO SCROLL CURSOR FOR ${toPg(sql)}`, p);
					for (;;) {
						const { rows } = await c.query(`FETCH 1000 FROM ${name}`);
						if (!rows.length) break;
						for (const r of rows) yield normaliseRow(r);
					}
					await c.query(`CLOSE ${name}`);
					if (own) await c.query("COMMIT");
				} catch (e) { if (own) await c.query("ROLLBACK").catch(() => {}); throw e; }
				finally { if (own) c.release(); }
			},
			async transaction(fn) {
				if (client !== pool) return fn(api);            // already inside one
				const c = await pool.connect();
				try {
					await c.query("BEGIN");
					const r = await fn(on(c));
					await c.query("COMMIT");
					return r;
				} catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
				finally { c.release(); }
			},
		};
		return api;
	};
	const api = on(pool);
	api.close = () => pool.end();
	api.pool = pool;
	return api;
}

/** "postgres://…" / "postgresql://…" → PostgreSQL; anything else → a SQLite file. */
function openDb(target, opts = {}) {
	const t = String(target || "");
	if (/^postgres(ql)?:\/\//i.test(t)) return pgDriver(t, opts);
	return sqliteDriver(t || ":memory:");
}

const isPg = target => /^postgres(ql)?:\/\//i.test(String(target || ""));

module.exports = { openDb, isPg, toPg };
