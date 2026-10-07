/**
 * Published assets (docs/SPEC-fad-service.md §4, §6): what the search and the pages read.
 *
 *   assets      one row per CVE / advisory / package: title, summary, JSON data, sources,
 *               `published` (0 = cached but not public — privacy rule §6)
 *   assets_fts  FTS5 index over key + aliases + title + summary, rowid = assets.id
 *   cve_signals per-CVE signals written by their own jobs (KEV, EPSS, EUVD, CERT-FR) so a
 *               job never rewrites the CVE record of another
 *   job_runs    one row per job: lease (so one worker runs it at a time), last result
 *
 * The read path never calls an upstream: everything here was written by a job.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const SCHEMA = `
CREATE TABLE IF NOT EXISTS assets (
	id INTEGER PRIMARY KEY,
	type TEXT NOT NULL,
	key TEXT NOT NULL,
	title TEXT,
	summary TEXT,
	data TEXT NOT NULL,
	sources TEXT NOT NULL,
	published INTEGER NOT NULL DEFAULT 1,
	updated_at INTEGER NOT NULL,
	UNIQUE (type, key)
);
CREATE VIRTUAL TABLE IF NOT EXISTS assets_fts USING fts5(key, aliases, title, summary, tokenize = 'unicode61 remove_diacritics 2');
CREATE TABLE IF NOT EXISTS cve_signals (
	cve TEXT PRIMARY KEY,
	kev TEXT,
	epss_score REAL,
	epss_percentile REAL,
	epss_date TEXT,
	euvd_id TEXT,
	euvd_exploited_since TEXT,
	certfr TEXT,
	updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cve_signals_euvd ON cve_signals (euvd_id);
CREATE TABLE IF NOT EXISTS cve_nvd (
	cve TEXT PRIMARY KEY,
	last_modified TEXT,
	data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS advisory_cve (
	advisory TEXT NOT NULL,
	cve TEXT NOT NULL,
	PRIMARY KEY (advisory, cve)
);
CREATE INDEX IF NOT EXISTS advisory_cve_by_cve ON advisory_cve (cve);
CREATE TABLE IF NOT EXISTS job_runs (
	job TEXT PRIMARY KEY,
	lease_until INTEGER NOT NULL DEFAULT 0,
	owner TEXT,
	last_started INTEGER,
	last_finished INTEGER,
	last_status TEXT,
	last_detail TEXT,
	state TEXT
);
`;

const SIGNAL_COLUMNS = ["kev", "epss_score", "epss_percentile", "epss_date", "euvd_id", "euvd_exploited_since", "certfr"];
const JSON_COLUMNS = new Set(["kev", "certfr"]);
/** Columns added after the first release: [table, column, type], created on open so an old database upgrades in place. */
const MIGRATIONS = [];

/** Turn free text into a safe FTS5 query: quoted tokens, prefix match on the last one. */
function ftsQuery(text) {
	const tokens = String(text || "").normalize("NFKC").match(/[\p{L}\p{N}][\p{L}\p{N}._-]*/gu) || [];
	if (!tokens.length) return null;
	return tokens.slice(0, 8).map((t, i, all) => `"${t.replace(/"/g, "")}"${i === all.length - 1 ? "*" : ""}`).join(" ");
}

function createAssetStore(db) {
	db.exec(SCHEMA);
	for (const [table, column, type] of MIGRATIONS) {
		const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
		if (!cols.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
	}
	const q = {
		find: db.prepare("SELECT id FROM assets WHERE type = ? AND key = ?"),
		insert: db.prepare("INSERT INTO assets (type, key, title, summary, data, sources, published, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
		update: db.prepare("UPDATE assets SET title = ?, summary = ?, data = ?, sources = ?, published = ?, updated_at = ? WHERE id = ?"),
		ftsDel: db.prepare("DELETE FROM assets_fts WHERE rowid = ?"),
		ftsAdd: db.prepare("INSERT INTO assets_fts (rowid, key, aliases, title, summary) VALUES (?, ?, ?, ?, ?)"),
		get: db.prepare("SELECT type, key, title, summary, data, sources, published, updated_at FROM assets WHERE type = ? AND key = ?"),
		signals: db.prepare("SELECT * FROM cve_signals WHERE cve = ?"),
		byAlias: db.prepare("SELECT cve FROM cve_signals WHERE euvd_id = ? LIMIT 1"),
		search: db.prepare(`SELECT a.type, a.key, a.title, a.summary, a.updated_at
			FROM assets_fts f JOIN assets a ON a.id = f.rowid
			WHERE assets_fts MATCH ? AND a.published = 1 AND (? IS NULL OR a.type = ?)
			ORDER BY rank LIMIT ?`),
		count: db.prepare("SELECT type, COUNT(*) AS n FROM assets WHERE published = 1 GROUP BY type"),
		nvdPut: db.prepare(`INSERT INTO cve_nvd (cve, last_modified, data) VALUES (?, ?, ?)
			ON CONFLICT(cve) DO UPDATE SET last_modified = excluded.last_modified, data = excluded.data`),
		nvdGet: db.prepare("SELECT last_modified, data FROM cve_nvd WHERE cve = ?"),
		linkDel: db.prepare("DELETE FROM advisory_cve WHERE advisory = ?"),
		linkAdd: db.prepare("INSERT OR IGNORE INTO advisory_cve (advisory, cve) VALUES (?, ?)"),
		forCve: db.prepare(`SELECT a.key, a.title FROM advisory_cve l JOIN assets a ON a.type = 'advisory' AND a.key = l.advisory
			WHERE l.cve = ? AND a.published = 1 ORDER BY a.key LIMIT 200`),
		byPrefix: db.prepare("SELECT key, data FROM assets WHERE type = ? AND key >= ? AND key < ?"),
		epss: db.prepare(`INSERT INTO cve_signals (cve, epss_score, epss_percentile, epss_date, updated_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(cve) DO UPDATE SET epss_score = excluded.epss_score, epss_percentile = excluded.epss_percentile,
				epss_date = excluded.epss_date, updated_at = excluded.updated_at`),
		euvd: db.prepare(`INSERT INTO cve_signals (cve, euvd_id, euvd_exploited_since, updated_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(cve) DO UPDATE SET euvd_id = excluded.euvd_id, euvd_exploited_since = excluded.euvd_exploited_since,
				updated_at = excluded.updated_at`),
	};
	const signalUpsert = Object.fromEntries(SIGNAL_COLUMNS.map(col => [col, db.prepare(
		`INSERT INTO cve_signals (cve, ${col}, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(cve) DO UPDATE SET ${col} = excluded.${col}, updated_at = excluded.updated_at`)]));

	const api = {
		db,
		/** Insert or replace one asset and its search entry. */
		upsert({ type, key, title = null, summary = null, aliases = [], data = {}, sources = [], published = true }) {
			const now = Date.now();
			const row = q.find.get(type, key);
			let id;
			if (row) { id = row.id; q.update.run(title, summary, JSON.stringify(data), JSON.stringify(sources), published ? 1 : 0, now, id); q.ftsDel.run(id); }
			else id = Number(q.insert.run(type, key, title, summary, JSON.stringify(data), JSON.stringify(sources), published ? 1 : 0, now).lastInsertRowid);
			q.ftsAdd.run(id, key, aliases.join(" "), title || "", summary || "");
			return id;
		},
		get(type, key, { includeUnpublished = false } = {}) {
			const row = q.get.get(type, key);
			if (!row || (!row.published && !includeUnpublished)) return null;
			return { type: row.type, key: row.key, title: row.title, summary: row.summary, data: JSON.parse(row.data),
				sources: JSON.parse(row.sources), published: !!row.published, updatedAt: row.updated_at };
		},
		/** Set one signal column for many CVEs in one transaction. rows: [[cve, value], …] */
		setSignal(column, rows) {
			const stmt = signalUpsert[column];
			if (!stmt) throw new Error(`unknown signal ${column}`);
			const now = Date.now();
			api.transaction(() => {
				for (const [cve, value] of rows) stmt.run(cve, JSON_COLUMNS.has(column) && value != null ? JSON.stringify(value) : value, now);
			});
		},
		signals(cve) {
			const row = q.signals.get(cve);
			if (!row) return null;
			const out = { ...row };
			for (const c of JSON_COLUMNS) out[c] = row[c] ? JSON.parse(row[c]) : null;
			return out;
		},
		/** rows: [[cve, score, percentile]] for one score date. */
		setEpss(rows, date) {
			const now = Date.now();
			api.transaction(() => { for (const [cve, score, pct] of rows) q.epss.run(cve, score, pct, date, now); });
		},
		/** rows: [[cve, euvdId|null, exploitedSince|null]] */
		setEuvd(rows) {
			const now = Date.now();
			api.transaction(() => { for (const [cve, id, since] of rows) q.euvd.run(cve, id, since, now); });
		},
		/** Every asset of a type whose key starts with `prefix` → [{ key, data }]. */
		listByPrefix(type, prefix) {
			return q.byPrefix.all(type, prefix, prefix + "\uffff").map(r => ({ key: r.key, data: JSON.parse(r.data) }));
		},
		/** rows: [{ id, lastModified, ... }] — NVD's enrichment, kept apart from the CVE record. */
		setNvd(rows) {
			api.transaction(() => { for (const r of rows) q.nvdPut.run(r.id, r.lastModified || null, JSON.stringify(r)); });
		},
		nvd(cve) {
			const row = q.nvdGet.get(cve);
			return row ? JSON.parse(row.data) : null;
		},
		/** The CVEs an advisory aliases (call inside a transaction for bulk imports). */
		linkAdvisory(advisoryKey, cves) {
			q.linkDel.run(advisoryKey);
			for (const cve of cves) q.linkAdd.run(advisoryKey, cve);
		},
		advisoriesForCve(cve) { return q.forCve.all(cve); },
		cveForEuvd(id) { return q.byAlias.get(id)?.cve || null; },
		search(text, { type = null, limit = 20 } = {}) {
			const match = ftsQuery(text);
			if (!match) return [];
			try { return q.search.all(match, type, type, Math.min(Math.max(1, limit | 0), 100)); }
			catch { return []; }
		},
		counts() { return Object.fromEntries(q.count.all().map(r => [r.type, Number(r.n)])); },
		transaction(fn) {
			db.exec("BEGIN IMMEDIATE");
			try { const r = fn(); db.exec("COMMIT"); return r; }
			catch (e) { db.exec("ROLLBACK"); throw e; }
		},
	};
	return api;
}

module.exports = { createAssetStore, ftsQuery, SIGNAL_COLUMNS };
