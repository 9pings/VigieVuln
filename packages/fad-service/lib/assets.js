/**
 * Published assets (docs/SPEC-fad-service.md §4, §6): what the search and the pages read.
 *
 *   assets      one row per CVE / advisory / package: title, summary, JSON data, sources,
 *               `published` (0 = cached but not public — privacy rule §6)
 *   search      SQLite: an FTS5 table (assets_fts, rowid = assets.id); PostgreSQL: a tsvector
 *               column with a GIN index — over key + aliases + title + summary
 *   cve_signals per-CVE signals written by their own jobs (KEV, EPSS, EUVD, CERT-FR) so a
 *               job never rewrites the CVE record of another
 *   job_runs    one row per job: lease (so one worker runs it at a time), last result
 *
 * The read path never calls an upstream: everything here was written by a job. Every method
 * is async (lib/db.js: SQLite or PostgreSQL). Inside `transaction(async t => …)` use `t`.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const SCHEMA = `
CREATE TABLE IF NOT EXISTS assets (
	id {ID},
	type TEXT NOT NULL,
	key TEXT NOT NULL,
	title TEXT,
	summary TEXT,
	data TEXT NOT NULL,
	sources TEXT NOT NULL,
	published INTEGER NOT NULL DEFAULT 1,
	updated_at {INT} NOT NULL,
	aliases TEXT,
	UNIQUE (type, key)
);
CREATE TABLE IF NOT EXISTS cve_signals (
	cve TEXT PRIMARY KEY,
	kev TEXT,
	epss_score {REAL},
	epss_percentile {REAL},
	epss_date TEXT,
	euvd_id TEXT,
	euvd_exploited_since TEXT,
	certfr TEXT,
	updated_at {INT} NOT NULL
);
CREATE INDEX IF NOT EXISTS cve_signals_euvd ON cve_signals (euvd_id);
CREATE TABLE IF NOT EXISTS cve_nvd (
	cve TEXT PRIMARY KEY,
	last_modified TEXT,
	data TEXT NOT NULL,
	updated_at {INT}
);
CREATE TABLE IF NOT EXISTS advisory_cve (
	advisory TEXT NOT NULL,
	cve TEXT NOT NULL,
	PRIMARY KEY (advisory, cve)
);
CREATE INDEX IF NOT EXISTS advisory_cve_by_cve ON advisory_cve (cve);
-- Which packages an advisory affects (OSV affected[].package → purl without version).
CREATE TABLE IF NOT EXISTS advisory_package (
	advisory TEXT NOT NULL,
	package TEXT NOT NULL,
	PRIMARY KEY (advisory, package)
);
CREATE INDEX IF NOT EXISTS advisory_package_by_package ON advisory_package (package);
-- Publication rule (spec §6): a registry package becomes public once K distinct clients
-- asked for it, or when it is seeded. Rows hold a TRUNCATED keyed hash of the client — no
-- token, no name — and are deleted the moment the package is published.
CREATE TABLE IF NOT EXISTS package_demand (
	package TEXT NOT NULL,
	tag TEXT NOT NULL,
	PRIMARY KEY (package, tag)
);
CREATE TABLE IF NOT EXISTS job_runs (
	job TEXT PRIMARY KEY,
	lease_until {INT} NOT NULL DEFAULT 0,
	owner TEXT,
	last_started {INT},
	last_finished {INT},
	last_status TEXT,
	last_detail TEXT,
	state TEXT
);
`;
const FTS = {
	sqlite: "CREATE VIRTUAL TABLE IF NOT EXISTS assets_fts USING fts5(key, aliases, title, summary, tokenize = 'unicode61 remove_diacritics 2')",
	pg: `ALTER TABLE assets ADD COLUMN IF NOT EXISTS search tsvector;
		CREATE INDEX IF NOT EXISTS assets_search ON assets USING GIN (search);
		CREATE INDEX IF NOT EXISTS assets_type_published ON assets (type, published)`,
};

const SIGNAL_COLUMNS = ["kev", "epss_score", "epss_percentile", "epss_date", "euvd_id", "euvd_exploited_since", "certfr"];
const JSON_COLUMNS = new Set(["kev", "certfr"]);
/** Columns added after the first release: [table, column, type], created on open so an old database upgrades in place. */
const MIGRATIONS = [["assets", "aliases", "TEXT"], ["cve_nvd", "updated_at", "{INT}"]];

/**
 * The only search input that reaches the database. Whitelist, not blacklist:
 *   - at most 200 characters, NFKC-normalised, no control character at all;
 *   - words made of letters and digits, joined only by . _ - : / @ inside a word;
 *     everything else (%, *, quotes, parentheses, operators…) is a separator, never sent;
 *   - at most 8 words, each 2 to 64 characters (a 1-character word is dropped);
 *   - prefix matching only for words of 3 characters or more: "a*" over the whole
 *     index would be a denial of service by search.
 * → [{ word, prefix }] — possibly empty, then nothing is queried at all.
 */
function searchTerms(text) {
	const s = String(text ?? "").slice(0, 200).normalize("NFKC");
	if (/[\u0000-\u001f\u007f-\u009f]/.test(s)) return [];
	const words = s.match(/[\p{L}\p{N}]+(?:[._\-:/@][\p{L}\p{N}]+)*/gu) || [];
	return words.filter(w => w.length >= 2 && w.length <= 64).slice(0, 8).map(w => ({ word: w, prefix: w.length >= 3 }));
}
const tokensOf = text => searchTerms(text).map(t => t.word);

/** Search terms → a safe FTS5 query: each word quoted, a prefix when long enough ("log4j" finds "log4j2"). */
function ftsQuery(text) {
	const terms = searchTerms(text);
	if (!terms.length) return null;
	// FTS5 tokenises on punctuation itself: a quoted word is a phrase of its parts.
	return terms.map(t => `"${t.word}"${t.prefix ? "*" : ""}`).join(" ");
}

/** Punctuation → spaces: PostgreSQL's parser reads "-2021" in "CVE-2021-1" as a signed number. */
const plain = text => String(text || "").normalize("NFKC").replace(/[^\p{L}\p{N}]+/gu, " ").trim();

/** Search terms → a safe PostgreSQL tsquery: alphanumeric parts ANDed, prefixes as for FTS5. */
function tsQuery(text) {
	const parts = searchTerms(text).flatMap(t => plain(t.word).toLowerCase().split(" ").filter(Boolean)
		.map((p, i, all) => `${p}${t.prefix && i === all.length - 1 && p.length >= 3 ? ":*" : ""}`)).slice(0, 16);
	return parts.length ? parts.join(" & ") : null;
}

async function migrate(driver) {
	for (const [table, column, type] of MIGRATIONS) {
		if (driver.dialect === "pg") { await driver.exec(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column} ${driver.ddl(type)}`); continue; }
		const cols = (await driver.all(`PRAGMA table_info(${table})`)).map(c => c.name);
		if (cols.includes(column)) continue;
		await driver.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${driver.ddl(type)}`);
		// Aliases used to live only in the search index: copy them back so a dump carries them.
		if (table === "assets" && column === "aliases")
			await driver.exec("UPDATE assets SET aliases = (SELECT f.aliases FROM assets_fts f WHERE f.rowid = assets.id)");
	}
}

const CHUNK = 400;

/**
 * One multi-row INSERT per CHUNK rows: `INSERT INTO t (cols) VALUES (…),(…) <tail>`.
 * `cell` lets a column be an SQL expression of its parameter (to_tsvector('simple', ?)).
 * Bulk imports are hundreds of thousands of rows: one round trip per row is what makes
 * PostgreSQL slow, not PostgreSQL. → total rows affected / returned rows.
 */
async function insertMany(d, table, cols, rows, tail = "", { cell = {}, returning = false } = {}) {
	let changes = 0;
	const out = [];
	for (let i = 0; i < rows.length; i += CHUNK) {
		const part = rows.slice(i, i + CHUNK);
		const tuple = `(${cols.map(c => cell[c] || "?").join(", ")})`;
		const sql = `INSERT INTO ${table} (${cols.join(", ")}) VALUES ${part.map(() => tuple).join(", ")} ${tail}`;
		const params = part.flat();
		if (returning) { const r = await d.all(sql, params); out.push(...r); changes += r.length; }
		else changes += (await d.run(sql, params)).changes;
	}
	return returning ? out : changes;
}

/** The asset API bound to one driver (the pool, or a transaction's connection). */
function bind(d) {
	const pg = d.dialect === "pg";
	const signal = col => `INSERT INTO cve_signals (cve, ${col}, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (cve) DO UPDATE SET ${col} = excluded.${col}, updated_at = excluded.updated_at`;
	const parseAsset = row => row && ({ type: row.type, key: row.key, title: row.title, summary: row.summary, data: JSON.parse(row.data),
		sources: JSON.parse(row.sources), published: !!Number(row.published), updatedAt: Number(row.updated_at) });

	const api = {
		driver: d,
		dialect: d.dialect,
		transaction: fn => d.transaction(tx => fn(bind(tx))),
		/** Insert or replace one asset and its search entry. */
		async upsert({ type, key, title = null, summary = null, aliases = [], data = {}, sources = [], published = true, updatedAt = Date.now() }) {
			const al = aliases.join(" ");
			const args = [type, key, title, summary, JSON.stringify(data), JSON.stringify(sources), published ? 1 : 0, updatedAt, al];
			if (pg) {
				const r = await d.get(`INSERT INTO assets (type, key, title, summary, data, sources, published, updated_at, aliases, search)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, to_tsvector('simple', ?))
					ON CONFLICT (type, key) DO UPDATE SET title = excluded.title, summary = excluded.summary, data = excluded.data,
						sources = excluded.sources, published = excluded.published, updated_at = excluded.updated_at,
						aliases = excluded.aliases, search = excluded.search
					RETURNING id`, [...args, plain([key, al, title || "", (summary || "").slice(0, 2000)].join(" "))]);
				return Number(r.id);
			}
			const r = await d.get(`INSERT INTO assets (type, key, title, summary, data, sources, published, updated_at, aliases)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (type, key) DO UPDATE SET title = excluded.title, summary = excluded.summary, data = excluded.data,
					sources = excluded.sources, published = excluded.published, updated_at = excluded.updated_at, aliases = excluded.aliases
				RETURNING id`, args);
			const id = Number(r.id);
			await d.run("DELETE FROM assets_fts WHERE rowid = ?", [id]);
			await d.run("INSERT INTO assets_fts (rowid, key, aliases, title, summary) VALUES (?, ?, ?, ?, ?)", [id, key, al, title || "", summary || ""]);
			return id;
		},
		/**
		 * Insert or replace many assets in a few statements. onlyNewer: keep ours when it is
		 * as fresh (dump restore). → how many were written.
		 */
		async upsertMany(items, { onlyNewer = false } = {}) {
			// One key twice in one statement is an error on PostgreSQL: the last one wins.
			items = [...new Map(items.map(a => [`${a.type}\u0000${a.key}`, a])).values()];
			if (!items.length) return 0;
			const cols = ["type", "key", "title", "summary", "data", "sources", "published", "updated_at", "aliases", ...(pg ? ["search"] : [])];
			const rows = items.map(a => {
				const al = (a.aliases || []).join(" ");
				const r = [a.type, a.key, a.title ?? null, a.summary ?? null, JSON.stringify(a.data ?? {}), JSON.stringify(a.sources ?? []),
					a.published === false ? 0 : 1, a.updatedAt ?? Date.now(), al];
				if (pg) r.push(plain([a.key, al, a.title || "", (a.summary || "").slice(0, 2000)].join(" ")));
				return r;
			});
			const tail = `ON CONFLICT (type, key) DO UPDATE SET title = excluded.title, summary = excluded.summary, data = excluded.data,
				sources = excluded.sources, published = excluded.published, updated_at = excluded.updated_at, aliases = excluded.aliases
				${pg ? ", search = excluded.search" : ""} ${onlyNewer ? "WHERE assets.updated_at < excluded.updated_at" : ""}
				RETURNING id, key, title, summary, aliases`;
			const written = await insertMany(d, "assets", cols, rows, tail, { cell: { search: "to_tsvector('simple', ?)" }, returning: true });
			if (!pg && written.length) {
				for (let i = 0; i < written.length; i += CHUNK) {
					const part = written.slice(i, i + CHUNK);
					await d.run(`DELETE FROM assets_fts WHERE rowid IN (${part.map(() => "?").join(", ")})`, part.map(r => Number(r.id)));
					await insertMany(d, "assets_fts", ["rowid", "key", "aliases", "title", "summary"],
						part.map(r => [Number(r.id), r.key, r.aliases || "", r.title || "", r.summary || ""]));
				}
			}
			return written.length;
		},
		/** Replace the CVE and package links of many advisories: [{ advisory, cves, packages|null }]. */
		async linkMany(links) {
			if (!links.length) return;
			for (let i = 0; i < links.length; i += CHUNK) {
				const part = links.slice(i, i + CHUNK);
				const ids = part.map(l => l.advisory), marks = ids.map(() => "?").join(", ");
				await d.run(`DELETE FROM advisory_cve WHERE advisory IN (${marks})`, ids);
				await insertMany(d, "advisory_cve", ["advisory", "cve"], part.flatMap(l => (l.cves || []).map(c => [l.advisory, c])), "ON CONFLICT DO NOTHING");
				const withPkgs = part.filter(l => Array.isArray(l.packages));
				if (withPkgs.length) {
					await d.run(`DELETE FROM advisory_package WHERE advisory IN (${withPkgs.map(() => "?").join(", ")})`, withPkgs.map(l => l.advisory));
					await insertMany(d, "advisory_package", ["advisory", "package"], withPkgs.flatMap(l => l.packages.map(p => [l.advisory, p])), "ON CONFLICT DO NOTHING");
				}
			}
		},
		/** A dumped asset row → stored when fresher than ours. → true when written. */
		async importAsset(r) {
			const cur = await d.get("SELECT updated_at FROM assets WHERE type = ? AND key = ?", [r.type, r.key]);
			if (cur && Number(cur.updated_at) >= r.updatedAt) return false;
			await api.upsert({ type: r.type, key: r.key, title: r.title, summary: r.summary, aliases: r.aliases ? String(r.aliases).split(" ").filter(Boolean) : [],
				data: r.data, sources: r.sources, published: !!r.published, updatedAt: r.updatedAt });
			return true;
		},
		async get(type, key, { includeUnpublished = false } = {}) {
			const row = await d.get("SELECT type, key, title, summary, data, sources, published, updated_at FROM assets WHERE type = ? AND key = ?", [type, key]);
			if (!row || (!Number(row.published) && !includeUnpublished)) return null;
			return parseAsset(row);
		},
		/** Set one signal column for many CVEs in one transaction. rows: [[cve, value], …] */
		async setSignal(column, rows) {
			if (!SIGNAL_COLUMNS.includes(column)) throw new Error(`unknown signal ${column}`);
			const now = Date.now();
			await d.transaction(tx => insertMany(tx, "cve_signals", ["cve", column, "updated_at"],
				rows.map(([cve, value]) => [cve, JSON_COLUMNS.has(column) && value != null ? JSON.stringify(value) : value, now]),
				`ON CONFLICT (cve) DO UPDATE SET ${column} = excluded.${column}, updated_at = excluded.updated_at`));
		},
		async signals(cve) {
			const row = await d.get("SELECT * FROM cve_signals WHERE cve = ?", [cve]);
			if (!row) return null;
			const out = { ...row };
			for (const c of JSON_COLUMNS) out[c] = row[c] ? JSON.parse(row[c]) : null;
			return out;
		},
		/** rows: [[cve, score, percentile]] for one score date. */
		async setEpss(rows, date) {
			const now = Date.now();
			await d.transaction(tx => insertMany(tx, "cve_signals", ["cve", "epss_score", "epss_percentile", "epss_date", "updated_at"],
				rows.map(([cve, score, pct]) => [cve, score, pct, date, now]),
				`ON CONFLICT (cve) DO UPDATE SET epss_score = excluded.epss_score, epss_percentile = excluded.epss_percentile,
					epss_date = excluded.epss_date, updated_at = excluded.updated_at`));
		},
		/** rows: [[cve, euvdId|null, exploitedSince|null]] */
		async setEuvd(rows) {
			const now = Date.now();
			await d.transaction(tx => insertMany(tx, "cve_signals", ["cve", "euvd_id", "euvd_exploited_since", "updated_at"],
				rows.map(([cve, id, since]) => [cve, id, since, now]),
				`ON CONFLICT (cve) DO UPDATE SET euvd_id = excluded.euvd_id, euvd_exploited_since = excluded.euvd_exploited_since,
					updated_at = excluded.updated_at`));
		},
		/** Dumped signal rows (whole rows) → written when fresher. */
		async importSignals(rows) {
			if (!rows.length) return 0;
			const cols = ["cve", ...SIGNAL_COLUMNS, "updated_at"];
			return insertMany(d, "cve_signals", cols, rows.map(r => cols.map(c => r[c] ?? null)),
				`ON CONFLICT (cve) DO UPDATE SET ${SIGNAL_COLUMNS.map(c => `${c} = excluded.${c}`).join(", ")}, updated_at = excluded.updated_at
				WHERE excluded.updated_at > cve_signals.updated_at`);
		},
		/** Dumped NVD rows → written when at least as fresh. */
		async importNvd(rows) {
			if (!rows.length) return 0;
			return insertMany(d, "cve_nvd", ["cve", "last_modified", "data", "updated_at"],
				rows.map(r => [r.cve, r.lastModified ?? null, JSON.stringify(r.data), r.updatedAt || 0]),
				`ON CONFLICT (cve) DO UPDATE SET last_modified = excluded.last_modified, data = excluded.data, updated_at = excluded.updated_at
				WHERE COALESCE(excluded.updated_at, 0) >= COALESCE(cve_nvd.updated_at, 0)`);
		},
		/** Assets of a type whose key starts with `prefix`, one at a time → { key, data }. */
		async *iteratePrefix(type, prefix) {
			for await (const r of d.iterate("SELECT key, data FROM assets WHERE type = ? AND key LIKE ?", [type, prefix + "%"])) yield { key: r.key, data: JSON.parse(r.data) };
		},
		async listByPrefix(type, prefix) {
			const out = [];
			for await (const r of api.iteratePrefix(type, prefix)) out.push(r);
			return out;
		},
		/** rows: [{ id, lastModified, ... }] — NVD's enrichment, kept apart from the CVE record. */
		async setNvd(rows, updatedAt = Date.now()) {
			await d.transaction(tx => insertMany(tx, "cve_nvd", ["cve", "last_modified", "data", "updated_at"],
				rows.map(r => [r.id, r.lastModified || null, JSON.stringify(r), updatedAt]),
				`ON CONFLICT (cve) DO UPDATE SET last_modified = excluded.last_modified, data = excluded.data, updated_at = excluded.updated_at`));
		},
		async nvd(cve) {
			const row = await d.get("SELECT data FROM cve_nvd WHERE cve = ?", [cve]);
			return row ? JSON.parse(row.data) : null;
		},
		/** The CVEs an advisory aliases (inside a transaction for bulk imports). */
		async linkAdvisory(advisoryKey, cves) {
			await d.run("DELETE FROM advisory_cve WHERE advisory = ?", [advisoryKey]);
			for (const cve of cves) await d.run("INSERT INTO advisory_cve (advisory, cve) VALUES (?, ?) ON CONFLICT DO NOTHING", [advisoryKey, cve]);
		},
		async advisoriesForCve(cve) {
			return d.all(`SELECT a.key, a.title FROM advisory_cve l JOIN assets a ON a.type = 'advisory' AND a.key = l.advisory
				WHERE l.cve = ? AND a.published = 1 ORDER BY a.key LIMIT 200`, [cve]);
		},
		/** The packages an advisory affects (inside a transaction for bulk imports). */
		async linkAdvisoryPackages(advisoryKey, packages) {
			await d.run("DELETE FROM advisory_package WHERE advisory = ?", [advisoryKey]);
			for (const p of packages) await d.run("INSERT INTO advisory_package (advisory, package) VALUES (?, ?) ON CONFLICT DO NOTHING", [advisoryKey, p]);
		},
		/** Published advisories affecting a package → [{ key, title, data }]. */
		async advisoriesForPackage(pkg) {
			const rows = await d.all(`SELECT a.key, a.title, a.data FROM advisory_package l JOIN assets a ON a.type = 'advisory' AND a.key = l.advisory
				WHERE l.package = ? AND a.published = 1 ORDER BY a.key LIMIT 300`, [pkg]);
			return rows.map(r => ({ key: r.key, title: r.title, data: JSON.parse(r.data) }));
		},
		async advisoryPackageLinks() { return Number((await d.get("SELECT COUNT(*) AS n FROM advisory_package")).n); },
		/**
		 * Record that one client (a truncated keyed tag) or the seed ("seed") asked for a
		 * package. → { distinct, seeded } so the caller can apply the publication rule.
		 */
		async demand(pkg, tag) {
			await d.run("INSERT INTO package_demand (package, tag) VALUES (?, ?) ON CONFLICT DO NOTHING", [pkg, tag]);
			return api.demandOf(pkg);
		},
		async demandOf(pkg) {
			const r = await d.get("SELECT COUNT(*) AS n, SUM(CASE WHEN tag = 'seed' THEN 1 ELSE 0 END) AS seeded FROM package_demand WHERE package = ?", [pkg]);
			return { distinct: Number(r.n), seeded: Number(r.seeded || 0) > 0 };
		},
		/** Publish an asset and forget who asked for it. */
		async publish(type, key) {
			const changed = (await d.run("UPDATE assets SET published = 1 WHERE type = ? AND key = ? AND published = 0", [type, key])).changes > 0;
			await d.run("DELETE FROM package_demand WHERE package = ?", [key]);
			return changed;
		},
		async isPublished(type, key) { return !!Number((await d.get("SELECT published FROM assets WHERE type = ? AND key = ?", [type, key]))?.published); },
		async cveForEuvd(id) { return (await d.get("SELECT cve FROM cve_signals WHERE euvd_id = ? LIMIT 1", [id]))?.cve || null; },
		async search(text, { type = null, limit = 20 } = {}) {
			const n = Math.min(Math.max(1, limit | 0), 100);
			const ranked = await api.searchRanked(text, { type, n });
			// An exact identifier (CVE-…, osv:GHSA-…, pkg:…) always comes first.
			const terms = searchTerms(text);
			if (terms.length !== 1) return ranked;
			const w = terms[0].word;
			const exact = await d.all(`SELECT type, key, title, summary, updated_at FROM assets
				WHERE key IN (?, ?, ?, ?) AND published = 1 AND (CAST(? AS TEXT) IS NULL OR type = ?)`,
			[w, w.toUpperCase(), `osv:${w}`, `certfr:${w.toUpperCase()}`, type, type]);
			if (!exact.length) return ranked;
			const keys = new Set(exact.map(r => r.key));
			return [...exact, ...ranked.filter(r => !keys.has(r.key))].slice(0, n);
		},
		async searchRanked(text, { type = null, n = 20 } = {}) {
			try {
				if (pg) {
					const q = tsQuery(text);
					if (!q) return [];
					return await d.all(`SELECT type, key, title, summary, updated_at FROM assets
						WHERE search @@ to_tsquery('simple', ?) AND published = 1 AND (CAST(? AS TEXT) IS NULL OR type = ?)
						ORDER BY ts_rank(search, to_tsquery('simple', ?)) DESC, key LIMIT ?`, [q, type, type, q, n]);
				}
				const match = ftsQuery(text);
				if (!match) return [];
				return await d.all(`SELECT a.type, a.key, a.title, a.summary, a.updated_at
					FROM assets_fts f JOIN assets a ON a.id = f.rowid
					WHERE assets_fts MATCH ? AND a.published = 1 AND (? IS NULL OR a.type = ?)
					ORDER BY rank LIMIT ?`, [match, type, type, n]);
			} catch { return []; }
		},
		async counts() {
			return Object.fromEntries((await d.all("SELECT type, COUNT(*) AS n FROM assets WHERE published = 1 GROUP BY type")).map(r => [r.type, Number(r.n)]));
		},
	};
	return api;
}

/** Create the schema (idempotent) and return the asset API on `driver`. */
async function createAssetStore(driver) {
	await driver.exec(driver.ddl(SCHEMA));
	await driver.exec(FTS[driver.dialect]);
	await migrate(driver);
	return bind(driver);
}

module.exports = { createAssetStore, ftsQuery, tsQuery, searchTerms, SIGNAL_COLUMNS };
