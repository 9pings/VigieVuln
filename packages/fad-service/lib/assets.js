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
-- What the "latest critical" / "most likely exploited" lists sort on, without parsing a JSON
-- per CVE: the CNA's headline score (from the CVE record) and NVD's, written by every path
-- that writes a CVE or an NVD row (jobs, dump restore). Shown only for published CVEs.
CREATE TABLE IF NOT EXISTS cve_rank (
	cve TEXT PRIMARY KEY,
	published TEXT,
	cna_score {REAL},
	nvd_score {REAL}
);
CREATE INDEX IF NOT EXISTS cve_rank_published ON cve_rank (published);
CREATE INDEX IF NOT EXISTS cve_signals_epss ON cve_signals (epss_score);
CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
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
/** "2024-03-01T10:15:09.143Z" → "2024-03-01T10:15:09": one sortable form for every source. */
const isoSecond = v => (typeof v === "string" && /^\d{4}-\d{2}-\d{2}/.test(v) ? v.slice(0, 19) : null);
const finiteScore = v => (v != null && Number.isFinite(Number(v)) ? Number(v) : null);
/** A CVE asset → [cve, published, cnaScore], or null when it must not be listed (unpublished, rejected). */
function rankOfCve(a) {
	if (a.type !== "cve") return undefined;
	if (a.published === false || a.data?.state === "REJECTED") return null;
	return [a.key, isoSecond(a.data?.published), finiteScore(a.data?.score)];
}
const CVSS_ORDER = ["4.0", "3.1", "3.0", "2.0"];
/** NVD row data → its headline score: newest CVSS version present, NVD's Primary first, highest. */
function nvdScore(data) {
	const ms = (data?.metrics || []).filter(m => finiteScore(m.score) != null);
	const v = CVSS_ORDER.find(x => ms.some(m => String(m.version) === x));
	if (!v) return null;
	const same = ms.filter(m => String(m.version) === v);
	const primary = same.filter(m => m.type === "Primary");
	return Math.max(...(primary.length ? primary : same).map(m => Number(m.score)));
}

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
	/** Keep cve_rank in step with CVE assets (CNA side) — a rejected/unpublished CVE leaves it. */
	async function rankCves(items) {
		const rows = [], gone = [];
		for (const a of items) { const r = rankOfCve(a); if (r) rows.push(r); else if (r === null) gone.push(a.key); }
		if (rows.length) await insertMany(d, "cve_rank", ["cve", "published", "cna_score"], rows,
			"ON CONFLICT (cve) DO UPDATE SET published = COALESCE(excluded.published, cve_rank.published), cna_score = excluded.cna_score");
		for (let i = 0; i < gone.length; i += CHUNK) {
			const part = gone.slice(i, i + CHUNK);
			await d.run(`DELETE FROM cve_rank WHERE cve IN (${part.map(() => "?").join(", ")})`, part);
		}
	}
	/** …and with NVD rows (NVD side). NVD's publication date only fills a CVE that has none. */
	async function rankNvd(rows) {
		if (rows.length) await insertMany(d, "cve_rank", ["cve", "published", "nvd_score"], rows,
			"ON CONFLICT (cve) DO UPDATE SET nvd_score = excluded.nvd_score, published = COALESCE(cve_rank.published, excluded.published)");
	}
	const signal = col => `INSERT INTO cve_signals (cve, ${col}, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (cve) DO UPDATE SET ${col} = excluded.${col}, updated_at = excluded.updated_at`;
	const parseAsset = row => row && ({ type: row.type, key: row.key, title: row.title, summary: row.summary, data: JSON.parse(row.data),
		sources: JSON.parse(row.sources), published: !!Number(row.published), updatedAt: Number(row.updated_at) });

	const countsMemo = { at: 0, value: null, pending: null };
	/**
	 * Published critical CVE ids (CNA or NVD headline >= 9.0), newest first, a page at a time —
	 * walked on cve_rank's published index, keyset-paginated, future dates skipped.
	 */
	async function* criticalPages({ pageSize = 200, maxPages = 50 } = {}) {
		const now = new Date().toISOString().slice(0, 19);
		let before = null;
		for (let i = 0; i < maxPages; i++) {
			const rows = await d.all(`SELECT cve, published FROM cve_rank WHERE published <= ? AND (cna_score >= 9 OR nvd_score >= 9)
				${before ? "AND (published < ? OR (published = ? AND cve < ?))" : ""} ORDER BY published DESC, cve DESC LIMIT ?`,
			before ? [now, before.published, before.published, before.cve, pageSize] : [now, pageSize]);
			if (!rows.length) return;
			before = rows[rows.length - 1];
			const pub = new Set(await api.publishedCves(rows.map(r => r.cve)));
			const ids = rows.map(r => r.cve).filter(c => pub.has(c));
			if (ids.length) yield ids;
			if (rows.length < pageSize) return;
		}
	}
	const api = {
		rankCves, rankNvd,
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
				if (type === "cve") await rankCves([{ type, key, data, published }]);
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
			if (type === "cve") await rankCves([{ type, key, data, published }]);
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
			if (items.some(a => a.type === "cve")) {
				const done = new Set(written.map(r => r.key));
				await rankCves(items.filter(a => a.type === "cve" && done.has(a.key)));
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
			const n = await insertMany(d, "cve_nvd", ["cve", "last_modified", "data", "updated_at"],
				rows.map(r => [r.cve, r.lastModified ?? null, JSON.stringify(r.data), r.updatedAt || 0]),
				`ON CONFLICT (cve) DO UPDATE SET last_modified = excluded.last_modified, data = excluded.data, updated_at = excluded.updated_at
				WHERE COALESCE(excluded.updated_at, 0) >= COALESCE(cve_nvd.updated_at, 0)`);
			// Ranked from what the table now holds (a fresher row of ours may have won).
			const kept = [];
			for (let i = 0; i < rows.length; i += CHUNK) {
				const part = rows.slice(i, i + CHUNK).map(r => r.cve);
				kept.push(...await d.all(`SELECT cve, data FROM cve_nvd WHERE cve IN (${part.map(() => "?").join(", ")})`, part));
			}
			await rankNvd(kept.map(r => { const x = JSON.parse(r.data); return [r.cve, isoSecond(x.published), nvdScore(x)]; }));
			return n;
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
			await d.transaction(async tx => {
				await insertMany(tx, "cve_nvd", ["cve", "last_modified", "data", "updated_at"],
					rows.map(r => [r.id, r.lastModified || null, JSON.stringify(r), updatedAt]),
					`ON CONFLICT (cve) DO UPDATE SET last_modified = excluded.last_modified, data = excluded.data, updated_at = excluded.updated_at`);
				await insertMany(tx, "cve_rank", ["cve", "published", "nvd_score"], rows.map(r => [r.id, isoSecond(r.published), nvdScore(r)]),
					"ON CONFLICT (cve) DO UPDATE SET nvd_score = excluded.nvd_score, published = COALESCE(cve_rank.published, excluded.published)");
			});
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
		/**
		 * The home-page lists, published CVEs only. kind:
		 *   "critical"   newest first, CNA or NVD headline score >= 9.0 (future dates ignored)
		 *   "exploited"  highest EPSS probability
		 *   "kev"        latest additions to CISA KEV
		 * → [{ cve, title, published, score, epss, epssPercentile, kev }]
		 */
		async listCves(kind, limit = 10) {
			limit = Math.max(1, Math.min(200, Number(limit) || 10));
			let ids;
			if (kind === "critical") {
				ids = [];
				for await (const page of criticalPages()) { ids.push(...page); if (ids.length >= limit) break; }
				ids = ids.slice(0, limit);
			} else if (kind === "exploited") {
				ids = (await d.all(`SELECT s.cve FROM cve_signals s JOIN assets a ON a.type = 'cve' AND a.key = s.cve AND a.published = 1
					WHERE s.epss_score IS NOT NULL ORDER BY s.epss_score DESC, s.cve DESC LIMIT ?`, [limit])).map(r => r.cve);
			} else if (kind === "kev") {
				// A few thousand rows at most: sorted here on the catalogue's own dateAdded.
				const rows = (await d.all("SELECT cve, kev FROM cve_signals WHERE kev IS NOT NULL")).map(r => ({ cve: r.cve, added: String(JSON.parse(r.kev)?.dateAdded || "") }));
				rows.sort((x, y) => y.added.localeCompare(x.added) || y.cve.localeCompare(x.cve));
				const pub = new Set((await api.publishedCves(rows.slice(0, limit * 2).map(r => r.cve))));
				ids = rows.filter(r => pub.has(r.cve)).slice(0, limit).map(r => r.cve);
			} else throw new Error(`unknown list ${kind}`);
			return api.cveRows(ids);
		},
		/**
		 * Latest critical vulnerabilities that an advisory ties to a library: CVEs scored >= 9.0
		 * (CNA or NVD), newest first, each with the packages its advisories name (withdrawn
		 * advisories excluded). → [{ cve, title, published, score, epss, kev,
		 *   packages: [{ key, advisory, entries }] }] — entries = the advisory's `affected` items
		 *   for that package (ranges, versions) so the caller can show what is fixed where.
		 */
		async listLibraries(limit = 10, { packagesPerCve = 5 } = {}) {
			limit = Math.max(1, Math.min(200, Number(limit) || 10));
			const out = [];
			const marks = list => list.map(() => "?").join(", ");
			// Critical CVEs newest first, a page at a time, until `limit` of them name a package.
			// Each step is an index lookup (the planner otherwise scans every CVE asset).
			for await (const ids of criticalPages()) {
				const ac = await d.all(`SELECT advisory, cve FROM advisory_cve WHERE cve IN (${marks(ids)})`, ids);
				const advisories = [...new Set(ac.map(r => r.advisory))];
				const pkgs = advisories.length ? await d.all(`SELECT advisory, package FROM advisory_package WHERE advisory IN (${marks(advisories)})`, advisories) : [];
				const withPkg = [...new Set(pkgs.map(r => r.advisory))];
				const docs = new Map();
				for (let i = 0; i < withPkg.length; i += CHUNK) {
					const part = withPkg.slice(i, i + CHUNK);
					for (const r of await d.all(`SELECT key, data FROM assets WHERE type = 'advisory' AND published = 1 AND key IN (${marks(part)})`, part)) {
						const data = JSON.parse(r.data);
						if (!data.withdrawn) docs.set(r.key, data);
					}
				}
				const pkgsOf = new Map();
				for (const r of pkgs) if (docs.has(r.advisory)) (pkgsOf.get(r.advisory) || pkgsOf.set(r.advisory, []).get(r.advisory)).push(r.package);
				const byCve = new Map();
				for (const r of ac) {
					for (const pkg of pkgsOf.get(r.advisory) || []) {
						const list = byCve.get(r.cve) || byCve.set(r.cve, new Map()).get(r.cve);
						if (!list.has(pkg)) list.set(pkg, { key: pkg, advisory: r.advisory, data: docs.get(r.advisory) });
					}
				}
				for (const id of ids) {
					if (out.length >= limit) break;
					const pk = byCve.get(id);
					if (pk) out.push({ cve: id, packages: [...pk.values()] });
				}
				if (out.length >= limit) break;
			}
			const rows = await api.cveRows(out.map(o => o.cve));
			return rows.map((r, i) => ({ ...r, packagesTotal: out[i].packages.length, packages: out[i].packages.slice(0, packagesPerCve) }));
		},
		async publishedPackages(keys) {
			if (!keys.length) return [];
			return (await d.all(`SELECT key FROM assets WHERE type = 'package' AND published = 1 AND key IN (${keys.map(() => "?").join(", ")})`, keys)).map(r => r.key);
		},
		async publishedCves(ids) {
			if (!ids.length) return [];
			return (await d.all(`SELECT key FROM assets WHERE type = 'cve' AND published = 1 AND key IN (${ids.map(() => "?").join(", ")})`, ids)).map(r => r.key);
		},
		/** One summary row per CVE id, in the given order (title, published, headline score, EPSS, KEV). */
		async cveRows(ids) {
			if (!ids.length) return [];
			const marks = ids.map(() => "?").join(", ");
			const [titles, ranks, sigs] = await Promise.all([
				d.all(`SELECT key, title FROM assets WHERE type = 'cve' AND key IN (${marks})`, ids),
				d.all(`SELECT cve, published, cna_score, nvd_score FROM cve_rank WHERE cve IN (${marks})`, ids),
				d.all(`SELECT cve, epss_score, epss_percentile, kev FROM cve_signals WHERE cve IN (${marks})`, ids)]);
			const by = (rows, k) => new Map(rows.map(r => [r[k], r]));
			const T = by(titles, "key"), R = by(ranks, "cve"), S = by(sigs, "cve");
			return ids.map(cve => {
				const r = R.get(cve) || {}, sg = S.get(cve) || {};
				const scores = [r.cna_score, r.nvd_score].map(finiteScore).filter(x => x != null);
				return { cve, title: T.get(cve)?.title || null, published: r.published || null, score: scores.length ? Math.max(...scores) : null,
					epss: finiteScore(sg.epss_score), epssPercentile: finiteScore(sg.epss_percentile), kev: sg.kev ? JSON.parse(sg.kev) : null };
			});
		},
		/** advisory keys → Map(advisory → [cve ids]) */
		async cvesOfAdvisories(keys) {
			const out = new Map(keys.map(k => [k, []]));
			for (let i = 0; i < keys.length; i += CHUNK) {
				const part = keys.slice(i, i + CHUNK);
				for (const r of await d.all(`SELECT advisory, cve FROM advisory_cve WHERE advisory IN (${part.map(() => "?").join(", ")}) ORDER BY cve`, part))
					out.get(r.advisory)?.push(r.cve);
			}
			return out;
		},
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
		/**
		 * Published assets per type. A full GROUP BY — callers on a hot or periodic path (home
		 * page, /ready, the metrics scrape) pass maxAgeMs and share one memoised, single-flight
		 * value instead of each scanning the table.
		 */
		counts({ maxAgeMs = 0 } = {}) {
			if (maxAgeMs && countsMemo.value && Date.now() - countsMemo.at <= maxAgeMs) return Promise.resolve(countsMemo.value);
			if (maxAgeMs && countsMemo.pending) return countsMemo.pending;
			const run = d.all("SELECT type, COUNT(*) AS n FROM assets WHERE published = 1 GROUP BY type")
				.then(rows => {
					const value = Object.fromEntries(rows.map(r => [r.type, Number(r.n)]));
					countsMemo.value = value; countsMemo.at = Date.now();
					return value;
				})
				.finally(() => { if (countsMemo.pending === run) countsMemo.pending = null; });
			countsMemo.pending = run;
			return run;
		},
	};
	return api;
}

/** Create the schema (idempotent) and return the asset API on `driver`. */
/**
 * cve_rank arrived after the first imports: fill it once from what is stored. Idempotent
 * (upserts) and marked done only at the end — an interrupted backfill simply runs again.
 */
async function backfillRank(driver, api, log = () => {}) {
	const flag = "cve_rank_v1";
	if (await driver.get("SELECT value FROM settings WHERE name = ?", [flag])) return;
	const t0 = Date.now();
	let batch = [], n = 0;
	for await (const r of driver.iterate("SELECT key, data, published FROM assets WHERE type = 'cve'")) {
		batch.push({ type: "cve", key: r.key, data: JSON.parse(r.data), published: !!Number(r.published) });
		if (batch.length >= 2000) { await api.rankCves(batch); n += batch.length; batch = []; }
	}
	await api.rankCves(batch); n += batch.length; batch = [];
	for await (const r of driver.iterate("SELECT cve, data FROM cve_nvd")) {
		const x = JSON.parse(r.data);
		batch.push([r.cve, isoSecond(x.published), nvdScore(x)]);
		if (batch.length >= 2000) { await api.rankNvd(batch); batch = []; }
	}
	await api.rankNvd(batch);
	await driver.run("INSERT INTO settings (name, value) VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value", [flag, String(Date.now())]);
	if (n) log(`cve_rank backfilled from ${n} CVE records in ${((Date.now() - t0) / 1000).toFixed(1)} s`);
}

async function createAssetStore(driver, { log } = {}) {
	await driver.exec(driver.ddl(SCHEMA));
	await driver.exec(FTS[driver.dialect]);
	await migrate(driver);
	const api = bind(driver);
	await backfillRank(driver, api, log);
	return api;
}

module.exports = { createAssetStore, ftsQuery, tsQuery, searchTerms, nvdScore, rankOfCve, SIGNAL_COLUMNS };
