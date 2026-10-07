/**
 * Daily database maintenance: merge the FTS5 index segments the imports leave behind,
 * let SQLite refresh its planner statistics, and truncate the WAL so it does not grow
 * between checkpoints. Cheap, safe while serving.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const DAY = 86400 * 1000;

/**
 * The pull-through resource cache grows with every miss: drop entries stale for more than
 * `staleDays`, then, above `maxBytes`, the least recently fetched ones. Mirrors (assets)
 * are never touched — they are the service's data, not a cache.
 */
function evictResources(db, { maxBytes = 20 * 1024 ** 3, staleDays = 30, now = Date.now() } = {}) {
	const exists = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'resources'").get();
	if (!exists) return { stale: 0, budget: 0 };
	const stale = Number(db.prepare("DELETE FROM resources WHERE fetched_at + ttl_ms < ?").run(now - staleDays * DAY).changes);
	let budget = 0;
	let total = Number(db.prepare("SELECT COALESCE(SUM(bytes), 0) AS b FROM resources").get().b);
	const oldest = db.prepare("SELECT key, bytes FROM resources ORDER BY fetched_at LIMIT 500");
	const drop = db.prepare("DELETE FROM resources WHERE key = ?");
	while (total > maxBytes) {
		const rows = oldest.all();
		if (!rows.length) break;
		db.exec("BEGIN IMMEDIATE");
		try {
			for (const r of rows) { drop.run(r.key); total -= Number(r.bytes); budget++; if (total <= maxBytes) break; }
			db.exec("COMMIT");
		} catch (e) { db.exec("ROLLBACK"); throw e; }
	}
	return { stale, budget };
}

async function run({ assets, options = {} }) {
	const db = assets.db;
	const t0 = Date.now();
	const ev = evictResources(db, { maxBytes: options.resourceCacheMaxBytes ?? undefined });
	db.exec("INSERT INTO assets_fts(assets_fts) VALUES ('optimize')");
	db.exec("PRAGMA optimize");
	const wal = db.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get();
	return `fts optimized, planner stats refreshed, resource cache: ${ev.stale} stale + ${ev.budget} over budget evicted, wal checkpoint ${wal ? JSON.stringify(wal) : "n/a"} in ${Date.now() - t0} ms`;
}

module.exports = { run, evictResources };
