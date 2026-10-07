/**
 * Daily database maintenance.
 *   SQLite      merge the FTS5 index segments the imports leave behind, refresh planner
 *               statistics, truncate the WAL.
 *   PostgreSQL  ANALYZE (autovacuum does the rest).
 * Both: the pull-through resource cache is bounded — entries stale for more than 30 days
 * go, then, above the budget, the least recently fetched. Mirrors (assets) are never
 * touched: they are the service's data, not a cache.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const DAY = 86400 * 1000;

async function evictResources(driver, { maxBytes = 20 * 1024 ** 3, staleDays = 30, now = Date.now() } = {}) {
	const stale = (await driver.run("DELETE FROM resources WHERE fetched_at + ttl_ms < ?", [now - staleDays * DAY])).changes;
	let budget = 0;
	let total = Number((await driver.get("SELECT COALESCE(SUM(bytes), 0) AS b FROM resources")).b);
	while (total > maxBytes) {
		const rows = await driver.all("SELECT key, bytes FROM resources ORDER BY fetched_at LIMIT 500");
		if (!rows.length) break;
		await driver.transaction(async tx => {
			for (const r of rows) {
				await tx.run("DELETE FROM resources WHERE key = ?", [r.key]);
				total -= Number(r.bytes); budget++;
				if (total <= maxBytes) break;
			}
		});
	}
	return { stale, budget };
}

async function run({ assets, options = {} }) {
	const d = assets.driver;
	const t0 = Date.now();
	const ev = await evictResources(d, { maxBytes: options.resourceCacheMaxBytes ?? undefined });
	let tail;
	if (d.dialect === "pg") {
		await d.exec("ANALYZE");
		tail = "analyzed";
	} else {
		await d.exec("INSERT INTO assets_fts(assets_fts) VALUES ('optimize')");
		await d.exec("PRAGMA optimize");
		const wal = await d.get("PRAGMA wal_checkpoint(TRUNCATE)");
		tail = `fts optimized, planner stats refreshed, wal checkpoint ${wal ? JSON.stringify(wal) : "n/a"}`;
	}
	return `${tail}, resource cache: ${ev.stale} stale + ${ev.budget} over budget evicted in ${Date.now() - t0} ms`;
}

module.exports = { run, evictResources };
