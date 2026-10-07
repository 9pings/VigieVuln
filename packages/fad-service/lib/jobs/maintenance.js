/**
 * Daily database maintenance: merge the FTS5 index segments the imports leave behind,
 * let SQLite refresh its planner statistics, and truncate the WAL so it does not grow
 * between checkpoints. Cheap, safe while serving.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
async function run({ assets }) {
	const db = assets.db;
	const t0 = Date.now();
	db.exec("INSERT INTO assets_fts(assets_fts) VALUES ('optimize')");
	db.exec("PRAGMA optimize");
	const wal = db.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get();
	return `fts optimized, planner stats refreshed, wal checkpoint ${wal ? JSON.stringify(wal) : "n/a"} in ${Date.now() - t0} ms`;
}

module.exports = { run };
