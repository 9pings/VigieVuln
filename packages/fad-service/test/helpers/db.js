// Test helper: open every store of the service on one database — a SQLite file/":memory:",
// or PostgreSQL. `pgUrl()` starts a throwaway postgres:16-alpine container once per test
// process when Docker is available (or uses FAD_SERVICE_TEST_PG), and returns null otherwise.
const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");

async function open(target = ":memory:") {
	const { openDb } = require("../../lib/db");
	const { createSqlStore } = require("../../lib/sql-store");
	const { createTokenStore } = require("../../lib/tokens");
	const { createAssetStore } = require("../../lib/assets");
	const driver = openDb(target);
	const assets = await createAssetStore(driver);
	return { driver, db: driver, assets, store: await createSqlStore({ driver }), tokens: await createTokenStore(driver) };
}

let pg = undefined, container = null;
function pgUrl() {
	if (pg !== undefined) return pg;
	if (process.env.FAD_SERVICE_TEST_PG) return (pg = process.env.FAD_SERVICE_TEST_PG);
	try { require.resolve("pg"); } catch { return (pg = null); }
	try {
		const name = `fad-test-pg-${process.pid}-${crypto.randomBytes(3).toString("hex")}`;
		execFileSync("docker", ["run", "-d", "--rm", "--name", name, "-e", "POSTGRES_PASSWORD=t", "-e", "POSTGRES_DB=fad", "-p", "127.0.0.1::5432", "postgres:16-alpine"], { stdio: "pipe", timeout: 60000 });
		container = name;
		const port = execFileSync("docker", ["port", name, "5432/tcp"], { encoding: "utf8" }).trim().split(":").pop();
		for (let i = 0; i < 60; i++) {
			try { execFileSync("docker", ["exec", name, "pg_isready", "-U", "postgres", "-h", "127.0.0.1"], { stdio: "pipe" }); break; }
			catch { execFileSync("sleep", ["0.5"]); }
		}
		process.on("exit", () => { try { execFileSync("docker", ["rm", "-f", name], { stdio: "pipe" }); } catch { /* gone */ } });
		pg = `postgres://postgres:t@127.0.0.1:${port}/fad`;
	} catch { pg = null; }
	return pg;
}

/** A fresh, empty PostgreSQL database for one test (a schema-less new database). */
async function freshPg() {
	const base = pgUrl();
	if (!base) return null;
	const { Client } = require("pg");
	const admin = new Client({ connectionString: base });
	await admin.connect();
	const name = `t_${crypto.randomBytes(5).toString("hex")}`;
	await admin.query(`CREATE DATABASE ${name}`);
	await admin.end();
	return base.replace(/\/fad$/, `/${name}`);
}

module.exports = { open, pgUrl, freshPg };
