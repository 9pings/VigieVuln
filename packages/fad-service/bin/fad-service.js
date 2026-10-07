#!/usr/bin/env node
/**
 * fad-service — public data service for fad-checker (docs/SPEC-fad-service.md).
 *
 *   fad-service serve  [--db <file>] [--port 8322] [--host 127.0.0.1] [--region fr]
 *                      [--workers N] [--rate <req/min per token>] [--log]
 *   fad-service token add --role client|admin [--label <text>] [--db <file>]
 *   fad-service token list|revoke <id> [--db <file>]
 *   fad-service worker [--db <file>] [--once] [--jobs cvelist,kev,epss,euvd,certfr] [--every <min>]
 *
 * Upstream API keys come from the environment, never from argv (visible in `ps`):
 *   FAD_SERVICE_NVD_KEY, FAD_SERVICE_GITHUB_TOKEN, FAD_SERVICE_WORDFENCE_KEY.
 *
 * Scaling: `--workers N` forks N processes on one host (node:cluster, they share the
 * port and the SQLite file). Across hosts, put a load balancer in front and use the
 * PostgreSQL store (spec §3) — instances never talk to each other.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const cluster = require("node:cluster");
const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");

const VERSION = require("../package.json").version;

function parseArgs(argv) {
	const out = { _: [] };
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (!a.startsWith("--")) { out._.push(a); continue; }
		const [k, inline] = a.slice(2).split("=", 2);
		if (inline !== undefined) out[k] = inline;
		else if (argv[i + 1] !== undefined && !argv[i + 1].startsWith("--")) out[k] = argv[++i];
		else out[k] = true;
	}
	return out;
}

const USAGE = `fad-service ${VERSION}
  fad-service serve [--db <file>] [--port 8322] [--host 127.0.0.1] [--region fr] [--workers N] [--rate 600] [--log]
  fad-service token add --role client|admin [--label <text>] [--db <file>]
  fad-service token list [--db <file>]
  fad-service token revoke <id> [--db <file>]
  fad-service worker [--db <file>] [--once] [--jobs cvelist,kev,epss,euvd,certfr] [--every 10]`;

function openAll(dbFile) {
	const { openDatabase, createSqliteStore } = require("../lib/sqlite-store");
	const { createTokenStore } = require("../lib/tokens");
	const db = openDatabase(dbFile);
	db.exec("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)");
	// The log salt is stable across restarts and workers, so one client keeps one tag,
	// but it never leaves the database: the tag cannot be reversed to the token.
	db.prepare("INSERT OR IGNORE INTO settings (name, value) VALUES ('log_salt', ?)").run(crypto.randomBytes(16).toString("hex"));
	const logSalt = db.prepare("SELECT value FROM settings WHERE name = 'log_salt'").get().value;
	const { createAssetStore } = require("../lib/assets");
	return { db, store: createSqliteStore({ db }), tokens: createTokenStore(db), assets: createAssetStore(db), logSalt };
}

function serveWorker(args) {
	const { createServiceServer } = require("../lib/server");
	const { store, tokens, assets, logSalt } = openAll(args.db);
	const { createJobRunner } = require("../lib/jobs");
	const jobs = createJobRunner({ assets });
	const server = createServiceServer({
		store, tokens, assets, jobStatus: jobs.status, logSalt, version: VERSION,
		region: String(args.region || process.env.FAD_SERVICE_REGION || "unknown"),
		ratePerMinute: args.rate !== undefined ? Number(args.rate) : 600,
		log: args.log ? line => process.stdout.write(line + "\n") : null,
		keys: {
			nvd: process.env.FAD_SERVICE_NVD_KEY || undefined,
			github: process.env.FAD_SERVICE_GITHUB_TOKEN || undefined,
			wordfence: process.env.FAD_SERVICE_WORDFENCE_KEY || undefined,
		},
	});
	const port = Number(args.port ?? 8322), host = String(args.host || "127.0.0.1");
	server.listen(port, host, () => {
		const where = `http://${host}:${server.address().port}`;
		console.log(`fad-service ${VERSION} listening on ${where} (pid ${process.pid}, store sqlite ${args.db})`);
	});
	const stop = () => server.close(() => process.exit(0));
	process.once("SIGTERM", stop);
	process.once("SIGINT", stop);
}

function serve(args) {
	args.db = path.resolve(String(args.db || process.env.FAD_SERVICE_DB || "fad-service.db"));
	const workers = args.workers === true ? os.availableParallelism() : Number(args.workers || 1);
	if (!Number.isInteger(workers) || workers < 1) throw new Error("--workers must be a positive integer");
	if (workers === 1 || !cluster.isPrimary) return serveWorker(args);
	// Create the schema once before forking, so workers never race on CREATE TABLE.
	openAll(args.db).db.close();
	let stopping = false;
	for (let i = 0; i < workers; i++) cluster.fork();
	cluster.on("exit", (worker, code, signal) => {
		if (stopping) return;
		console.error(`worker ${worker.process.pid} exited (${signal || code}); restarting`);
		cluster.fork();
	});
	const stop = () => {
		stopping = true;
		for (const w of Object.values(cluster.workers)) w.process.kill("SIGTERM");
		process.exit(0);
	};
	process.once("SIGTERM", stop);
	process.once("SIGINT", stop);
}

/**
 * Ingestion: run the jobs that are due, then sleep. Several workers (or several hosts on
 * one database) can run side by side — each job is leased, so it never runs twice at once.
 */
async function worker(args) {
	const { createJobRunner, JOBS } = require("../lib/jobs");
	const { assets } = openAll(path.resolve(String(args.db || process.env.FAD_SERVICE_DB || "fad-service.db")));
	const names = args.jobs ? String(args.jobs).split(",").map(s => s.trim()).filter(Boolean) : Object.keys(JOBS);
	for (const n of names) if (!JOBS[n]) throw new Error(`unknown job ${n} (known: ${Object.keys(JOBS).join(", ")})`);
	const runner = createJobRunner({ assets, log: line => console.log(`${new Date().toISOString()} ${line}`) });
	const everyMs = Math.max(1, Number(args.every || 10)) * 60 * 1000;
	for (;;) {
		await runner.runDue(names);
		if (args.once) return;
		await new Promise(ok => setTimeout(ok, everyMs));
	}
}

function token(args) {
	const { db, tokens } = openAll(path.resolve(String(args.db || process.env.FAD_SERVICE_DB || "fad-service.db")));
	try {
		const [, action, id] = args._;
		if (action === "add") {
			const created = tokens.add({ role: args.role || "client", label: args.label === true ? "" : args.label });
			console.log(`token #${created.id} (${args.role || "client"}) — shown once, store it now:\n${created.token}`);
		} else if (action === "list") {
			for (const t of tokens.list())
				console.log(`#${t.id}\t${t.role}\t${t.revokedAt ? "revoked" : "active"}\t${new Date(t.createdAt).toISOString()}\t${t.label || ""}`);
		} else if (action === "revoke") {
			if (!id) throw new Error("token revoke <id>");
			console.log(tokens.revoke(id) ? `token #${id} revoked` : `no active token #${id}`);
		} else throw new Error(USAGE);
	} finally { db.close(); }
}

function main(argv = process.argv.slice(2)) {
	const args = parseArgs(argv);
	if (args.version || args.v) { console.log(VERSION); return; }
	const cmd = args._[0];
	if (cmd === "serve") return serve(args);
	if (cmd === "token") return token(args);
	if (cmd === "worker") return worker(args).catch(error => { console.error(`fad-service worker: ${error.message}`); process.exitCode = 1; });
	console.error(USAGE);
	process.exitCode = 2;
}

try { main(); }
catch (error) { console.error(`fad-service: ${error.message}`); process.exitCode = 2; }
