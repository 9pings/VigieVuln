#!/usr/bin/env node
/**
 * fad-service — public data service for fad-checker (docs/SPEC-fad-service.md).
 *
 *   fad-service serve   [--config f.json] [--db f] [--port 8322] [--host 127.0.0.1] [--region fr]
 *                       [--workers N] [--rate N] [--log] [--log-file f] [--log-format text|json] [--trust-proxy]
 *   fad-service worker  [--config f.json] [--db f] [--once] [--jobs cvelist,kev,…]
 *   fad-service token   add --role client|admin [--label t] | list | revoke <id>
 *   fad-service backup  [--config f.json] [--db f] (--out file.db | --dir d [--keep 7])
 *   fad-service config  [--config f.json]          print the effective configuration
 *
 * Configuration: see lib/config.js (defaults ← JSON file ← flags). Upstream API keys come
 * from the environment only: FAD_SERVICE_NVD_KEY, FAD_SERVICE_GITHUB_TOKEN,
 * FAD_SERVICE_WORDFENCE_KEY; FAD_SERVICE_METRICS_TOKEN for the metrics listener.
 *
 * Signals: SIGTERM/SIGINT drain and stop (health turns 503 first), SIGHUP reopens the log
 * file (external logrotate).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const cluster = require("node:cluster");
const crypto = require("node:crypto");
const fs = require("node:fs");
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
  fad-service serve  [--config f.json] [--db f] [--port 8322] [--host 127.0.0.1] [--region fr] [--workers N]
                     [--rate 600] [--log] [--log-file f] [--log-format text|json] [--trust-proxy]
  fad-service worker [--config f.json] [--db f] [--once] [--jobs cvelist,kev,epss,euvd,certfr,nvd,osv,maintenance]
  fad-service token  add --role client|admin [--label <text>] | list | revoke <id>   [--db f]
  fad-service backup [--config f.json] [--db f] (--out <file.db> | --dir <dir> [--keep 7])
  fad-service config [--config f.json]`;

function openAll(dbFile) {
	const { openDatabase, createSqliteStore } = require("../lib/sqlite-store");
	const { createTokenStore } = require("../lib/tokens");
	const { createAssetStore } = require("../lib/assets");
	const db = openDatabase(dbFile);
	db.exec("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)");
	// The log salt is stable across restarts and workers, so one client keeps one tag,
	// but it never leaves the database: the tag cannot be reversed to the token.
	db.prepare("INSERT OR IGNORE INTO settings (name, value) VALUES ('log_salt', ?)").run(crypto.randomBytes(16).toString("hex"));
	const logSalt = db.prepare("SELECT value FROM settings WHERE name = 'log_salt'").get().value;
	return { db, store: createSqliteStore({ db }), tokens: createTokenStore(db), assets: createAssetStore(db), logSalt };
}

function makeLogger(cfg, { inWorker = false } = {}) {
	const { createLogger, createWorkerLogger } = require("../lib/logger");
	const opts = { file: cfg.log.file, format: cfg.log.format, level: cfg.log.level, maxBytes: cfg.log.maxBytes, keep: cfg.log.keep };
	return inWorker ? createWorkerLogger(opts) : createLogger(opts);
}

/** One HTTP process: the server, its counters, graceful stop. */
function serveProcess(cfg, { logger, pushMetrics = null }) {
	const { createServiceServer } = require("../lib/server");
	const { createServerAnalytics } = require("../lib/analytics");
	const { createCounters } = require("../lib/metrics");
	const { secretsFromEnv } = require("../lib/config");
	const { db, store, tokens, assets, logSalt } = openAll(cfg.db);
	const { createJobRunner } = require("../lib/jobs");
	const jobs = createJobRunner({ assets });
	const counters = createCounters();
	const serverAnalytics = cfg.analytics.provider === "server" ? createServerAnalytics(db) : null;
	const server = createServiceServer({
		store, tokens, assets, jobStatus: jobs.status, logSalt, version: VERSION, region: String(cfg.region),
		ratePerMinute: cfg.rateLimit.client, publicRatePerMinute: cfg.rateLimit.public, cacheSeconds: cfg.cacheSeconds,
		trustProxy: !!cfg.trustProxy, brand: cfg.brand, analytics: cfg.analytics, serverAnalytics, counters,
		logger: cfg.log.access ? logger : null, keys: secretsFromEnv(),
	});
	server.listen(cfg.listen.port, cfg.listen.host, () => {
		logger.info("listening", { url: `http://${cfg.listen.host}:${server.address().port}`, pid: process.pid, version: VERSION, db: cfg.db });
	});
	if (pushMetrics) {
		const t = setInterval(() => pushMetrics(counters.drain(server.fadStats)), 5000);
		t.unref?.();
	}
	let stopping = false;
	const stop = async () => {
		if (stopping) return;
		stopping = true;
		logger.info("draining", { pid: process.pid });
		await server.fadDrain(cfg.shutdownSeconds * 1000);
		if (pushMetrics) pushMetrics(counters.drain(server.fadStats));
		serverAnalytics?.close();
		try { db.exec("PRAGMA wal_checkpoint(PASSIVE)"); db.close(); } catch { /* already closed */ }
		logger.info("stopped", { pid: process.pid });
		process.exit(0);
	};
	process.once("SIGTERM", stop);
	process.once("SIGINT", stop);
	return { server, counters, assets, jobs };
}

async function serve(cfg) {
	const workers = cfg.workers === true ? os.availableParallelism() : Number(cfg.workers || 1);
	if (!Number.isInteger(workers) || workers < 1) throw new Error("workers must be a positive integer");
	const { createAggregate, render, startMetricsServer } = require("../lib/metrics");
	const metricsOn = cfg.metrics.enabled !== false;
	const [mHost, mPort] = String(cfg.metrics.listen || "127.0.0.1:9464").split(/:(?=\d+$)/);

	if (workers === 1) {
		const logger = makeLogger(cfg);
		process.on("SIGHUP", () => logger.reopen());
		const agg = createAggregate();
		const { assets, jobs } = serveProcess(cfg, { logger, pushMetrics: delta => agg.add(delta) });
		if (metricsOn) await startMetricsServer({ host: mHost, port: Number(mPort), token: cfg.metrics.token,
			collect: () => render(agg, { jobs: jobs.status(), assets: assets.counts(), workers: 1 }) });
		return;
	}
	if (!cluster.isPrimary) {
		const logger = makeLogger(cfg, { inWorker: true });
		serveProcess(cfg, { logger, pushMetrics: delta => process.send?.({ fadMetrics: delta }) });
		return;
	}
	// Primary: owns the log file, the metrics listener and the worker lifecycle.
	const logger = makeLogger(cfg);
	process.on("SIGHUP", () => logger.reopen());
	const { db, assets } = openAll(cfg.db);          // schema created once, before forking
	const { createJobRunner } = require("../lib/jobs");
	const jobs = createJobRunner({ assets });
	const agg = createAggregate();
	if (metricsOn) await startMetricsServer({ host: mHost, port: Number(mPort), token: cfg.metrics.token,
		collect: () => render(agg, { jobs: jobs.status(), assets: assets.counts(), workers }) });
	let stopping = false;
	const fork = () => {
		const w = cluster.fork();
		w.on("message", m => {
			if (m?.fadLog) logger.line(m.fadLog);
			else if (m?.fadMetrics) agg.add(m.fadMetrics);
		});
	};
	for (let i = 0; i < workers; i++) fork();
	cluster.on("exit", (worker, code, signal) => {
		if (stopping) return;
		logger.warn("worker exited, restarting", { pid: worker.process.pid, code, signal });
		fork();
	});
	const stop = () => {
		if (stopping) return;
		stopping = true;
		logger.info("stopping workers", { workers });
		for (const w of Object.values(cluster.workers)) w.process.kill("SIGTERM");
		const done = () => { if (!Object.keys(cluster.workers).length) { db.close(); logger.close(); process.exit(0); } };
		cluster.on("exit", done);
		setTimeout(() => process.exit(0), (cfg.shutdownSeconds + 5) * 1000).unref();
		done();
	};
	process.once("SIGTERM", stop);
	process.once("SIGINT", stop);
}

/**
 * Ingestion: run the jobs that are due, then sleep. Several workers (or several hosts on
 * one database) can run side by side — each job is leased, so it never runs twice at once.
 * On SIGTERM the leases this process holds are released, so another worker can take over.
 */
async function worker(cfg, args) {
	const { createJobRunner, JOBS } = require("../lib/jobs");
	const logger = makeLogger(cfg);
	process.on("SIGHUP", () => logger.reopen());
	const { db, assets } = openAll(cfg.db);
	const list = args.jobs ? String(args.jobs) : (cfg.jobs.enabled ? cfg.jobs.enabled.join(",") : null);
	const names = list ? list.split(",").map(s => s.trim()).filter(Boolean) : Object.keys(JOBS);
	for (const n of names) if (!JOBS[n]) throw new Error(`unknown job ${n} (known: ${Object.keys(JOBS).join(", ")})`);
	const owner = `${os.hostname()}:${process.pid}`;
	const runner = createJobRunner({ assets, owner, log: line => logger.info(line), jobOptions: { osvEcosystems: cfg.jobs.osvEcosystems } });
	const stop = () => {
		logger.info("worker stopping, releasing leases", { owner });
		try { db.prepare("UPDATE job_runs SET lease_until = 0, last_status = 'interrupted' WHERE owner = ? AND lease_until > 0").run(owner); } catch { /* db gone */ }
		try { db.close(); } catch { /* already */ }
		process.exit(0);
	};
	process.once("SIGTERM", stop);
	process.once("SIGINT", stop);
	const everyMs = Math.max(1, Number(cfg.jobs.everyMinutes || 10)) * 60 * 1000;
	for (;;) {
		await runner.runDue(names);
		if (args.once) { db.close(); return; }
		await new Promise(ok => setTimeout(ok, everyMs));
	}
}

/**
 * Online backup: `VACUUM INTO` writes a consistent, compacted copy while the service
 * runs. With --dir, files are named by UTC timestamp and only the newest --keep are kept.
 */
function backup(cfg, args) {
	const { openDatabase } = require("../lib/sqlite-store");
	let out = args.out;
	if (!out && args.dir) {
		fs.mkdirSync(String(args.dir), { recursive: true });
		out = path.join(String(args.dir), `fad-service-${new Date().toISOString().replace(/[:.]/g, "-")}.db`);
	}
	if (!out) throw new Error("backup needs --out <file.db> or --dir <dir>");
	if (fs.existsSync(out)) throw new Error(`${out} exists`);
	const db = openDatabase(cfg.db);
	const t0 = Date.now();
	try { db.prepare("VACUUM INTO ?").run(path.resolve(String(out))); } finally { db.close(); }
	console.log(`backup ${out} (${(fs.statSync(out).size / 1048576).toFixed(1)} MB, ${((Date.now() - t0) / 1000).toFixed(1)} s)`);
	if (args.dir) {
		const keep = Math.max(1, Number(args.keep || 7));
		const files = fs.readdirSync(String(args.dir)).filter(f => /^fad-service-.*\.db$/.test(f)).sort();
		for (const f of files.slice(0, Math.max(0, files.length - keep))) { fs.rmSync(path.join(String(args.dir), f)); console.log(`removed ${f}`); }
	}
}

function token(cfg, args) {
	const { db, tokens } = openAll(cfg.db);
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
	if (!["serve", "worker", "token", "backup", "config"].includes(cmd)) { console.error(USAGE); process.exitCode = 2; return; }
	const { loadConfig } = require("../lib/config");
	const cfg = loadConfig(args);
	if (cmd === "config") { console.log(JSON.stringify({ ...cfg, metrics: { ...cfg.metrics, token: cfg.metrics.token ? "(set)" : null } }, null, 2)); return; }
	if (cmd === "serve") return serve(cfg).catch(fail);
	if (cmd === "worker") return worker(cfg, args).catch(fail);
	if (cmd === "token") return token(cfg, args);
	if (cmd === "backup") return backup(cfg, args);
}

function fail(error) { console.error(`fad-service: ${error.message}`); process.exitCode = 1; }

try { main(); }
catch (error) { console.error(`fad-service: ${error.message}`); process.exitCode = 2; }
