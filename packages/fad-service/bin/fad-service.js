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
 *   fad-service seed    --ecosystem npm|pypi|maven|gem|composer|nuget|golang (--list f | --popular)
 *   fad-service keygen  --out <dir>                 Ed25519 key pair that signs dumps
 *   fad-service dump    [--kind public|private|full] [--since <ISO date>] [--out <dir>] [--include-packages]
 *   fad-service restore <x.manifest.json> [--trust-key pub.pem]
 *   fad-service verify  <x.manifest.json> --trust-key pub.pem
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
  fad-service serve  [--config f.json] [--db f.db|postgres://…] [--port 8322] [--host 127.0.0.1] [--region fr] [--workers N]
                     [--rate 600] [--log] [--log-file f] [--log-format text|json] [--trust-proxy]
  fad-service worker [--config f.json] [--db f] [--once] [--force] [--jobs cvelist,kev,epss,euvd,certfr,nvd,osv,maintenance]
  fad-service token  add --role client|admin [--label <text>] | list | revoke <id>   [--db f]
  fad-service backup [--config f.json] [--db f] (--out <file.db> | --dir <dir> [--keep 7])
  fad-service config [--config f.json]
  fad-service keygen --out <dir>
  fad-service dump   [--config f.json] [--kind public|private|full] [--since <ISO date>] [--out <dir>] [--include-packages]
  fad-service restore [--config f.json] <x.manifest.json> [--trust-key <pub.pem>]
  fad-service verify <x.manifest.json> --trust-key <pub.pem>
  fad-service seed   [--config f.json] --ecosystem npm|pypi|maven|gem|composer|nuget|golang (--list <file> | --popular) [--concurrency 4]`;

/** Open the database (SQLite file or postgres:// URL) and every store on it. */
async function openAll(target) {
	const { openDb } = require("../lib/db");
	const { createSqlStore } = require("../lib/sql-store");
	const { createTokenStore } = require("../lib/tokens");
	const { createAssetStore } = require("../lib/assets");
	const driver = openDb(target);
	await driver.exec("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)");
	// The log salt is stable across restarts, workers and instances, so one client keeps one
	// tag, but it never leaves the database: the tag cannot be reversed to the token.
	const secret = async name => {
		await driver.run("INSERT INTO settings (name, value) VALUES (?, ?) ON CONFLICT DO NOTHING", [name, crypto.randomBytes(16).toString("hex")]);
		return (await driver.get("SELECT value FROM settings WHERE name = ?", [name])).value;
	};
	const assets = await createAssetStore(driver, { log: m => console.error(`fad-service: ${m}`) });
	return { driver, assets, store: await createSqlStore({ driver }), tokens: await createTokenStore(driver),
		logSalt: await secret("log_salt"), demandSalt: await secret("demand_salt") };
}

/** Close cleanly: SQLite checkpoints its WAL first. */
async function closeAll(driver) {
	try { if (driver.dialect === "sqlite") await driver.exec("PRAGMA wal_checkpoint(PASSIVE)"); } catch { /* busy */ }
	try { await driver.close(); } catch { /* already closed */ }
}

function makeLogger(cfg, { inWorker = false } = {}) {
	const { createLogger, createWorkerLogger } = require("../lib/logger");
	const opts = { file: cfg.log.file, format: cfg.log.format, level: cfg.log.level, maxBytes: cfg.log.maxBytes, keep: cfg.log.keep };
	return inWorker ? createWorkerLogger(opts) : createLogger(opts);
}

/** One HTTP process: the server, its counters, graceful stop. */
async function serveProcess(cfg, { logger, pushMetrics = null }) {
	const { createServiceServer } = require("../lib/server");
	const { createServerAnalytics } = require("../lib/analytics");
	const { createCounters } = require("../lib/metrics");
	const { secretsFromEnv } = require("../lib/config");
	const { driver, store, tokens, assets, logSalt, demandSalt } = await openAll(cfg.db);
	const { createRegistryLayer } = require("../lib/registry");
	const { createUpstreamFetcher } = require("../lib/upstream");
	const registry = createRegistryLayer({ assets, threshold: cfg.registry.publishThreshold, salt: demandSalt });
	const { createUpstreamPolicy } = require("../lib/upstream-policy");
	const keys = secretsFromEnv();
	const policy = createUpstreamPolicy({ budgets: cfg.upstream.budgets, clientPerHour: cfg.upstream.clientPerHour,
		nvdKey: !!keys.nvd, githubToken: !!keys.github });
	const { createJobRunner } = require("../lib/jobs");
	const jobs = createJobRunner({ assets });
	const counters = createCounters();
	const serverAnalytics = cfg.analytics.provider === "server" ? await createServerAnalytics(driver) : null;
	const server = createServiceServer({
		store, tokens, assets, jobStatus: jobs.status, logSalt, version: VERSION, region: String(cfg.region),
		ratePerMinute: cfg.rateLimit.client, publicRatePerMinute: cfg.rateLimit.public, cacheSeconds: cfg.cacheSeconds,
		trustProxy: !!cfg.trustProxy, maxInFlight: cfg.maxInFlight, maxConnections: cfg.maxConnections, brand: cfg.brand, analytics: cfg.analytics, serverAnalytics, counters,
		logger: cfg.log.access ? logger : null, keys, registry, dumps: cfg.dumps, admit: policy.admit,
		fetcher: createUpstreamFetcher(globalThis.fetch, { mavenMirrors: cfg.upstream.mavenMirrors }),
	});
	server.listen(cfg.listen.port, cfg.listen.host, () => {
		logger.info("listening", { url: `http://${cfg.listen.host}:${server.address().port}`, pid: process.pid, version: VERSION, db: driver.dialect });
		server.warm().catch(e => logger.warn("warm-up failed", { error: String(e.message || e) }));
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
		await serverAnalytics?.close();
		await closeAll(driver);
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
	const { createAggregate, render, startMetricsServer, isLoopback } = require("../lib/metrics");
	const metricsOn = cfg.metrics.enabled !== false;
	const [mHost, mPort] = String(cfg.metrics.listen || "127.0.0.1:9464").split(/:(?=\d+$)/);
	// Checked before anything listens: startMetricsServer refuses too, but by then the public
	// port would already be serving and the refusal would only reach a log.
	if (metricsOn && !cfg.metrics.token && !isLoopback(mHost))
		throw new Error(`metrics listen on ${mHost}:${mPort} is not loopback: set FAD_SERVICE_METRICS_TOKEN, listen on 127.0.0.1, or --no-metrics`);

	if (workers === 1) {
		const logger = makeLogger(cfg);
		process.on("SIGHUP", () => logger.reopen());
		const agg = createAggregate();
		const { assets, jobs } = await serveProcess(cfg, { logger, pushMetrics: delta => agg.add(delta) });
		if (metricsOn) await startMetricsServer({ host: mHost, port: Number(mPort), token: cfg.metrics.token,
			collect: async () => render(agg, { jobs: await jobs.status(), assets: await assets.counts({ maxAgeMs: 60000 }), workers: 1 }) });
		return;
	}
	if (!cluster.isPrimary) {
		const logger = makeLogger(cfg, { inWorker: true });
		await serveProcess(cfg, { logger, pushMetrics: delta => process.send?.({ fadMetrics: delta }) });
		return;
	}
	// Primary: owns the log file, the metrics listener and the worker lifecycle.
	const logger = makeLogger(cfg);
	process.on("SIGHUP", () => logger.reopen());
	const { driver, assets } = await openAll(cfg.db);          // schema created once, before forking
	const { createJobRunner } = require("../lib/jobs");
	const jobs = createJobRunner({ assets });
	const agg = createAggregate();
	if (metricsOn) await startMetricsServer({ host: mHost, port: Number(mPort), token: cfg.metrics.token,
		collect: async () => render(agg, { jobs: await jobs.status(), assets: await assets.counts({ maxAgeMs: 60000 }), workers }) });
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
		const done = async () => { if (!Object.keys(cluster.workers).length) { await closeAll(driver); logger.close(); process.exit(0); } };
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
	const { driver, assets } = await openAll(cfg.db);
	const list = args.jobs ? String(args.jobs) : (cfg.jobs.enabled ? cfg.jobs.enabled.join(",") : null);
	const names = list ? list.split(",").map(s => s.trim()).filter(Boolean)
		: Object.keys(JOBS).filter(n => !JOBS[n].optIn || (n === "dump" && cfg.dumps.daily));
	for (const n of names) if (!JOBS[n]) throw new Error(`unknown job ${n} (known: ${Object.keys(JOBS).join(", ")})`);
	const owner = `${os.hostname()}:${process.pid}`;
	let runner;
	runner = createJobRunner({ assets, owner, log: line => logger.info(line), jobOptions: { osvEcosystems: cfg.jobs.osvEcosystems,
		resourceCacheMaxBytes: cfg.jobs.resourceCacheBytes, dumps: cfg.dumps, baseUrl: cfg.brand.baseUrl, version: VERSION,
		instance: { name: cfg.brand.name, baseUrl: cfg.brand.baseUrl }, sources: () => runner.status() } });
	const stop = async () => {
		logger.info("worker stopping, releasing leases", { owner });
		try { await driver.run("UPDATE job_runs SET lease_until = 0, last_status = 'interrupted' WHERE owner = ? AND lease_until > 0", [owner]); } catch { /* db gone */ }
		await closeAll(driver);
		process.exit(0);
	};
	process.once("SIGTERM", stop);
	process.once("SIGINT", stop);
	const everyMs = Math.max(1, Number(cfg.jobs.everyMinutes || 10)) * 60 * 1000;
	for (;;) {
		if (args.force) for (const n of names) await runner.runJob(n);   // run now, due or not
		else await runner.runDue(names);
		if (args.once) { await closeAll(driver); return; }
		await new Promise(ok => setTimeout(ok, everyMs));
	}
}

/**
 * Online backup: `VACUUM INTO` writes a consistent, compacted copy while the service
 * runs. With --dir, files are named by UTC timestamp and only the newest --keep are kept.
 */
function backup(cfg, args) {
	const { isPg } = require("../lib/db");
	if (isPg(cfg.db)) throw new Error("backup copies a SQLite file — on PostgreSQL use pg_dump (or your provider's snapshots)");
	const { DatabaseSync } = require("node:sqlite");
	let out = args.out;
	if (!out && args.dir) {
		fs.mkdirSync(String(args.dir), { recursive: true });
		out = path.join(String(args.dir), `fad-service-${new Date().toISOString().replace(/[:.]/g, "-")}.db`);
	}
	if (!out) throw new Error("backup needs --out <file.db> or --dir <dir>");
	if (fs.existsSync(out)) throw new Error(`${out} exists`);
	// The copy holds token hashes, the log/demand salts and the whole resource cache: it is
	// created 0600 BEFORE anything is written into it (VACUUM INTO accepts an empty file).
	fs.closeSync(fs.openSync(String(out), "wx", 0o600));
	const db = new DatabaseSync(cfg.db);
	const t0 = Date.now();
	try { db.prepare("VACUUM INTO ?").run(path.resolve(String(out))); }
	catch (error) { fs.rmSync(String(out), { force: true }); throw error; }
	finally { db.close(); }
	console.log(`backup ${out} (${(fs.statSync(out).size / 1048576).toFixed(1)} MB, ${((Date.now() - t0) / 1000).toFixed(1)} s)`);
	if (args.dir) {
		const keep = Math.max(1, Number(args.keep || 7));
		const files = fs.readdirSync(String(args.dir)).filter(f => /^fad-service-.*\.db$/.test(f)).sort();
		for (const f of files.slice(0, Math.max(0, files.length - keep))) { fs.rmSync(path.join(String(args.dir), f)); console.log(`removed ${f}`); }
	}
}

/**
 * Seed a list of packages through an in-process server (same path as a client request),
 * authenticated by an in-memory admin token: nothing is written to the token table, so a
 * seed killed midway leaves no live admin token behind.
 */
async function seedCommand(cfg, args) {
	const { seed, readSpecs } = require("../lib/registry/seed");
	const { createServiceServer } = require("../lib/server");
	const { createRegistryLayer } = require("../lib/registry");
	const { createUpstreamFetcher } = require("../lib/upstream");
	const type = String(args.ecosystem || "");
	const specs = readSpecs(type, { list: args.list === true ? null : args.list, popular: !!args.popular });
	const { driver, store, tokens, assets, demandSalt } = await openAll(cfg.db);
	const registry = createRegistryLayer({ assets, threshold: cfg.registry.publishThreshold, salt: demandSalt });
	// Earlier versions stored a temporary admin token, left active if the seed was killed.
	for (const t of await tokens.list())
		if (t.label === "seed (temporary)" && !t.revokedAt) { await tokens.revoke(t.id); console.log(`revoked leftover seed token #${t.id}`); }
	const { withEphemeralToken } = require("../lib/tokens");
	const temp = withEphemeralToken(tokens, { role: "admin", label: "seed" });
	const server = createServiceServer({ store, tokens: temp.tokens, assets, registry, ratePerMinute: 0, publicRatePerMinute: 0,
		fetcher: createUpstreamFetcher(globalThis.fetch, { mavenMirrors: cfg.upstream.mavenMirrors }) });
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	try {
		const t0 = Date.now();
		const r = await seed({ baseUrl: `http://127.0.0.1:${server.address().port}`, token: temp.token, type, specs, assets,
			concurrency: Number(args.concurrency || 4), log: line => console.log(line) });
		console.log(`seeded ${type}: ${r.ok} ok, ${r.missing} not found, ${r.failed} failed (${((Date.now() - t0) / 1000).toFixed(1)} s)`);
		if (r.failed) process.exitCode = 1;
	} finally {
		await new Promise(ok => server.close(ok));
		await closeAll(driver);
	}
}

/** An Ed25519 key pair for signing dumps: private 0600, public to publish. */
function keygen(args) {
	const dir = String(args.out || "");
	if (!dir || args.out === true) throw new Error("keygen needs --out <dir>");
	fs.mkdirSync(dir, { recursive: true });
	const priv = path.join(dir, "dump-signing.key"), pub = path.join(dir, "dump-signing.pub.pem");
	if (fs.existsSync(priv)) throw new Error(`${priv} exists — refusing to overwrite a signing key`);
	const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
	fs.writeFileSync(priv, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
	fs.writeFileSync(pub, publicKey.export({ type: "spki", format: "pem" }));
	const { keyFingerprint } = require("../lib/fad").fad("dump-format");
	console.log(`private key ${priv} (keep it secret, set dumps.signingKeyFile)\npublic key  ${pub} (publish it; fingerprint ${keyFingerprint(fs.readFileSync(pub, "utf8"))})`);
}

async function dumpCommand(cfg, args) {
	const { buildDump, pruneDumps } = require("../lib/dumps/build");
	const kind = String(args.kind || "public");
	const { driver, assets } = await openAll(cfg.db);
	const { createJobRunner } = require("../lib/jobs");
	try {
		const dir = args.out && args.out !== true ? path.resolve(String(args.out)) : path.join(cfg.dumps.dir, kind === "full" ? "full" : kind);
		const since = args.since ? Date.parse(String(args.since)) : null;
		if (args.since && !Number.isFinite(since)) throw new Error("--since must be an ISO date");
		const t0 = Date.now();
		const m = await buildDump({ driver, dir, kind, since, includePackages: !!args["include-packages"] || cfg.dumps.publicIncludesPackages,
			signingKeyPem: cfg.dumps.signingKeyFile ? fs.readFileSync(cfg.dumps.signingKeyFile, "utf8") : null,
			baseUrl: cfg.brand.baseUrl, trackers: cfg.dumps.trackers, instance: { name: cfg.brand.name, baseUrl: cfg.brand.baseUrl },
			version: VERSION, sources: await createJobRunner({ assets }).status() });
		console.log(`${m.id}: ${(m.payload.bytes / 1048576).toFixed(1)} MB in ${((Date.now() - t0) / 1000).toFixed(1)} s — ${JSON.stringify(m.counts)}${cfg.dumps.signingKeyFile ? ", signed" : ", NOT signed (no dumps.signingKeyFile)"}${m.torrent ? `\n${m.torrent.magnet}` : ""}`);
		if (!args.out || args.out === true) for (const id of pruneDumps(dir, cfg.dumps.keep)) console.log(`removed ${id}`);
	} finally { await closeAll(driver); }
}

async function restoreCommand(cfg, args) {
	const { restoreDump } = require("../lib/dumps/restore");
	const manifestPath = args._[1];
	if (!manifestPath) throw new Error("restore <x.manifest.json>");
	const { driver, assets, store } = await openAll(cfg.db);
	try {
		const publicKeyPem = args["trust-key"] && args["trust-key"] !== true ? fs.readFileSync(String(args["trust-key"]), "utf8") : null;
		if (!publicKeyPem) console.warn("warning: no --trust-key — integrity checked (sha256), origin NOT verified");
		const t0 = Date.now();
		const { manifest, counts } = await restoreDump({ assets, store, manifestPath: path.resolve(manifestPath), publicKeyPem });
		console.log(`restored ${manifest.id} in ${((Date.now() - t0) / 1000).toFixed(1)} s — ${JSON.stringify(counts)}`);
	} finally { await closeAll(driver); }
}

async function verifyCommand(args) {
	const { openDump, keyFingerprint } = require("../lib/fad").fad("dump-format");
	const manifestPath = args._[1];
	if (!manifestPath || !args["trust-key"] || args["trust-key"] === true) throw new Error("verify <x.manifest.json> --trust-key <pub.pem>");
	const pem = fs.readFileSync(String(args["trust-key"]), "utf8");
	const { manifest } = await openDump(path.resolve(manifestPath), { publicKeyPem: pem });
	console.log(`OK ${manifest.id} — signed by ${keyFingerprint(pem)}, payload sha256 ${manifest.payload.sha256}`);
}

async function token(cfg, args) {
	const { driver, tokens } = await openAll(cfg.db);
	try {
		const [, action, id] = args._;
		if (action === "add") {
			const created = await tokens.add({ role: args.role || "client", label: args.label === true ? "" : args.label });
			console.log(`token #${created.id} (${args.role || "client"}) — shown once, store it now:\n${created.token}`);
		} else if (action === "list") {
			for (const t of await tokens.list())
				console.log(`#${t.id}\t${t.role}\t${t.revokedAt ? "revoked" : "active"}\t${new Date(t.createdAt).toISOString()}\t${t.label || ""}`);
		} else if (action === "revoke") {
			if (!id) throw new Error("token revoke <id>");
			console.log((await tokens.revoke(id)) ? `token #${id} revoked` : `no active token #${id}`);
		} else throw new Error(USAGE);
	} finally { await closeAll(driver); }
}

function main(argv = process.argv.slice(2)) {
	const args = parseArgs(argv);
	if (args.version || args.v) { console.log(VERSION); return; }
	// Help before anything else: `serve --help` must never start a server or create a database.
	if (args.help || args._.includes("-h") || args._[0] === "help") { console.log(USAGE); return; }
	const cmd = args._[0];
	if (cmd === "keygen") return keygen(args);
	if (cmd === "verify") return verifyCommand(args).catch(fail);
	if (!["serve", "worker", "token", "backup", "config", "seed", "dump", "restore"].includes(cmd)) { console.error(USAGE); process.exitCode = 2; return; }
	const { loadConfig } = require("../lib/config");
	const cfg = loadConfig(args);
	if (cmd === "config") {
		const masked = String(cfg.db).replace(/^(postgres(?:ql)?:\/\/[^:/@]+:)[^@]*@/i, "$1***@");
		console.log(JSON.stringify({ ...cfg, db: masked, metrics: { ...cfg.metrics, token: cfg.metrics.token ? "(set)" : null } }, null, 2));
		return;
	}
	if (cmd === "serve") return serve(cfg).catch(fail);
	if (cmd === "worker") return worker(cfg, args).catch(fail);
	if (cmd === "token") return token(cfg, args).catch(fail);
	if (cmd === "backup") return backup(cfg, args);
	if (cmd === "seed") return seedCommand(cfg, args).catch(fail);
	if (cmd === "dump") return dumpCommand(cfg, args).catch(fail);
	if (cmd === "restore") return restoreCommand(cfg, args).catch(fail);
}

function fail(error) { console.error(`fad-service: ${error.message}`); process.exitCode = 1; }

try { main(); }
catch (error) { console.error(`fad-service: ${error.message}`); process.exitCode = 2; }
