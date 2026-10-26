/**
 * lib/proxy-cache.js — shared, persistent proxy-cache for vigievuln's public data sources.
 *
 * A scan of a real reactor makes hundreds of registry/advisory lookups, and every
 * machine that scans makes them again. This module turns ONE of those machines into
 * a cache point for the others:
 *
 *   vigievuln serve-cache                       # start the server (default 127.0.0.1:8321)
 *   vigievuln -s ./proj --proxy-cache http://127.0.0.1:8321
 *
 * Server: POST /v1/resource accepts a provider, data type and subject parameters.
 * Provider files under lib/providers/ build the upstream request. The on-disk key
 * names the requested resource (NVD CVE, OSV package/version, registry package),
 * not its URL or HTTP body. OSV, Packagist and EPSS retain upstream batching while
 * persisting and coalescing each item independently. Immutable body generations
 * and atomic metadata switches preserve a good entry across crashes and outages.
 *
 * Concurrent identical requests share one upstream call. Expired entries can be
 * served while they refresh; failed refreshes retain the last good result. Large
 * responses are spooled for concurrent readers even when they exceed the normal
 * persistent-body limit. CVE release archives have a separate 1 GiB body limit.
 *
 * Client: lib/providers/index.js exposes getResource(provider, type, params).
 * The route uses a local semantic cache, this shared server, or direct transport.
 * A dead proxy is classified against the requested source by source-health;
 * custom/private registry URLs use the direct path.
 *
 * Persistence is the point: the server may be restarted and entries outlive it. The
 * store deliberately lives in its OWN root (~/.fad-checker-proxy-cache/), NEVER inside
 * the client cache dir ~/.fad-checker/ — the scan's per-pass caches and the shared
 * server base are two different roles and must not be bundled, swapped or merged by
 * --export-cache / --import-cache together.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const http = require("http");
const engineLib = require("./resource-cache/engine");
const { createCacheStore, DEFAULT_CACHE_DIR } = require("./resource-cache/fs-store");
const {
	createResourceEngine, upstreamHeadersFor, ttlForUrl, sendJson,
	DEFAULT_TTL_MS, TTL_BY_SOURCE, DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_STORE_BYTES,
	DEFAULT_UPSTREAM_TIMEOUT_MS, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_ENTRIES,
} = engineLib;

const DEFAULT_PORT = 8321;
const DEFAULT_HOST = "127.0.0.1";
/** The scan's own per-pass cache root — the proxy store must never live inside it. */
const CLIENT_CACHE_DIR = () => path.join(os.homedir(), ".fad-checker");

// -------------------------------------------------------------- server ----

function readRequestBody(req, maxBytes) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		let n = 0;
		req.on("data", c => {
			n += c.length;
			if (n > maxBytes) { reject(new Error("request body too large")); req.destroy(); return; }
			chunks.push(c);
		});
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});
}

/**
 * The proxy-cache HTTP server: routes, the shared token and store ownership around the
 * resource engine (lib/resource-cache/engine.js). Endpoints:
 *   POST /v1/resource    — typed provider request
 *   GET  /__health         — liveness (no auth)
 *   GET  /__stats          — counters + entry count
 *   POST|DELETE /__clear  — wipe the store
 */
function createProxyCacheServer(opts = {}) {
	const {
		store = createCacheStore(),
		maxStoreBytes = DEFAULT_MAX_STORE_BYTES,
		maxEntries = DEFAULT_MAX_ENTRIES,
		upstreamTimeoutMs = DEFAULT_UPSTREAM_TIMEOUT_MS,
		maxConcurrent = DEFAULT_MAX_CONCURRENT,
		token = null,
	} = opts;
	if (!Number.isSafeInteger(maxStoreBytes) || maxStoreBytes < 1) throw new Error("maxStoreBytes must be a positive safe integer");
	const stats = { startedAt: Date.now(), requests: 0, hits: 0, misses: 0, coalesced: 0, stale: 0, upstream: 0, errors: 0 };
	const engine = createResourceEngine({ ...opts, store, stats });
	// One writer owns cleanup and quota accounting (a shared database store needs none).
	const unlock = store.claimOwner ? store.claimOwner() : () => {};
	try { store.configureLimits?.(maxStoreBytes, maxEntries); }
	catch (error) { unlock(); throw error; }

	const crypto = require("crypto");
	const same = (a, b) => {
		const x = crypto.createHash("sha256").update(String(a ?? "")).digest(), y = crypto.createHash("sha256").update(String(b)).digest();
		return crypto.timingSafeEqual(x, y);
	};
	const authorized = req => !token || same(req.headers["x-fad-proxy-token"], token) || same(req.headers.authorization, "Bearer " + token);

	async function handle(req, res) {
		stats.requests++;
		const target = req.url.replace(/^\/+/, "");
		if (target === "__health") return sendJson(res, 200, { ok: true, uptimeMs: Date.now() - stats.startedAt });
		if (!authorized(req)) return sendJson(res, 401, { error: "unauthorized", "x-fad-proxy": "unauthorized" });
		if (target === "__stats" && req.method === "GET") return sendJson(res, 200, { ...stats, entries: store.size(), bodyBytes: store.bodyBytes?.(), storeBytes: store.diskBytes?.(), activeUpstream: engine.activeUpstream(), limits: { maxTransferBytes: engine.limits.maxTransferBytes, maxStoreBytes, maxConcurrent, maxEntries, upstreamTimeoutMs } });
		if (target === "__clear" && (req.method === "POST" || req.method === "DELETE")) {
			const cleared = store.size();
			store.clear();
			return sendJson(res, 200, { cleared });
		}
		if (target === "v1/resource" && req.method === "POST") {
			let payload;
			try { payload = JSON.parse((await readRequestBody(req, 2 * 1024 * 1024)).toString("utf8")); }
			catch { return sendJson(res, 400, { error: "invalid resource request" }); }
			// The same whitelist as vigievuln: a serve-cache reachable on a network must not
			// forward anything fad itself would never send.
			try { payload = require("./resource-cache/validate").validateResource(payload); }
			catch (error) { return sendJson(res, 400, { error: error.message, ...(error.field ? { field: error.field } : {}) }); }
			return engine.handleResource(payload, res);
		}
		return sendJson(res, 404, { error: "expected /v1/resource or a control endpoint" });
	}

	const server = http.createServer((req, res) => {
		handle(req, res).catch(err => {
			stats.errors++;
			if (!res.headersSent) sendJson(res, 502, { error: String(err.message || err) }, { "x-fad-proxy": "error" });
			else res.destroy();
		});
	});
	server.requestTimeout = upstreamTimeoutMs;
	server.headersTimeout = Math.min(30000, upstreamTimeoutMs);
	server.maxConnections = Math.max(64, maxConcurrent * 8);
	server.setTimeout(upstreamTimeoutMs + 30000, socket => socket.destroy());
	const close = server.close.bind(server);
	server.close = callback => { engine.abortAll(); return close(callback); };
	server.once("close", unlock);
	server.once("error", unlock);
	server.fadStats = stats;
	server.fadStore = store;
	return server;
}

/** Convenience: create + listen. Resolves { server, url, port } once the socket is open. */
function startProxyCacheServer(opts = {}) {
	const { port = DEFAULT_PORT, host = DEFAULT_HOST } = opts;
	const server = createProxyCacheServer(opts);
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		try { server.listen(port, host, () => resolve({ server, url: `http://${host}:${server.address().port}`, port: server.address().port })); }
		catch (error) { server.emit("error", error); }
	});
}

// ------------------------------------------------------ outbound proxy ----

/**
 * Read the corporate-proxy URL from a raw argv: `--proxy <url>` for a scan,
 * `--upstream-proxy <url>` under the serve-cache subcommand. Exact-token match —
 * `--proxy-cache` (a different feature) must never be read as `--proxy`.
 * Returns null when absent or without a usable value.
 */
function parseProxyFlag(argv = process.argv) {
	const names = argv[2] === "serve-cache" ? ["--upstream-proxy"] : ["--proxy"];
	for (const name of names) {
		const i = argv.indexOf(name);
		if (i > -1 && argv[i + 1] && !argv[i + 1].startsWith("-")) return argv[i + 1];
	}
	return null;
}

/** True when the running runtime honors HTTP(S)_PROXY for global fetch. */
function runtimeSupportsEnvProxy() {
	if (typeof Bun !== "undefined") return true;   // bun honors http_proxy natively
	const v = process.versions.node.split(".").map(Number);
	return v[0] > 24 || (v[0] === 24 && v[1] >= 0); // node >= 24 via NODE_USE_ENV_PROXY
}

/**
 * Re-exec the current CLI with the corporate proxy applied to every outbound
 * request: NODE_USE_ENV_PROXY=1 makes Node >= 24's built-in fetch honor
 * HTTP_PROXY/HTTPS_PROXY (bun honors them natively), and both are read at process
 * start — so the only reliable place to apply them is a fresh process. The
 * `loopGuard` env prevents recursion; `noProxy` (the --proxy-cache host, if any)
 * keeps local cache traffic out of the corporate tunnel.
 */
function reexecWithProxy({ proxyUrl, loopGuard = "__FAD_PROXY_REEXEC__", noProxy = null, env = process.env, spawnImpl = null }) {
	const { spawn } = require("child_process");
	const e = { ...env, NODE_USE_ENV_PROXY: "1", HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, [loopGuard]: "1" };
	if (noProxy) e.NO_PROXY = [env.NO_PROXY, noProxy].filter(Boolean).join(",");
	// Rebuild the command line for the runtime we're in: under node it is
	// `node <script> args`; under bun (incl. the compiled binary, where argv[1] is
	// the executable itself) the executable replays argv from index 1 — the same
	// self-re-exec contract lib/retire.js uses for the vendored-JS mode.
	const isBun = !!(process.versions && process.versions.bun);
	const args = isBun ? process.argv.slice(1) : [process.argv[1], ...process.argv.slice(2)];
	const child = (spawnImpl || spawn)(process.execPath, args, { stdio: "inherit", env: e });
	child.on("exit", (code, sig) => process.exit(sig ? 1 : (code ?? 0)));
	child.on("error", err => { console.error(`proxy re-exec failed: ${err.message}`); process.exit(1); });
}

module.exports = {
	DEFAULT_TTL_MS, TTL_BY_SOURCE, DEFAULT_MAX_BODY_BYTES, DEFAULT_PORT, DEFAULT_HOST, DEFAULT_CACHE_DIR, CLIENT_CACHE_DIR,
	ttlForUrl, upstreamHeadersFor, createCacheStore, createProxyCacheServer, startProxyCacheServer,
	parseProxyFlag, runtimeSupportsEnvProxy, reexecWithProxy,
};
