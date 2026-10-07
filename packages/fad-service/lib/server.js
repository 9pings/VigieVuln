/**
 * The fad-service HTTP server: the resource engine shared with `fad-checker serve-cache`,
 * behind per-client tokens, roles and a rate limit.
 *
 *   GET  /health          public   liveness + region + store kind (client instance selection)
 *   POST /v1/resource     client   the fad --proxy-cache protocol, unchanged
 *   GET  /admin/stats     admin    counters + store size
 *   POST /admin/purge     admin    drop one resource { provider, type, params }
 *
 * Privacy rule (spec §6): a log line carries method, route, status, latency and a salted
 * hash of the token — never the coordinates requested, which travel in the POST body.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const http = require("node:http");
const crypto = require("node:crypto");
const { fad } = require("./fad");

const SECURITY_HEADERS = {
	"x-content-type-options": "nosniff",
	"referrer-policy": "no-referrer",
	"content-security-policy": "default-src 'none'; frame-ancestors 'none'",
	"x-frame-options": "DENY",
	"strict-transport-security": "max-age=31536000; includeSubDomains",
	"cross-origin-resource-policy": "same-origin",
};
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const ROUTES = new Set(["/health", "/v1/resource", "/admin/stats", "/admin/purge"]);

function readBody(req, maxBytes) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		let n = 0;
		req.on("data", c => {
			n += c.length;
			if (n > maxBytes) { reject(Object.assign(new Error("request body too large"), { status: 413 })); req.destroy(); return; }
			chunks.push(c);
		});
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});
}

/** Fixed one-minute window per key. Per process: with N workers the effective limit is ×N. */
function createRateLimiter(perMinute) {
	const windows = new Map();
	return key => {
		if (!perMinute) return true;
		const now = Date.now(), slot = Math.floor(now / 60000);
		let w = windows.get(key);
		if (!w || w.slot !== slot) {
			if (windows.size > 10000) windows.clear();
			w = { slot, n: 0 };
			windows.set(key, w);
		}
		return ++w.n <= perMinute;
	};
}

/**
 * opts: { store, tokens, region, version, fetcher, keys, logSalt, log, ratePerMinute,
 *         ...engine limits (maxBodyBytes, maxTransferBytes, upstreamTimeoutMs, maxConcurrent) }
 */
function createServiceServer(opts = {}) {
	const { store, tokens, region = "unknown", version = "0", keys = {}, log = null, ratePerMinute = 600 } = opts;
	if (!store || !tokens) throw new Error("fad-service needs a store and a token store");
	const { createResourceEngine, upstreamHeadersFor, sendJson } = fad("resource-cache/engine");
	const stats = { startedAt: Date.now(), requests: 0, hits: 0, misses: 0, coalesced: 0, stale: 0, upstream: 0, errors: 0 };
	const engine = createResourceEngine({ ...opts, store, stats, keys });
	const limited = createRateLimiter(ratePerMinute);
	const logSalt = opts.logSalt || crypto.randomBytes(16).toString("hex");
	const clientTag = principal => principal
		? crypto.createHmac("sha256", logSalt).update(principal.hash).digest("hex").slice(0, 12) : "-";

	function authenticate(req) {
		const auth = String(req.headers.authorization || "");
		const raw = auth.startsWith("Bearer ") ? auth.slice(7).trim() : req.headers["x-fad-proxy-token"];
		return raw ? tokens.verify(String(raw)) : null;
	}

	async function route(req, res, principal) {
		const url = new URL(req.url, "http://service.invalid");
		const p = url.pathname;
		if (p === "/health" && req.method === "GET")
			return sendJson(res, 200, { ok: true, service: "fad-service", version, region, store: store.kind, uptimeMs: Date.now() - stats.startedAt });
		if (!ROUTES.has(p)) return sendJson(res, 404, { error: "not found" });
		if (!principal) return sendJson(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });
		if (!limited(principal.hash)) return sendJson(res, 429, { error: "rate limit exceeded" }, { "retry-after": "60" });

		if (p === "/v1/resource" && req.method === "POST") {
			let payload;
			try { payload = JSON.parse((await readBody(req, MAX_REQUEST_BYTES)).toString("utf8")); }
			catch (error) { return sendJson(res, error.status || 400, { error: error.status ? error.message : "invalid resource request" }); }
			return engine.handleResource(payload, res);
		}
		if (principal.role !== "admin") return sendJson(res, 403, { error: "admin role required" });
		if (p === "/admin/stats" && req.method === "GET")
			return sendJson(res, 200, { ...stats, entries: store.size(), bodyBytes: store.bodyBytes?.() ?? null, activeUpstream: engine.activeUpstream() });
		if (p === "/admin/purge" && req.method === "POST") {
			let payload, key;
			try {
				payload = JSON.parse((await readBody(req, MAX_REQUEST_BYTES)).toString("utf8"));
				const { getProvider, providerKey } = fad("providers");
				const request = getProvider(payload.provider).build(payload.type, payload.params);
				const headers = upstreamHeadersFor(request.url, { ...request.init?.headers, ...payload.headers }, keys);
				key = providerKey(payload.provider, payload.type, payload.params, headers);
			} catch (error) { return sendJson(res, 400, { error: error.message }); }
			return sendJson(res, 200, { purged: await store.purge(key) });
		}
		return sendJson(res, 405, { error: "method not allowed" });
	}

	const server = http.createServer((req, res) => {
		const started = Date.now();
		stats.requests++;
		for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
		const principal = authenticate(req);
		res.once("finish", () => {
			if (!log) return;
			const route = new URL(req.url, "http://service.invalid").pathname;
			log(`${new Date(started).toISOString()} ${req.method} ${ROUTES.has(route) ? route : "/*"} ${res.statusCode} ${Date.now() - started}ms client=${clientTag(principal)}`);
		});
		route(req, res, principal).catch(err => {
			stats.errors++;
			if (!res.headersSent) sendJson(res, 502, { error: String(err.message || err) }, { "x-fad-proxy": "error" });
			else res.destroy();
		});
	});
	const timeout = opts.upstreamTimeoutMs || 120000;
	server.requestTimeout = timeout;
	server.headersTimeout = Math.min(30000, timeout);
	server.setTimeout(timeout + 30000, socket => socket.destroy());
	const close = server.close.bind(server);
	server.close = callback => { engine.abortAll(); return close(callback); };
	server.fadStats = stats;
	server.fadStore = store;
	return server;
}

module.exports = { createServiceServer, createRateLimiter, SECURITY_HEADERS };
