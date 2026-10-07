/**
 * Operational metrics in the Prometheus text format, served on their OWN listener
 * (config `metrics.listen`, default 127.0.0.1:9464) — never on the public port, so the
 * public surface stays what the spec lists, and a scraper on the private network needs no
 * route through the reverse proxy. Optional bearer token (`FAD_SERVICE_METRICS_TOKEN`).
 *
 * Under `--workers N` each worker pushes its counters to the primary every few seconds
 * over the cluster IPC channel; the primary owns the listener and serves the sum, so one
 * scrape sees the whole host.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const http = require("node:http");
const crypto = require("node:crypto");

/** Constant-time comparison of two strings (hashed first, so lengths do not leak). */
function sameSecret(a, b) {
	const h = v => crypto.createHash("sha256").update(String(v ?? "")).digest();
	return crypto.timingSafeEqual(h(a), h(b));
}

const ENGINE_KEYS = ["hits", "misses", "coalesced", "stale", "upstream", "errors"];

/** Per-process counters. */
function createCounters() {
	const http = new Map();          // `${route}|${status}` → { n, seconds }
	return {
		observe({ route, status, ms }) {
			const k = `${route}|${status}`;
			const c = http.get(k) || { n: 0, seconds: 0 };
			c.n++; c.seconds += ms / 1000;
			http.set(k, c);
		},
		/** Take and reset the deltas (pushed to the primary). */
		drain(engineStats) {
			const out = { http: Object.fromEntries(http), engine: {} };
			http.clear();
			for (const k of ENGINE_KEYS) {
				const now = engineStats?.[k] || 0;
				out.engine[k] = now - (this._last?.[k] || 0);
			}
			this._last = Object.fromEntries(ENGINE_KEYS.map(k => [k, engineStats?.[k] || 0]));
			return out;
		},
	};
}

/** Totals across processes (in the primary, or the single process). */
function createAggregate() {
	const http = new Map();
	const engine = Object.fromEntries(ENGINE_KEYS.map(k => [k, 0]));
	return {
		add(delta) {
			for (const [k, c] of Object.entries(delta.http || {})) {
				const t = http.get(k) || { n: 0, seconds: 0 };
				t.n += c.n; t.seconds += c.seconds;
				http.set(k, t);
			}
			for (const k of ENGINE_KEYS) engine[k] += delta.engine?.[k] || 0;
		},
		http, engine,
	};
}

const esc = v => String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");

/** Prometheus exposition text. `extra` = gauges read at scrape time (jobs, assets). */
function render(agg, { jobs = [], assets = {}, startedAt = Date.now(), workers = 1 } = {}) {
	const L = [];
	L.push("# HELP fad_http_requests_total HTTP requests by route family and status.", "# TYPE fad_http_requests_total counter");
	for (const [k, c] of agg.http) { const [route, status] = k.split("|"); L.push(`fad_http_requests_total{route="${esc(route)}",status="${esc(status)}"} ${c.n}`); }
	L.push("# HELP fad_http_request_seconds_sum Total time spent answering, by route family.", "# TYPE fad_http_request_seconds_sum counter");
	const byRoute = new Map();
	for (const [k, c] of agg.http) { const r = k.split("|")[0]; byRoute.set(r, (byRoute.get(r) || 0) + c.seconds); }
	for (const [r, s] of byRoute) L.push(`fad_http_request_seconds_sum{route="${esc(r)}"} ${s.toFixed(6)}`);
	L.push("# HELP fad_resource_cache_total Resource-cache outcomes (hit, miss, coalesced, stale) and upstream calls/errors.", "# TYPE fad_resource_cache_total counter");
	for (const k of ENGINE_KEYS) L.push(`fad_resource_cache_total{result="${k}"} ${agg.engine[k]}`);
	L.push("# HELP fad_job_last_success_timestamp_seconds Last successful run of each ingestion job.", "# TYPE fad_job_last_success_timestamp_seconds gauge");
	for (const j of jobs) if (j.status === "ok" && j.lastFinished) L.push(`fad_job_last_success_timestamp_seconds{job="${esc(j.job)}"} ${Math.floor(j.lastFinished / 1000)}`);
	L.push("# HELP fad_job_last_failed Whether the last run of a job failed (1) or not (0).", "# TYPE fad_job_last_failed gauge");
	for (const j of jobs) L.push(`fad_job_last_failed{job="${esc(j.job)}"} ${j.status === "error" ? 1 : 0}`);
	L.push("# HELP fad_assets Published assets by type.", "# TYPE fad_assets gauge");
	for (const [type, n] of Object.entries(assets)) L.push(`fad_assets{type="${esc(type)}"} ${n}`);
	L.push("# TYPE fad_workers gauge", `fad_workers ${workers}`);
	L.push("# TYPE fad_uptime_seconds gauge", `fad_uptime_seconds ${Math.floor((Date.now() - startedAt) / 1000)}`);
	L.push("# TYPE process_resident_memory_bytes gauge", `process_resident_memory_bytes ${process.memoryUsage().rss}`);
	return L.join("\n") + "\n";
}

const isLoopback = host => /^(127\.\d+\.\d+\.\d+|::1|localhost)$/i.test(String(host).replace(/^\[|\]$/g, ""));

/**
 * The metrics listener. `collect()` → the exposition text. Off loopback a token is
 * mandatory: route families, job states and counters are internal reconnaissance for
 * anything else on the same network (another container, another tenant).
 */
function startMetricsServer({ host = "127.0.0.1", port = 9464, token = null, collect }) {
	if (!token && !isLoopback(host))
		throw new Error(`metrics listen on ${host}:${port} is not loopback: set FAD_SERVICE_METRICS_TOKEN, listen on 127.0.0.1, or --no-metrics`);
	const server = http.createServer(async (req, res) => {
		if (req.url !== "/metrics" || req.method !== "GET") { res.writeHead(404); return res.end(); }
		if (token && !sameSecret(req.headers.authorization, `Bearer ${token}`)) { res.writeHead(401, { "www-authenticate": "Bearer" }); return res.end(); }
		let body;
		try { body = await collect(); } catch (e) { res.writeHead(500); return res.end(String(e.message)); }
		res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
		res.end(body);
	});
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(port, host, () => resolve(server));
	});
}

module.exports = { createCounters, createAggregate, render, startMetricsServer, isLoopback };
