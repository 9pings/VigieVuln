/**
 * The fad-service HTTP server: the resource engine shared with `fad-checker serve-cache`,
 * behind per-client tokens, roles and a rate limit, plus the public site.
 *
 *   GET  /health          public   liveness + region + store kind (client instance selection);
 *                                  503 while draining, so a load balancer stops sending traffic
 *   GET  /ready           public   readiness: database answers and data is loaded
 *   POST /v1/resource     client   the fad --proxy-cache protocol, unchanged
 *   GET  /admin/stats     admin    counters + store size
 *   GET  /admin/analytics admin    aggregate audience counters (analytics.provider = "server")
 *   POST /admin/purge     admin    drop one resource { provider, type, params }
 *   GET  / · /search · /cve/:id · /advisory/(certfr|osv)/:id · /sources · /legal   public HTML
 *   GET  /api/search · /api/cve/:id                                                public JSON
 *   GET  /static/(site.css|brand.css|logo|analytics.js)                            public
 *
 * Public reads are rate-limited per IP, cacheable (ETag + Cache-Control) and never touch
 * an upstream: they read what the ingestion jobs wrote.
 *
 * Privacy rule (spec §6): a log line carries method, route FAMILY, status, latency, a
 * request id and a salted hash of the token — never the coordinates requested, and never
 * which CVE a visitor read.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { fad } = require("./fad");
const web = require("./web/render");
const { pickLocale, makeT } = require("./web/i18n");
const { clientAnalytics } = require("./analytics");

const SECURITY_HEADERS = {
	"x-content-type-options": "nosniff",
	"referrer-policy": "no-referrer",
	"content-security-policy": "default-src 'none'; frame-ancestors 'none'",
	"x-frame-options": "DENY",
	"strict-transport-security": "max-age=31536000; includeSubDomains",
	"cross-origin-resource-policy": "same-origin",
	"permissions-policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
};
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const BASE_PAGE_CSP = { "default-src": ["'none'"], "style-src": ["'self'"], "img-src": ["'self'"], "form-action": ["'self'"],
	"base-uri": ["'none'"], "frame-ancestors": ["'none'"] };
const SITE_CSS = fs.readFileSync(path.join(__dirname, "web", "site.css"));
const ID_PATTERNS = [
	[/^CVE-\d{4}-\d{4,}$/i, id => `/cve/${id.toUpperCase()}`],
	[/^GCVE-0-(\d{4})-(\d{4,})$/i, (id, m) => `/cve/CVE-${m[1]}-${m[2]}`],
	[/^CERT(?:FR|A)-\d{4}-(?:AVI|ALE)-\d{1,5}$/i, id => `/advisory/certfr/${id.toUpperCase()}`],
	[/^(?:GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|MAL-\d{4}-\d+|RUSTSEC-\d{4}-\d+)$/i,
		id => `/advisory/osv/${/^GHSA/i.test(id) ? "GHSA" + id.slice(4).toLowerCase() : id.toUpperCase()}`],
];
const ROUTES = new Set(["/health", "/ready", "/v1/resource", "/admin/stats", "/admin/analytics", "/admin/purge"]);
const LOGO_TYPES = { ".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp", ".jpg": "image/jpeg", ".jpeg": "image/jpeg" };

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

/** The route family a request is logged and counted under — never the CVE or the query. */
function routeFamily(pathname) {
	if (ROUTES.has(pathname)) return pathname;
	if (pathname === "/") return "/";
	return /^\/(cve|advisory\/certfr|advisory\/osv|api\/search|api\/cve|search|sources|legal|static)\b/.exec(pathname)?.[0] || "/*";
}

const cspString = parts => Object.entries(parts).map(([k, v]) => `${k} ${[...new Set(v)].join(" ")}`).join("; ");

/**
 * opts: { store, tokens, assets, jobStatus, region, version, fetcher, keys, logSalt,
 *         log (text-line callback) | logger ({ info }), ratePerMinute, publicRatePerMinute,
 *         cacheSeconds, trustProxy, brand, analytics (config), serverAnalytics, counters,
 *         ...engine limits (maxBodyBytes, maxTransferBytes, upstreamTimeoutMs, maxConcurrent) }
 */
function createServiceServer(opts = {}) {
	const { store, tokens, region = "unknown", version = "0", keys = {}, log = null, logger = null, ratePerMinute = 600,
		assets = null, jobStatus = () => [], publicRatePerMinute = 300, cacheSeconds = 300, trustProxy = false,
		brand = {}, analytics = null, serverAnalytics = null, counters = null } = opts;
	if (!store || !tokens) throw new Error("fad-service needs a store and a token store");
	const { createResourceEngine, upstreamHeadersFor, sendJson } = fad("resource-cache/engine");
	const stats = { startedAt: Date.now(), requests: 0, hits: 0, misses: 0, coalesced: 0, stale: 0, upstream: 0, errors: 0 };
	const engine = createResourceEngine({ ...opts, store, stats, keys });
	const limited = createRateLimiter(ratePerMinute);
	const publicLimited = createRateLimiter(publicRatePerMinute);
	const logSalt = opts.logSalt || crypto.randomBytes(16).toString("hex");
	const clientTag = principal => principal
		? crypto.createHmac("sha256", logSalt).update(principal.hash).digest("hex").slice(0, 12) : "-";
	let draining = false;

	// Branding and third-party analytics are fixed at start-up: a page never reads config.
	const client = clientAnalytics(analytics);
	const csp = { ...BASE_PAGE_CSP };
	for (const [k, v] of Object.entries(client.csp)) csp[k] = [...(csp[k] || []), ...v];
	const PAGE_CSP = cspString(csp);
	const brandCss = Buffer.from(brand.accent ? `:root { --accent: ${brand.accent}; }\n` : "");
	let logo = null;
	if (brand.logo) {
		const type = LOGO_TYPES[path.extname(brand.logo).toLowerCase()];
		if (!type) throw new Error("brand.logo must be an .svg, .png, .webp or .jpg file");
		logo = { type, body: fs.readFileSync(brand.logo) };
	}
	const site = { brand: { ...brand, hasLogo: !!logo }, analyticsHead: client.head };

	function authenticate(req) {
		const auth = String(req.headers.authorization || "");
		const raw = auth.startsWith("Bearer ") ? auth.slice(7).trim() : req.headers["x-fad-proxy-token"];
		return raw ? tokens.verify(String(raw)) : null;
	}

	/** Client address: the socket, or — behind a trusted proxy — the entry that proxy appended. */
	function clientIp(req) {
		if (trustProxy) {
			const xff = String(req.headers["x-forwarded-for"] || "").split(",").map(s => s.trim()).filter(Boolean);
			if (xff.length) return xff[xff.length - 1];
		}
		return String(req.socket.remoteAddress || "?");
	}

	/** A cacheable public answer: ETag + Cache-Control, 304 on a matching If-None-Match. */
	function sendPublic(req, res, code, type, body, extra = {}) {
		const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
		const etag = `"${crypto.createHash("sha1").update(buf).digest("base64url")}"`;
		const headers = { "content-type": type, etag, vary: "Accept-Language",
			"cache-control": code === 200 ? `public, max-age=${cacheSeconds}, stale-while-revalidate=3600` : "no-store", ...extra };
		if (type.startsWith("text/html")) headers["content-security-policy"] = PAGE_CSP;
		if (code === 200 && req.headers["if-none-match"] === etag) { res.writeHead(304, headers); return res.end(); }
		res.writeHead(code, { ...headers, "content-length": buf.length });
		res.end(req.method === "HEAD" ? undefined : buf);
	}

	function routeStatic(req, res, p) {
		if (p === "/static/site.css") return sendPublic(req, res, 200, "text/css; charset=utf-8", SITE_CSS), true;
		if (p === "/static/brand.css") return sendPublic(req, res, 200, "text/css; charset=utf-8", brandCss), true;
		// An SVG is a document: sandboxed so a logo can never run script on this origin.
		if (p === "/static/logo" && logo) return sendPublic(req, res, 200, logo.type, logo.body, { "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox" }), true;
		if (p === "/static/analytics.js" && client.initScript) return sendPublic(req, res, 200, "text/javascript; charset=utf-8", client.initScript), true;
		return false;
	}

	/** Public pages and JSON. → true when the request was answered. */
	function routePublic(req, res, url, ctx) {
		const p = url.pathname;
		if (req.method !== "GET" && req.method !== "HEAD") return false;
		if (p.startsWith("/static/")) return routeStatic(req, res, p);
		if (!assets) return false;
		const isPage = ["/", "/search", "/sources", "/legal"].includes(p) || /^\/(cve|advisory\/certfr|advisory\/osv)\/[^/]+$/.test(p);
		const isApi = p === "/api/search" || /^\/api\/cve\/[^/]+$/.test(p);
		if (!isPage && !isApi) return false;
		if (!publicLimited("ip:" + clientIp(req))) { sendJson(res, 429, { error: "rate limit exceeded" }, { "retry-after": "60" }); return true; }
		const locale = pickLocale(url.searchParams.get("lang"), req.headers["accept-language"]);
		const t = makeT(locale);
		const q = String(url.searchParams.get("q") || "").slice(0, 200).trim();
		const type = ["cve", "advisory"].includes(url.searchParams.get("type")) ? url.searchParams.get("type") : null;
		const page = (code, title, body) => sendPublic(req, res, code, "text/html; charset=utf-8",
			web.layout({ t, locale, title, body, q, path: p + (q ? `?q=${encodeURIComponent(q)}` : ""), site }));

		if (p === "/api/search") {
			ctx.search = true;
			sendPublic(req, res, 200, "application/json", JSON.stringify({ query: q, results: q ? assets.search(q, { type, limit: Number(url.searchParams.get("limit")) || 20 }) : [] }));
			return true;
		}
		if (p.startsWith("/api/cve/")) {
			const id = decodeURIComponent(p.slice(9)).toUpperCase();
			const asset = assets.get("cve", id);
			if (!asset) sendPublic(req, res, 404, "application/json", JSON.stringify({ error: "not found" }));
			else sendPublic(req, res, 200, "application/json", JSON.stringify({ ...asset, signals: assets.signals(id),
				nvd: assets.nvd(id), advisories: assets.advisoriesForCve(id) }));
			return true;
		}
		if (p === "/") { page(200, t("Search"), web.home({ t, counts: assets.counts(), site })); return true; }
		if (p === "/sources") { page(200, t("Data sources"), web.sourcesPage({ t, jobs: jobStatus() })); return true; }
		if (p === "/legal") { page(200, t("Legal notice"), web.legalPage({ t, site })); return true; }
		if (p === "/search") {
			ctx.search = !!q;
			// An exact identifier goes straight to its page.
			for (const [re, target] of ID_PATTERNS) {
				const m = re.exec(q);
				if (m) { res.writeHead(302, { location: `${target(q, m)}?lang=${locale}`, "cache-control": "no-store" }); res.end(); return true; }
			}
			if (/^EUVD-\d{4}-\d+$/i.test(q)) {
				const cve = assets.cveForEuvd(q.toUpperCase());
				if (cve) { res.writeHead(302, { location: `/cve/${cve}?lang=${locale}`, "cache-control": "no-store" }); res.end(); return true; }
			}
			page(200, `${t("Search")} · ${q}`, q ? web.results({ t, locale, q, rows: assets.search(q, { type, limit: 50 }) }) : "");
			return true;
		}
		if (p.startsWith("/cve/")) {
			const id = decodeURIComponent(p.slice(5)).toUpperCase();
			const asset = /^CVE-\d{4}-\d{4,}$/.test(id) ? assets.get("cve", id) : null;
			if (!asset) { page(404, t("Not found"), web.notFound({ t })); return true; }
			ctx.asset = `cve:${id}`;
			const { gcveId, gcveUrl } = fad("gcve");
			const { certfrUrl } = fad("certfr");
			page(200, id, web.cvePage({ t, locale, asset, signals: assets.signals(id), gcve: gcveId(id), gcveUrl, certfrUrl,
				nvd: assets.nvd(id), advisories: assets.advisoriesForCve(id),
				euvdUrl: e => `https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(e)}` }));
			return true;
		}
		if (p.startsWith("/advisory/osv/")) {
			const id = decodeURIComponent(p.slice(14));
			const asset = assets.get("advisory", "osv:" + id);
			if (!asset) { page(404, t("Not found"), web.notFound({ t })); return true; }
			ctx.asset = `osv:${id}`;
			page(200, id, web.osvAdvisoryPage({ t, locale, asset }));
			return true;
		}
		if (p.startsWith("/advisory/certfr/")) {
			const ref = decodeURIComponent(p.slice(17)).toUpperCase();
			const asset = assets.get("advisory", "certfr:" + ref);
			if (!asset) { page(404, t("Not found"), web.notFound({ t })); return true; }
			ctx.asset = `certfr:${ref}`;
			page(200, ref, web.advisoryPage({ t, locale, asset }));
			return true;
		}
		return false;
	}

	async function route(req, res, principal, ctx) {
		const url = new URL(req.url, "http://service.invalid");
		const p = url.pathname;
		if (p === "/health" && req.method === "GET")
			return sendJson(res, draining ? 503 : 200, { ok: !draining, draining, service: "fad-service", version, region, store: store.kind, uptimeMs: Date.now() - stats.startedAt });
		if (p === "/ready" && req.method === "GET") {
			let ok = !draining, cves = 0;
			try { cves = assets ? (assets.counts().cve || 0) : 0; store.size(); } catch { ok = false; }
			if (assets && !cves) ok = false;
			return sendJson(res, ok ? 200 : 503, { ready: ok, cves });
		}
		if (routePublic(req, res, url, ctx)) return;
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
		if (p === "/admin/analytics" && req.method === "GET") {
			if (!serverAnalytics) return sendJson(res, 404, { error: "server analytics disabled (analytics.provider)" });
			return sendJson(res, 200, serverAnalytics.report(Math.min(366, Number(url.searchParams.get("days")) || 30)));
		}
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
		const given = String(req.headers["x-request-id"] || "");
		const rid = /^[A-Za-z0-9._-]{8,64}$/.test(given) ? given : crypto.randomBytes(8).toString("hex");
		for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
		res.setHeader("x-request-id", rid);
		if (draining) res.setHeader("connection", "close");
		const principal = authenticate(req);
		const ctx = { search: false, asset: null };
		res.once("finish", () => {
			const family = routeFamily(new URL(req.url, "http://service.invalid").pathname);
			const ms = Date.now() - started;
			counters?.observe({ route: family, status: res.statusCode, ms });
			if (serverAnalytics && !family.startsWith("/admin") && !["/health", "/ready", "/v1/resource", "/static", "/*"].includes(family))
				serverAnalytics.record({ family, status: res.statusCode, asset: ctx.asset, search: ctx.search });
			// A load balancer probes every few seconds: a healthy answer is not worth a log line.
			const probe = (family === "/health" || family === "/ready") && res.statusCode === 200;
			if (probe) logger?.debug("http", { route: family, status: res.statusCode, ms, rid });
			else if (logger) logger.info("http", { method: req.method, route: family, status: res.statusCode, ms, rid, client: clientTag(principal) });
			else if (log && !probe) log(`${new Date(started).toISOString()} ${req.method} ${family} ${res.statusCode} ${ms}ms client=${clientTag(principal)} rid=${rid}`);
		});
		route(req, res, principal, ctx).catch(err => {
			stats.errors++;
			logger?.error("request failed", { rid, error: String(err.message || err) });
			if (!res.headersSent) sendJson(res, 502, { error: String(err.message || err) }, { "x-fad-proxy": "error" });
			else res.destroy();
		});
	});
	const timeout = opts.upstreamTimeoutMs || 120000;
	server.requestTimeout = timeout;
	server.headersTimeout = Math.min(30000, timeout);
	server.keepAliveTimeout = 5000;
	server.setTimeout(timeout + 30000, socket => socket.destroy());
	const close = server.close.bind(server);
	server.close = callback => { engine.abortAll(); return close(callback); };
	/**
	 * Graceful stop: /health turns 503 at once (the load balancer stops routing here), the
	 * listener stops accepting, idle keep-alive sockets close, and requests in flight get
	 * up to `graceMs` to finish. → a promise resolved once the server is closed.
	 */
	server.fadDrain = (graceMs = 25000) => new Promise(resolve => {
		draining = true;
		const timer = setTimeout(() => { server.closeAllConnections?.(); }, graceMs);
		timer.unref?.();
		close(() => { clearTimeout(timer); resolve(); });
		server.closeIdleConnections?.();
	});
	server.fadStats = stats;
	server.fadStore = store;
	server.fadEngine = engine;
	return server;
}

module.exports = { createServiceServer, createRateLimiter, routeFamily, SECURITY_HEADERS };
