/**
 * The fad-service HTTP server: the resource engine shared with `fad-checker serve-cache`,
 * behind per-client tokens, roles and a rate limit.
 *
 *   GET  /health          public   liveness + region + store kind (client instance selection)
 *   POST /v1/resource     client   the fad --proxy-cache protocol, unchanged
 *   GET  /admin/stats     admin    counters + store size
 *   POST /admin/purge     admin    drop one resource { provider, type, params }
 *   GET  / · /search · /cve/:id · /advisory/certfr/:ref · /sources · /legal   public HTML
 *   GET  /api/search · /api/cve/:id                                           public JSON
 *
 * Public reads are rate-limited per IP, cacheable (ETag + Cache-Control) and never touch
 * an upstream: they read what the ingestion jobs wrote.
 *
 * Privacy rule (spec §6): a log line carries method, route, status, latency and a salted
 * hash of the token — never the coordinates requested, which travel in the POST body.
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

const SECURITY_HEADERS = {
	"x-content-type-options": "nosniff",
	"referrer-policy": "no-referrer",
	"content-security-policy": "default-src 'none'; frame-ancestors 'none'",
	"x-frame-options": "DENY",
	"strict-transport-security": "max-age=31536000; includeSubDomains",
	"cross-origin-resource-policy": "same-origin",
};
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const PAGE_CSP = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const SITE_CSS = fs.readFileSync(path.join(__dirname, "web", "site.css"));
const ID_PATTERNS = [
	[/^CVE-\d{4}-\d{4,}$/i, id => `/cve/${id.toUpperCase()}`],
	[/^GCVE-0-(\d{4})-(\d{4,})$/i, (id, m) => `/cve/CVE-${m[1]}-${m[2]}`],
	[/^CERT(?:FR|A)-\d{4}-(?:AVI|ALE)-\d{1,5}$/i, id => `/advisory/certfr/${id.toUpperCase()}`],
	[/^(?:GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|MAL-\d{4}-\d+|RUSTSEC-\d{4}-\d+)$/i,
		id => `/advisory/osv/${/^GHSA/i.test(id) ? "GHSA" + id.slice(4).toLowerCase() : id.toUpperCase()}`],
];
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
	const { store, tokens, region = "unknown", version = "0", keys = {}, log = null, ratePerMinute = 600,
		assets = null, jobStatus = () => [], publicRatePerMinute = 300, cacheSeconds = 300 } = opts;
	if (!store || !tokens) throw new Error("fad-service needs a store and a token store");
	const { createResourceEngine, upstreamHeadersFor, sendJson } = fad("resource-cache/engine");
	const stats = { startedAt: Date.now(), requests: 0, hits: 0, misses: 0, coalesced: 0, stale: 0, upstream: 0, errors: 0 };
	const engine = createResourceEngine({ ...opts, store, stats, keys });
	const limited = createRateLimiter(ratePerMinute);
	const publicLimited = createRateLimiter(publicRatePerMinute);
	const logSalt = opts.logSalt || crypto.randomBytes(16).toString("hex");
	const clientTag = principal => principal
		? crypto.createHmac("sha256", logSalt).update(principal.hash).digest("hex").slice(0, 12) : "-";

	function authenticate(req) {
		const auth = String(req.headers.authorization || "");
		const raw = auth.startsWith("Bearer ") ? auth.slice(7).trim() : req.headers["x-fad-proxy-token"];
		return raw ? tokens.verify(String(raw)) : null;
	}

	/** A cacheable public answer: ETag + Cache-Control, 304 on a matching If-None-Match. */
	function sendPublic(req, res, code, type, body) {
		const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
		const etag = `"${crypto.createHash("sha1").update(buf).digest("base64url")}"`;
		const headers = { "content-type": type, etag, vary: "Accept-Language",
			"cache-control": code === 200 ? `public, max-age=${cacheSeconds}, stale-while-revalidate=3600` : "no-store" };
		if (type.startsWith("text/html")) headers["content-security-policy"] = PAGE_CSP;
		if (code === 200 && req.headers["if-none-match"] === etag) { res.writeHead(304, headers); return res.end(); }
		res.writeHead(code, { ...headers, "content-length": buf.length });
		res.end(req.method === "HEAD" ? undefined : buf);
	}

	/** Public pages and JSON. → true when the request was answered. */
	function routePublic(req, res, url) {
		const p = url.pathname;
		if (req.method !== "GET" && req.method !== "HEAD") return false;
		if (p === "/static/site.css") { sendPublic(req, res, 200, "text/css; charset=utf-8", SITE_CSS); return true; }
		if (!assets) return false;
		const isPage = ["/", "/search", "/sources", "/legal"].includes(p) || /^\/(cve|advisory\/certfr|advisory\/osv)\/[^/]+$/.test(p);
		const isApi = p === "/api/search" || /^\/api\/cve\/[^/]+$/.test(p);
		if (!isPage && !isApi) return false;
		const ip = String(req.socket.remoteAddress || "?");
		if (!publicLimited("ip:" + ip)) { sendJson(res, 429, { error: "rate limit exceeded" }, { "retry-after": "60" }); return true; }
		const locale = pickLocale(url.searchParams.get("lang"), req.headers["accept-language"]);
		const t = makeT(locale);
		const q = String(url.searchParams.get("q") || "").slice(0, 200).trim();
		const type = ["cve", "advisory"].includes(url.searchParams.get("type")) ? url.searchParams.get("type") : null;
		const page = (code, title, body) => sendPublic(req, res, code, "text/html; charset=utf-8",
			web.layout({ t, locale, title, body, q, path: p + (q ? `?q=${encodeURIComponent(q)}` : "") }));

		if (p === "/api/search") {
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
		if (p === "/") { page(200, t("Search"), web.home({ t, counts: assets.counts() })); return true; }
		if (p === "/sources") { page(200, t("Data sources"), web.sourcesPage({ t, jobs: jobStatus() })); return true; }
		if (p === "/legal") { page(200, t("Legal notice"), web.legalPage({ t })); return true; }
		if (p === "/search") {
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
			page(200, id, web.osvAdvisoryPage({ t, locale, asset }));
			return true;
		}
		if (p.startsWith("/advisory/certfr/")) {
			const ref = decodeURIComponent(p.slice(17)).toUpperCase();
			const asset = assets.get("advisory", "certfr:" + ref);
			if (!asset) { page(404, t("Not found"), web.notFound({ t })); return true; }
			page(200, ref, web.advisoryPage({ t, locale, asset }));
			return true;
		}
		return false;
	}

	async function route(req, res, principal) {
		const url = new URL(req.url, "http://service.invalid");
		const p = url.pathname;
		if (p === "/health" && req.method === "GET")
			return sendJson(res, 200, { ok: true, service: "fad-service", version, region, store: store.kind, uptimeMs: Date.now() - stats.startedAt });
		if (routePublic(req, res, url)) return;
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
			// Public paths name a CVE or an advisory — public data, but still a reading habit:
			// they are logged by family only.
			const family = ROUTES.has(route) ? route : (/^\/(cve|advisory|api|search|sources|legal|static)\b/.exec(route)?.[0] || (route === "/" ? "/" : "/*"));
			log(`${new Date(started).toISOString()} ${req.method} ${family} ${res.statusCode} ${Date.now() - started}ms client=${clientTag(principal)}`);
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
