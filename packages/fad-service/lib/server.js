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
	"cross-origin-opener-policy": "same-origin",
};
const STATIC_MAX_AGE = 31536000;
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const BASE_PAGE_CSP = { "default-src": ["'none'"], "style-src": ["'self'"], "img-src": ["'self'"], "form-action": ["'self'"],
	"base-uri": ["'none'"], "frame-ancestors": ["'none'"] };
const SITE_CSS = fs.readFileSync(path.join(__dirname, "web", "site.css"));
const ID_PATTERNS = [
	[/^CVE-\d{4}-\d{4,}$/i, id => `/cve/${id.toUpperCase()}`],
	[/^pkg:(npm|pypi|maven|gem|composer|nuget|golang)\/[^@\s]+$/i, id => web.pkgPath(id.replace(/^pkg:[a-z]+/i, m => m.toLowerCase()))],
	[/^GCVE-0-(\d{4})-(\d{4,})$/i, (id, m) => `/cve/CVE-${m[1]}-${m[2]}`],
	[/^CERT(?:FR|A)-\d{4}-(?:AVI|ALE)-\d{1,5}$/i, id => `/advisory/certfr/${id.toUpperCase()}`],
	[/^(?:GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|MAL-\d{4}-\d+|RUSTSEC-\d{4}-\d+)$/i,
		id => `/advisory/osv/${/^GHSA/i.test(id) ? "GHSA" + id.slice(4).toLowerCase() : id.toUpperCase()}`],
];
const ROUTES = new Set(["/health", "/ready", "/v1/resource", "/admin/stats", "/admin/analytics", "/admin/purge"]);
const DUMP_FILE = /^fad-(public|private)-\d{8}T\d{6}Z(?:-delta)?\.(jsonl\.gz|manifest\.json|manifest\.sig|torrent)$/;
const DUMP_TYPES = { "jsonl.gz": "application/gzip", "manifest.json": "application/json", "manifest.sig": "text/plain; charset=utf-8", torrent: "application/x-bittorrent" };

/** Serve a file with single-range support (web seeds and resumed downloads need it). */
function sendFile(req, res, file, type, extra = {}) {
	let st;
	try { st = fs.statSync(file); } catch { res.writeHead(404, { "content-type": "application/json" }); return res.end('{"error":"not found"}'); }
	const headers = { "content-type": type, "accept-ranges": "bytes", "last-modified": st.mtime.toUTCString(),
		"cache-control": "public, max-age=86400, immutable", ...extra };
	const m = /^bytes=(\d*)-(\d*)$/.exec(String(req.headers.range || ""));
	if (m && (m[1] || m[2])) {
		let start = m[1] ? Number(m[1]) : st.size - Number(m[2]);
		let end = m[1] && m[2] ? Number(m[2]) : st.size - 1;
		start = Math.max(0, start); end = Math.min(st.size - 1, end);
		if (start > end || start >= st.size) { res.writeHead(416, { "content-range": `bytes */${st.size}` }); return res.end(); }
		res.writeHead(206, { ...headers, "content-range": `bytes ${start}-${end}/${st.size}`, "content-length": end - start + 1 });
		if (req.method === "HEAD") return res.end();
		return fs.createReadStream(file, { start, end }).pipe(res);
	}
	res.writeHead(200, { ...headers, "content-length": st.size });
	if (req.method === "HEAD") return res.end();
	fs.createReadStream(file).pipe(res);
}
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

/**
 * Fixed one-minute window per key. Per process: with N workers the effective limit is ×N.
 * The table is bounded by evicting the OLDEST keys (Map insertion order) — never by
 * clearing it, which would let one client flooding new keys reset everyone's counters.
 */
function createRateLimiter(perMinute, { maxKeys = 50000 } = {}) {
	const windows = new Map();
	return key => {
		if (!perMinute) return true;
		const slot = Math.floor(Date.now() / 60000);
		let w = windows.get(key);
		if (!w || w.slot !== slot) {
			windows.delete(key);
			while (windows.size >= maxKeys) windows.delete(windows.keys().next().value);
			w = { slot, n: 0 };
			windows.set(key, w);
		}
		return ++w.n <= perMinute;
	};
}

/** Rate-limit bucket of an address: IPv6 by /64 (one subscriber), IPv4 as is. */
function addressBucket(ip) {
	const a = String(ip || "?").replace(/^::ffff:/i, "");
	if (!a.includes(":")) return a;
	const [left, right] = a.split("::");
	const head = left ? left.split(":") : [];
	const groups = right === undefined ? a.split(":") : [...head, ...Array(Math.max(0, 8 - head.length - right.split(":").filter(Boolean).length)).fill("0"), ...right.split(":").filter(Boolean)];
	return groups.slice(0, 4).map(x => (x || "0").toLowerCase()).join(":") + "::/64";
}

/** The route family a request is logged and counted under — never the CVE or the query. */
function routeFamily(pathname) {
	if (ROUTES.has(pathname)) return pathname;
	if (pathname === "/") return "/";
	return /^\/(cve|advisory\/certfr|advisory\/osv|pkg|api\/search|api\/cve|search|sources|legal|static|dumps)\b/.exec(pathname)?.[0] || "/*";
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
		brand = {}, analytics = null, serverAnalytics = null, counters = null, registry = null, dumps = null } = opts;
	if (!store || !tokens) throw new Error("fad-service needs a store and a token store");
	const { createResourceEngine, upstreamHeadersFor, sendJson } = fad("resource-cache/engine");
	const stats = { startedAt: Date.now(), requests: 0, hits: 0, misses: 0, coalesced: 0, stale: 0, upstream: 0, errors: 0 };
	const engine = createResourceEngine({ ...opts, store, stats, keys, transform: registry ? registry.transform : null });
	const limited = createRateLimiter(ratePerMinute);
	const publicLimited = createRateLimiter(publicRatePerMinute);
	const logSalt = opts.logSalt || crypto.randomBytes(16).toString("hex");
	const clientTag = principal => principal
		? crypto.createHmac("sha256", logSalt).update(principal.hash).digest("hex").slice(0, 12) : "-";
	let draining = false;
	// Overload guard: past this many requests in flight in this process, shed load with a
	// 503 instead of queueing (a per-IP limit alone cannot stop a distributed flood).
	const maxInFlight = opts.maxInFlight || 256;
	let inFlight = 0;

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
	// Static files are versioned by content, so they can be cached for a year.
	const contentHash = buf => crypto.createHash("sha1").update(buf || "").digest("hex").slice(0, 10);
	const assetVersions = { css: contentHash(SITE_CSS), brand: contentHash(brandCss), logo: logo ? contentHash(logo.body) : null };
	const site = { brand: { ...brand, hasLogo: !!logo }, analyticsHead: client.head, assetVersions };
	// The public half of the dump-signing key, published so anyone can verify a build.
	let signingPub = null;
	if (dumps?.signingKeyFile) {
		try { signingPub = crypto.createPublicKey(fs.readFileSync(dumps.signingKeyFile, "utf8")).export({ type: "spki", format: "pem" }); }
		catch { signingPub = null; }
	}

	// Home-page counters: a GROUP BY over the whole table, cached for a minute.
	let countsCache = { at: 0, value: null };
	const counts = () => {
		if (!countsCache.value || Date.now() - countsCache.at > 60000) countsCache = { at: Date.now(), value: assets.counts() };
		return countsCache.value;
	};

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

	function routeStatic(req, res, p, url) {
		// Versioned URLs (?v=<hash>) are immutable; an unversioned request gets the default TTL.
		const immutable = url.searchParams.has("v") ? { "cache-control": `public, max-age=${STATIC_MAX_AGE}, immutable` } : {};
		if (p === "/static/site.css") return sendPublic(req, res, 200, "text/css; charset=utf-8", SITE_CSS, immutable), true;
		if (p === "/static/brand.css") return sendPublic(req, res, 200, "text/css; charset=utf-8", brandCss, immutable), true;
		// An SVG is a document: sandboxed so a logo can never run script on this origin.
		if (p === "/static/logo" && logo) return sendPublic(req, res, 200, logo.type, logo.body, { "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox", ...immutable }), true;
		if (p === "/static/analytics.js" && client.initScript) return sendPublic(req, res, 200, "text/javascript; charset=utf-8", client.initScript), true;
		return false;
	}

	/** /dumps: public builds (HTML list, files, latest manifest, signing key); private ones need a client token. */
	function routeDumps(req, res, url, principal) {
		const p = url.pathname;
		if (!dumps || !p.startsWith("/dumps")) return false;
		const { listDumps } = require("./dumps/build");
		const pubDir = path.join(dumps.dir, "public"), privDir = path.join(dumps.dir, "private");
		if (p === "/dumps/signing-key.pem") {
			if (!signingPub) return sendJson(res, 404, { error: "no signing key configured" }), true;
			return sendPublic(req, res, 200, "application/x-pem-file", signingPub), true;
		}
		if (p === "/dumps/latest.json") {
			const m = listDumps(pubDir).find(x => !x.delta);
			return (m ? sendPublic(req, res, 200, "application/json", JSON.stringify(m, null, 2)) : sendJson(res, 404, { error: "no public build yet" })), true;
		}
		let m = /^\/dumps\/files\/([^/]+)$/.exec(p);
		if (m) {
			if (!DUMP_FILE.test(m[1]) || !m[1].startsWith("fad-public-")) return sendJson(res, 404, { error: "not found" }), true;
			return sendFile(req, res, path.join(pubDir, m[1]), DUMP_TYPES[m[1].replace(/^[^.]+\./, "")]), true;
		}
		m = /^\/dumps\/private\/([^/]+)$/.exec(p);
		if (m) {
			if (!principal) return sendJson(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" }), true;
			if (m[1] === "latest.json") {
				const x = listDumps(privDir).find(d => !d.delta);
				return (x ? sendJson(res, 200, x) : sendJson(res, 404, { error: "no private build yet" })), true;
			}
			if (!DUMP_FILE.test(m[1]) || !m[1].startsWith("fad-private-")) return sendJson(res, 404, { error: "not found" }), true;
			return sendFile(req, res, path.join(privDir, m[1]), DUMP_TYPES[m[1].replace(/^[^.]+\./, "")], { "cache-control": "private, no-store" }), true;
		}
		if (p === "/dumps") {
			const locale = pickLocale(url.searchParams.get("lang"), req.headers["accept-language"]);
			const t = makeT(locale);
			const { keyFingerprint } = fad("dump-format");
			sendPublic(req, res, 200, "text/html; charset=utf-8", web.layout({ t, locale, title: t("Data dumps"), path: "/dumps", site,
				body: web.dumpsPage({ t, builds: listDumps(pubDir), fingerprint: signingPub ? keyFingerprint(signingPub) : null }) }));
			return true;
		}
		return false;
	}

	/** Public pages and JSON. → true when the request was answered. */
	function routePublic(req, res, url, ctx) {
		const p = url.pathname;
		if (req.method !== "GET" && req.method !== "HEAD") return false;
		if (p.startsWith("/static/")) return routeStatic(req, res, p, url);
		if (p.startsWith("/dumps")) return routeDumps(req, res, url, ctx.principal);
		if (!assets) return false;
		const isPage = ["/", "/search", "/sources", "/legal"].includes(p) || /^\/(cve|advisory\/certfr|advisory\/osv)\/[^/]+$/.test(p)
			|| /^\/pkg\/(npm|pypi|maven|gem|composer|nuget|golang)\/.+$/.test(p);
		const isApi = p === "/api/search" || /^\/api\/cve\/[^/]+$/.test(p);
		if (!isPage && !isApi) return false;
		if (!publicLimited("ip:" + addressBucket(clientIp(req)))) { sendJson(res, 429, { error: "rate limit exceeded" }, { "retry-after": "60" }); return true; }
		const locale = pickLocale(url.searchParams.get("lang"), req.headers["accept-language"]);
		const t = makeT(locale);
		const q = String(url.searchParams.get("q") || "").slice(0, 200).trim();
		const type = ["cve", "advisory", "package"].includes(url.searchParams.get("type")) ? url.searchParams.get("type") : null;
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
		if (p === "/") { page(200, t("Search"), web.home({ t, counts: counts(), site })); return true; }
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
		if (p.startsWith("/pkg/")) {
			const m = /^\/pkg\/([a-z]+)\/(.+)$/.exec(p);
			const { packageKey, packageOfOsv } = require("./registry/purl");
			const key = m ? packageKey(m[1], m[2].split("/").map(decodeURIComponent).join("/")) : null;
			const asset = key ? assets.get("package", key) : null;
			if (!asset) { page(404, t("Not found"), web.notFound({ t })); return true; }
			ctx.asset = key;
			const { versionAffected } = require("./registry/versions");
			const advisories = assets.advisoriesForPackage(key).map(a => ({ ...a,
				entries: (a.data.affected || []).filter(e => packageOfOsv({ ecosystem: e.ecosystem, name: e.name }) === key) }));
			page(200, asset.data.name, web.packagePage({ t, locale, asset, advisories, versionAffected }));
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
			try { cves = assets ? (counts().cve || 0) : 0; } catch { ok = false; }
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
			await engine.handleResource(payload, res);
			if (registry && res.statusCode === 200) {
				const seed = principal.role === "admin" && req.headers["x-fad-seed"] === "1";
				try { registry.recordDemand(payload, principal, { seed }); } catch { /* never fail an answered request */ }
			}
			return;
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
		const pathOnly = String(req.url || "").split("?")[0];
		// A dump download streams a file for minutes at almost no CPU: it must not occupy a
		// slot of the overload guard, or a few dozen downloads would shed every page.
		const download = /^\/dumps\/(files|private)\//.test(pathOnly);
		if (!download && inFlight >= maxInFlight && pathOnly !== "/health" && pathOnly !== "/ready") {
			res.writeHead(503, { "content-type": "application/json", "retry-after": "5" });
			res.end(JSON.stringify({ error: "overloaded" }));
			counters?.observe({ route: "overload", status: 503, ms: 0 });
			return;
		}
		if (!download) { inFlight++; res.once("close", () => { inFlight--; }); }
		const principal = authenticate(req);
		const ctx = { search: false, asset: null, principal };
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
			if (err instanceof URIError) {        // a malformed %-escape in the path
				if (!res.headersSent) return sendJson(res, 400, { error: "malformed URL" });
				return res.destroy();
			}
			stats.errors++;
			logger?.error("request failed", { rid, error: String(err.message || err) });
			// The detail stays in the log; an anonymous caller learns nothing about the inside.
			if (!res.headersSent) sendJson(res, 502, { error: principal ? String(err.message || err) : "internal error", rid }, { "x-fad-proxy": "error" });
			else res.destroy();
		});
	});
	const timeout = opts.upstreamTimeoutMs || 120000;
	server.requestTimeout = timeout;
	server.headersTimeout = Math.min(30000, timeout);
	server.keepAliveTimeout = 5000;
	server.maxConnections = opts.maxConnections || 2048;
	server.maxHeadersCount = 100;
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

module.exports = { createServiceServer, createRateLimiter, addressBucket, routeFamily, SECURITY_HEADERS };
