/**
 * lib/resource-cache/engine.js — the pull-through resource cache, without its transport.
 *
 * Extracted from lib/proxy-cache.js so the same engine serves `fad-checker serve-cache`
 * (a relay on a filesystem store) and `fad-service` (a public service on a SQLite or
 * PostgreSQL store). It knows nothing about routes, tokens or ownership locks: it takes
 * a typed resource request `{ provider, type, params, headers }` and answers it on a Node
 * ServerResponse, from the store or from the upstream the provider names.
 *
 * What it guarantees, whatever the store:
 *   - typed keys (provider/type/params + credential scope), never a client URL;
 *   - single-flight: concurrent identical lookups share one upstream request, and
 *     overlapping batches (OSV, EPSS) share per-item work;
 *   - stale-while-revalidate and stale-if-error: a dead upstream never becomes a dead cache;
 *   - bounded transfers, bounded concurrency, an upstream deadline;
 *   - server-held API keys override client ones (upstreamHeadersFor).
 *
 * The store interface is documented in ./fs-store.js. Store calls are awaited, so a
 * store may be synchronous (directory, node:sqlite) or asynchronous (PostgreSQL).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { Readable, Transform } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const { responseHeaders } = require("../providers/common");
const { sourceForUrl } = require("../source-health");

const DEFAULT_TTL_MS = 24 * 3600 * 1000;
/**
 * Per-source TTLs, aligned with the per-pass client caches (see README "Caching"):
 * OSV 12h, NVD 7d, endoflife.date 7d, EPSS/KEV 24h, everything else (registries,
 * deps.dev, CIRCL) falls back to the 24h default. An explicit --ttl overrides all.
 */
const TTL_BY_SOURCE = {
	osv: 12 * 3600 * 1000,
	nvd: 7 * 24 * 3600 * 1000,
	eol: 7 * 24 * 3600 * 1000,
	epss: 24 * 3600 * 1000,
	kev: 24 * 3600 * 1000,
	euvd: 24 * 3600 * 1000,
	certfr: 24 * 3600 * 1000,
};

const DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAX_TRANSFER_BYTES = 1024 * 1024 * 1024;
const DEFAULT_MAX_STORE_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 120000;
const DEFAULT_MAX_CONCURRENT = 16;
const DEFAULT_MAX_ENTRIES = 10000;
const FAILURE_RETRY_MS = 30 * 1000;

/**
 * API keys the server may hold so the instances behind it don't have to. A key
 * configured HERE wins over whatever a client sent; a client-sent key is forwarded
 * when the server has none. Cache entries are keyed by the CLIENT url, so a keyed
 * fetch and a keyless one share the same entry — the fleet shares the server's quota.
 *   nvd       → header `apiKey: <key>`      (services.nvd.nist.gov — same as lib/nvd.js)
 *   wordfence → `Authorization: Bearer <k>` (www.wordfence.com — same as the live-snapshot lane)
 *   github    → `Authorization: Bearer <t>` (api.github.com — advisory lanes, pooled rate limit)
 */
function upstreamHeadersFor(target, reqHeaders = {}, keys = {}) {
	const headers = {
		"user-agent": (reqHeaders["user-agent"] && String(reqHeaders["user-agent"])) || "fad-checker-proxy-cache",
		"accept": reqHeaders.accept || "application/json",
	};
	// Forward the client's own credentials for this host (the proxy is in the trust path:
	// every request it makes is one a client asked for). NVD's header is spelled `apiKey`
	// (lib/nvd.js) but Node's http server lowercases every incoming header name, so both
	// spellings are read and re-emitted as one — a server key must overwrite, not sit
	// beside, the client's (same name, different case, ambiguous on the wire).
	const clientApiKey = reqHeaders.apiKey ?? reqHeaders.apikey;
	if (clientApiKey != null) headers.apiKey = clientApiKey;
	for (const h of ["authorization", "x-github-api-version"]) {
		if (reqHeaders[h] != null) headers[h] = reqHeaders[h];
	}
	const host = hostOf(target);
	if (keys.nvd && /(^|\.)nvd\.nist\.gov$/.test(host)) headers.apiKey = keys.nvd;
	if (keys.wordfence && /(^|\.)wordfence\.com$/.test(host)) headers.authorization = "Bearer " + keys.wordfence;
	if (keys.github && /(^|\.)github\.com$/.test(host)) headers.authorization = "Bearer " + keys.github;
	return headers;
}

function hostOf(url) {
	try { return new URL(String(url)).hostname.toLowerCase(); } catch { return null; }
}

/** TTL that applies to one URL (override > per-source > default). */
function ttlForUrl(url, { defaultTtlMs = DEFAULT_TTL_MS, overrideTtlMs = null } = {}) {
	if (overrideTtlMs) return overrideTtlMs;
	const src = sourceForUrl(url);
	return (src && TTL_BY_SOURCE[src.id]) || defaultTtlMs;
}

function sendJson(res, code, obj, headers = {}) {
	const body = JSON.stringify(obj);
	res.writeHead(code, { "content-type": "application/json", ...headers });
	res.end(body);
}

/**
 * Build an engine over a store. Returns:
 *   handleResource(payload, res)  answer one typed resource request on `res`
 *   stats                         counters (requests are counted by the transport)
 *   activeUpstream()              upstream requests in flight
 *   abortAll()                    abort every upstream request (shutdown)
 *   limits                        the effective limits
 */
function createResourceEngine(opts = {}) {
	const {
		store,
		fetcher = globalThis.fetch,
		defaultTtlMs = DEFAULT_TTL_MS,
		overrideTtlMs = null,
		maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
		maxTransferBytes = DEFAULT_MAX_TRANSFER_BYTES,
		upstreamTimeoutMs = DEFAULT_UPSTREAM_TIMEOUT_MS,
		maxConcurrent = DEFAULT_MAX_CONCURRENT,
		maxEntries = DEFAULT_MAX_ENTRIES,
		swr = true,
		keys = {},           // { nvd, wordfence, github } — see upstreamHeadersFor
		stats = { startedAt: Date.now(), requests: 0, hits: 0, misses: 0, coalesced: 0, stale: 0, upstream: 0, errors: 0 },
	} = opts;
	if (!store) throw new Error("resource engine needs a store");
	for (const [name, value] of Object.entries({ maxBodyBytes, maxTransferBytes, upstreamTimeoutMs, maxConcurrent, maxEntries }))
		if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive safe integer`);

	const active = new Set();
	async function withUpstream(work) {
		if (active.size >= maxConcurrent) throw new Error("proxy upstream concurrency limit reached");
		const controller = new AbortController();
		active.add(controller);
		const timer = setTimeout(() => controller.abort(new Error("proxy upstream deadline exceeded")), upstreamTimeoutMs);
		timer.unref?.();
		try { return await work(controller.signal); }
		finally { clearTimeout(timer); active.delete(controller); }
	}
	function byteLimit(limit, writer = null) {
		let bytes = 0;
		return new Transform({ transform(chunk, encoding, done) {
			try {
				bytes += chunk.length;
				if (bytes > limit) throw new Error("proxy transfer limit exceeded");
				if (writer) writer.account(chunk.length);
				done(null, chunk);
			} catch (error) { done(error); }
		} });
	}
	async function boundedJson(response, signal) {
		const chunks = [];
		const limiter = byteLimit(Math.min(maxTransferBytes, DEFAULT_MAX_BODY_BYTES));
		await pipeline(Readable.fromWeb(response.body), limiter, async source => {
			for await (const chunk of source) chunks.push(chunk);
		}, { signal });
		return JSON.parse(Buffer.concat(chunks).toString("utf8"));
	}

	const inflight = new Map();
	const itemInflight = new Map();
	const failureUntil = new Map();

	const rememberFailure = key => {
		for (const [k, until] of failureUntil) if (until <= Date.now()) failureUntil.delete(k);
		if (failureUntil.size >= maxEntries) failureUntil.delete(failureUntil.keys().next().value);
		failureUntil.set(key, Date.now() + FAILURE_RETRY_MS);
	};
	const ttlFor = url => ttlForUrl(url, { defaultTtlMs, overrideTtlMs });

	function serveEntry(res, entry, tag) {
		const release = store.acquire(entry);
		res.writeHead(200, {
			...responseHeaders(new Headers(entry.responseHeaders || {})),
			"content-type": entry.contentType || "application/octet-stream",
			"content-length": entry.bytes,
			"x-fad-proxy": tag,
			"x-fad-proxy-fetched-at": new Date(entry.fetchedAt).toISOString(),
		});
		const stream = store.openBody(entry);
		res.once("close", () => stream.destroy());
		stream.on("error", () => res.destroy()).on("close", release).pipe(res);
	}

	/** Spool with backpressure before publishing. Followers share the same bounded transfer. */
	async function runFetch(target, { res = null, reqHeaders = {}, stale = null, cacheKey = target,
		method = "GET", body = undefined, ttlMs = ttlFor(target), cacheLimitBytes = maxBodyBytes } = {}) {
		// A store may cap the size of what it keeps (the SQLite store keeps bodies in rows):
		// above it the body is streamed to the client once from the spool and not kept.
		if (Number.isFinite(store.maxEntryBytes)) cacheLimitBytes = Math.min(cacheLimitBytes, store.maxEntryBytes);
		return withUpstream(async signal => {
			stats.upstream++;
			const headers = upstreamHeadersFor(target, reqHeaders, keys);
			if (body != null && reqHeaders["content-type"]) headers["content-type"] = reqHeaders["content-type"];
			const up = await fetcher(target, { method, headers, signal,
				...(body == null ? {} : { body }), redirect: "follow" });
			const fetchedAt = Date.now(), retainedHeaders = responseHeaders(up.headers);
			const contentType = up.headers.get("content-type") || "application/octet-stream";
			if (up.status !== 200 || !up.body) {
				if (stale && (up.status === 403 || up.status === 429 || up.status >= 500)) {
					stats.stale++;
					if (res && !res.destroyed) serveEntry(res, stale, "stale");
					await up.body?.cancel();
					return { stored: false, status: up.status, staleServed: true };
				}
				if (res && !res.destroyed) {
					res.writeHead(up.status, { "content-type": contentType, "x-fad-proxy": "pass" });
					if (up.body) await pipeline(Readable.fromWeb(up.body), byteLimit(maxTransferBytes), res, { signal });
					else res.end();
				} else await up.body?.cancel();
				return { stored: false, status: up.status };
			}
			const writer = store.createWriter();
			try {
				if (Number(up.headers.get("content-length")) > maxTransferBytes) {
					await up.body.cancel(); throw new Error("proxy transfer limit exceeded");
				}
				await pipeline(Readable.fromWeb(up.body), byteLimit(maxTransferBytes, writer), writer.sink(), { signal });
				const bytes = await writer.bytes();
				const metadata = { fetchedAt, ttlMs, contentType, responseHeaders: retainedHeaders, bytes };
				if (bytes <= cacheLimitBytes) {
					await writer.commit(cacheKey, metadata);
					if (res && !res.destroyed) serveEntry(res, await store.get(cacheKey), "miss");
					return { stored: true, status: 200, bytes };
				}
				const transient = await writer.detach(metadata);
				if (res && !res.destroyed) serveEntry(res, transient, "miss");
				return { stored: false, status: 200, bytes, transient };
			} catch (error) { await writer.abort(); throw error; }
		});
	}

	/** Single-flight wrapper: concurrent identical lookups share one upstream fetch. */
	function viaInflight(cacheKey, target, runOpts) {
		let p = inflight.get(cacheKey);
		if (!p) {
			// Registered synchronously, before the first await, so a concurrent caller
			// always finds it — the store lookup may be asynchronous.
			p = (async () => {
				const old = await store.get(cacheKey);
				const release = old ? store.acquire(old) : () => {};
				try {
					const result = await runFetch(target, { ...runOpts, cacheKey });
					if (result.status === 403 || result.status === 429 || result.status >= 500) rememberFailure(cacheKey);
					else failureUntil.delete(cacheKey);
					return result;
				} catch (err) {
					rememberFailure(cacheKey);
					throw err;
				} finally { release(); }
			})().finally(() => inflight.delete(cacheKey));
			inflight.set(cacheKey, p);
		}
		return p;
	}

	async function handleCached(res, { target, cacheKey, reqHeaders = {}, method = "GET", body = undefined,
		ttlMs = ttlFor(target), cacheLimitBytes = maxBodyBytes }) {
		let entry = await store.get(cacheKey);
		// Older cached GitHub pages lack pagination metadata and cannot prove completeness.
		if (entry && target.includes("api.github.com/repos/") && target.includes("/security-advisories") && !entry.responseHeaders) entry = null;
		const fresh = !!(entry && (Date.now() - entry.fetchedAt) < entry.ttlMs);
		if (fresh) {
			stats.hits++;
			return serveEntry(res, entry, "hit");
		}
		if ((failureUntil.get(cacheKey) || 0) > Date.now()) {
			if (entry) { stats.stale++; return serveEntry(res, entry, "stale"); }
			return sendJson(res, 502, { error: "upstream unavailable and no cached response" }, { "x-fad-proxy": "error" });
		}
		if (swr && entry) {
			// Serve the stale copy now, refresh in the background — instances get
			// the shared base immediately and the next reader sees the fresh one.
			stats.stale++;
			serveEntry(res, entry, "stale");
			viaInflight(cacheKey, target, { reqHeaders, method, body, ttlMs, cacheLimitBytes }).catch(() => {});
			return;
		}
		// Blocking miss (or expired with --no-swr). Coalesce on an already-running fetch.
		if (inflight.has(cacheKey)) {
			stats.coalesced++;
			let completed;
			try { completed = await inflight.get(cacheKey); }
			catch (err) {
				stats.errors++;
				if (entry) { stats.stale++; return serveEntry(res, entry, "stale"); }
				return sendJson(res, 502, { error: String(err.message || err) }, { "x-fad-proxy": "error" });
			}
			const e2 = await store.get(cacheKey);
			if (e2) { stats.hits++; return serveEntry(res, e2, "hit"); }
			if (completed.transient) { stats.coalesced++; return serveEntry(res, completed.transient, "coalesced"); }
			if (completed.status !== 200) {
				return sendJson(res, completed.status, { error: `upstream returned ${completed.status}` }, { "x-fad-proxy": "pass" });
			}
		}
		stats.misses++;
		try {
			await viaInflight(cacheKey, target, { res, reqHeaders, stale: entry, method, body, ttlMs, cacheLimitBytes });
		} catch (err) {
			stats.errors++;
			// Stale-if-error: a dead upstream must not become a dead shared cache.
			if (entry && !res.headersSent) { stats.stale++; return serveEntry(res, entry, "stale"); }
			if (!res.headersSent) return sendJson(res, 502, { error: String(err.message || err) }, { "x-fad-proxy": "error" });
			res.destroy();
		}
	}

	// Batch APIs retain their upstream batching, while cache keys and concurrent
	// reservations belong to each package/version or CVE. Overlapping batches only
	// fetch the items that are not already pending in another request.
	async function handleBatch(res, provider, type, params, reqHeaders) {
		const batch = provider.batch(type, params);
		const items = batch.items;
		const effectiveHeaders = upstreamHeadersFor(provider.build(type, params).url, reqHeaders, keys);
		const { providerKey } = require("../providers");
		const keysForItems = items.map(item => providerKey(provider.id, item.type, item.params, effectiveHeaders));
		// Validate every cached body/backoff before reserving anything. An early return
		// after reserving would leave promises in itemInflight with no producer.
		const entries = await Promise.all(keysForItems.map(key => store.get(key)));
		if (entries.reduce((n, entry) => n + (entry?.bytes || 0), 0) > Math.min(maxTransferBytes, DEFAULT_MAX_BODY_BYTES))
			throw new Error("proxy batch response limit exceeded");
		const cachedBodies = await Promise.all(entries.map(async entry => entry ? JSON.parse((await store.readBody(entry)).toString("utf8")) : undefined));
		if (keysForItems.some((key, i) => !entries[i] && (failureUntil.get(key) || 0) > Date.now()))
			return sendJson(res, 502, { error: "upstream unavailable and no cached response" }, { "x-fad-proxy": "error" });
		// From here to the end of the loop nothing is awaited: reservations made by
		// overlapping batches are visible to each other.
		const results = new Array(items.length);
		const waits = [];
		const reserved = [];
		let awaitedBytes = 0;
		const assignResult = (i, body) => {
			awaitedBytes += Buffer.byteLength(JSON.stringify(body));
			if (awaitedBytes > Math.min(maxTransferBytes, DEFAULT_MAX_BODY_BYTES)) throw new Error("proxy batch response limit exceeded");
			results[i] = body;
		};
		for (let i = 0; i < items.length; i++) {
			const key = keysForItems[i];
			const entry = entries[i];
			const fresh = entry && Date.now() - entry.fetchedAt < entry.ttlMs;
			if (fresh || (entry && swr)) {
				stats[fresh ? "hits" : "stale"]++;
				results[i] = cachedBodies[i];
				if (fresh) continue;
			}
			if ((failureUntil.get(key) || 0) > Date.now()) {
				if (entry) { results[i] ??= cachedBodies[i]; continue; }
				return sendJson(res, 502, { error: "upstream unavailable and no cached response" }, { "x-fad-proxy": "error" });
			}
			let promise = itemInflight.get(key);
			if (promise) stats.coalesced++;
			else {
				let resolve, reject;
				promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
				promise.catch(() => {});
				itemInflight.set(key, promise);
				reserved.push({ item: items[i], key, entry, resolve, reject, release: entry ? store.acquire(entry) : () => {} });
				stats.misses++;
			}
			if (results[i] === undefined) waits.push(promise.then(body => { assignResult(i, body); }, error => {
				if (entry) { stats.stale++; assignResult(i, cachedBodies[i]); }
				else throw error;
			}));
		}
		if (reserved.length) {
			(async () => {
				try {
					const subset = provider.batch(type, batch.pack(reserved.map(row => row.item)));
					const request = provider.build(type, subset.pack(subset.items));
					const headers = upstreamHeadersFor(request.url, reqHeaders, keys);
					if (request.init?.headers) Object.assign(headers, request.init.headers);
					stats.upstream++;
					const bodies = await withUpstream(async signal => {
						const up = await fetcher(request.url, { ...request.init, headers, signal, redirect: "follow" });
						if (!up.ok) { await up.body?.cancel(); throw new Error(`upstream returned ${up.status}`); }
						return subset.split(await boundedJson(up, signal));
					});
					if (bodies.length !== reserved.length) throw new Error("incomplete provider batch response");
					for (let j = 0; j < reserved.length; j++) {
						const row = reserved[j], body = bodies[j];
						const bytes = Buffer.from(JSON.stringify(body));
						if (bytes.length <= maxBodyBytes) {
							await store.put(row.key, bytes, { fetchedAt: Date.now(), ttlMs: overrideTtlMs || provider.ttlMs || defaultTtlMs,
								contentType: "application/json", bytes: bytes.length });
						}
						failureUntil.delete(row.key);
						row.resolve(body);
					}
				} catch (error) {
					stats.errors++;
					for (const row of reserved) { rememberFailure(row.key); row.reject(error); }
				} finally {
					for (const row of reserved) { row.release(); itemInflight.delete(row.key); }
				}
			})().catch(() => {});
		}
		try { await Promise.all(waits); }
		catch (error) { return sendJson(res, 502, { error: error.message }, { "x-fad-proxy": "error" }); }
		return sendJson(res, 200, batch.merge(results), { "x-fad-proxy": reserved.length ? "miss" : "hit" });
	}

	/**
	 * One typed resource request → an answer on `res`. An invalid request is a 400; a
	 * failure once the request is under way rejects, and the transport answers 502.
	 */
	async function handleResource(payload, res) {
		let provider, request, reqHeaders;
		const { getProvider, providerKey } = require("../providers");
		try {
			provider = getProvider(payload?.provider);
			request = provider.build(payload.type, payload.params);
			reqHeaders = { ...request.init?.headers, ...payload.headers };
			if (provider.id === "wordfence" && !keys.wordfence && !new Headers(reqHeaders).get("authorization"))
				return sendJson(res, 503, { error: "Wordfence API key missing: configure --wordfence-key on the cache server or supply a client key" });
			if (provider.batch?.(payload.type, payload.params))
				return handleBatch(res, provider, payload.type, payload.params, reqHeaders);
		} catch (error) { return sendJson(res, 400, { error: error.message }); }
		const effectiveHeaders = upstreamHeadersFor(request.url, reqHeaders, keys);
		const cacheKey = providerKey(payload.provider, payload.type, payload.params, effectiveHeaders);
		return handleCached(res, { target: request.url, cacheKey, reqHeaders,
			method: request.init?.method || "GET", body: request.init?.body,
			ttlMs: overrideTtlMs || provider.ttlMs || defaultTtlMs,
			cacheLimitBytes: payload.provider === "github" && payload.type === "cve-archive"
				? 1024 * 1024 * 1024 : maxBodyBytes });
	}

	return {
		handleResource, stats,
		activeUpstream: () => active.size,
		abortAll: () => { for (const controller of active) controller.abort(); },
		limits: { maxBodyBytes, maxTransferBytes, upstreamTimeoutMs, maxConcurrent, maxEntries },
	};
}

module.exports = {
	createResourceEngine, upstreamHeadersFor, ttlForUrl, sendJson,
	DEFAULT_TTL_MS, TTL_BY_SOURCE, DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_TRANSFER_BYTES, DEFAULT_MAX_STORE_BYTES,
	DEFAULT_UPSTREAM_TIMEOUT_MS, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_ENTRIES, FAILURE_RETRY_MS,
};
