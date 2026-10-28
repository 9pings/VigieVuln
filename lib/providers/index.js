/**
 * The single entry point for public data lookups. Callers name the provider,
 * operation and subject; the provider owns HTTP details. The router chooses a
 * local semantic cache, the shared server, or a direct source request.
 */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { requestKey, credentialScope, responseHeaders, responseFetchedAt } = require("./common");
const providers = [
	require("./nvd"), require("./osv"), require("./packagist"), require("./epss"),
	require("./kev"), require("./eol"), require("./npm"), require("./pypi"),
	require("./ruby"), require("./go"), require("./nuget"),
	require("./wordfence"), require("./wordpress"), require("./github"), require("./drupal"),
	require("./maven"), require("./hashid"), require("./osvdb"), require("./retire"),
	require("./euvd"), require("./certfr"),
];
const byId = new Map(providers.map(provider => [provider.id, provider]));
let route = { hosted: false, proxyUrl: null, token: null, store: null, health: null, fetcher: null, maxBodyBytes: 32 * 1024 * 1024 };
const inFlight = new Map();
const copyResponse = response => typeof response?.clone === "function" ? response.clone() : response;

function configureResourceRoute(options = {}) {
	if (options.proxyUrl != null && !/^https?:\/\//i.test(String(options.proxyUrl)))
		throw new Error("proxy-cache URL must be http(s)");
	route = { ...route, ...options, proxyUrl: options.proxyUrl ? String(options.proxyUrl).replace(/\/+$/, "") : null };
	return route;
}
function hasProxyRoute() { return !!route.proxyUrl; }
function hasHostedProxy() { return !!route.proxyUrl && !!route.hosted; }
function getProvider(id) {
	const provider = byId.get(id);
	if (!provider) throw new Error(`unknown data provider: ${id}`);
	return provider;
}
function providerKey(id, type, params, headers = {}) {
	const provider = getProvider(id);
	const scope = credentialScope(headers);
	return provider.key ? provider.key(type, params, scope) : requestKey(id, type, params, scope);
}
function cachedResponse(entry, tag = "hit") {
	return new Response(fs.readFileSync(entry.bodyPath), { status: 200,
		headers: { ...responseHeaders(new Headers(entry.responseHeaders || {})), "content-type": entry.contentType || "application/octet-stream", "x-fad-proxy": tag,
			"x-fad-proxy-fetched-at": new Date(entry.fetchedAt).toISOString() } });
}
function persist(store, key, response, body, ttlMs) {
	if (!store || !response.ok || body.byteLength > route.maxBodyBytes) return;
	const tmp = path.join(store.entriesDir, ".tmp-" + crypto.randomBytes(8).toString("hex"));
	fs.writeFileSync(tmp, body);
	store.commit(key, tmp, { fetchedAt: responseFetchedAt(response), ttlMs,
		contentType: response.headers.get("content-type") || "application/octet-stream",
		responseHeaders: responseHeaders(response.headers), bytes: body.byteLength });
}

async function getResource(id, type, params, options = {}) {
	const provider = getProvider(id);
	const request = provider.build(type, params);
	if (request.proxyOnly && (!route.proxyUrl || options.direct || options.urlOverride))
		throw new Error(`${id}.${type} requires a proxy; direct bulk fallback is unavailable`);
	const outboundHeaders = { ...request.init?.headers,
		...(options.headers instanceof Headers ? Object.fromEntries(options.headers.entries()) : options.headers || {}) };
	const headers = new Headers(outboundHeaders);
	const target = options.urlOverride || request.url;
	const key = providerKey(id, type, params, headers) + (options.urlOverride ? `:origin:${crypto.createHash("sha256").update(target).digest("hex")}` : "");
	// Hosted online requests must reach the proxy's one-hour freshness policy even
	// when a caller supplied a local store explicitly. Offline mode may use it.
	const store = options.urlOverride || options.streaming || (hasHostedProxy() && !options.offline) ? null : (options.store || route.store);
	let entry = store?.get(key) || null;
	if (entry && id === "github" && type === "publisher-advisories" && !entry.responseHeaders) entry = null;
	if (entry && Date.now() - entry.fetchedAt < entry.ttlMs) return cachedResponse(entry);
	if (options.offline) {
		if (entry) return cachedResponse(entry, "stale");
		throw new Error(`no cached ${id}.${type} result for ${JSON.stringify(params)}`);
	}
	const flight = options.streaming ? null : inFlight.get(key);
	if (flight) {
		const result = await flight;
		return copyResponse(result);
	}
	const work = (async () => {
		try {
			const fetcher = options.fetcher || route.fetcher || globalThis.fetch;
			let response;
			if (route.proxyUrl && !options.direct && !options.urlOverride) {
				const proxyHeaders = { "content-type": "application/json" };
				if (route.token) proxyHeaders["x-fad-proxy-token"] = route.token;
				const callProxy = () => fetcher(`${route.proxyUrl}/v1/resource`, { method: "POST", headers: proxyHeaders,
					redirect: "error", // Never forward a proxy credential to a redirected origin.
					body: JSON.stringify({ provider: id, type, params, headers: Object.fromEntries(headers.entries()) }),
					...(options.signal ? { signal: options.signal } : {}) });
				response = route.health && !entry
					? await require("../source-health").guardedFetch({ health: route.health,
						fetch: callProxy, ...(route.sleep ? { sleep: route.sleep } : {}) })(request.url,
						options.signal ? { signal: options.signal } : undefined)
					: await callProxy();
			} else {
				response = await fetcher(target, { ...request.init, headers: outboundHeaders,
					...(options.signal ? { signal: options.signal } : {}) });
			}
			if (response.headers?.get?.("x-fad-proxy") === "stale") route.health?.markStale?.(id, response.headers.get("x-fad-proxy-fetched-at"));
			if (entry && (response.status === 403 || response.status === 429 || response.status >= 500)) {
				route.health?.markStale?.(id, new Date(entry.fetchedAt).toISOString());
				return cachedResponse(entry, "stale");
			}
			if (!response.ok || !store || options.noStore) return response;
			const length = Number(response.headers.get("content-length"));
			if (Number.isFinite(length) && length > route.maxBodyBytes) return response;
			const body = Buffer.from(await response.clone().arrayBuffer());
			try { persist(store, key, response, body, provider.ttlMs); } catch { /* source result remains usable */ }
			return response;
		} catch (error) {
			if (entry) { route.health?.markStale?.(id, new Date(entry.fetchedAt).toISOString()); return cachedResponse(entry, "stale"); }
			if (route.health && !options.urlOverride && !route.health.isDown(require("../source-health").sourceForUrl(request.url)?.id)) {
				const { sourceForUrl } = require("../source-health");
				const source = sourceForUrl(request.url);
				if (source) route.health.markOutage(source.id, { url: request.url, code: error.code || error.message });
			}
			throw error;
		}
	})();
	if (!options.streaming) inFlight.set(key, work);
	let shared;
	try { shared = await work; return options.streaming ? shared : copyResponse(shared); }
	finally {
		if (!options.streaming) {
			inFlight.delete(key);
			// Every caller receives its own clone. Release the unconsumed source
			// branch after queued followers have cloned it, so large scans do not
			// retain one unused fetch stream per resource.
			if (typeof shared?.clone === "function" && shared.body)
				setImmediate(() => { try { shared.body.cancel().catch(() => {}); } catch { /* already consumed */ } });
		}
	}
}

module.exports = { providers, getProvider, providerKey, configureResourceRoute, getResource, hasProxyRoute, hasHostedProxy };
