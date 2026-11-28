/**
 * The single entry point for public data lookups. Callers name the provider,
 * operation and subject; the provider owns HTTP details. The router chooses a
 * local semantic cache, the shared server, or a direct source request.
 */
const crypto = require("node:crypto");
const { requestKey, credentialScope, responseHeaders, cacheResponseHeaders, responseFetchedAt } = require("./common");
const providers = [
	require("./nvd"), require("./osv"), require("./packagist"), require("./epss"),
	require("./kev"), require("./eol"), require("./npm"), require("./pypi"),
	require("./ruby"), require("./go"), require("./nuget"),
	require("./wordfence"), require("./wordpress"), require("./wpvulnerability"), require("./github"), require("./drupal"),
	require("./maven"), require("./hashid"), require("./osvdb"), require("./retire"),
	require("./euvd"), require("./certfr"), require("./gcve"), require("./vigievuln"), require("./alpine"), require("./debian"), require("./rubysec"), require("./redhat"), require("./nginx"), require("./package-releases"), require("./freexian"), require("./mit-kerberos"),
];
const byId = new Map(providers.map(provider => [provider.id, provider]));
let route = { hosted: false, proxyUrl: null, token: null, store: null, hostedStore: null, health: null, fetcher: null, maxBodyBytes: 32 * 1024 * 1024 };
const inFlight = new Map();
let proxyThrottle = require('./proxy-throttle').createProxyThrottle();
const copyResponse = response => typeof response?.clone === "function" ? response.clone() : response;

function configureResourceRoute(options = {}) {
	if (options.resetRateLimit) proxyThrottle = require('./proxy-throttle').createProxyThrottle();
	if (options.proxyUrl != null && !/^https?:\/\//i.test(String(options.proxyUrl)))
		throw new Error("proxy-cache URL must be http(s)");
	route = { ...route, ...options, proxyUrl: options.proxyUrl ? String(options.proxyUrl).replace(/\/+$/, "") : null };
	return route;
}
function hasProxyRoute() { return !!route.proxyUrl; }
function hasHostedProxy() { return !!route.proxyUrl && !!route.hosted; }
function resourceOrigin() { return route.proxyUrl ? `proxy:${crypto.createHash('sha256').update(route.proxyUrl).digest('hex')}` : 'direct'; }
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
function cachedResponse(entry, tag = "hit", store, refreshStatus) {
	return new Response(store.readBody(entry), { status: 200,
		headers: { ...responseHeaders(new Headers(entry.responseHeaders || {})), "content-type": entry.contentType || "application/octet-stream", "x-fad-proxy": tag,
			"x-fad-proxy-fetched-at": new Date(entry.fetchedAt).toISOString(), ...(refreshStatus ? {"x-fad-proxy-reason":"refresh-failed", ...(Number.isInteger(refreshStatus) ? {"x-fad-proxy-refresh-status":String(refreshStatus)} : {})} : {}) } });
}
function persist(store, key, response, body, ttlMs) {
	if (!store || !response.ok || body.byteLength > route.maxBodyBytes) return;
	store.put(key, body, { fetchedAt: responseFetchedAt(response), ttlMs,
		contentType: response.headers.get("content-type") || "application/octet-stream",
		responseHeaders: cacheResponseHeaders(response.headers), bytes: body.byteLength });
}

async function getResource(id, type, params, options = {}) {
	const provider = getProvider(id);
	const failureKey = require('./common').failureKey(id, type, params);
	const revalidate = !options.offline && !!(options.forceRefresh || require('../cache/policy').shouldForceUpdate()) && provider.revalidateTypes?.includes(type);
	const request = provider.build(type, params);
	if (request.proxyOnly && (!route.proxyUrl || options.direct || options.urlOverride))
		throw new Error(`${id}.${type} requires a proxy; direct bulk fallback is unavailable`);
	const outboundHeaders = { ...request.init?.headers,
		...(options.headers instanceof Headers ? Object.fromEntries(options.headers.entries()) : options.headers || {}) };
	const headers = new Headers(outboundHeaders);
	const target = options.urlOverride || request.url;
	const key = providerKey(id, type, params, headers) + (options.urlOverride ? `:origin:${crypto.createHash("sha256").update(target).digest("hex")}` : "");
	// Only the dedicated, origin-scoped hosted store contains proxy-confirmed data.
	// Never mistake an older direct-source cache for a fresh hosted response.
	const store = options.urlOverride || options.streaming ? null : (hasHostedProxy() && !options.offline ? route.hostedStore : (options.store || route.store));
	let entry = store?.get(key) || null;
	if (entry && id === "github" && type === "publisher-advisories" && !entry.responseHeaders) entry = null;
	const policy=require('../cache/policy');
	const cachedFresh = entry && (options.offline
		? Date.now() >= entry.fetchedAt && Date.now()-entry.fetchedAt < Math.min(entry.ttlMs,policy.DEFAULT_TTL_MS)
		: policy.fresh(entry.fetchedAt,entry.ttlMs));
	if (entry && !options.forceRefresh && !revalidate && cachedFresh) return cachedResponse(entry,'hit',store);
	if (options.offline) {
		if (entry) return cachedResponse(entry, "stale",store);
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
			let conditional=false;
			let response;
			if (route.proxyUrl && !options.direct && !options.urlOverride) {
				const proxyHeaders = { "content-type": "application/json", "x-vigievuln-client-version": require('../../package.json').version };
				if (route.token) proxyHeaders["x-fad-proxy-token"] = route.token;
				const sendProxy = () => fetcher(`${route.proxyUrl}/v1/resource`, { method: "POST", headers: proxyHeaders,
					redirect: "error", // Never forward a proxy credential to a redirected origin.
					body: JSON.stringify({ provider: id, type, params, headers: Object.fromEntries(headers.entries()), ...(revalidate ? {revalidate:true} : {}) }),
					...((options.signal || route.hosted || options.requestTimeoutMs) ? { signal: options.signal || AbortSignal.timeout(options.requestTimeoutMs || 15000) } : {}) });
				const callProxy = () => (route.proxyThrottle || proxyThrottle).request(sendProxy, options.signal, {label: `${id}.${type}`, retryDenied: options.retryProxyDenied !== false, retryTransient: route.hosted && !options.noSourceRetry, ...(route.proxyRateLimitMaxWaitMs != null ? {waitBudgetMs:route.proxyRateLimitMaxWaitMs} : {}), ...(route.proxyRateLimitMaxRetries != null ? {rateRetries:route.proxyRateLimitMaxRetries} : {})});
				response = route.health && !entry && !route.hosted && !options.noSourceRetry
					? await require("../scan/source-health").guardedFetch({ health: route.health, requestKey: failureKey, handledRateLimit:true, onRetry:route.onRetry,
						fetch: callProxy, ...(route.sleep ? { sleep: route.sleep } : {}) })(request.url,
						options.signal ? { signal: options.signal } : undefined)
					: await callProxy();
			} else {
				const directHeaders={...outboundHeaders};
				if(entry && typeof store?.touch==='function' && (request.init?.method||'GET').toUpperCase()==='GET') {
					if(entry.responseHeaders?.etag){directHeaders['if-none-match']=entry.responseHeaders.etag;conditional=true;}
					else if(entry.responseHeaders?.['last-modified']){directHeaders['if-modified-since']=entry.responseHeaders['last-modified'];conditional=true;}
				}
				const privatePom = id === 'maven' && options.urlOverride && options.requestTimeoutMs && !require('../scan/source-health').sourceForUrl(target);
				const host = privatePom && new URL(target).host;
				response = await fetcher(target, { ...request.init, headers: directHeaders,
					...(privatePom ? {[require('../scan/source-health').REQUEST_SOURCE]:{id:`maven:${host}`,label:`Maven POM (${host})`,flag:'check repository availability'}} : {}), [require('../scan/source-health').REQUEST_KEY]: failureKey,
					...(options.signal ? { signal: options.signal } : options.requestTimeoutMs ? {
						signal: AbortSignal.timeout(options.requestTimeoutMs), [require('../scan/source-health').ATTEMPT_TIMEOUT]: options.requestTimeoutMs,
					} : {}) });
			}
			if(response.status===304 && conditional) {
				const stamp=Date.now(),ttlMs=Math.min(provider.ttlMs||policy.DEFAULT_TTL_MS,policy.DEFAULT_TTL_MS);
				await store.touch(key,entry,{fetchedAt:stamp,ttlMs,responseHeaders:{...entry.responseHeaders,...cacheResponseHeaders(response.headers)}});
				const current=await store.get(key);
				if(!current)throw Error('cached resource disappeared during revalidation');
				return cachedResponse(current,'revalidated',store);
			}
			if (response.headers?.get?.("x-fad-proxy") === "stale")
				route.health?.markStale?.(id, response.headers.get("x-fad-proxy-fetched-at"),{reason:response.headers.get('x-fad-proxy-reason'),requestKey:failureKey,refreshStatus:response.headers.get('x-fad-proxy-refresh-status'),refreshCause:response.headers.get('x-fad-proxy-refresh-cause'),retryAfter:response.headers.get('retry-after')});
			if (hasHostedProxy() && route.health && !options.noSourceRetry && (response.status === 403 || response.status === 429 || response.status >= 500)) {
				const source = require('../scan/source-health').sourceForUrl(request.url);
				if (source) route.health.markOutage(source.id, {url: request.url, code: require('./request-failure').responseFailure(response,{viaProxy:true}).reason, requestKey: failureKey});
			}
			if (entry && (response.status === 403 || response.status === 429 || response.status >= 500)) {
				route.health?.markStale?.(id, new Date(entry.fetchedAt).toISOString(),{reason:'refresh-failed',requestKey:failureKey});
				return cachedResponse(entry, "stale",store,response.status);
			}
			if (!response.ok || !store || options.noStore) return response;
			if (response.headers.get('x-fad-proxy') === 'stale') return response;
			// A mirror or batch without an upstream timestamp cannot establish freshness.
			if (hasHostedProxy() && (response.headers.get("x-fad-proxy") === "stale" || !Number.isFinite(Date.parse(response.headers.get("x-fad-proxy-fetched-at") || "")))) return response;
			const length = Number(response.headers.get("content-length"));
			if (Number.isFinite(length) && length > route.maxBodyBytes) return response;
			const body = Buffer.from(await response.clone().arrayBuffer());
			try { persist(store, key, response, body, Math.min(provider.ttlMs || policy.DEFAULT_TTL_MS, policy.DEFAULT_TTL_MS)); } catch { /* source result remains usable */ }
			return response;
		} catch (error) {
			if (entry) { route.health?.markStale?.(id, new Date(entry.fetchedAt).toISOString(),{reason:'refresh-failed',requestKey:failureKey}); return cachedResponse(entry, "stale",store,true); }
			if (route.health && !options.noSourceRetry && !options.urlOverride) {
				const { sourceForUrl } = require("../scan/source-health");
				const source = sourceForUrl(request.url);
				if (source) route.health.markOutage(source.id, { url: request.url, code: error.code || error.message, requestKey: failureKey });
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

module.exports = { providers, getProvider, providerKey, configureResourceRoute, getResource, hasProxyRoute, hasHostedProxy, resourceOrigin };
