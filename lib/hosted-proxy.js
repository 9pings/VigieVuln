"use strict";
const ORIGINS = Object.freeze({ fr: "https://api.vigievuln.fr", com: "https://api.vigievuln.com" });

function resolveHostedProxy(options, env = process.env) {
  if (!options.vigievulnProxy) return {};
  const domain = options.vigievulnProxy === true ? "fr" : options.vigievulnProxy;
  if (!Object.hasOwn(ORIGINS, domain)) throw new Error("--vigievuln-proxy accepts fr or com");
  if (options.proxyCache) throw new Error("choose --vigievuln-proxy or --proxy-cache, not both");
  const token = options.proxyCacheToken || env.VIGIEVULN_PROXY_CACHE_TOKEN || env.FAD_PROXY_CACHE_TOKEN;
  if (!options.offline && !token) throw new Error("--vigievuln-proxy requires a proxy key from https://www.vigievuln.fr/account; set VIGIEVULN_PROXY_CACHE_TOKEN");
  return { proxyCache: ORIGINS[domain], proxyCacheToken: token || null };
}

async function checkHostedProxy(url, token, fetcher = globalThis.fetch) {
  let response;
  try {
    response = await fetcher(url + "/v1/proxy/status", { headers: { authorization: "Bearer " + token },
      redirect: "error", signal: AbortSignal.timeout(15000) });
  } catch { throw new Error("VigieVuln proxy is unreachable; check your connection and proxy endpoint"); }
  try {
    if (response.status === 401 || response.status === 403) throw new Error("VigieVuln proxy key is invalid, expired or revoked; create a key from your verified account");
    if (!response.ok) throw new Error(`VigieVuln proxy is unavailable (HTTP ${response.status})`);
    const data = await response.json();
    if (data.ok !== true || data.service !== "vigievuln-proxy") throw new Error("unexpected VigieVuln proxy response");
  } finally { if (!response.bodyUsed) await response.body?.cancel(); }
}
module.exports = { ORIGINS, resolveHostedProxy, checkHostedProxy };
