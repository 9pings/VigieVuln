"use strict";
const ORIGINS = Object.freeze({ fr: "https://api.vigievuln.fr", com: "https://api.vigievuln.com" });

function resolveHostedProxy(options, env = process.env) {
  const configured = typeof options.proxyCache === 'string' ? options.proxyCache.replace(/\/+$/, '').toLowerCase() : '';
  const alias = ['default', 'vigievuln'].includes(configured);
  const official = Object.keys(ORIGINS).find(key => ORIGINS[key] === configured);
  if (!options.vigievulnProxy && !alias && !official) return {};
  const domain = official || (alias || options.vigievulnProxy === true ? "fr" : options.vigievulnProxy);
  if (!Object.hasOwn(ORIGINS, domain)) throw new Error("--vigievuln-proxy accepts fr or com");
  if (options.vigievulnProxy && options.proxyCache && !alias && !official) throw new Error("choose --vigievuln-proxy or --proxy-cache, not both");
  const token = options.proxyCacheToken || env.VIGIEVULN_PROXY_CACHE_TOKEN || env.FAD_PROXY_CACHE_TOKEN;
  if (!options.offline && !token && !options.allowProxyLogin) throw new Error("VigieVuln proxy requires a proxy key; register or sign in at https://www.vigievuln.fr/account, then set VIGIEVULN_PROXY_CACHE_TOKEN or --set-proxy-cache-token");
  return { proxyCache: ORIGINS[domain], proxyCacheToken: token || null, vigievulnProxy: domain };
}

async function loginForProxy({ origin, email, password, fetcher = globalThis.fetch }) {
  // Both public domains use the same account service; .com redirects to .fr.
  const accountOrigin = 'https://www.vigievuln.fr';
  const post = (path, body, token) => fetcher(accountOrigin + path, { method:'POST', redirect:'error',
    headers:{'content-type':'application/json', ...(token ? {authorization:'Bearer '+token} : {})},
    body:JSON.stringify(body), signal:AbortSignal.timeout(15000) });
  const login = await post('/v1/accounts/login', {email,password});
  if (!login.ok) throw new Error(`VigieVuln login failed (HTTP ${login.status}); check your credentials and verified account`);
  const session = (await login.json()).token;
  if (typeof session !== 'string' || !session) throw new Error('invalid account login response');
  try {
    const response = await post('/v1/accounts/proxy-keys', {name:'VigieVuln CLI'}, session);
    if (!response.ok) throw new Error(`proxy key creation failed (HTTP ${response.status}); check your account key limit`);
    const data = await response.json();
    if (typeof data?.key?.token !== 'string' || !data.key.token) throw new Error('invalid proxy key response');
    return data.key.token;
  } finally { try { await post('/v1/accounts/logout', {}, session); } catch { /* session expires automatically */ } }
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
module.exports = { ORIGINS, resolveHostedProxy, checkHostedProxy, loginForProxy };
