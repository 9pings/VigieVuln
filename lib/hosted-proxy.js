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

async function loginForProxy({ email, password, fetcher = globalThis.fetch, ask, interactive, warn }) {
  const {createAccountClient} = require('./account-client');
  const {requireTerms} = require('./account-terms');
  let session = null;
  const store = {read:()=>session, write:value=>{session=value;}, clear:()=>{session=null;}};
  const account = createAccountClient({fetcher, sessionStore:store});
  const login = await account.login({email,password});
  try {
    await requireTerms({account, terms:login.terms, ask, interactive, warn});
    return await createProxyKey(account);
  } finally { try { await account.logout(); } catch { /* session expires automatically */ } }
}

async function createProxyKey(account) {
  try { return (await account.createProxyKey()).token; }
  catch (error) {
    if (error.code === 'FORBIDDEN') throw new Error('proxy key creation forbidden; check your account and current terms with vigievuln login, then retry');
    throw error;
  }
}

async function checkHostedProxy(url, token, fetcher = globalThis.fetch) {
  let response;
  try {
    response = await fetcher(url + "/v1/proxy/status", { headers: { authorization: "Bearer " + token, "x-vigievuln-client-version": require('../package.json').version },
      redirect: "error", signal: AbortSignal.timeout(15000) });
  } catch { throw new Error("VigieVuln proxy is unreachable; check your connection and proxy endpoint"); }
  try {
    if (response.status === 401 || response.status === 403) throw new Error("VigieVuln proxy key is invalid, expired or revoked; create a key from your verified account");
    if (response.status === 426) {
      let data; try { data = await response.json(); } catch { /* keep the generic upgrade message */ }
      const minimum = typeof data?.minimumCliVersion === 'string' && /^\d+\.\d+\.\d+$/.test(data.minimumCliVersion) ? ` ${data.minimumCliVersion} or newer` : '';
      throw new Error(`VigieVuln${minimum} is required by the proxy. Update with npm install -g vigievuln@latest or visit https://github.com/9pings/VigieVuln/releases`);
    }
    if (!response.ok) throw new Error(`VigieVuln proxy is unavailable (HTTP ${response.status})`);
    const data = await response.json();
    if (data.ok !== true || data.service !== "vigievuln-proxy") throw new Error("unexpected VigieVuln proxy response");
  } finally { if (!response.bodyUsed) await response.body?.cancel(); }
}
module.exports = { ORIGINS, resolveHostedProxy, checkHostedProxy, loginForProxy, createProxyKey };
