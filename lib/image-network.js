'use strict';
// Image acquisition is an explicitly requested registry operation; advisory
// providers use the same scoped cache and guarded proxy transport as source scans.
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const config = require('./config');
const { loadLayers, applyLayers } = require('./options-env');
const { proxyScope, proxyOrigin, requireHttpConsent } = require('./proxy-scope');
const { resolveHostedProxy } = require('./hosted-proxy');
const { applySourceProfile, proxyOnlyFetch } = require('./source-profile');
const { configureResourceRoute } = require('./providers');
const { setActiveCacheDir, getCacheDir } = require('./cache-directory');

function imageResourceStore(cacheDir, options) {
 const directory=options.vigievulnProxy && options.proxyCache
  ? path.join(cacheDir,'hosted-resources',crypto.createHash('sha256').update(options.proxyCache).digest('hex'))
  : path.join(cacheDir,'resource-cache');
 return require('./resource-cache/sqlite-store').createCacheStore(directory);
}

function configureImageNetwork(command, injected = {}) {
 const initial=command.opts(),layers=loadLayers({cwd:process.cwd(),configPath:initial.config,program:command});
 const options=applyLayers(command,layers,config.load());
 if(options.forceUpdate && options.offline)throw Error('--force-update requires an online scan or cache preparation.');
 if(options.stableAdvisoryAgeDays!==undefined && (!Number.isSafeInteger(options.stableAdvisoryAgeDays)||options.stableAdvisoryAgeDays<1||options.stableAdvisoryAgeDays>36500))throw Error('--stable-advisory-age-days must be an integer from 1 to 36500.');
 const previousForce=require('./cache-policy').shouldForceUpdate();
 Object.assign(options,resolveHostedProxy(options));
 const inherited = command.getOptionValueSource('proxyCacheToken') !== 'cli' &&
  !Object.hasOwn(layers.fileLayer,'proxyCacheToken') && !Object.hasOwn(layers.envLayer,'proxyCacheToken') &&
  !process.env.VIGIEVULN_PROXY_CACHE_TOKEN && !process.env.FAD_PROXY_CACHE_TOKEN;
 const savedOrigin=config.get('proxyCacheTokenOrigin');
 if(options.proxyCache && inherited && config.get('proxyAnonymousOrigin')===String(options.proxyCache).replace(/\/+$/,''))options.proxyCacheToken=null;
 if(options.proxyCache && options.proxyCacheToken && inherited && savedOrigin && savedOrigin!==String(options.proxyCache).replace(/\/+$/,''))throw Error('Saved proxy key belongs to another server; supply its key explicitly.');
 if(options.proxyCache && !options.vigievulnProxy && options.proxyCacheToken && inherited && savedOrigin!==String(options.proxyCache).replace(/\/+$/,''))throw Error('Saved proxy key cannot be sent to an unbound custom proxy; supply its key explicitly.');
 const profile=applySourceProfile(options,{explicit:name=>command.getOptionValueSource(name)==='cli'});Object.assign(options,profile.options);
 const originalFetch=globalThis.fetch, baseFetch=injected.fetcher || originalFetch;
 if(options.proxyCache){
  const origin=proxyOrigin(options.proxyCache);
  if(!options.offline)requireHttpConsent(origin,{acceptedOrigin:config.get('insecureHttpOrigin'),allow:command.getOptionValueSource('allowInsecureHttp')==='cli' && !!options.allowInsecureHttp});
  // Even under profile=all, proxy-confirmed evidence must never mix with a
  // direct-source cache. A custom cache-dir becomes the root of scoped stores.
  const scopeOpts=options.cacheDir ? {homeDir:path.resolve(options.cacheDir)} : {};
  if(scopeOpts.homeDir)fs.mkdirSync(scopeOpts.homeDir,{recursive:true,mode:0o700});
  setActiveCacheDir(proxyScope(origin,scopeOpts));
 } else if(options.cacheDir) setActiveCacheDir(path.resolve(options.cacheDir));
 const cacheDir=getCacheDir();
 const {guardedFetch,createSourceHealth,displaySourceRetry,getRetryAttempts,setRetryAttempts} = require('./source-health');
 const health = createSourceHealth();
 const previousRetries = getRetryAttempts();
 const retries = setRetryAttempts(options.retries ?? 5);
 const guarded=options.offline ? async()=>{throw Error('offline: network request blocked');} : options.proxyCache ? proxyOnlyFetch(baseFetch,options.proxyCache) : guardedFetch({health, fetch:baseFetch, retries, onRetry:displaySourceRetry});
 if(options.proxyCache && !options.offline){
  const hosted=!!options.vigievulnProxy;
  configureResourceRoute({proxyUrl:options.proxyCache,hosted,resetRateLimit:true,proxyRateLimitMaxWaitMs:options.proxyRateLimitWaitMs,token:options.proxyCacheToken || process.env.VIGIEVULN_PROXY_CACHE_TOKEN || process.env.FAD_PROXY_CACHE_TOKEN || null,
   fetcher:guarded,health,onRetry:displaySourceRetry,store:hosted?null:imageResourceStore(cacheDir,options),
   hostedStore:hosted?imageResourceStore(cacheDir,options):null});
 }else configureResourceRoute({proxyUrl:null,hosted:false,token:null,store:null,hostedStore:null,fetcher:null,health:null,onRetry:null});
 require('./cache-policy').setForceUpdate(!!options.forceUpdate);
 globalThis.fetch=guarded;
 return {options:{...options,...injected,cacheDir,fetcher:guarded,registryFetcher:options.offline?guarded:(injected.registryFetcher||baseFetch)},warnings:profile.warnings,notices:profile.notices,
  restore(){setRetryAttempts(previousRetries);globalThis.fetch=originalFetch;configureResourceRoute({proxyUrl:null,hosted:false,token:null,store:null,hostedStore:null,fetcher:null,health:null,onRetry:null});setActiveCacheDir(null);require('./cache-policy').setForceUpdate(previousForce);}};
}
module.exports={configureImageNetwork,imageResourceStore};
