'use strict';

// Geographic selection concerns the operator providing the advisory service,
// not the country in which an advisory was authored or a server is hosted.
// Package registries and non-vulnerability metadata remain available.
const PROFILES = new Set(['all', 'us', 'eu', 'proxy']);
const RESTRICTED_APP_OPTIONS = ['wordfenceFeed', 'wordfenceLive', 'wordfenceFeedUrl', 'wordfenceApiKey',
 'drupalAdvisories', 'drupalAdvisoriesLive', 'prestashopAdvisories', 'prestashopAdvisoriesLive',
 'typo3Advisories', 'typo3AdvisoriesLive', 'spipAdvisories', 'spipAdvisoriesLive'];

function applySourceProfile(options, {explicit = () => false} = {}) {
 const out = {...options};
 const profile = String(out.sourceProfile || 'all').toLowerCase();
 if (!PROFILES.has(profile)) throw new Error('source profile must be all, us, eu or proxy');
 out.sourceProfile = profile;
 const warnings = [];
 if (profile === 'eu' || profile === 'us') {
  if (RESTRICTED_APP_OPTIONS.some(name => !!out[name])) throw new Error('Regional source profiles cannot use explicitly configured CMS advisory feeds: their origin cannot be verified.');
  if (out.snyk) throw new Error('Regional source profiles cannot run Snyk; choose all sources for this integration.');
  if (profile === 'eu' && (explicit('osvDb') && out.osvDb || out.osvDbRefresh)) throw new Error('--osv-db is unavailable in the EU-only source profile.');
  // Application plugins auto-read source snapshots whose origin is not isolated
  // by region in current cache formats. Suppress them until provenance is scoped.
  out.appPlugins = 'none';
  out.disableBinaryId = true; // hash lookups mix EU and US providers in one pipeline
  if (profile === 'eu') {
   Object.assign(out, {osv:false, osvDb:false, nvd:false, epss:false, kev:false, retire:false, nvdCpeMatch:false});
   out.disableCveProject = true;
  } else {
   Object.assign(out, {euvd:false, certfr:false, packagistAudit:false});
   out.disableGcve = true;
  }
  warnings.push(`The ${profile.toUpperCase()}-only profile excludes sources outside that region. CMS advisory plugins and native-binary identity are disabled because their current caches combine sources; advisory coverage is incomplete.`);
 }
 if (profile === 'proxy') {
  if (!out.proxyCache) throw new Error('The proxy-only profile requires a configured proxy; run vigievuln setup.');
  if (out.snyk) throw new Error('Snyk cannot be used in the proxy-only profile.');
 }
 return {options:out, warnings};
}

/** Network transport guard: provider bypasses and unrecognised redirects fail closed. */
function proxyOnlyFetch(fetcher, proxyUrl) {
 const { proxyOrigin } = require('./proxy-scope');
 const origin = proxyOrigin(proxyUrl);
 return (input, init = {}) => {
  let url;
  try { url = new URL(typeof input === 'string' || input instanceof URL ? String(input) : input.url); }
  catch { throw new Error('proxy-only: invalid network URL'); }
  if (url.origin !== origin || url.username || url.password) throw new Error('proxy-only: direct network request blocked');
  return fetcher(input, {...init, redirect:'error'});
 };
}

/** Dedicated transport used only by the official account client while issuing a key. */
function officialAccountFetch(fetcher) {
 const {ACCOUNT_ORIGIN} = require('./account-client');
 const methods = new Map([['/v1/accounts/me','GET'],['/v1/accounts/login','POST'],['/v1/accounts/logout','POST'],['/v1/accounts/terms','POST'],['/v1/accounts/proxy-keys','POST']]);
 return (input, init = {}) => {
  let url; try { url = new URL(typeof input === 'string' || input instanceof URL ? String(input) : input.url); }
  catch { throw new Error('official account: invalid URL'); }
  if (url.origin !== ACCOUNT_ORIGIN || url.username || url.password || url.search || url.hash || methods.get(url.pathname) !== String(init.method || 'GET').toUpperCase())
   throw new Error('official account: request blocked');
  return fetcher(input, {...init,redirect:'error'});
 };
}

module.exports = { applySourceProfile, proxyOnlyFetch, officialAccountFetch };
