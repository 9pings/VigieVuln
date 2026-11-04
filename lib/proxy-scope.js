'use strict';

// Isolation is local provenance, not a cryptographic signature of the bundle.
// Never populate this directory from the legacy, unscoped cache.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const preparedScopes=new Set();

function proxyOrigin(input) {
 let url;
 try { url = new URL(input); } catch { throw new Error('Proxy must be an HTTP(S) origin.'); }
 if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash)
  throw new Error('Proxy must be an origin without credentials, path, query or fragment.');
 return url.origin;
}

function requireHttpConsent(origin, {acceptedOrigin, allow = false} = {}) {
 const canonical = proxyOrigin(origin);
 if (canonical.startsWith('http://') && !allow && acceptedOrigin !== canonical)
  throw new Error(`HTTP connection to ${canonical} is not encrypted. Run setup to confirm this server or pass --allow-insecure-http for this invocation.`);
 return canonical;
}

const HTTP_WARNING = 'HTTP does not encrypt the connection: passwords, account sessions and proxy keys may be exposed. Use HTTPS on untrusted networks.';

function proxyScope(origin, {homeDir = os.homedir()} = {}) {
 const canonical = proxyOrigin(origin);
 const root = path.join(homeDir, '.vigie-vuln-proxy-scopes');
 const id = crypto.createHash('sha256').update(canonical).digest('hex');
 const scope = path.join(root, id);
 let created = false;
 for (const dir of [root, scope]) {
  try { fs.mkdirSync(dir, {mode:0o700}); if (dir === scope) created = true; } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('Unsafe proxy cache scope directory.');
 }
 const marker = path.join(scope, 'origin.json');
 if (created) fs.writeFileSync(marker, JSON.stringify({version:1, origin:canonical}), {flag:'wx', mode:0o600});
 if (!fs.existsSync(marker)) throw new Error('Proxy cache scope has no origin marker.');
 const st = fs.lstatSync(marker);
 if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1) throw new Error('Unsafe proxy cache scope marker.');
 let meta;
 try { meta = JSON.parse(fs.readFileSync(marker, 'utf8')); } catch { throw new Error('Invalid proxy cache scope marker.'); }
 if (meta.version !== 1 || meta.origin !== canonical) throw new Error('Proxy cache scope origin mismatch.');
 const cacheDir = path.join(scope, '.vigie-vuln');
 if (fs.existsSync(cacheDir)) {
  const cacheStat = fs.lstatSync(cacheDir);
  if (!cacheStat.isDirectory() || cacheStat.isSymbolicLink()) throw new Error('Unsafe proxy cache directory.');
 }
 if(!preparedScopes.has(cacheDir)){
  require('./cache-startup').prepareScopedCache(cacheDir);
  preparedScopes.add(cacheDir);
 }
 return cacheDir;
}

module.exports = {proxyScope, proxyOrigin, requireHttpConsent, HTTP_WARNING};
