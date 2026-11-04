'use strict';

// Interactive setup is additive: the old config and cache remain usable until
// the selected sign-in and optional cache import have succeeded.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Readable, Transform } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const zlib = require('node:zlib');
const { ACCOUNT_ORIGIN, createAccountClient } = require('./account-client');
const { createAccountSessionStore } = require('./account-session');
const { ensureSignedIn } = require('./cli-project-commands');
const { importCache } = require('./cache-archive-sqlite');
const { ORIGINS } = require('./hosted-proxy');
const { proxyOrigin, HTTP_WARNING } = require('./proxy-scope');

const MAX_SEED_BYTES = 4 * 1024 * 1024 * 1024;
const HELP = `Usage: vigievuln setup\n       vigievuln setup --mode <direct|official|server> [--sources <all|us|eu>] [--server-url <url>] [--seed] [--seed-url <url>] [--accept-terms <version>] [--allow-insecure-http]\nWithout flags, use the interactive setup. With flags, no prompt is displayed.\nAuthenticated modes use an existing session or VIGIEVULN_EMAIL and VIGIEVULN_PASSWORD.\nReview the server terms before explicitly accepting their exact version. HTTP requires confirmation, or --allow-insecure-http without a terminal.\n`;

async function prompt(label, secret = false) {
  if (!process.stdin.isTTY || !process.stderr.isTTY) throw new Error('setup requires an interactive terminal');
  const { Input, Password } = require('enquirer');
  const Prompt = secret ? Password : Input;
  try { return await new Prompt({message:label.replace(/:\s*$/, ''), stdin:process.stdin, stdout:process.stderr}).run(); }
  catch (error) { if (!error || typeof error === 'string') throw new Error('Setup cancelled.'); throw error; }
}

function seedEndpoint(origin) {
  const canonical = proxyOrigin(origin);
  return (canonical === ORIGINS.fr || canonical === ORIGINS.com ? ACCOUNT_ORIGIN : canonical) + '/dumps/vigievuln-cli-cache.tar.gz';
}

// Inspect only a small prefix. The manifest precedes the SQLite data in server
// bundles; unfamiliar layouts simply leave the database size unknown.
function sqliteBytesFromPrefix(bytes) {
  try {
    const tar = zlib.gunzipSync(bytes, {finishFlush:zlib.constants.Z_SYNC_FLUSH, maxOutputLength:1024*1024});
    for (let offset=0; offset+512<=tar.length;) {
      const h=tar.subarray(offset,offset+512), name=h.subarray(0,100).toString('utf8').split('\0')[0];
      const sizeText=h.subarray(124,136).toString('ascii').split('\0')[0].trim();
      if (!/^[0-7]+$/.test(sizeText)) return null;
      const size=parseInt(sizeText,8), start=offset+512;
      if (!Number.isSafeInteger(size) || size<0) return null;
      if (name === '.vigie-vuln/cli-bundle-meta.json') {
        if (size>65536 || start+size>tar.length) return null;
        const m=JSON.parse(tar.subarray(start,start+size).toString('utf8'));
        return m.format==='vigievuln-sqlite-cache' && m.payload?.file==='cache.sqlite' && Number.isSafeInteger(m.payload.bytes) && m.payload.bytes>0 ? m.payload.bytes : null;
      }
      offset=start+Math.ceil(size/512)*512;
    }
  } catch { /* optional preview; the full import still validates the archive */ }
  return null;
}

async function estimateSeed({origin,token,anonymous=false,fetcher=globalThis.fetch}) {
  const endpoint=seedEndpoint(origin),headers={...(token?{authorization:`Bearer ${token}`}:{ }),'x-vigievuln-client-version':require('../package.json').version};
  const result={downloadBytes:null,sqliteBytes:null};
  const request=extra=>({redirect:'error',credentials:'omit',cache:'no-store',signal:AbortSignal.timeout(10000),...extra,headers:{...headers,...extra.headers}});
  const valid=r=>r && r.ok && !r.redirected && (!r.url || r.url===endpoint);
  try {
    const head=await fetcher(endpoint,request({method:'HEAD'}));
    if (valid(head)) {const value=head.headers.get('content-length');if (/^\d+$/.test(value||'') && Number.isSafeInteger(Number(value))) result.downloadBytes=Number(value);}
    if (head?.body && !head.body.locked) await head.body.cancel().catch(()=>{});
  } catch { /* estimate is optional */ }
  try {
    const part=await fetcher(endpoint,request({method:'GET',headers:{range:'bytes=0-16383'}}));
    const range=/^bytes 0-(\d+)\/(\d+)$/.exec(part.headers.get('content-range')||'');
    if (valid(part) && part.status===206 && range && Number(range[1])<16384 && Number.isSafeInteger(Number(range[2]))) {
      if (result.downloadBytes===null || result.downloadBytes===Number(range[2])) {
        result.downloadBytes=Number(range[2]);
        const reader=part.body?.getReader();let chunks=[],length=0;
        if (reader) try { for (;;) {const {done,value}=await reader.read();if(done)break;length+=value.byteLength;if(length>16384)break;chunks.push(Buffer.from(value));} } finally {await reader.cancel().catch(()=>{});reader.releaseLock();}
        if (length<=16384) result.sqliteBytes=sqliteBytesFromPrefix(Buffer.concat(chunks));
      }
    }
    if (part.body && !part.body.locked) await part.body.cancel().catch(()=>{});
  } catch { /* range requests may be disabled */ }
  return result;
}

async function downloadSeed({ origin, token, anonymous = false, targetDir, fetcher = globalThis.fetch, importFn = importCache, onProgress, requireUsableSeed = false, onEstimate, confirm }) {
  if (!token && !anonymous) throw new Error('Sign in before importing a proxy cache.');
  // Official API hosts only expose proxy endpoints; the bundle is served by
  // the canonical website. Select the host explicitly, never by redirecting a
  // request carrying the account key. Custom instances use their own origin.
  const endpoint = seedEndpoint(origin);
  if (onEstimate || confirm) {
    onProgress?.({phase:'estimating'});
    const estimate=await estimateSeed({origin,token,anonymous,fetcher});
    onEstimate?.(estimate);
    if (confirm && !await confirm(estimate)) return {cancelled:true};
  }
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'vigievuln-setup-'));
  const file = path.join(dir, 'seed.tar.gz');
  let response;
  try {
    onProgress?.({phase:'connecting'});
    response = await fetcher(endpoint, { redirect:'error', credentials:'omit', cache:'no-store',
      headers:{...(token ? {authorization:`Bearer ${token}`} : {}), 'x-vigievuln-client-version':require('../package.json').version}, signal:AbortSignal.timeout(600000) });
    if (response.redirected || (response.url && response.url !== endpoint)) throw new Error('Proxy cache redirects are not permitted.');
    if (!response.ok || !response.body) throw new Error(`Proxy cache download failed (HTTP ${response.status}).`);
    if (!/^application\/(?:gzip|octet-stream)(?:\s*;|$)/i.test(response.headers.get('content-type') || ''))
      throw new Error('Proxy returned an unexpected cache content type.');
    const length = Number(response.headers.get('content-length'));
    if (Number.isFinite(length) && length > MAX_SEED_BYTES) throw new Error('Proxy cache exceeds the size limit.');
    let bytes = 0;
    onProgress?.({phase:'downloading',bytes,total:Number.isFinite(length) && length > 0 ? length : null});
    const limit = new Transform({ transform(chunk, enc, cb) { bytes += chunk.length; onProgress?.({phase:'downloading',bytes,total:Number.isFinite(length) && length > 0 ? length : null}); cb(bytes > MAX_SEED_BYTES ? new Error('Proxy cache exceeds the size limit.') : null, chunk); } });
    await pipeline(Readable.fromWeb(response.body), limit, fs.createWriteStream(file, {mode:0o600, flags:'wx'}));
    onProgress?.({phase:'downloaded',bytes});
    return await importFn(file, {replace:false, force:false, ...(targetDir ? {targetDir} : {}), ...(onProgress ? {onProgress} : {}), ...(requireUsableSeed ? {requireUsableSeed:true} : {})});
  } finally {
    if (response?.body && !response.body.locked) void response.body.cancel().catch(()=>{});
    await fs.promises.rm(dir, {recursive:true, force:true});
  }
}

// Unknown, malformed or unreachable endpoints retain the historical authenticated
// behaviour. Never infer that authentication is disabled from a failed request.
async function authenticationRequired(origin, fetcher = globalThis.fetch) {
  const endpoint=proxyOrigin(origin)+'/v1/proxy/capabilities';let response,reader;
  try {
    response=await fetcher(endpoint,{redirect:'error',credentials:'omit',cache:'no-store',signal:AbortSignal.timeout(5000)});
    if (!response.ok || response.redirected || (response.url && response.url !== endpoint) || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '') || !response.body) return true;
    reader=response.body.getReader();const chunks=[];let length=0;
    for (;;) { const {done,value}=await reader.read();if(done)break;length+=value.byteLength;if(length>8192)return true;chunks.push(Buffer.from(value)); }
    const data=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return !(data?.service==='vigievuln-proxy' && data.schema===1 && data.authenticationRequired===false);
  } catch { return true; }
  finally { if (reader) { try { await reader.cancel(); } catch {} reader.releaseLock(); } else if (response?.body && !response.body.locked) void response.body.cancel().catch(()=>{}); }
}

async function select(message, choices) {
  const { Select } = require('enquirer');
  try { return await new Select({ message, choices, initial: 0, stdin:process.stdin, stdout:process.stderr }).run(); }
  catch (error) { if (!error || typeof error === 'string') throw new Error('Setup cancelled.'); throw error; }
}

function parseOptions(args) {
 const opts = {};
 for (let i=0;i<args.length;i++) {
  const flag=args[i];
  if (flag === '--allow-insecure-http') { if (opts.allowInsecureHttp) throw Error('duplicate --allow-insecure-http'); opts.allowInsecureHttp=true; continue; }
  if (flag === '--seed') { if (opts.seed) throw Error('duplicate --seed'); opts.seed=true; continue; }
  const key={'--mode':'mode','--sources':'sources','--server-url':'serverUrl','--seed-url':'seedUrl','--accept-terms':'acceptTerms'}[flag];
  if (!key || opts[key] || !args[i+1] || args[i+1].startsWith('--')) throw Error(`invalid setup option ${flag}`);
  opts[key]=args[++i];
 }
 if (!['direct','official','server'].includes(opts.mode)) throw Error('--mode must be direct, official or server');
 if (opts.sources && (opts.mode !== 'direct' || !['all','us','eu'].includes(opts.sources))) throw Error('--sources requires direct mode and must be all, us or eu');
 if ((opts.mode === 'server') !== !!opts.serverUrl) throw Error('--server-url is required only for server mode');
 if (opts.seedUrl && (!opts.seed || opts.mode !== 'direct')) throw Error('--seed-url requires --seed and direct mode');
 if (opts.acceptTerms && opts.mode === 'direct' && !opts.seed) throw Error('--accept-terms requires an authenticated mode or --seed');
 if (opts.serverUrl) opts.serverUrl=proxyOrigin(opts.serverUrl);
 if (opts.seedUrl) opts.seedUrl=proxyOrigin(opts.seedUrl);
 return opts;
}

async function run(args = [], deps = {}) {
  if (args.length && args.every(a => a === '--help' || a === '-h')) { (deps.out || console.log)(HELP); return; }
  const options = args.length ? parseOptions(args) : null;
  const interactive = deps.interactive ?? !!(process.stdin.isTTY && process.stderr.isTTY);
  if (!options && !interactive) throw new Error('setup requires an interactive terminal or explicit --mode');
  const ask = deps.ask || prompt, choose = deps.select || select, out = deps.out || console.log, warn = deps.warn || console.error;
  let lastProgressAt = 0, lastPhase = '';
  const formatBytes = n => `${(n / 1024 / 1024).toFixed(1)} MiB`;
  const reportSeedProgress = event => {
    const now = Date.now(), changed = event.phase !== lastPhase;
    if (!changed && (!interactive || now - lastProgressAt < 3000)) return;
    lastPhase = event.phase; lastProgressAt = now;
    const count = Number.isSafeInteger(event.count) ? ` (${event.count}${Number.isSafeInteger(event.total) ? `/${event.total}` : ''})` : '';
    const message = {
      estimating:'Checking bundle size…',
      connecting:'Connecting to the bundle server…',
      downloading:`Downloading bundle: ${formatBytes(event.bytes || 0)}${event.total ? ` / ${formatBytes(event.total)}` : ''}`,
      downloaded:`Download complete: ${formatBytes(event.bytes || 0)}.`,
      extracting:'Extracting bundle…', validating:`Validating bundle${count}…`,
      checking:'Checking SQLite database integrity…',
      'index-osv':`Importing and indexing OSV advisories${count}…`,
      'index-cve':`Importing and indexing CVEProject advisories${count}…`,
      'index-build':'Building the advisory index; this may take several minutes…',
      'index-gcve':'Importing and indexing GCVE advisories…',
      merging:'Merging the bundle into the local cache; this may take several minutes…',
    }[event.phase];
    if (message) warn(message);
  };
  const getSeed = deps.downloadSeed || (args => downloadSeed({...args,...(deps.fetcher ? {fetcher:deps.fetcher} : {}),onProgress:reportSeedProgress,requireUsableSeed:true,
    onEstimate:({downloadBytes,sqliteBytes})=>{
      const gb=n=>`${(n/1e9).toFixed(2)} GB`;
      warn(`Bundle download: ${downloadBytes===null?'unknown size':gb(downloadBytes)} (compressed).`);
      if (sqliteBytes!==null) warn(`SQLite data: ${gb(sqliteBytes)}. Allow roughly ${gb(sqliteBytes*2)} free for extraction and merge, plus the existing cache; the downloaded archive uses temporary space separately. SQLite journals may require more.`);
      else warn('Disk usage is unknown; extraction and merging require additional space beyond the downloaded archive and existing cache.');
    },
    ...(!options && interactive ? {confirm:async()=>await choose('Continue with bundle download?', [{name:'no',message:'No — skip the bundle'},{name:'yes',message:'Yes — download and import'}])==='yes'} : {})}));
  const cfg = deps.config || require('./config');
  const original = cfg.load();
  (deps.banner || (() => require('./ui').banner(require('../package.json').version)))();
  const mode = options ? (options.mode === 'server' ? 'custom' : options.mode) : await choose('How should VigieVuln obtain vulnerability data?', [
    {name:'direct', message:'Autonomous — query sources directly'},
    {name:'official', message:'VigieVuln database — official service'},
    {name:'custom', message:'Local VigieVuln server — enter its URL'},
  ]);
  let profile = 'proxy', proxy = null;
  if (mode === 'direct') {
    profile = options ? (options.sources || 'all') : await choose('Which services should be used? (region of the service operator)', [
      {name:'all', message:'All sources (default)'},
      {name:'us', message:'US services only'},
      {name:'eu', message:'European services only'},
    ]);
    if (profile === 'us' || profile === 'eu') warn('Regional source selection limits advisory coverage and disables CMS plugins and native-binary identification.');
  } else if (mode === 'official') proxy = ORIGINS.fr;
  else if (mode === 'custom') proxy = options ? options.serverUrl : proxyOrigin(String(await ask('VigieVuln server URL (include http:// or https://): ')).trim());
  else throw new Error('Invalid setup mode.');
  const seed = options ? !!options.seed : await choose('Initialise the local cache from a server bundle?', [
    {name:'no', message:'No (default)'}, {name:'yes', message:'Yes — sign in and download the bundle'},
  ]) === 'yes';
  let seedOrigin = proxy;
  if (seed && !proxy) {
    const source = options ? (options.seedUrl ? 'custom' : 'official') : await choose('Which server supplies the bundle?', [
      {name:'official', message:'Official VigieVuln site (default)'},
      {name:'custom', message:'Another VigieVuln server'},
    ]);
    seedOrigin = source === 'official' ? ORIGINS.fr : options ? options.seedUrl : proxyOrigin(String(await ask('VigieVuln server URL (include http:// or https://): ')).trim());
  }
  const accountNeeded = profile === 'proxy' || seed;
  let session, key, origin, anonymous = false;
  if (accountNeeded) {
    origin = seedOrigin || proxy || ORIGINS.fr;
    const accountOrigin = origin === ORIGINS.fr || origin === ORIGINS.com ? ACCOUNT_ORIGIN : origin;
    if (accountOrigin.startsWith('http://')) {
      warn(HTTP_WARNING);
      if (original.insecureHttpOrigin !== accountOrigin && !options?.allowInsecureHttp) {
        if (options || !interactive) throw new Error('HTTP requires explicit confirmation; pass --allow-insecure-http for non-interactive setup.');
        const answer = await choose(`Allow unencrypted HTTP to ${accountOrigin}?`, [{name:'no',message:'No (default)'},{name:'yes',message:'Yes, allow this server'}]);
        if (answer !== 'yes') throw new Error('Setup cancelled: HTTP connection not approved.');
      }
    }
    const official = origin === ORIGINS.fr || origin === ORIGINS.com;
    anonymous = !official && !(await (deps.authenticationRequired || authenticationRequired)(origin, deps.fetcher));
    if (anonymous) {
      if (seed) {
        warn('The current proxy bundle may be partial; its source coverage remains subject to the scan report.');
        const targetDir = profile === 'proxy' ? (deps.proxyScope || require('./proxy-scope').proxyScope)(origin) : undefined;
        const imported = await getSeed({origin,anonymous:true,targetDir});
        if (imported?.cancelled) warn('Bundle download skipped.');
        if (imported?.stats?.skipped?.length) warn(`Cache entries not imported: ${imported.stats.skipped.join(', ')}`);
      }
    } else {
    const persistent = (deps.createSessionStore || createAccountSessionStore)();
    let staged = await persistent.read();
    const tempStore = {read:()=>staged, write:value=>{staged=value;}, clear:()=>{staged=null;}};
    const account = (deps.createAccountClient || createAccountClient)({sessionStore:tempStore, accountOrigin});
    const env = deps.env || process.env;
    if (options && (env.VIGIEVULN_EMAIL || env.VIGIEVULN_PASSWORD || options.acceptTerms)) {
      let result;
      if (env.VIGIEVULN_EMAIL || env.VIGIEVULN_PASSWORD) {
      if (!env.VIGIEVULN_EMAIL || !env.VIGIEVULN_PASSWORD) throw Error('VIGIEVULN_EMAIL and VIGIEVULN_PASSWORD are both required');
      result=await account.login({email:env.VIGIEVULN_EMAIL,password:env.VIGIEVULN_PASSWORD});
      } else result=await account.me();
      if (result.terms && !result.terms.accepted && options.acceptTerms) {
        if (result.terms.version !== options.acceptTerms) throw Error('terms version does not match --accept-terms');
        warn(`Accepting terms ${result.terms.version}: ${result.terms.url}`);
        await account.acceptTerms(result.terms.version);
        result={...result,terms:{...result.terms,accepted:true}};
      }
      await require('./account-terms').requireTerms({account,terms:result.terms,interactive:false,warn});
    } else await (deps.ensureSignedIn || ensureSignedIn)({account, store:tempStore, ask, interactive:options ? false : interactive, warn, accountOrigin});
    session = staged;
    if (seed) {
      if (!session || typeof session.token !== 'string' || !session.token) throw new Error('Account session is unavailable; sign in again.');
      warn('The current proxy bundle may be partial; its source coverage remains subject to the scan report.');
      const targetDir = profile === 'proxy' ? (deps.proxyScope || require('./proxy-scope').proxyScope)(origin) : undefined;
      // Bundle download accepts the signed-in account session. Do not create a
      // durable proxy key until the requested seed has been imported.
      const imported = await getSeed({origin,token:session.token,targetDir});
      if (imported?.cancelled) warn('Bundle download skipped.');
      if (imported?.stats?.skipped?.length) warn(`Cache entries not imported: ${imported.stats.skipped.join(', ')}`);
    }
    if (profile === 'proxy') {
      key = await account.createProxyKey();
      if (!key || typeof key.token !== 'string' || !key.token) throw new Error('Proxy did not issue an account key.');
    }
    await persistent.write(session);
    }
  }
  const updated = { ...original, sourceProfile:profile };
  if (profile === 'proxy') updated.proxyCache = proxy;
  else delete updated.proxyCache;
  if (origin?.startsWith('http://')) updated.insecureHttpOrigin = origin;
  if (profile === 'proxy') {
    if (anonymous) updated.proxyAnonymousOrigin = proxy;
    else delete updated.proxyAnonymousOrigin;
  } else delete updated.proxyAnonymousOrigin;
  if (key) { updated.proxyCacheToken = key.token; updated.proxyCacheTokenOrigin = origin; }
  cfg.save(updated);
  out(`Setup saved: ${profile}. Existing caches were preserved.`);
}

module.exports = { run, prompt, proxyOrigin, downloadSeed, estimateSeed, sqliteBytesFromPrefix, authenticationRequired, HELP };
