'use strict';

// OCI transport only: no image execution, Docker client or credential helper.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { Readable, Transform } = require('node:stream');
const { pipeline } = require('node:stream/promises');

const ACCEPT = [
  'application/vnd.oci.image.index.v1+json', 'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.docker.distribution.manifest.v2+json',
].join(', ');
const DEFAULT_LIMITS = Object.freeze({ metadataBytes: 16 * 1024 * 1024, blobBytes: 8 * 1024 ** 3,
  totalBytes: 32 * 1024 ** 3, descriptors: 100000, depth: 16, timeoutMs: 120000, redirects: 5 });

function parseReference(value) {
  const input = String(value || '').replace(/^docker:\/\//, '');
  if (!input || /[\s?#\\]/.test(input) || input.includes('://')) throw Error('invalid image reference');
  const at = input.indexOf('@');
  let name = at < 0 ? input : input.slice(0, at);
  let reference = at < 0 ? null : input.slice(at + 1);
  if (at >= 0 && !reference) throw Error('invalid image digest');
  if (reference) { if (!/^[a-z0-9]+:[a-f0-9]+$/.test(reference)) throw Error('invalid image digest'); digestParts(reference); }
  const colon = name.lastIndexOf(':');
  if (colon > name.lastIndexOf('/')) {
    const tag = name.slice(colon + 1);
    if (!/^[\w][\w.-]{0,127}$/.test(tag)) throw Error('invalid image tag');
    if (!reference) reference = tag;
    name = name.slice(0, colon);
  }
  const parts = name.split('/');
  const explicitRegistry = parts.length > 1 && (/[.:]/.test(parts[0]) || parts[0] === 'localhost');
  let registry = explicitRegistry ? parts.shift() : 'registry-1.docker.io';
  if (registry === 'docker.io' || registry === 'index.docker.io') registry = 'registry-1.docker.io';
  if (registry === 'registry-1.docker.io' && parts.length === 1) parts.unshift('library');
  if (!parts.length || parts.some(p => !/^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/.test(p))) throw Error('invalid image repository');
  const host = new URL(`https://${registry}`);
  if (host.username || host.password || host.pathname !== '/' || !host.hostname) throw Error('invalid registry host');
  return { registry, repository: parts.join('/'), reference: reference || 'latest', original: input };
}

function digestParts(digest) {
  const match = /^([a-z0-9]+):([a-f0-9]+)$/.exec(String(digest));
  if (!match || match[1] !== 'sha256') throw Error('unsupported image digest algorithm');
  const size = crypto.createHash(match[1]).digest().length * 2;
  if (match[2].length !== size) throw Error('invalid image digest length');
  return { algorithm: match[1], hex: match[2] };
}

async function readBounded(response, limit) {
  const chunks = []; let size = 0;
  if (!response.body) throw Error('empty registry response');
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > limit) throw Error('registry metadata exceeds configured limit');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function bearerChallenge(header) {
  if (!/^Bearer\s/i.test(header || '')) return null;
  const fields = {};
  for (const match of header.matchAll(/([\w]+)="((?:[^"\\]|\\.)*)"/g)) fields[match[1].toLowerCase()] = match[2].replace(/\\(.)/g, '$1');
  if (!fields.realm) throw Error('registry Bearer challenge has no realm');
  return fields;
}

function createRegistryTransport(ref, options, limits) {
  const origin = `${options.insecure ? 'http' : 'https'}://${ref.registry}`;
  const base = `${origin}/v2/${ref.repository}`;
  const fetcher = options.fetcher || globalThis.fetch;
  let authorization = options.credentials?.token ? `Bearer ${options.credentials.token}` : null;
  const basic = options.credentials?.username !== undefined
    ? 'Basic ' + Buffer.from(`${options.credentials.username}:${options.credentials.password || ''}`).toString('base64') : null;
  async function request(url, headers = {}) {
    let current = new URL(url), requestHeaders = { ...headers };
    for (let count = 0; count <= limits.redirects; count++) {
      let response;
      try { response = await fetcher(current.href, { headers: requestHeaders, redirect: 'manual', signal: AbortSignal.timeout(limits.timeoutMs) }); }
      catch { throw Error('registry network request failed'); }
      if (![301, 302, 303, 307, 308].includes(response.status)) return response;
      const location = response.headers.get('location');
      await response.body?.cancel();
      if (!location) throw Error('registry redirect has no location');
      const next = new URL(location, current);
      if (!['https:', 'http:'].includes(next.protocol) || next.username || next.password || (next.protocol === 'http:' && !options.insecure)) throw Error('unsafe registry redirect');
      if (next.origin !== current.origin) delete requestHeaders.Authorization;
      current = next;
    }
    throw Error('too many registry redirects');
  }
  async function registryGet(url, accept, allow404 = false) {
    const headers = { ...(accept ? { Accept: accept } : {}), ...(authorization ? { Authorization: authorization } : {}) };
    let response = await request(url, headers);
    if (response.status === 401) {
      const header = response.headers.get('www-authenticate');
      await response.body?.cancel();
      const challenge = bearerChallenge(header);
      if (challenge) {
        const realm = new URL(challenge.realm);
        if (!['https:', 'http:'].includes(realm.protocol) || realm.username || realm.password || (realm.protocol !== 'https:' && !options.insecure)) throw Error('unsafe registry authentication realm');
        if (challenge.service) realm.searchParams.set('service', challenge.service);
        realm.searchParams.set('scope', `repository:${ref.repository}:pull`);
        const trusted = realm.origin === origin || (options.authOrigins || []).includes(realm.origin);
        if (basic && !trusted) throw Error('cross-origin registry authentication requires an explicitly trusted auth origin');
        const tokenResponse = await request(realm.href, basic ? { Authorization: basic } : {});
        if (!tokenResponse.ok) { await tokenResponse.body?.cancel(); throw Error(`registry authentication failed (HTTP ${tokenResponse.status})`); }
        let token;
        try { token = JSON.parse((await readBounded(tokenResponse, limits.metadataBytes)).toString('utf8')); }
        catch { throw Error('invalid registry authentication response'); }
        if (typeof (token.token || token.access_token) !== 'string') throw Error('registry authentication returned no token');
        authorization = `Bearer ${token.token || token.access_token}`;
      } else if (/^Basic\b/i.test(header || '') && basic) authorization = basic;
      else throw Error('registry requires credentials or an unsupported authentication scheme');
      response = await request(url, { ...headers, Authorization: authorization });
    }
    if (!response.ok && !(allow404 && response.status === 404)) { await response.body?.cancel(); throw Error(`registry request failed (HTTP ${response.status})`); }
    return response;
  }
  return { registryGet, base };
}

// Resolve only the top-level manifest/index. Its content digest covers all
// selected platforms and layers, so an unchanged digest can reuse an inventory.
async function fetchRegistryDigest(reference, options = {}) {
  if (options.offline) throw Error('registry resolution is unavailable in offline mode');
  const ref = parseReference(reference), limits = {...DEFAULT_LIMITS, ...options.limits};
  for (const [key, value] of Object.entries(limits)) if (!Number.isSafeInteger(value) || value <= 0) throw Error(`invalid registry limit: ${key}`);
  const {registryGet, base} = createRegistryTransport(ref, options, limits);
  const response = await registryGet(`${base}/manifests/${encodeURIComponent(ref.reference)}`, ACCEPT);
  const buffer = await readBounded(response, limits.metadataBytes);
  const digest = `sha256:${crypto.createHash('sha256').update(buffer).digest('hex')}`;
  const expected = ref.reference.includes(':') ? ref.reference : response.headers.get('docker-content-digest');
  if (expected && digest !== expected) throw Error('image manifest digest mismatch');
  const document = JSON.parse(buffer.toString('utf8'));
  if (document.schemaVersion !== 2 || (!Array.isArray(document.manifests) && !Array.isArray(document.layers))) throw Error('invalid image manifest');
  return digest;
}

async function fetchRegistryImage(reference, options = {}) {
  if (options.offline) throw Error('registry image acquisition is unavailable in offline mode; supply an archive or inventory');
  const ref = parseReference(reference);
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  for (const [key, value] of Object.entries(limits)) if (!Number.isSafeInteger(value) || value <= 0) throw Error(`invalid registry limit: ${key}`);
  const { registryGet, base } = createRegistryTransport(ref, options, limits);
  const root = await fs.promises.mkdtemp(path.join(options.tmpDir || os.tmpdir(), 'vv-registry-'));
  const cleanup = () => fs.promises.rm(root, { recursive: true, force: true });
  let bytes = 0, descriptors = 0;
  const diagnostics = [];
  const blobs = new Map();
  const blobPath = digest => { const { algorithm, hex } = digestParts(digest); return path.join(root, 'blobs', algorithm, hex); };
  async function saveBuffer(buffer, expected) {
    const digest = expected || `sha256:${crypto.createHash('sha256').update(buffer).digest('hex')}`;
    const { algorithm, hex } = digestParts(digest);
    if (crypto.createHash(algorithm).update(buffer).digest('hex') !== hex) throw Error('image manifest digest mismatch');
    if (!blobs.has(digest)) {
      bytes += buffer.length;
      if (bytes > limits.totalBytes) throw Error('registry download exceeds configured total limit');
      const file = blobPath(digest);
      await fs.promises.mkdir(path.dirname(file), { recursive: true });
      await fs.promises.writeFile(file, buffer, { flag: 'wx', mode: 0o600 });
      blobs.set(digest, buffer.length);
    }
    return digest;
  }
  async function downloadBlob(descriptor) {
    if (++descriptors > limits.descriptors) throw Error('too many image descriptors');
    if (!Number.isSafeInteger(descriptor.size) || descriptor.size < 0 || descriptor.size > limits.blobBytes) throw Error('invalid or oversized image blob');
    if (blobs.has(descriptor.digest)) {
      if (blobs.get(descriptor.digest) !== descriptor.size) throw Error('conflicting image blob size');
      return;
    }
    const { algorithm, hex } = digestParts(descriptor.digest), file = blobPath(descriptor.digest);
    const response = await registryGet(`${base}/blobs/${descriptor.digest}`);
    await fs.promises.mkdir(path.dirname(file), { recursive: true });
    let size = 0;
    const hash = crypto.createHash(algorithm);
    const limiter = new Transform({ transform(chunk, _encoding, callback) {
      size += chunk.length; bytes += chunk.length;
      if (size > descriptor.size || bytes > limits.totalBytes) return callback(Error('image blob exceeds declared size or configured total limit'));
      hash.update(chunk); callback(null, chunk);
    } });
    await pipeline(Readable.fromWeb(response.body), limiter, fs.createWriteStream(file, { flags: 'wx', mode: 0o600 }));
    if (size !== descriptor.size || hash.digest('hex') !== hex) throw Error('image blob size/digest mismatch');
    blobs.set(descriptor.digest, size);
  }
  function platformMatches(platform) {
    if (!options.platform || !platform) return true;
    const requested = options.platform.split('/');
    if (requested.length < 2 || requested.length > 3 || requested.some(x => !x)) throw Error('invalid requested platform');
    return requested[0] === platform.os && requested[1] === platform.architecture && (requested.length < 3 || requested[2] === platform.variant);
  }
  async function manifest(id, depth = 0, expectedSize) {
    if (++descriptors > limits.descriptors || depth > limits.depth) throw Error('image index exceeds configured limits');
    const response = await registryGet(`${base}/manifests/${encodeURIComponent(id)}`, ACCEPT);
    const buffer = await readBounded(response, limits.metadataBytes);
    if (expectedSize !== undefined && expectedSize !== buffer.length) throw Error('image manifest size mismatch');
    const expected = id.includes(':') ? id : response.headers.get('docker-content-digest');
    const digest = await saveBuffer(buffer, expected);
    const document = JSON.parse(buffer.toString('utf8'));
    if (document.schemaVersion !== 2) throw Error('unsupported image manifest schema');
    const type = document.mediaType || response.headers.get('content-type')?.split(';')[0];
    if (Array.isArray(document.manifests)) {
      const children = document.manifests.filter(d => {
        const attestation = d.artifactType || d.annotations?.['vnd.docker.reference.type'] === 'attestation-manifest' || (d.platform?.os === 'unknown' && d.platform?.architecture === 'unknown');
        if (attestation) { diagnostics.push({ kind: 'non-image-artifact', digest: d.digest, artifactType: d.artifactType || d.annotations?.['vnd.docker.reference.type'] || 'unknown-platform' }); return false; }
        return platformMatches(d.platform);
      });
      const manifests = [];
      for (const child of children) {
        const descriptor = await manifest(child.digest, depth + 1, child.size);
        if (!descriptor) continue;
        manifests.push({ ...descriptor, ...(child.platform ? { platform: child.platform } : {}), ...(child.annotations ? { annotations: child.annotations } : {}) });
      }
      // A selected-platform layout has its own index; original registry digest remains evidence.
      return { mediaType: type, digest, size: buffer.length, children: manifests };
    }
    if (document.artifactType || document.subject || (document.config?.mediaType && !['application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'].includes(document.config.mediaType))) {
      diagnostics.push({ kind: 'non-image-artifact', digest, artifactType: document.artifactType || document.config?.mediaType || 'subject' });
      return null;
    }
    if (!document.config || !Array.isArray(document.layers)) throw Error('invalid image manifest');
    if (document.config.size > limits.metadataBytes) throw Error('image config exceeds metadata limit');
    await downloadBlob(document.config);
    const config = JSON.parse(await fs.promises.readFile(blobPath(document.config.digest), 'utf8'));
    if (!platformMatches(config)) throw Error('requested platform differs from image configuration');
    for (const layer of document.layers) await downloadBlob(layer);
    return { mediaType: type, digest, size: buffer.length, platform: { os: config.os, architecture: config.architecture, ...(config.variant ? { variant: config.variant } : {}) } };
  }
  try {
    const descriptor = await manifest(ref.reference);
    const flatten = item => !item ? [] : item.children ? item.children.flatMap(flatten) : [item];
    const leaves = flatten(descriptor);
    if (!leaves.length) throw Error(options.platform ? 'requested platform is absent from image index' : 'image index contains no runnable images');
    await fs.promises.writeFile(path.join(root, 'oci-layout'), JSON.stringify({ imageLayoutVersion: '1.0.0' }));
    await fs.promises.writeFile(path.join(root, 'index.json'), JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: leaves }));
    return { path: root, metadata: { reference: ref.original, registry: ref.registry, repository: ref.repository,
      digest: descriptor?.digest || null, diagnostics, resolvedAt: new Date().toISOString(), platforms: leaves.map(d => d.platform), acquisition: 'registry' }, cleanup };
  } catch (error) { await cleanup(); throw error; }
}

// Publisher-provided inventories are assertions, not verified signatures or a
// guarantee that the inventory is complete. Every fetched descriptor is hashed.
async function fetchRegistrySboms(reference, options = {}) {
  if (options.offline) throw Error('registry SBOM acquisition is unavailable in offline mode');
  const ref = parseReference(reference), limits = { ...DEFAULT_LIMITS, ...options.limits };
  for (const [key, value] of Object.entries(limits)) if (!Number.isSafeInteger(value) || value <= 0) throw Error(`invalid registry limit: ${key}`);
  const { registryGet, base } = createRegistryTransport(ref, options, limits);
  const diagnostics = [], documents = [], leaves = [], attached = [], visited = new Set();
  let count = 0, total = 0;
  const fail = (kind, detail) => diagnostics.push({ kind, ...detail });
  function account(buffer) { total += buffer.length; if (total > limits.totalBytes) throw Error('registry download exceeds configured total limit'); }
  async function data(url, descriptor, accept, optional = false) {
    if (++count > limits.descriptors) throw Error('too many image descriptors');
    if (descriptor && (!Number.isSafeInteger(descriptor.size) || descriptor.size < 0 || descriptor.size > limits.metadataBytes)) throw Error('invalid or oversized registry metadata descriptor');
    const response = await registryGet(url, accept, optional);
    if (response.status === 404) { await response.body?.cancel(); return null; }
    const body = await readBounded(response, limits.metadataBytes); account(body);
    const claimed = descriptor?.digest || response.headers.get('docker-content-digest');
    if (descriptor && descriptor.size !== body.length) throw Error('registry metadata size mismatch');
    const hash = 'sha256:' + crypto.createHash('sha256').update(body).digest('hex');
    if (claimed && (digestParts(claimed), claimed !== hash)) throw Error('registry metadata digest mismatch');
    return { body, digest: hash, response };
  }
  const parse = (buffer) => { try { return JSON.parse(buffer.toString('utf8')); } catch { throw Error('invalid registry JSON metadata'); } };
  const manifest = (id, descriptor) => data(`${base}/manifests/${encodeURIComponent(id)}`, descriptor, ACCEPT);
  const blob = desc => data(`${base}/blobs/${encodeURIComponent(desc.digest)}`, desc);
  function matches(platform) {
    if (!options.platform) return true;
    const p = options.platform.split('/'); if (p.length < 2 || p.length > 3 || p.some(x => !x)) throw Error('invalid requested platform');
    return p[0] === platform?.os && p[1] === platform?.architecture && (p.length < 3 || p[2] === platform?.variant);
  }
  async function walk(id, descriptor, platform, depth) {
    if (depth > limits.depth) throw Error('image index exceeds configured depth');
    const fetched = await manifest(id, descriptor);
    if (id.includes(':') && id !== fetched.digest) throw Error('image manifest digest mismatch');
    if (visited.has(fetched.digest)) return; visited.add(fetched.digest);
    const doc = parse(fetched.body);
    if (doc.schemaVersion !== 2) throw Error('unsupported image manifest schema');
    if (Array.isArray(doc.manifests)) {
      for (const child of doc.manifests) {
        const annotation = child.annotations || {};
        if (annotation['vnd.docker.reference.type'] === 'attestation-manifest') { attached.push(child); continue; }
        if (child.artifactType || (child.platform?.os === 'unknown' && child.platform?.architecture === 'unknown')) { fail('unclassified-index-artifact', { digest: child.digest }); continue; }
        if (child.platform && !matches(child.platform)) continue;
        await walk(child.digest, child, child.platform || platform, depth + 1);
      }
      return fetched.digest;
    }
    if (doc.artifactType || doc.subject || !doc.config || !Array.isArray(doc.layers)) { fail('not-image-manifest', { digest: fetched.digest }); return fetched.digest; }
    const config = parse((await blob(doc.config)).body);
    const actual = { os: config.os, architecture: config.architecture, ...(config.variant ? { variant: config.variant } : {}) };
    if (platform && (platform.os !== actual.os || platform.architecture !== actual.architecture || (platform.variant && platform.variant !== actual.variant))) throw Error('image platform descriptor/config mismatch');
    if (matches(actual)) leaves.push({ digest: fetched.digest, platform: actual });
    return fetched.digest;
  }
  const digest = await walk(ref.reference, null, null, 0);
  if (!leaves.length) throw Error(options.platform ? 'requested platform is absent from image index' : 'image index contains no runnable images');
  async function scanArtifact(descriptor, leaf, source) {
    const fetched = await manifest(descriptor.digest, descriptor), artifact = parse(fetched.body);
    if (artifact.subject && artifact.subject.digest !== leaf.digest) { fail('artifact-subject-mismatch', { digest: descriptor.digest }); return; }
    if (source === 'oci-referrers' && !artifact.subject) { fail('artifact-subject-missing', { digest: descriptor.digest }); return; }
    if (!Array.isArray(artifact.layers)) { fail('unsupported-artifact', { digest: descriptor.digest }); return; }
    for (const layer of artifact.layers) {
      const media = layer.mediaType || '';
      if (!/json/i.test(media)) { fail('unsupported-sbom-media-type', { digest: layer.digest, mediaType: media }); continue; }
      const fetchedLayer = await blob(layer); let value;
      try { value = parse(fetchedLayer.body); } catch { fail('invalid-sbom-json', { digest: layer.digest }); continue; }
      let document = value;
      if (value._type && value.predicate) {
        if (!Array.isArray(value.subject) || !value.subject.some(item => item.digest?.sha256 === leaf.digest.slice(7))) { fail('attestation-subject-mismatch', { digest: layer.digest }); continue; }
        document = value.predicate;
      }
      if (!(document?.spdxVersion || document?.bomFormat === 'CycloneDX')) { fail('unsupported-sbom-format', { digest: layer.digest }); continue; }
      documents.push({ document: value._type && value.predicate ? value : document, expectedDigest: leaf.digest, platform: leaf.platform, source: { kind: source, reference: ref.original, manifestDigest: descriptor.digest, blobDigest: layer.digest, binding: { kind: artifact.subject ? 'oci-subject' : 'buildkit-index', digest: leaf.digest }, signatureVerified: false } });
    }
  }
  for (const leaf of leaves) {
    for (const descriptor of attached) if (descriptor.annotations?.['vnd.docker.reference.digest'] === leaf.digest) await scanArtifact(descriptor, leaf, 'buildkit-index');
    let url = `${base}/referrers/${leaf.digest}`, pages = 0;
    while (url) {
      if (++pages > limits.depth) throw Error('registry referrers pagination exceeds configured limit');
      const result = await data(url, null, 'application/vnd.oci.image.index.v1+json', true);
      if (!result) { fail('referrers-unavailable', { digest: leaf.digest }); break; }
      const index = parse(result.body); if (!Array.isArray(index.manifests)) throw Error('invalid referrers response');
      for (const descriptor of index.manifests) await scanArtifact(descriptor, leaf, 'oci-referrers');
      const link = result.response.headers.get('link'), match = link && /<([^>]+)>\s*;\s*rel="?next"?/i.exec(link);
      if (!match) { url = null; continue; }
      const next = new URL(match[1], url); if (next.origin !== new URL(base).origin || !next.pathname.startsWith(new URL(base).pathname + '/referrers/')) throw Error('unsafe referrers pagination URL'); url = next.href;
    }
  }
  return { documents, metadata: { reference: ref.original, digest, platforms: leaves.map(x => x.platform), resolvedAt: new Date().toISOString(), signatureVerified: false }, diagnostics };
}

async function fetchRegistryTags(reference, options = {}) {
  if (options.offline) throw Error('registry tags are unavailable offline');
  const ref=parseReference(reference),limits={...DEFAULT_LIMITS,...options.limits};
  const maxPages=limits.maxTagPages??100,maxTags=limits.maxTags??100000;
  if(!Number.isSafeInteger(maxPages)||maxPages<=0||!Number.isSafeInteger(maxTags)||maxTags<=0)throw Error('invalid registry tag limits');
  const {registryGet,base}=createRegistryTransport(ref,options,limits),endpoint=new URL(`${base}/tags/list`),tags=new Set(),seen=new Set();
  let next=endpoint.href;
  for(let page=0;next;page++){
    if(page>=maxPages || seen.has(next))throw Error('registry tag pagination exceeds limits or repeats');seen.add(next);
    const res=await registryGet(next,'application/json');let body;
    try{body=JSON.parse((await readBounded(res,limits.metadataBytes)).toString('utf8'));}catch{throw Error('invalid registry tag response');}
    if(!Array.isArray(body.tags) || body.tags.some(t=>typeof t!=='string'||!/^\w[\w.-]{0,127}$/.test(t)))throw Error('invalid registry tag response');
    for(const tag of body.tags){tags.add(tag);if(tags.size>maxTags)throw Error('registry tag count exceeds limit');}
    const link=res.headers.get('link');if(!link){next=null;continue;}
    const match=/<([^>]+)>\s*;\s*rel="?next"?/i.exec(link);if(!match)throw Error('invalid registry pagination link');
    const url=new URL(match[1],next);if(url.origin!==endpoint.origin || url.pathname!==endpoint.pathname || url.username || url.password)throw Error('unsafe registry pagination link');next=url.href;
  }
  return {tags:[...tags],registry:ref.registry,repository:ref.repository};
}
async function fetchRegistryTagPlatform(reference,platform,options={}) {
 if(options.offline)throw Error('registry manifest is unavailable offline');
 if(!platform?.os||!platform?.architecture)throw Error('image platform is unavailable');
 const ref=parseReference(reference),limits={...DEFAULT_LIMITS,...options.limits},{registryGet,base}=createRegistryTransport(ref,options,limits);
 const matches=p=>p?.os===platform.os&&p?.architecture===platform.architecture&&(!platform.variant||p.variant===platform.variant);
 async function readManifest(id,depth=0,expectedSize,declaredPlatform){
  if(depth>limits.depth)throw Error('image index exceeds configured depth');
  const res=await registryGet(`${base}/manifests/${encodeURIComponent(id)}`,ACCEPT),buffer=await readBounded(res,limits.metadataBytes);
  if(expectedSize!==undefined&&expectedSize!==buffer.length)throw Error('image manifest size mismatch');
  const digest=`sha256:${crypto.createHash('sha256').update(buffer).digest('hex')}`,expected=id.includes(':')?id:res.headers.get('docker-content-digest');
  if(expected&&expected!==digest)throw Error('image manifest digest mismatch');const doc=JSON.parse(buffer.toString('utf8'));
  if(doc.schemaVersion!==2)throw Error('unsupported image manifest schema');
  if(Array.isArray(doc.manifests)){
   for(const d of doc.manifests){if(d.artifactType||d.annotations?.['vnd.docker.reference.type']==='attestation-manifest'||(d.platform&&!matches(d.platform)))continue;
    const child=await readManifest(d.digest,depth+1,d.size,d.platform||declaredPlatform);if(child)return {digest,platformDigest:child.platformDigest};}
   return null;
  }
  if(doc.artifactType||doc.subject||!doc.config||!Array.isArray(doc.layers))return null;
  const descriptor=doc.config;digestParts(descriptor.digest);if(!Number.isSafeInteger(descriptor.size)||descriptor.size<0||descriptor.size>limits.metadataBytes)throw Error('invalid image config size');
  const resConfig=await registryGet(`${base}/blobs/${descriptor.digest}`),bytes=await readBounded(resConfig,limits.metadataBytes);
  if(bytes.length!==descriptor.size||`sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`!==descriptor.digest)throw Error('image config digest/size mismatch');
  const config=JSON.parse(bytes.toString('utf8'));
  if(declaredPlatform && (config.os!==declaredPlatform.os || config.architecture!==declaredPlatform.architecture || (config.variant && declaredPlatform.variant && config.variant!==declaredPlatform.variant)))throw Error('image index and config platform mismatch');
  const effective={...declaredPlatform,...config,variant:config.variant||declaredPlatform?.variant};
  return matches(effective)?{digest,platformDigest:digest}:null;
 }
 return readManifest(ref.reference);
}
module.exports = { fetchRegistryImage, fetchRegistryDigest, fetchRegistrySboms, fetchRegistryTags, fetchRegistryTagPlatform, parseReference, bearerChallenge, DEFAULT_LIMITS };
