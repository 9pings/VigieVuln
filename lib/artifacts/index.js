'use strict';

// Image archives are untrusted data. Nothing in them is executed, and no archive
// path is ever handed directly to a host filesystem API.
const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { Transform } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const tar = require('tar-stream');
const fzstd = require('fzstd');

const DEFAULT_LIMITS = Object.freeze({ maxBytes: 20 * 1024 ** 3, maxFileBytes: 8 * 1024 ** 3, maxEntries: 1000000, maxMetadataBytes: 16 * 1024 ** 2, maxDepth: 256 });
function limits(options) {
  const result = { ...DEFAULT_LIMITS, ...(options.limits || {}) };
  for (const [k, v] of Object.entries(result)) if (!Number.isSafeInteger(v) || v < 1) throw new Error(`Invalid artifact limit ${k}`);
  return result;
}
// Backslashes and drive prefixes are ordinary file name characters on POSIX
// (systemd ships `system-systemd\x2dcryptsetup.slice`); on Windows they would
// be separators or drives, so such entries are skipped there before extraction.
const hostUnsafe = value => path.sep !== '/' && (value.includes('\\') || /^[A-Za-z]:/.test(value));
function cleanName(value, lim) {
  if (typeof value !== 'string' || value.includes('\0') || hostUnsafe(value) || value.startsWith('/')) throw new Error(`Unsafe archive path: ${value}`);
  const parts = value.split('/').filter(p => p && p !== '.');
  if (parts.includes('..') || parts.length > lim.maxDepth) throw new Error(`Unsafe archive path: ${value}`);
  return parts.join('/');
}
function digest(buffer) { return crypto.createHash('sha256').update(buffer).digest('hex'); }
function digestVerifier(value, options) {
  const match = /^([a-z][a-z0-9]*):([a-f0-9]+)$/.exec(String(value));
  const algorithms = { sha256: () => crypto.createHash('sha256'), sha512: () => crypto.createHash('sha512'), ...(options.digestAlgorithms || {}) };
  if (!match || !Object.hasOwn(algorithms, match[1]) || typeof algorithms[match[1]] !== 'function') throw new Error('Unsupported or invalid image digest');
  const hash = algorithms[match[1]]();
  if (!hash || typeof hash.update !== 'function' || typeof hash.digest !== 'function') throw new Error('Invalid digest adapter');
  return { algorithm: match[1], expected: match[2], hash };
}
async function hashFile(file, algorithm = 'sha256') {
  const h = crypto.createHash(algorithm); for await (const c of fs.createReadStream(file)) h.update(c); return h.digest('hex');
}
function layerDiffIds(config, count, state) {
  const ids = config.rootfs?.diff_ids;
  if (ids === undefined) { state.warnings.push('Image configuration does not declare layer diff_ids; uncompressed layer content is not bound to the configuration.'); return null; }
  if (!Array.isArray(ids) || ids.length !== count || ids.some(id => typeof id !== 'string')) throw new Error('Image configuration layer diff_ids count or format is invalid');
  if (config.rootfs?.type && config.rootfs.type !== 'layers') throw new Error('Unsupported image rootfs type');
  return ids;
}
async function decompressor(file, options) {
  const fd = await fsp.open(file, 'r'); const head = Buffer.alloc(4); await fd.read(head, 0, 4, 0); await fd.close();
  if (head[0] === 0x1f && head[1] === 0x8b) return zlib.createGunzip();
  if (head.readUInt32LE(0) === 0xfd2fb528) {
    if (!options.preferPortableZstd && typeof zlib.createZstdDecompress === 'function') return zlib.createZstdDecompress();
    let decoder; return new Transform({
      construct(cb) { decoder = new fzstd.Decompress(chunk => this.push(Buffer.from(chunk))); cb(); },
      transform(chunk, enc, cb) { try { decoder.push(chunk); cb(); } catch (e) { cb(e); } },
      flush(cb) { try { decoder.push(new Uint8Array(0), true); cb(); } catch (e) { cb(e); } }
    });
  }
  for (const codec of options.compressions || []) {
    if (typeof codec.probe !== 'function' || typeof codec.create !== 'function') throw new Error('Invalid compression adapter');
    if (await codec.probe(head, file)) return codec.create();
  }
  return new Transform({ transform(c, e, cb) { cb(null, c); } });
}
async function readTar(file, workspace, state, options, expectedDiffId) {
  const verifier = expectedDiffId !== undefined ? digestVerifier(expectedDiffId, options) : null;
  const entries = []; const extract = tar.extract(); let failure;
  extract.on('entry', (header, stream, next) => {
    (async () => {
      const skip = typeof header.name === 'string' && (hostUnsafe(header.name) || (['symlink', 'link'].includes(header.type) && hostUnsafe(String(header.linkname || ''))));
      const name = skip ? header.name : cleanName(header.name, state.limits);
      if (Buffer.byteLength(header.name) + Buffer.byteLength(header.linkname || '') + Buffer.byteLength(JSON.stringify(header.pax || {})) > state.limits.maxMetadataBytes) throw new Error('Archive metadata size limit exceeded');
      if (++state.entries > state.limits.maxEntries) throw new Error('Archive entry limit exceeded');
      if (!Number.isSafeInteger(header.size) || header.size < 0 || header.size > state.limits.maxFileBytes) throw new Error(`Archive file size limit exceeded: ${name}`);
      state.bytes += header.size;
      if (state.bytes > state.limits.maxBytes) throw new Error('Archive decompressed size limit exceeded');
      if (skip) { state.warnings.push(`Skipped archive entry whose name cannot be represented on this host: ${header.name}`); for await (const _ of stream) {} next(); return; }
      const entry = { name, type: header.type, linkname: header.linkname, size: header.size };
      if (header.type === 'file' || header.type === 'contiguous-file') {
        entry.file = path.join(workspace, `entry-${state.serial++}`);
        await pipeline(stream, fs.createWriteStream(entry.file, { mode: 0o600, flags: 'wx' }));
      } else { for await (const _ of stream) {} }
      entries.push(entry); next();
    })().catch(e => { failure = e; stream.destroy(); extract.destroy(e); });
  });
  const decoder = await decompressor(file, options);
  // Count the full uncompressed stream, including padding and metadata headers.
  let streamBytes = 0;
  const counter = new Transform({ transform(c, e, cb) { if (verifier) verifier.hash.update(c); streamBytes += c.length; if (streamBytes > state.limits.maxBytes + state.limits.maxEntries * 2048) cb(new Error('Archive stream size limit exceeded')); else cb(null, c); } });
  try { await pipeline(fs.createReadStream(file), decoder, counter, extract); } catch (e) { throw failure || e; }
  if (verifier && verifier.hash.digest('hex') !== verifier.expected) throw new Error(`Image layer diff_id mismatch: ${expectedDiffId}`);
  return entries;
}
async function safePath(root, name, lim, followFinal = false) {
  let parts = cleanName(name, lim).split('/').filter(Boolean), resolved = [], hops = 0;
  while (parts.length) {
    const p = parts.shift();
    // Like Linux at `/`, `..` at the artifact root stays at the root.
    if (p === '..') { resolved.pop(); continue; }
    if (!p || p === '.') continue;
    const candidate = path.join(root, ...resolved, p); let st;
    try { st = await fsp.lstat(candidate); } catch (e) { if (e.code !== 'ENOENT' && e.code !== 'ENOTDIR') throw e; }
    if (st && st.isSymbolicLink() && (parts.length || followFinal)) {
      if (++hops > 40) throw new Error('Too many symbolic links');
      const link = await fsp.readlink(candidate);
      if (hostUnsafe(link) || link.includes('\0')) throw new Error('Unsafe symbolic link');
      if (link.startsWith('/')) resolved = [];
      parts = [...link.split('/'), ...parts]; continue;
    }
    resolved.push(p);
  }
  return path.join(root, ...resolved);
}
async function remove(p) { await fsp.rm(p, { recursive: true, force: true }); }
async function parents(root, name, lim) {
  const parts = cleanName(name, lim).split('/').filter(Boolean); parts.pop(); let current = '';
  for (const part of parts) {
    current = current ? `${current}/${part}` : part;
    const p = await safePath(root, current, lim, true); let st;
    try { st = await fsp.lstat(p); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (st && !st.isDirectory()) await remove(p);
    await fsp.mkdir(p, { recursive: true, mode: 0o700 });
  }
}
async function applyLayer(root, entries, state, whiteouts) {
  const lim = state.limits;
  if (whiteouts) for (const e of entries) {
    const base = path.posix.basename(e.name), dir = path.posix.dirname(e.name);
    if (!base.startsWith('.wh.')) continue;
    if (base === '.wh..wh..opq') {
      // An opaque directory replaces what lower layers had at `dir`. A lower symlink
      // there is replaced by the directory itself, never followed to its target.
      const parent = await safePath(root, dir === '.' ? '' : dir, lim); let st;
      try { st = await fsp.lstat(parent); } catch (err) { if (err.code !== 'ENOENT' && err.code !== 'ENOTDIR') throw err; }
      if (st && !st.isDirectory()) { await remove(parent); await fsp.mkdir(parent, { mode: 0o700 }); continue; }
      let names = []; try { names = await fsp.readdir(parent); } catch (err) { if (err.code !== 'ENOENT' && err.code !== 'ENOTDIR') throw err; }
      for (const n of names) await remove(path.join(parent, n));
    } else {
      const name = base.slice(4); if (!name || name === '.' || name === '..') throw new Error('Invalid whiteout');
      await remove(await safePath(root, path.posix.join(dir, name), lim));
    }
  }
  const deferred = new Map();
  for (const e of entries) {
    if (!e.name || (whiteouts && path.posix.basename(e.name).startsWith('.wh.'))) continue;
    if (!['file', 'contiguous-file', 'directory', 'symlink', 'link'].includes(e.type)) { state.warnings.push(`Unsupported archive entry type ${e.type}: ${e.name}`); continue; }
    deferred.delete(e.name);
    await parents(root, e.name, lim);
    const p = await safePath(root, e.name, lim);
    if (e.type === 'directory') {
      let st; try { st = await fsp.lstat(p); } catch (err) { if (err.code !== 'ENOENT') throw err; }
      if (st && !st.isDirectory()) await remove(p);
      await fsp.mkdir(p, { recursive: true, mode: 0o700 });
    } else if (e.type === 'link') {
      // The last entry at a path wins, including when an earlier hardlink is deferred.
      await remove(p);
      const target = await safePath(root, cleanName(e.linkname, lim), lim, true);
      let st; try { st = await fsp.stat(target); } catch (err) { if (err.code !== 'ENOENT') throw err; }
      if (st) { if (!st.isFile()) throw new Error(`Invalid hardlink target: ${e.linkname}`); await fsp.link(target, p); }
      else deferred.set(e.name, e);
    } else {
      await remove(p);
      if (e.type === 'symlink') {
        if (typeof e.linkname !== 'string' || e.linkname.includes('\0') || hostUnsafe(e.linkname)) throw new Error(`Unsafe link: ${e.name}`);
        // Store absolute container links as relative host links; `..` clamps at the root as on Linux.
        const targetParts = e.linkname.startsWith('/') ? [] : e.name.split('/').slice(0, -1);
        for (const segment of e.linkname.split('/')) { if (!segment || segment === '.') continue; if (segment === '..') targetParts.pop(); else targetParts.push(segment); }
        const target = path.join(root, ...targetParts); await fsp.symlink(path.relative(path.dirname(p), target) || '.', p);
      } else await fsp.copyFile(e.file, p);
    }
  }
  while (deferred.size) {
    let progress = false;
    for (const [name, e] of deferred) {
      const target = await safePath(root, cleanName(e.linkname, lim), lim, true);
      let st; try { st = await fsp.stat(target); } catch (err) { if (err.code === 'ENOENT') continue; throw err; }
      if (!st.isFile()) throw new Error(`Invalid hardlink target: ${e.linkname}`);
      await parents(root, name, lim);
      const p = await safePath(root, name, lim); await remove(p); await fsp.link(target, p);
      deferred.delete(name); progress = true;
    }
    if (!progress) throw new Error('Unresolved hardlink target');
  }
}
async function readJson(file, state) {
  const stat = await fsp.stat(file); if (stat.size > state.limits.maxMetadataBytes) throw new Error('Image metadata size limit exceeded');
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); } catch (e) { throw new Error(`Invalid image metadata: ${e.message}`); }
}
function entryMap(entries) {
  const map = new Map(); for (const e of entries) { if (map.has(e.name)) throw new Error(`Duplicate archive entry: ${e.name}`); map.set(e.name, e); } return map;
}
function need(map, name, lim) { const e = map.get(cleanName(name, lim)); if (!e || !e.file) throw new Error(`Missing image archive entry: ${name}`); return e.file; }
async function openArtifact(input, options = {}) {
  const lim = limits(options); const abs = path.resolve(input); const stat = await fsp.stat(abs);
  for (const adapter of options.sources || []) {
    if (!adapter || typeof adapter.probe !== 'function' || typeof adapter.open !== 'function') throw new Error('Invalid artifact source adapter');
    if (await adapter.probe(abs, { stat, options })) {
      const result = await adapter.open(abs, options);
      if (!result || !Array.isArray(result.targets) || typeof result.cleanup !== 'function' || result.targets.some(t => !t || typeof t.id !== 'string' || typeof t.kind !== 'string' || typeof t.root !== 'string' || !t.metadata || typeof t.metadata !== 'object')) throw new Error('Invalid artifact source result');
      return result;
    }
  }
  const temp = require('../temp-roots').track(await fsp.mkdtemp(path.join(options.tmpdir || os.tmpdir(), 'vigievuln-artifact-')));
  const state = { limits: lim, entries: 0, bytes: 0, serial: 0, warnings: [] }; let cleaned = false;
  const cleanup = async () => { if (!cleaned) { cleaned = true; await remove(temp); require('../temp-roots').untrack(temp); } };
  try {
    const targets = [];
    const root = async () => { const dir = path.join(temp, `root-${targets.length}`); await fsp.mkdir(dir); return dir; };
    const makeTarget = (r, kind, id, metadata) => targets.push({ id, kind, metadata: { ...metadata, warnings: [...state.warnings] }, root: r });
    let map, layoutDir;
    if (stat.isDirectory()) {
      if (fs.existsSync(path.join(abs, 'oci-layout')) && fs.existsSync(path.join(abs, 'index.json'))) layoutDir = abs;
      else { makeTarget(abs, 'rootfs', `rootfs:${abs}`, { format: 'directory', source: abs }); return { targets, cleanup }; }
    } else if (stat.isFile()) {
      const entries = await readTar(abs, temp, state, options);
      const names = new Set(entries.map(e => e.name));
      if (!names.has('manifest.json') && !(names.has('oci-layout') && names.has('index.json'))) {
        const r = await root(); await applyLayer(r, entries, state, false);
        makeTarget(r, 'rootfs', `rootfs:sha256:${await hashFile(abs)}`, { format: 'rootfs-archive', source: abs });
        return { targets, cleanup };
      }
      map = entryMap(entries);
    } else throw new Error('Artifact must be a directory or archive file');
    const get = async name => {
      name = cleanName(name, lim);
      if (map) return need(map, name, lim);
      const p = path.join(layoutDir, ...name.split('/')); const real = await fsp.realpath(p), base = await fsp.realpath(layoutDir);
      if (real !== base && !real.startsWith(base + path.sep)) throw new Error(`OCI path escapes layout: ${name}`);
      return real;
    };
    if (map && map.has('manifest.json')) {
      const manifest = await readJson(await get('manifest.json'), state);
      if (!Array.isArray(manifest) || !manifest.length) throw new Error('Invalid Docker image manifest');
      for (const item of manifest) {
        if (!item || !Array.isArray(item.Layers) || typeof item.Config !== 'string') throw new Error('Invalid Docker image manifest entry');
        const warningStart = state.warnings.length;
        const configFile = await get(item.Config), config = await readJson(configFile, state), configHash = await hashFile(configFile);
        const diffIds = layerDiffIds(config, item.Layers.length, state), r = await root();
        for (const [index, layer] of item.Layers.entries()) await applyLayer(r, await readTar(await get(layer), temp, state, options, diffIds?.[index]), state, true);
        makeTarget(r, 'image', `docker:sha256:${configHash}`, { format: 'docker-save', source: abs, tags: item.RepoTags || [], platform: { os: config.os, architecture: config.architecture, variant: config.variant }, imageConfig: { labels: Object.fromEntries(['org.opencontainers.image.source','org.opencontainers.image.version','org.opencontainers.image.revision'].filter(k=>typeof config.config?.Labels?.[k]==='string').map(k=>[k,config.config.Labels[k]])) }, configDigest: `sha256:${configHash}`, layers: item.Layers });
        targets[targets.length - 1].metadata.warnings = state.warnings.slice(warningStart);
      }
    } else {
      const layout = await readJson(await get('oci-layout'), state); if (!layout.imageLayoutVersion) throw new Error('Invalid OCI layout');
      const blob = async desc => {
        if (!desc || typeof desc.digest !== 'string' || !Number.isSafeInteger(desc.size) || desc.size < 0) throw new Error('Invalid OCI descriptor');
        const verifier = digestVerifier(desc.digest, options);
        const file = await get(`blobs/${verifier.algorithm}/${verifier.expected}`), st = await fsp.stat(file);
        if (st.size !== desc.size) throw new Error(`OCI descriptor integrity mismatch: ${desc.digest}`);
        for await (const chunk of fs.createReadStream(file)) verifier.hash.update(chunk);
        if (verifier.hash.digest('hex') !== verifier.expected) throw new Error(`OCI descriptor integrity mismatch: ${desc.digest}`);
        return file;
      };
      const index = await readJson(await get('index.json'), state), globalWarnings = [];
      const visit = async (desc, ancestry = [], platform) => {
        if (desc.artifactType || desc.annotations?.['vnd.docker.reference.type'] === 'attestation-manifest' || (desc.platform?.os === 'unknown' && desc.platform?.architecture === 'unknown')) {
          globalWarnings.push(`Skipped non-image artifact ${desc.digest || '(unknown digest)'}`); return;
        }
        if (ancestry.includes(desc.digest) || ancestry.length >= lim.maxDepth) throw new Error('OCI index cycle or depth limit');
        const document = await readJson(await blob(desc), state);
        if (Array.isArray(document.manifests)) { for (const child of document.manifests) await visit(child, [...ancestry, desc.digest], child.platform || platform); return; }
        if (document.artifactType || document.subject || (document.config?.mediaType && !['application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'].includes(document.config.mediaType))) {
          globalWarnings.push(`Skipped non-image artifact ${desc.digest}`); return;
        }
        if (!document.config || !Array.isArray(document.layers)) throw new Error('Invalid OCI image manifest');
        const warningStart = state.warnings.length;
        const config = await readJson(await blob(document.config), state), diffIds = layerDiffIds(config, document.layers.length, state), r = await root();
        for (const [index, layer] of document.layers.entries()) await applyLayer(r, await readTar(await blob(layer), temp, state, options, diffIds?.[index]), state, true);
        makeTarget(r, 'image', `oci:${desc.digest}`, { format: 'oci-layout', source: abs, digest: desc.digest, tags: desc.annotations?.['org.opencontainers.image.ref.name'] ? [desc.annotations['org.opencontainers.image.ref.name']] : [], platform: platform || { os: config.os, architecture: config.architecture, variant: config.variant }, imageConfig: { labels: Object.fromEntries(['org.opencontainers.image.source','org.opencontainers.image.version','org.opencontainers.image.revision'].filter(k=>typeof config.config?.Labels?.[k]==='string').map(k=>[k,config.config.Labels[k]])) }, configDigest: document.config.digest, layers: document.layers.map(l => l.digest) });
        targets[targets.length - 1].metadata.warnings = state.warnings.slice(warningStart);
      };
      if (!Array.isArray(index.manifests) || !index.manifests.length) throw new Error('Invalid OCI index');
      for (const desc of index.manifests) await visit(desc, [], desc.platform);
      if (!targets.length) throw new Error('OCI index contains no runnable image manifests');
      for (const target of targets) target.metadata.warnings.push(...globalWarnings);
    }
    return { targets, cleanup };
  } catch (e) {
    await cleanup();
    if (e.code === 'ENOSPC') throw Object.assign(new Error(
      'Temporary space exhausted while extracting the image in ' + path.dirname(temp) +
      '. Set TMPDIR to a filesystem with more free space.', { cause: e }), { code: e.code });
    throw e;
  }
}
module.exports = { openArtifact, DEFAULT_LIMITS };
