'use strict';

// Native advisory documents are immutable entries in an append-only journal.
// Small, rebuildable hash shards point into it; ordinary scans read only requested
// packages and versions. Source identity is independent of transport provenance.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { StringDecoder } = require('node:string_decoder');
const DEFAULT_QUERY_TTL_MS = 4 * 3600e3;
const MAX_TRANSACTION_BYTES = 32 * 1024 * 1024;
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value);
const key = (...parts) => JSON.stringify(parts);
function packageName(ecosystem, name) {
  if (ecosystem === 'PyPI') return name.toLowerCase().replace(/[-_.]+/g, '-');
  return ['Maven', 'npm', 'NuGet', 'Packagist'].includes(ecosystem) ? name.toLowerCase() : name;
}
function timestamp(value, label = 'fetchedAt') {
  if (!Number.isSafeInteger(value) || value <= 0 || value > Date.now() + 300000) throw new Error(`invalid advisory ${label}`);
  return value;
}
function string(value, label) {
  if (typeof value !== 'string' || !value || value.length > 4096 || /[\x00-\x1f]/.test(value)) throw new Error(`invalid advisory ${label}`);
  return value;
}
function source(value) { return string(value, 'source'); }
function date(value, label) {
  if (value == null) return 0;
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) throw new Error(`invalid advisory ${label}`);
  return Date.parse(value);
}
const advisoryId = record => record.id || record.document.id || record.document.cveMetadata?.vulnId || record.document.cveMetadata?.cveId;
const nativeCve = record => ['gcve', 'cveproject'].includes(record.source);
function isWithdrawn(record) {
  return !!(record.withdrawnAt || record.document.withdrawn || (nativeCve(record) && record.document.cveMetadata?.state === 'REJECTED'));
}
function validateRecord(input) {
  if (!plain(input) || !plain(input.document)) throw new Error('invalid advisory record');
  source(input.source); string(advisoryId(input), 'id'); timestamp(input.fetchedAt);
  for (const field of ['modified', 'published', 'withdrawn']) date(input.document[field], field);
  for (const field of ['modifiedAt', 'publishedAt', 'withdrawnAt']) date(input[field], field);
  if (nativeCve(input)) for (const field of ['dateUpdated', 'datePublished', 'dateRejected']) date(input.document.cveMetadata?.[field], field);
  if (input.provenance != null && !plain(input.provenance)) throw new Error('invalid advisory provenance');
  if (input.source === 'osv' && input.document.affected != null) {
    if (!Array.isArray(input.document.affected)) throw new Error('invalid OSV affected');
    for (const affected of input.document.affected) {
      if (!plain(affected)) throw new Error('invalid OSV affected entry');
      if (affected.versions != null && (!Array.isArray(affected.versions) || affected.versions.some(v => typeof v !== 'string'))) throw new Error('invalid OSV versions');
      if (affected.ranges != null && !Array.isArray(affected.ranges)) throw new Error('invalid OSV ranges');
    }
  }
  return input;
}
function validateQuery(input) {
  if (!plain(input) || input.complete !== true || !Array.isArray(input.ids)) throw new Error('incomplete advisory query');
  source(input.source); string(input.ecosystem, 'ecosystem'); string(input.name, 'name'); string(input.version, 'version'); timestamp(input.fetchedAt);
  for (const id of input.ids) string(id, 'query id');
  if (new Set(input.ids).size !== input.ids.length) throw new Error('duplicate advisory query id');
  if (input.provenance != null && !plain(input.provenance)) throw new Error('invalid query provenance');
  return input;
}
function validateCoverage(input) {
  if (!plain(input) || typeof input.complete !== 'boolean') throw new Error('invalid advisory seed coverage');
  source(input.source); string(input.ecosystem, 'ecosystem'); timestamp(input.fetchedAt);
  if (input.provenance != null && !plain(input.provenance)) throw new Error('invalid seed provenance');
  if (input.recordCount != null && (!Number.isSafeInteger(input.recordCount) || input.recordCount < 0)) throw new Error('invalid seed record count');
  if (input.sha256 != null && !/^[a-f0-9]{64}$/.test(input.sha256)) throw new Error('invalid seed checksum');
  return input;
}
const recordKey = record => key(record.source, advisoryId(record));
// Maven coordinates are case-sensitive. Package shards remain folded for
// compatibility, but consultations must not share freshness or results
// across differently cased coordinates.
const queryKey = query => key(query.source || 'osv', query.ecosystem, query.ecosystem === 'Maven' ? query.name : packageName(query.ecosystem, query.name), query.version);
const coverageKey = coverage => key(coverage.source, coverage.ecosystem);
function packageKeys(record) {
  // Other native schemas can supply explicit normalized package bindings without
  // modifying or conflating their original documents.
  const packages = ['osv', 'osv-legacy-maven'].includes(record.source) ? (record.document.affected || []).map(a => a.package) : (record.packages || []);
  return [...new Set(packages.filter(p => plain(p) && typeof p.ecosystem === 'string' && p.ecosystem && typeof p.name === 'string' && p.name).map(p => {
    return key(p.ecosystem, packageName(p.ecosystem, p.name));
  }))];
}
function revision(record) {
  return Math.max(date(record.document.modified, 'modified'), date(record.document.withdrawn, 'withdrawn'),
    date(record.modifiedAt, 'modifiedAt'), date(record.withdrawnAt, 'withdrawnAt'),
    nativeCve(record) ? date(record.document.cveMetadata?.dateUpdated, 'dateUpdated') : 0,
    nativeCve(record) ? date(record.document.cveMetadata?.dateRejected, 'dateRejected') : 0);
}
function wins(incoming, existing) {
  if (!existing) return true;
  const newer = revision(incoming), older = revision(existing);
  if (newer !== older) return newer > older;
  // A stale response cannot resurrect a withdrawal at the same source revision.
  if (isWithdrawn(incoming) !== isWithdrawn(existing)) return isWithdrawn(incoming);
  return incoming.fetchedAt >= existing.fetchedAt;
}
function queryCoversRecord(query, record) {
  if (!query) return false;
  if ((record.contentChangedAt ?? record.fetchedAt) <= query.fetchedAt) return true;
  const fingerprint = query.provenance?.documentHashes?.[advisoryId(record)];
  return typeof fingerprint === 'string' && fingerprint === hash(JSON.stringify(record.document));
}
function selectAdvisoryRecord(incoming, existing) { return wins(incoming, existing) ? incoming : existing; }
function atomicJson(file, body, { durable = false } = {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  const serialized = JSON.stringify(body);
  try {
    const fd = fs.openSync(temporary, 'wx', 0o600);
    try { fs.writeFileSync(fd, serialized); if (durable) fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(temporary, file);
    if (durable && process.platform !== 'win32') {
      const directory = fs.openSync(path.dirname(file), 'r');
      try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
    }
  }
  finally { try { fs.unlinkSync(temporary); } catch {} }
  return hash(serialized);
}

function* journalTransactions(file, { allowTail = false } = {}) {
  const fd = fs.openSync(file, 'r'), buffer = Buffer.alloc(64 * 1024), decoder = new StringDecoder('utf8');
  let pending = '', offset = 0;
  try {
    let length;
    while ((length = fs.readSync(fd, buffer, 0, buffer.length, null))) {
      pending += decoder.write(buffer.subarray(0, length));
      let end;
      while ((end = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, end); pending = pending.slice(end + 1);
        if (Buffer.byteLength(line) > MAX_TRANSACTION_BYTES) throw new Error('oversized advisory transaction');
        const transaction = JSON.parse(line);
        if (transaction.schema !== 1 || !Array.isArray(transaction.records) || !Array.isArray(transaction.queries) || !Array.isArray(transaction.coverages) || JSON.stringify({ schema: 1, records: transaction.records, queries: transaction.queries, coverages: transaction.coverages }) !== line) throw new Error('invalid advisory transaction');
        for (const record of transaction.records) { validateRecord(record); packageKeys(record); }
        for (const query of transaction.queries) validateQuery(query);
        for (const coverage of transaction.coverages) validateCoverage(coverage);
        yield { transaction, offset, line: line + '\n' };
        offset += Buffer.byteLength(line) + 1;
      }
      if (Buffer.byteLength(pending) > MAX_TRANSACTION_BYTES) throw new Error('oversized advisory transaction');
    }
    pending += decoder.end();
    if (pending && !allowTail) throw new Error('truncated advisory journal');
  } finally { fs.closeSync(fd); }
}

class AdvisoryStore {
  constructor({ cacheDir = require('./cache-directory').getCacheDir() } = {}) {
    this.directory = path.join(cacheDir, 'advisory-store');
    this.journal = path.join(this.directory, 'events.jsonl');
    this.checkpoint = path.join(this.directory, 'checkpoint.json');
    this.lock = path.join(this.directory, '.lock');
  }
  _size() { try { return fs.statSync(this.journal).size; } catch (e) { if (e.code === 'ENOENT') return 0; throw e; } }
  _locked(action) {
    fs.mkdirSync(this.directory, { recursive: true });
    const deadline = Date.now() + 10000;
    for (;;) {
      try { fs.writeFileSync(this.lock, JSON.stringify({ pid: process.pid }), { flag: 'wx', mode: 0o600 }); break; }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        try {
          const owner = JSON.parse(fs.readFileSync(this.lock, 'utf8'));
          if (Number.isSafeInteger(owner.pid) && owner.pid > 0) {
            try { process.kill(owner.pid, 0); } catch (e) { if (e.code === 'ESRCH') { fs.unlinkSync(this.lock); continue; } }
          }
        } catch { /* A writer may still be filling its lock file. */ }
        if (Date.now() >= deadline) throw new Error('advisory store is busy');
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
      }
    }
    try {
      this._recover();
      try { return action(); }
      catch (error) {
        if (error.code !== 'ADVISORY_INDEX_INTEGRITY') throw error;
        // A derived file can lag its durable manifest after a power loss.
        // Rebuild under the existing lock and retry; never treat it as empty.
        this._recover(true);
        return action();
      }
    }
    finally { fs.unlinkSync(this.lock); }
  }
  _indexFailure() { const error = new Error('advisory index integrity mismatch'); error.code = 'ADVISORY_INDEX_INTEGRITY'; return error; }
  _relative(file) { return path.relative(this.directory, file).split(path.sep).join('/'); }
  _flush(cache) {
    for (const [file, shard] of cache) this._manifest[this._relative(file)] = atomicJson(file, shard);
  }
  _checkpoint(bytes) {
    // Only the authoritative journal and small checksum manifest need fsync.
    // Derived shards are verified lazily on every read and rebuilt on mismatch.
    atomicJson(this.checkpoint, { schema: 2, bytes, shards: this._manifest }, { durable: true });
  }
  _shardFile(kind, identity) { return path.join(this.directory, kind, `${hash(identity).slice(0, 2)}.json`); }
  _shard(kind, identity, cache) {
    const file = this._shardFile(kind, identity);
    if (cache?.has(file)) return cache.get(file);
    let shard;
    const expected = this._manifest?.[this._relative(file)];
    try {
      const serialized = fs.readFileSync(file, 'utf8');
      if (hash(serialized) !== expected) throw this._indexFailure();
      shard = JSON.parse(serialized); if (!plain(shard)) throw this._indexFailure();
    }
    catch (error) { if (error.code !== 'ENOENT') throw error; if (expected) throw this._indexFailure(); shard = Object.create(null); }
    if (cache) cache.set(file, shard);
    return shard;
  }
  _lookup(kind, identity, cache) { return this._shard(kind, identity, cache)[identity] || null; }
  _readJson(pointer) {
    if (!pointer) return null;
    if (!Number.isSafeInteger(pointer.offset) || pointer.offset < 0 || !Number.isSafeInteger(pointer.length) || pointer.length <= 0 || pointer.length > MAX_TRANSACTION_BYTES) throw new Error('invalid advisory record pointer');
    const buffer = Buffer.alloc(pointer.length), fd = fs.openSync(this.journal, 'r');
    try { if (fs.readSync(fd, buffer, 0, buffer.length, pointer.offset) !== buffer.length) throw new Error('truncated advisory record'); }
    finally { fs.closeSync(fd); }
    if (hash(buffer) !== pointer.sha256) throw new Error('advisory record checksum mismatch');
    return JSON.parse(buffer.toString('utf8'));
  }
  _record(identity, cache) {
    const pointer = this._lookup('records', identity, cache), record = this._readJson(pointer);
    if (record) validateRecord(record);
    if (record && recordKey(record) !== identity) throw new Error('advisory record identity mismatch');
    return record ? { ...record, contentChangedAt: pointer.contentChangedAt ?? record.fetchedAt, observations: pointer.observations || [{ fetchedAt: record.fetchedAt, provenance: record.provenance || {} }] } : null;
  }
  _query(tuple, { now = Date.now(), ttlMs = DEFAULT_QUERY_TTL_MS } = {}) {
    if (!Number.isFinite(ttlMs) || ttlMs < 0) throw new Error('invalid advisory query TTL');
    const identity = queryKey(tuple), query = this._readJson(this._lookup('queries', identity));
    if (!query) return null;
    validateQuery(query);
    // Existing folded-key consultations may have been written for a different
    // case. Treat them as a cache miss; never reuse them as evidence.
    if (queryKey(query) !== identity) {
      if (tuple.ecosystem === 'Maven') return null;
      throw new Error('advisory query identity mismatch');
    }
    for (const id of query.ids) if (!this._record(key(query.source, id))) return null;
    return { ...query, fresh: query.provenance?.stale !== true && now >= query.fetchedAt && now - query.fetchedAt < ttlMs };
  }
  _coverage(tuple, { now = Date.now(), ttlMs = DEFAULT_QUERY_TTL_MS } = {}) {
    const identity = coverageKey({ ...tuple, source: tuple.source || 'osv' });
    const entry = this._lookup('coverages', identity), coverage = this._readJson(entry?.current || entry);
    if (!coverage) return null;
    validateCoverage(coverage);
    if (coverageKey(coverage) !== identity) throw new Error('advisory coverage identity mismatch');
    const fresh = item => item.provenance?.stale !== true && now >= item.fetchedAt && now - item.fetchedAt < ttlMs;
    const baseline = this._readJson(entry?.lastComplete) || (coverage.complete ? coverage : null);
    if (baseline) {
      validateCoverage(baseline);
      if (!baseline.complete || coverageKey(baseline) !== identity) throw new Error('advisory baseline identity mismatch');
    }
    return { ...coverage, fresh: fresh(coverage), lastComplete: baseline ? { ...baseline, fresh: fresh(baseline) } : null };
  }
  _packageRecords(ecosystem, name, wantedSource, includeWithdrawn) {
    const pkg = key(ecosystem, packageName(ecosystem, name)), refs = this._lookup('packages', pkg) || [];
    if (!Array.isArray(refs) || refs.some(ref => typeof ref !== 'string')) throw new Error('invalid advisory package index');
    return refs.map(identity => this._record(identity)).filter(record => {
      if (!record || !packageKeys(record).includes(pkg)) throw new Error('advisory package identity mismatch');
      return (!wantedSource || record.source === wantedSource) && (includeWithdrawn || !isWithdrawn(record));
    });
  }
  _apply(transaction, offset, cache = new Map(), flush = true) {
    let recordOffset = offset + Buffer.byteLength('{"schema":1,"records":[');
    for (const record of transaction.records) {
      validateRecord(record);
      const serialized = JSON.stringify(record), length = Buffer.byteLength(serialized);
      const identity = recordKey(record), previous = this._record(identity, cache);
      const observations = previous?.observations || [], observation = { fetchedAt: record.fetchedAt, provenance: record.provenance || {} };
      const observationIndex = observations.findIndex(item => JSON.stringify(item.provenance) === JSON.stringify(observation.provenance));
      if (observationIndex < 0) observations.push(observation);
      else if (observations[observationIndex].fetchedAt < observation.fetchedAt) observations[observationIndex] = observation;
      if (wins(record, previous)) {
        for (const pkg of packageKeys(previous || { source: 'osv', document: {} })) {
          const shard = this._shard('packages', pkg, cache);
          const refs = shard[pkg] || [];
          shard[pkg] = refs.filter(ref => ref !== identity);
        }
        for (const pkg of packageKeys(record)) {
          const shard = this._shard('packages', pkg, cache);
          if (!shard[pkg]) shard[pkg] = [];
          if (!shard[pkg].includes(identity)) shard[pkg].push(identity);
        }
        const contentChangedAt = previous && JSON.stringify(previous.document) === JSON.stringify(record.document) ? previous.contentChangedAt : record.fetchedAt;
        this._shard('records', identity, cache)[identity] = { offset: recordOffset, length, sha256: hash(serialized), contentChangedAt, observations };
      } else this._shard('records', identity, cache)[identity].observations = observations;
      recordOffset += length + 1;
    }
    let queryOffset = recordOffset - (transaction.records.length ? 1 : 0) + Buffer.byteLength('],"queries":[');
    for (const query of transaction.queries) {
      validateQuery(query);
      const serialized = JSON.stringify(query), length = Buffer.byteLength(serialized);
      const identity = queryKey(query), shard = this._shard('queries', identity, cache), previous = this._readJson(shard[identity]);
      if (!previous || query.fetchedAt >= previous.fetchedAt) shard[identity] = { offset: queryOffset, length, sha256: hash(serialized) };
      queryOffset += length + 1;
    }
    let coverageOffset = queryOffset - (transaction.queries.length ? 1 : 0) + Buffer.byteLength('],"coverages":[');
    for (const coverage of transaction.coverages) {
      validateCoverage(coverage);
      const serialized = JSON.stringify(coverage), length = Buffer.byteLength(serialized);
      const identity = coverageKey(coverage), shard = this._shard('coverages', identity, cache), entry = shard[identity];
      const previous = this._readJson(entry?.current || entry);
      const priorCompletePointer = entry?.lastComplete || (previous?.complete ? entry?.current || entry : null);
      const priorComplete = this._readJson(priorCompletePointer);
      const pointer = { offset: coverageOffset, length, sha256: hash(serialized) };
      // Latest collection status and historical completeness are independent:
      // a partial refresh must be visible without erasing the older baseline.
      const current = !previous || coverage.fetchedAt >= previous.fetchedAt ? pointer : entry.current || entry;
      const lastComplete = coverage.complete && (!priorComplete || coverage.fetchedAt >= priorComplete.fetchedAt) ? pointer : priorCompletePointer;
      shard[identity] = { current, lastComplete };
      coverageOffset += length + 1;
    }
    if (flush) this._flush(cache);
  }
  _recover(force = false) {
    const size = this._size();
    let checkpoint = null;
    try { checkpoint = JSON.parse(fs.readFileSync(this.checkpoint, 'utf8')); } catch {}
    if (!force && checkpoint?.schema === 2 && checkpoint.bytes === size && plain(checkpoint.shards)) { this._manifest = checkpoint.shards; return; }
    // All shards are derived. A crash between journal append and index updates
    // is repaired from bounded journal lines, without loading the full database.
    this._manifest = Object.create(null);
    for (const kind of ['records', 'packages', 'queries', 'coverages']) fs.rmSync(path.join(this.directory, kind), { recursive: true, force: true });
    if (!size) {
      // An initialized empty store must itself be a valid portable journal.
      const fd = fs.openSync(this.journal, 'a', 0o600); fs.closeSync(fd);
      this._checkpoint(0); return;
    }
    const cache = new Map(); let offset = 0;
    for (const item of journalTransactions(this.journal, { allowTail: true })) {
      this._apply(item.transaction, item.offset, cache, false);
      offset = item.offset + Buffer.byteLength(item.line);
    }
    this._flush(cache);
    // An unterminated final transaction was never committed. Retain all complete
    // transactions; never publish an incomplete query as verified coverage.
    if (offset !== size) fs.truncateSync(this.journal, offset);
    this._checkpoint(offset);
  }
  commit({ records = [], queries = [], coverages = [] } = {}) {
    if (!Array.isArray(records) || !Array.isArray(queries) || !Array.isArray(coverages)) throw new Error('invalid advisory transaction');
    // JSON round-trip rejects unserializable inputs and detaches caller objects.
    const transaction = JSON.parse(JSON.stringify({ schema: 1, records, queries, coverages }));
    for (const record of transaction.records) { validateRecord(record); packageKeys(record); }
    for (const query of transaction.queries) validateQuery(query);
    for (const coverage of transaction.coverages) validateCoverage(coverage);
    const line = JSON.stringify(transaction) + '\n';
    if (Buffer.byteLength(line) > MAX_TRANSACTION_BYTES) throw new Error('oversized advisory transaction; split the import into batches');
    if (!records.length && !queries.length && !coverages.length) return;
    return this._locked(() => {
      const incoming = new Set(transaction.records.map(recordKey));
      for (const query of transaction.queries) for (const id of query.ids) {
        const identity = key(query.source, id);
        if (!incoming.has(identity) && !this._lookup('records', identity)) throw new Error(`missing advisory detail: ${id}`);
      }
      const offset = this._size(), fd = fs.openSync(this.journal, 'a', 0o600);
      try { fs.writeFileSync(fd, line); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      this._apply(transaction, offset);
      this._checkpoint(offset + Buffer.byteLength(line));
    });
  }
  getRecord(recordSource, id) {
    return this._locked(() => this._record(key(recordSource, id)));
  }
  getQuery(tuple, { now = Date.now(), ttlMs = DEFAULT_QUERY_TTL_MS } = {}) {
    return this._locked(() => this._query(tuple, { now, ttlMs }));
  }
  getSourceCoverage(recordSource, ecosystem = '*', options = {}) {
    return this._locked(() => this._coverage({ source: recordSource, ecosystem }, options));
  }
  getQuerySummary(recordSource = 'osv', { now = Date.now(), ttlMs = DEFAULT_QUERY_TTL_MS } = {}) {
    if (!Number.isFinite(ttlMs) || ttlMs < 0) throw new Error('invalid advisory query TTL');
    return this._locked(() => {
      const directory = path.join(this.directory, 'queries');
      const files = Object.keys(this._manifest).filter(file => /^queries\/[a-f0-9]{2}\.json$/.test(file)).map(file => file.slice('queries/'.length));
      let count = 0, oldestFetchedAt = null, newestFetchedAt = null, staleCount = 0;
      for (const file of files) {
        if (!/^[a-f0-9]{2}\.json$/.test(file)) continue;
        let serialized;
        try { serialized = fs.readFileSync(path.join(directory, file), 'utf8'); }
        catch (error) { if (error.code === 'ENOENT') throw this._indexFailure(); throw error; }
        if (hash(serialized) !== this._manifest[`queries/${file}`]) throw this._indexFailure();
        const shard = JSON.parse(serialized);
        if (!plain(shard)) throw new Error('invalid advisory query index');
        for (const [identity, pointer] of Object.entries(shard)) {
          const query = validateQuery(this._readJson(pointer));
          if (queryKey(query) !== identity) throw new Error('advisory query identity mismatch');
          if (query.source !== recordSource) continue;
          count++;
          oldestFetchedAt = oldestFetchedAt == null ? query.fetchedAt : Math.min(oldestFetchedAt, query.fetchedAt);
          newestFetchedAt = newestFetchedAt == null ? query.fetchedAt : Math.max(newestFetchedAt, query.fetchedAt);
          if (query.provenance?.stale === true || now < query.fetchedAt || now - query.fetchedAt >= ttlMs) staleCount++;
        }
      }
      return { count, oldestFetchedAt, newestFetchedAt, staleCount, complete: false, scope: 'consulted-package-versions' };
    });
  }
  getPackageRecords(ecosystem, name, { source: wantedSource = 'osv', includeWithdrawn = false } = {}) {
    return this._locked(() => {
      return this._packageRecords(ecosystem, name, wantedSource, includeWithdrawn);
    });
  }
  getPackageView(tuple, options = {}) {
    return this._locked(() => {
      const wantedSource = tuple.source || 'osv', query = this._query(tuple, options);
      const records = this._packageRecords(tuple.ecosystem, tuple.name, wantedSource, true);
      if (wantedSource === 'osv' && tuple.ecosystem === 'Maven') {
        for (const legacy of this._packageRecords(tuple.ecosystem, tuple.name, 'osv-legacy-maven', true)) {
          // A native revision or withdrawal supersedes every projected legacy
          // copy, including one whose old package association was removed.
          if (!this._record(key('osv', advisoryId(legacy)))) records.push(legacy);
        }
      }
      const queryRecords = query ? query.ids.map(id => this._record(key(wantedSource, id))) : [];
      const combined = new Map([...records, ...queryRecords].map(record => [recordKey(record), record]));
      return {
        query,
        coverage: this._coverage(tuple, options),
        records: [...combined.values()], // includes tombstones for reconciliation
        queryRecords, // includes valid API hits without indexable affected entries
        querySuperseded: !!query && [...combined.values()].some(record => !queryCoversRecord(query, record)),
      };
    });
  }
  async importRecords(iterable, { source: recordSource = 'osv', fetchedAt = Date.now(), provenance = { transport: 'seed' }, batchSize = 250, coverages = [], envelopes = false } = {}) {
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1000) throw new Error('invalid advisory import batch size');
    fs.mkdirSync(this.directory, { recursive: true });
    const temporary = path.join(this.directory, `.import-${process.pid}-${crypto.randomBytes(8).toString('hex')}.jsonl`);
    const fd = fs.openSync(temporary, 'wx', 0o600); let batch = [], batchBytes = 0, count = 0;
    const flush = () => {
      if (!batch.length) return;
      const line = JSON.stringify({ schema: 1, records: batch, queries: [], coverages: [] }) + '\n';
      if (Buffer.byteLength(line) > MAX_TRANSACTION_BYTES) throw new Error('oversized advisory import batch');
      fs.writeFileSync(fd, line); batch = []; batchBytes = 0;
    };
    try {
      try {
        for await (const document of iterable) {
          const record = envelopes ? document : { source: recordSource, document, fetchedAt, provenance };
          validateRecord(record); packageKeys(record);
          const bytes = Buffer.byteLength(JSON.stringify(record));
          if (bytes > MAX_TRANSACTION_BYTES - 512) throw new Error('oversized native advisory record');
          if (batchBytes + bytes > MAX_TRANSACTION_BYTES - 512) flush();
          batch.push(record); batchBytes += bytes + 1; count++;
          if (batch.length >= batchSize) flush();
        }
        flush();
        if (!Array.isArray(coverages)) throw new Error('invalid seed coverages');
        for (const coverage of coverages) validateCoverage(coverage);
        if (coverages.length) fs.writeFileSync(fd, JSON.stringify({ schema: 1, records: [], queries: [], coverages }) + '\n');
      } finally { fs.closeSync(fd); }
      this.mergeJournal(temporary);
      return count;
    } finally { fs.rmSync(temporary, { force: true }); }
  }
  async importEnvelopes(iterable, options = {}) {
    return this.importRecords(iterable, { ...options, envelopes: true });
  }
  mergeJournal(file) {
    if (path.resolve(file) === path.resolve(this.journal)) return;
    // Validate the entire source before exposing any imported advisory. Import
    // writes each derived shard once; only pointer metadata, not native advisory
    // bodies, accumulates in memory for a large seed.
    for (const _item of journalTransactions(file)) { /* validation pass */ }
    return this._locked(() => {
      const cache = new Map(), fd = fs.openSync(this.journal, 'a', 0o600);
      let offset = this._size();
      try {
        for (const item of journalTransactions(file)) {
          fs.writeFileSync(fd, item.line);
          this._apply(item.transaction, offset, cache, false);
          offset += Buffer.byteLength(item.line);
        }
        fs.fsyncSync(fd);
      } finally { fs.closeSync(fd); }
      this._flush(cache);
      this._checkpoint(offset);
    });
  }
}

function openAdvisoryStore(options) { return require('./advisory-store-sqlite').openAdvisoryStore(options); }
module.exports = { openAdvisoryStore, AdvisoryStore, DEFAULT_QUERY_TTL_MS, validateRecord, validateQuery, validateCoverage, packageName, packageKeys, queryKey, coverageKey, recordKey, advisoryId, queryCoversRecord, isWithdrawn, selectAdvisoryRecord, revision, wins, hash, key, journalTransactions };
