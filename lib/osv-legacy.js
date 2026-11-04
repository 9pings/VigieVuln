'use strict';
// Published 1.1.x cached full advisory details independently from lossy tuple
// filenames. Only those native documents are reusable; filenames never prove
// that a package/version was checked, and negative query lists are not migrated.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { validateRecord } = require('./advisory-store');

function importLegacyOsvDetails(store, { cacheDir, legacyDir = path.join(cacheDir, 'osv-cache'), force = false } = {}) {
  const marker = path.join(store.directory, 'legacy-details-import.json');
  let directoryMtime;
  try { directoryMtime = fs.statSync(legacyDir).mtimeMs; }
  catch (error) { if (error.code === 'ENOENT') return { imported: 0, skipped: 0 }; throw error; }
  try {
    const previous = JSON.parse(fs.readFileSync(marker, 'utf8'));
    if (!force && previous.schema === 1 && previous.directory === path.resolve(legacyDir) && previous.directoryMtime === directoryMtime) return { ...previous, previouslyImported: true };
  } catch {}
  let entries;
  try { entries = fs.readdirSync(legacyDir, { withFileTypes: true }); }
  catch (error) { if (error.code === 'ENOENT') return { imported: 0, skipped: 0 }; throw error; }
  fs.mkdirSync(store.directory, { recursive: true });
  const temporary = path.join(store.directory, `.legacy-${process.pid}-${crypto.randomBytes(8).toString('hex')}.jsonl`);
  const fd = fs.openSync(temporary, 'wx', 0o600); let imported = 0, skipped = 0, batch = [];
  const flush = () => {
    if (!batch.length) return;
    fs.writeFileSync(fd, JSON.stringify({ schema: 1, records: batch, queries: [], coverages: [] }) + '\n'); batch = [];
  };
  try {
    try {
      for (const entry of entries) {
        if (!/^vuln_.+\.json$/.test(entry.name)) continue;
        if (!entry.isFile()) { skipped++; continue; }
        let record;
        try {
          const file = path.join(legacyDir, entry.name), stat = fs.lstatSync(file);
          if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024 * 1024) throw new Error('invalid legacy advisory file');
          const cached = JSON.parse(fs.readFileSync(file, 'utf8')), document = cached.body;
          record = { source: 'osv', document, fetchedAt: cached._fetchedAt, provenance: { transport: 'legacy-cache', format: '1.1.x-detail' } };
          validateRecord(record);
          if (!document.withdrawn && !document.affected?.some(affected => affected.package?.ecosystem && affected.package?.name)) throw new Error('legacy advisory has no package identity');
        } catch { skipped++; continue; }
        // A large but valid document gets its own bounded transaction.
        if (Buffer.byteLength(JSON.stringify(record)) > 512 * 1024) { flush(); batch.push(record); flush(); }
        else { batch.push(record); if (batch.length >= 25) flush(); }
        imported++;
      }
      flush();
    } finally { fs.closeSync(fd); }
    if (imported) store.mergeJournal(temporary);
    const result = { schema: 1, directory: path.resolve(legacyDir), directoryMtime, imported, skipped, importedAt: Date.now() };
    fs.writeFileSync(marker, JSON.stringify(result), { mode: 0o600 });
    return result;
  } finally { fs.rmSync(temporary, { force: true }); }
}

module.exports = { importLegacyOsvDetails };
