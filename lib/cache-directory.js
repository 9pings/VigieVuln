'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {spawnSync} = require('node:child_process');
const warned = new Set();

// The cache is separate from account sessions and from the proxy server store.
function resolveDirectory(currentName, legacyName, {homeDir = os.homedir(), fsImpl = fs, platform = process.platform, spawn = spawnSync, warn = console.error} = {}) {
  const current = path.join(homeDir, currentName);
  const legacy = path.join(homeDir, legacyName);
  const marker = path.join(homeDir, currentName + '.migration-pending');
  const stat = file => {
    try { return fsImpl.lstatSync(file); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  };
  const checkCurrent = () => {
    const entry = stat(current);
    if (entry && (entry.isSymbolicLink() || !entry.isDirectory()))
      throw new Error('VigieVuln cache directory must be a directory, not a symbolic link');
    return entry;
  };
  const warnPending = () => {
    if (warned.has(current)) return;
    warned.add(current);
    const show = value => '"' + value.replace(/[\x00-\x1f\x7f"]/g, c => c === '"' ? '\\"' : `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`) + '"';
    let previous;
    try { previous = stat(legacy); } catch { /* leave recovery to the user */ }
    const recovery = previous?.isDirectory() && !previous.isSymbolicLink()
      ? `Stop VigieVuln, back up or move ${show(current)}, then rename ${show(legacy)} to ${show(current)}.`
      : `Stop VigieVuln and inspect ${show(legacy)} safely; it is not a regular directory and requires manual recovery.`;
    warn(`VigieVuln cache migration failed; previous data remains at ${show(legacy)} and is not being used. ` +
      `${recovery} After recovery, remove ${show(marker)}.`);
  };
  if (checkCurrent()) {
    let pending;
    try { pending = stat(marker); } catch { /* an unreadable reminder must not block the cache */ }
    if (pending && pending.isFile() && !pending.isSymbolicLink()) {
      let previous;
      try { previous = stat(legacy); } catch { previous = true; }
      if (previous) warnPending();
    }
    return current;
  }
  const old = stat(legacy);
  if (!old) return current;
  // Do not let an mv fallback copy or delete a cache on another filesystem.
  const parent = stat(homeDir);
  if (old.isDirectory() && !old.isSymbolicLink() && parent && old.dev === parent.dev) {
    try {
      if (!checkCurrent()) {
        // Node's POSIX rename can replace an empty destination created concurrently.
        // GNU mv -n -T uses no-clobber semantics. Darwin's renameatx_np
        // syscall with RENAME_EXCL refuses an existing destination atomically.
        // Windows rename refuses a target. On failure retain the old directory.
        if (platform === 'linux') spawn('/bin/mv', ['-n', '-T', '--', legacy, current], {stdio:'ignore'});
        else if (platform === 'darwin') spawn('/usr/bin/perl', ['-e',
          'exit(syscall(488, -2, $ARGV[0], -2, $ARGV[1], 4) == 0 ? 0 : 1)', legacy, current], {stdio:'ignore'});
        else if (platform === 'win32') fsImpl.renameSync(legacy, current);
      }
    } catch { /* Keep the legacy data and fall back to a fresh directory. */ }
  }
  if (!checkCurrent()) {
    try { fsImpl.mkdirSync(current, {mode:0o700}); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    checkCurrent();
  }
  if (stat(legacy)) {
    // The marker contains no paths or configuration and is never overwritten.
    try { fsImpl.writeFileSync(marker, '', {flag:'wx', mode:0o600}); } catch { /* warning still appears now */ }
    warnPending();
  }
  return current;
}
const getCacheDir = options => resolveDirectory('.vigie-vuln', '.fad-checker', options);
const getProxyCacheDir = options => resolveDirectory('.vigie-vuln-proxy-cache', '.fad-checker-proxy-cache', options);
module.exports = {getCacheDir, getProxyCacheDir};
