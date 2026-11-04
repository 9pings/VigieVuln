'use strict';

const DEFAULT_TTL_MS = 4 * 60 * 60 * 1000;
let forceUpdate = false;
function setForceUpdate(value) { forceUpdate = value === true; }
function shouldForceUpdate() { return forceUpdate; }
function fresh(fetchedAt, ttlMs = DEFAULT_TTL_MS, now = Date.now()) {
 return !forceUpdate && Number.isFinite(fetchedAt) && fetchedAt > 0 && now >= fetchedAt && now - fetchedAt < Math.min(ttlMs, DEFAULT_TTL_MS);
}
// Legacy registry caches carry one timestamp for the whole map. If some old
// entries were not refreshed, keep their oldest timestamp instead of making
// them appear newly consulted, and never replace them with transient errors.
function preserveEntries(cache, previous) {
 if (!previous?.entries) return cache;
 let retained=false;
 for (const [key,value] of Object.entries(previous.entries)) {
  const next=cache.entries[key];
  if (!Object.hasOwn(cache.entries,key) || (next?.error && !next.absent)) {
   cache.entries[key]=value;retained=true;
  }
 }
 if(retained) cache.meta={...cache.meta,fetchedAt:Math.min(Number(cache.meta?.fetchedAt)||0,Number(previous.fetchedAt)||0)};
 return cache;
}
module.exports = {DEFAULT_TTL_MS, setForceUpdate, shouldForceUpdate, fresh, preserveEntries};
