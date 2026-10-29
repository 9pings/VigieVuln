'use strict';

// The hosted service permits 7200 requests/minute per key. Leave headroom for
// concurrent scans and preflight, and coordinate all providers in this process.
function createProxyThrottle({ intervalMs = 10, maxPerMinute = 6000, sleep = (ms, signal) => require('node:timers/promises').setTimeout(ms, undefined, {signal}), now = Date.now, warn = console.error } = {}) {
  let next = 0, blockedUntil = 0, warnedPacing = false, requests = 0, window = -1, count = 0;
  const lastWarning = new Map();
  function reserve(earliest) {
    let slot = Math.max(now(), next, blockedUntil, earliest);
    let current = Math.floor(slot / 60000);
    if (current !== window) { window = current; count = 0; }
    if (count >= maxPerMinute) {
      slot = (window + 1) * 60000; window++; count = 0;
      warn(`Proxy: request budget reached; waiting ${Math.ceil(Math.max(0, slot - now()) / 1000)}s for the next window.`);
    }
    count++;
    next = slot + intervalMs;
    return slot;
  }
  function abortError() { const error = new Error('Proxy request aborted while waiting for rate limit.'); error.name = 'AbortError'; return error; }
  async function wait(ms, signal) {
    if (signal?.aborted) throw abortError();
    if (!signal) return sleep(ms);
    let onAbort;
    try { await Promise.race([sleep(ms, signal), new Promise((_, reject) => { onAbort = () => reject(abortError()); signal.addEventListener('abort', onAbort, {once:true}); })]); }
    finally { signal.removeEventListener('abort', onAbort); }
  }
  async function acquire(signal) {
    let slot = reserve(0);
    if (++requests === 10 && !warnedPacing) { warnedPacing = true; warn('Proxy: pacing requests to respect the server rate limit.'); }
    for (;;) {
      if (slot < blockedUntil) slot = reserve(blockedUntil);
      const delay = slot - now();
      if (delay <= 0) break;
      await wait(delay, signal);
    }
  }
  function delayFrom(response) {
    const raw = response.headers?.get?.('retry-after');
    const seconds = raw && /^\d+$/.test(raw) ? Number(raw) : null;
    const date = raw && seconds === null ? Date.parse(raw) : NaN;
    return Math.max(1000, seconds !== null ? seconds * 1000 : Number.isFinite(date) ? date - now() : 10000);
  }
  async function request(fetcher, signal, {retryDenied = true, retryTransient = true} = {}) {
    let limitRetries = 0, transientRetries = 0;
    for (;;) {
      await acquire(signal);
      const response = await fetcher();
      const limited = response.status === 429 || (retryDenied && response.status === 503 && response.headers?.get?.('x-fad-proxy') === 'denied');
      if (!limited) {
        if (!retryTransient || ![502,503,504].includes(response.status) || transientRetries++ >= 2 || (response.status === 503 && !retryDenied && response.headers?.get?.('x-fad-proxy') === 'denied')) return response;
        if (response.body && !response.body.locked) void response.body.cancel().catch(() => {});
        await wait(transientRetries * 500, signal);
        continue;
      }
      if (limitRetries >= 3) return response;
      limitRetries++;
      const delay = delayFrom(response);
      if (delay > 60000) { warn(`Proxy rate limit: retry requested after ${Math.ceil(delay / 1000)}s; stopping this request.`); return response; }
      blockedUntil = Math.max(blockedUntil, now() + delay);
      next = Math.max(next, blockedUntil);
      if (!lastWarning.has(response.status) || now() - lastWarning.get(response.status) >= 10000) {
        lastWarning.set(response.status, now());
        warn(`Proxy rate limit (HTTP ${response.status}): waiting ${Math.ceil(delay / 1000)}s before retrying (attempt ${limitRetries}/3).`);
      }
      if (response.body && !response.body.locked) void response.body.cancel().catch(() => {});
    }
  }
  return { request };
}
module.exports = { createProxyThrottle };
