'use strict';

// The hosted service permits 7200 requests/minute per key. Leave headroom for
// concurrent scans and preflight, and coordinate all providers in this process.
function createProxyThrottle({ intervalMs = 10, maxPerMinute = 6000, maxWaitMs = 45000, maxRateRetries = 15, sleep = (ms, signal) => require('node:timers/promises').setTimeout(ms, undefined, {signal}), now = Date.now, warn = msg => require('./ui').networkNotice(msg), subscribeSkip = ttySkipSubscription } = {}) {
  let next = 0, blockedUntil = 0, warnedPacing = false, requests = 0, window = -1, count = 0, skipped = false, stopListening = null;
  const skipWaiters=new Set();
  function skipRetries() { skipped=true;next=now();for(const resolve of skipWaiters)resolve(); }
  function reserve(earliest) {
    let slot = Math.max(now(), next, skipped ? 0 : blockedUntil, earliest);
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
  async function wait(ms, signal, canSkip = false) {
    if (signal?.aborted) throw abortError();
    const controller=new AbortController();let onAbort,resolveSkip;
    if(canSkip && skipped)return false;
    if(canSkip && !stopListening)stopListening=subscribeSkip(skipRetries) || (()=>{});
    const choices=[Promise.resolve().then(()=>sleep(ms,controller.signal)).then(()=>true)];
    if(signal)choices.push(new Promise((_,reject)=>{onAbort=()=>reject(abortError());signal.addEventListener('abort',onAbort,{once:true});}));
    if(canSkip)choices.push(new Promise(resolve=>{resolveSkip=()=>resolve(false);skipWaiters.add(resolveSkip);}));
    try { return await Promise.race(choices); }
    finally {controller.abort();if(onAbort)signal.removeEventListener('abort',onAbort);if(resolveSkip){skipWaiters.delete(resolveSkip);if(!skipWaiters.size && stopListening){stopListening();stopListening=null;}}}
  }
  async function acquire(signal) {
    if (signal?.aborted) throw abortError();
    let slot = reserve(0);
    if (++requests === 10 && !warnedPacing) { warnedPacing = true; warn('Proxy: pacing requests to respect the server rate limit.'); }
    for (;;) {
      if (!skipped && slot < blockedUntil) slot = reserve(blockedUntil);
      const delay = slot - now();
      if (delay <= 0) break;
      if(await wait(delay, signal, !skipped && blockedUntil > now())===false)return false;
    }
    return true;
  }
  function delayFrom(response) {
    const raw = response.headers?.get?.('retry-after');
    const seconds = raw && /^\d+$/.test(raw) ? Number(raw) : null;
    const date = raw && seconds === null ? Date.parse(raw) : NaN;
    return Math.max(3000, seconds !== null ? seconds * 1000 : Number.isFinite(date) ? date - now() : 3000);
  }
  async function request(fetcher, signal, {retryDenied = true, retryTransient = true, waitBudgetMs = maxWaitMs, rateRetries = maxRateRetries, label = null} = {}) {
    if (!Number.isSafeInteger(waitBudgetMs) || waitBudgetMs < 0 || !Number.isSafeInteger(rateRetries) || rateRetries < 0) throw new Error('Invalid proxy retry budget');
    let limitRetries = 0, transientRetries = 0, waitedMs = 0;
    const context = label ? ` [${label}]` : '';
    // Retry allowance belongs to this lookup. Cooldowns remain coordinated across
    // concurrent lookups, but one resource cannot disable retries for the scan.
    function scheduleCooldown(delay) {
      if (delay > waitBudgetMs - waitedMs) {
        warn(`Proxy retry wait budget exhausted${context}: another ${Math.ceil(delay / 1000)}s would exceed this request's budget. Continuing with cached data when available; other requests retain their retries.`);
        return false;
      }
      waitedMs += delay;
      blockedUntil = Math.max(blockedUntil, now() + delay);
      next = Math.max(next, blockedUntil);
      return true;
    }
    let lastLimited = null;
    for (;;) {
      if (!(await acquire(signal))) {
        next = now();
        if (lastLimited && (!skipped || lastLimited.status===200)) return lastLimited;
        if(skipped){const error=new Error('Proxy rate-limit retry skipped by user.');error.code='PROXY_RETRY_SKIPPED';if(lastLimited)error.status=lastLimited.status;throw error;}
        continue;
      }
      let response;
      try { response=await fetcher(); }
      catch(error) {
        if(signal?.aborted)throw abortError();
        if(error?.name==='AbortError')throw error;
        if(lastLimited?.status===200)return lastLimited;
        throw error;
      }
      const stale=response.status===200 && response.headers?.get?.('x-fad-proxy')==='stale' && response.headers?.get?.('x-fad-proxy-reason')==='refresh-failed';
      const cause=response.headers?.get?.('x-fad-proxy-refresh-cause'), refreshStatus=response.headers?.get?.('x-fad-proxy-refresh-status');
      const staleLimit=stale && ((cause==='rate-limit' && refreshStatus==='429') || (retryDenied && cause==='admission' && refreshStatus==='503'));
      const limited = staleLimit || response.status === 429 || (retryDenied && response.status === 503 && response.headers?.get?.('x-fad-proxy') === 'denied');
      if (!limited) {
        if (skipped || !retryTransient || ![502,503,504].includes(response.status) || transientRetries >= 2 || limitRetries + transientRetries >= rateRetries || (response.status === 503 && !retryDenied && response.headers?.get?.('x-fad-proxy') === 'denied')) {
          if(response.status!==200 && lastLimited?.status===200)return lastLimited;
          if (lastLimited?.body && !lastLimited.body.locked) void lastLimited.body.cancel().catch(()=>{});
          return response;
        }
        if(!scheduleCooldown(3000))return lastLimited?.status===200?lastLimited:response;
        transientRetries++;
        if (response.body && !response.body.locked) void response.body.cancel().catch(() => {});
        continue;
      }
      if (skipped) {
        // A provider admission denial may leave other cached resources usable.
        // A global 429 still receives a minimum probe interval, without retries.
        if (response.status === 429 || refreshStatus === '429') next = Math.max(next, now() + 1000);
        return response.status !== 200 && lastLimited?.status === 200 ? lastLimited : response;
      }
      const delay = delayFrom(response);
      if (limitRetries + transientRetries >= rateRetries) return response.status !== 200 && lastLimited?.status === 200 ? lastLimited : response;
      limitRetries++;
      if (!scheduleCooldown(delay)) return response.status !== 200 && lastLimited?.status === 200 ? lastLimited : response;
      const status = staleLimit ? `refresh HTTP ${refreshStatus}; cached response available` : `HTTP ${response.status}`;
      const reason = response.status === 503 || refreshStatus === '503'
        ? 'Proxy upstream request temporarily deferred' : 'Proxy rate limit';
      warn(`${reason}${context} (${status}): waiting ${Math.ceil(delay / 1000)}s before retrying (retry ${limitRetries + transientRetries}/${rateRetries} for this request).${process.stdin?.isTTY?' Press S or Esc to skip retries.':''}`);
      if (lastLimited?.body && !lastLimited.body.locked) void lastLimited.body.cancel().catch(()=>{});
      lastLimited = staleLimit ? response.clone() : response;
      if (response.body && !response.body.locked) void response.body.cancel().catch(() => {});
    }
  }
  return { request };
}
function ttySkipSubscription(skip, input=process.stdin, signalInterrupt=()=>process.kill(process.pid,'SIGINT')) {
  if(!input?.isTTY || typeof input.setRawMode!=='function')return null;
  const wasRaw=!!input.isRaw,wasPaused=input.isPaused();
  const parser=new (require('node:stream').PassThrough)();require('node:readline').emitKeypressEvents(parser);
  let multi=false,disposed=false;
  const dispose=()=>{if(disposed)return;disposed=true;input.removeListener('data',onData);parser.removeAllListeners('keypress');parser.destroy();if(!wasRaw && input.isRaw)input.setRawMode(false);if(wasPaused)input.pause();};
  parser.on('keypress',(str,key)=>{if(key?.ctrl && key.name==='c' && !wasRaw){dispose();signalInterrupt();return;}if(key?.name==='escape'||(!multi&&(str==='s'||str==='S')))skip();});
  const onData=chunk=>{const text=String(chunk);multi=text.length>1 && !text.startsWith('\u001b');parser.write(chunk);multi=false;};
  try{if(!wasRaw)input.setRawMode(true);input.on('data',onData);if(wasPaused)input.resume();}
  catch{dispose();return null;}
  return dispose;
}
module.exports = { createProxyThrottle, ttySkipSubscription };
