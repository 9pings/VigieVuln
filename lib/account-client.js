'use strict';

const { createAccountSessionStore, validateAccountSession } = require('./account-session');

const ACCOUNT_ORIGIN = 'https://www.vigievuln.fr';
const DEFAULT_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 64 * 1024;

class AccountClientError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = 'AccountClientError';
    this.code = code;
    if (status !== undefined) this.status = status;
  }
}

const invalidResponse = () => new AccountClientError('INVALID_RESPONSE', 'Invalid account API response.');
const isAccount = value => value && typeof value === 'object' && !Array.isArray(value) &&
  typeof value.id === 'string' && value.id.length > 0 && typeof value.email === 'string' && value.email.length > 0;

/**
 * Account authentication for future project commands; no proxy config or keys.
 * Only the transport, store, clock and timeout are injectable; never the origin.
 * login({email,password}) -> {account,expiresAt}; me() -> {account};
 * logout() -> {revoked}. logout always clears local storage, including on a
 * remote error, which is still reported (revocation is then unconfirmed).
 * The password exists only in the in-flight request, never in the store.
 */
function createAccountClient({ fetcher = globalThis.fetch, now = Date.now,
  sessionStore = createAccountSessionStore({ now }), timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (typeof fetcher !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2147483647) {
    throw new AccountClientError('INVALID_OPTIONS', 'Invalid account transport or timeout.');
  }

  async function request(route, method, body, token) {
    const controller = new AbortController();
    let timer;
    let response;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => {
        reject(new AccountClientError('TIMEOUT', 'Account API request timed out.'));
        controller.abort();
      }, timeoutMs);
    });
    const operation = async () => {
      response = await fetcher(ACCOUNT_ORIGIN + '/v1/accounts/' + route, {
        method, redirect: 'error', credentials: 'omit', cache: 'no-store',
        headers: { accept: 'application/json', ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...(token ? { authorization: 'Bearer ' + token } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}), signal: controller.signal,
      });
      if (controller.signal.aborted) {
        if (response.body && !response.body.locked) void response.body.cancel().catch(() => {});
        throw new AccountClientError('TIMEOUT', 'Account API request timed out.');
      }
      // Also reject an injected transport that reports a redirect/followed URL.
      if (response.redirected || (response.status >= 300 && response.status < 400) ||
          (response.url && response.url !== ACCOUNT_ORIGIN + '/v1/accounts/' + route)) {
        throw new AccountClientError('REDIRECT_REFUSED', 'Account API redirects are forbidden.');
      }
      if (!response.ok) {
        const code = ({ 401: 'UNAUTHORIZED', 403: 'FORBIDDEN', 429: 'RATE_LIMITED' })[response.status] || 'HTTP_ERROR';
        throw new AccountClientError(code, `Account API request failed (HTTP ${response.status}).`, response.status);
      }
      if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '') || !response.body) throw invalidResponse();
      const reader = response.body.getReader();
      const cancel = () => { void reader.cancel().catch(() => {}); };
      controller.signal.addEventListener('abort', cancel, { once: true });
      const chunks = [];
      let size = 0;
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > MAX_RESPONSE_BYTES) throw invalidResponse();
          chunks.push(Buffer.from(value));
        }
      } finally {
        // Do not allow cancellation of an injected stream to hold up the timeout.
        controller.signal.removeEventListener('abort', cancel);
        cancel();
        reader.releaseLock();
      }
      let data;
      try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { throw invalidResponse(); }
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw invalidResponse();
      return data;
    };
    try { return await Promise.race([operation(), deadline]); }
    catch (error) {
      if (error instanceof AccountClientError) throw error;
      // Fetch/JSON errors can include a URL, credentials or response contents.
      throw new AccountClientError('NETWORK_ERROR', 'Unable to reach the account API.');
    } finally {
      clearTimeout(timer);
      controller.abort();
      if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
    }
  }

  async function currentSession() {
    const session = await sessionStore.read();
    if (!session) throw new AccountClientError('NOT_AUTHENTICATED', 'No account session. Sign in first.');
    return validateAccountSession(session, now());
  }

  async function login(credentials = {}) {
    const { email, password } = credentials || {};
    if (typeof email !== 'string' || !email.trim() || email.length > 254 ||
        typeof password !== 'string' || !password || Buffer.byteLength(password, 'utf8') > 512) {
      throw new AccountClientError('INVALID_CREDENTIALS', 'An email and password are required.');
    }
    const data = await request('login', 'POST', { email, password });
    let session;
    try { session = validateAccountSession(data, now()); }
    catch { throw invalidResponse(); }
    if (data.tokenType !== 'Bearer' || !isAccount(data.account)) throw invalidResponse();
    try { await sessionStore.write(session); }
    catch (error) {
      // Avoid leaving a newly issued session alive when local persistence fails.
      try { await request('logout', 'POST', {}, session.token); } catch { /* expires server-side */ }
      throw error;
    }
    return { account: data.account, expiresAt: session.expiresAt };
  }

  async function me() {
    const session = await currentSession();
    try {
      const data = await request('me', 'GET', undefined, session.token);
      if (!isAccount(data.account)) throw invalidResponse();
      return { account: data.account };
    } catch (error) {
      if (error.code === 'UNAUTHORIZED') await sessionStore.clear();
      throw error;
    }
  }

  async function createProxyKey() {
    const session = await currentSession();
    const data = await request('proxy-keys', 'POST', { name: 'VigieVuln CLI' }, session.token);
    if (typeof data?.key?.token !== 'string' || !data.key.token) throw invalidResponse();
    return { token: data.key.token };
  }

  async function logout() {
    try {
      const stored = await sessionStore.read();
      if (!stored) return { revoked: 0 };
      let session;
      try { session = validateAccountSession(stored, now()); }
      catch (error) { if (error.code === 'SESSION_EXPIRED') return { revoked: 0 }; throw error; }
      const data = await request('logout', 'POST', {}, session.token);
      if (!Number.isSafeInteger(data.revoked) || data.revoked < 0) throw invalidResponse();
      return { revoked: data.revoked };
    } finally { await sessionStore.clear(); }
  }

  return { login, logout, me, createProxyKey };
}

module.exports = { ACCOUNT_ORIGIN, DEFAULT_TIMEOUT_MS, createAccountClient, AccountClientError };
