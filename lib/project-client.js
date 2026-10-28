"use strict";
const ORIGIN = "https://www.vigievuln.fr";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const COORD = /^[A-Za-z0-9@_][A-Za-z0-9@._+~/-]*$/;
const SIMPLE = /^[A-Za-z0-9._-]{1,100}$/;
// Allow room for server-normalized descriptors, while bounding memory use.
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

class ProjectClientError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = 'ProjectClientError';
    this.code = code;
    if (status !== undefined) this.status = status;
  }
}

// Match the server's coordinate rules BEFORE anything leaves the machine.
function coordinate(value, optional = false) {
  if (optional && (value === undefined || value === null || value === '')) return '';
  if (typeof value !== 'string') return null;
  const result = value.trim();
  return result.length <= 256 && COORD.test(result) && !result.includes('..') &&
    !result.includes('//') && !result.endsWith('/') ? result : null;
}

// Rebuild the body from allowed fields before it leaves the client. Coordinates
// themselves can be private and must be reviewed by the user before sending.
function sanitizeDescriptor(input) {
  if (!input || input.schema !== "fad-deps/2" || !Array.isArray(input.deps) || input.deps.length > 5000) throw new Error("expected a fad-deps/2 project descriptor");
  const deps = input.deps.map((d,i) => {
    const name = coordinate(d?.name), namespace = coordinate(d?.namespace, true);
    if (!d || !SIMPLE.test(d.ecosystem || "") || !SIMPLE.test(d.ecosystemType || "") ||
        name === null || namespace === null ||
        !["direct","transitive","unknown"].includes(d.relation) || !SIMPLE.test(d.scope || "")) throw new Error(`invalid dependency ${i}`);
    const version = d.version == null ? null : require("./deps-descriptor").cleanVersion(d.version);
    if (d.version != null && !version) throw new Error(`invalid version for dependency ${i}`);
    if (d.versions !== undefined && (!Array.isArray(d.versions) || d.versions.length !== (version ? 1 : 0) || (version && d.versions[0] !== version)))
      throw new Error(`ambiguous versions for dependency ${i}`);
    return {ecosystem:d.ecosystem,ecosystemType:d.ecosystemType,namespace,name,
      version,versions:version ? [version] : [],scope:d.scope,isDev:!!d.isDev,relation:d.relation};
  });
  const out={schema:"fad-deps/2",generator:"vigievuln",deps};
  if (Buffer.byteLength(JSON.stringify(out)) > 1900000) throw new Error("project descriptor exceeds the upload limit");
  return out;
}
async function projectRequest(path, {session, method="GET", body, fetcher=globalThis.fetch, timeoutMs=15000} = {}) {
  if (typeof session !== "string" || !/^[A-Za-z0-9_-]{1,200}$/.test(session)) throw new Error("an account session is required");
  if (!/^\/v1\/projects(?:\/[0-9a-f-]+)?$/i.test(path)) throw new Error("invalid project endpoint");
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2147483647) throw new Error('invalid project request timeout');
  const invalid = () => new ProjectClientError('INVALID_RESPONSE', 'Invalid project service response.');
  const tooLarge = () => new ProjectClientError('RESPONSE_TOO_LARGE', 'Project service response exceeds the size limit.');
  const controller = new AbortController();
  let response, timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new ProjectClientError('TIMEOUT', 'Project request timed out.'));
      controller.abort();
    }, timeoutMs);
  });
  const operation = async () => {
    response = await fetcher(ORIGIN+path,{method,redirect:"error",credentials:'omit',cache:'no-store',signal:controller.signal,
      headers:{authorization:`Bearer ${session}`,accept:"application/json",...(body ? {"content-type":"application/json"} : {})},
      ...(body ? {body:JSON.stringify(body)} : {})});
    if (controller.signal.aborted) {
      if (response.body && !response.body.locked) void response.body.cancel().catch(() => {});
      throw new ProjectClientError('TIMEOUT', 'Project request timed out.');
    }
    if (response.redirected || (response.status >= 300 && response.status < 400) ||
        (response.url && response.url !== ORIGIN + path)) {
      throw new ProjectClientError('REDIRECT_REFUSED', 'Project API redirects are forbidden.');
    }
    if (!response.ok) {
      const code = ({401:'UNAUTHORIZED',403:'FORBIDDEN',409:'REVISION_CONFLICT',429:'RATE_LIMITED'})[response.status] || 'HTTP_ERROR';
      throw new ProjectClientError(code, `project request failed (HTTP ${response.status})`, response.status);
    }
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '') || !response.body) throw invalid();
    if (Number(response.headers.get('content-length')) > MAX_RESPONSE_BYTES) throw tooLarge();
    const reader = response.body.getReader();
    const cancel = () => { void reader.cancel().catch(() => {}); };
    controller.signal.addEventListener('abort', cancel, {once:true});
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const {value, done} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_RESPONSE_BYTES) throw tooLarge();
        chunks.push(Buffer.from(value));
      }
    } finally {
      controller.signal.removeEventListener('abort', cancel);
      cancel();
      reader.releaseLock();
    }
    let data;
    try { data = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(Buffer.concat(chunks))); }
    catch { throw invalid(); }
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw invalid();
    return data;
  };
  try { return await Promise.race([operation(), deadline]); }
  catch (error) {
    if (error instanceof ProjectClientError) throw error;
    throw new ProjectClientError('NETWORK_ERROR', 'Unable to reach the project API.');
  } finally {
    clearTimeout(timer);
    controller.abort();
    if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
  }
}
async function createProject({session,name,descriptor,fetcher}) {
  if (typeof name !== "string" || !name.trim() || name.length>120) throw new Error("a project name is required");
  return projectRequest("/v1/projects",{session,method:"POST",body:{name,descriptor:sanitizeDescriptor(descriptor)},fetcher});
}
async function updateProject({session,id,revision,descriptor,fetcher}) {
  if (!UUID.test(id || "") || !Number.isSafeInteger(revision) || revision<1) throw new Error("project id and current revision are required");
  return projectRequest(`/v1/projects/${id}`,{session,method:"PUT",body:{revision,descriptor:sanitizeDescriptor(descriptor)},fetcher});
}
module.exports={sanitizeDescriptor,projectRequest,createProject,updateProject,ProjectClientError,MAX_RESPONSE_BYTES};
