const crypto = require("node:crypto");

function requestKey(provider, operation, params, scope = "") {
	return JSON.stringify([provider, operation, params, scope]);
}
function credentialScope(headers = {}) {
	const h = new Headers(headers);
	const secret = [h.get("authorization") || "", h.get("apikey") || ""].join("\0");
	return secret.replace(/\0/g, "") ? crypto.createHash("sha256").update(secret).digest("hex") : "";
}
// Only headers needed to interpret a public response belong in the cache.
// Never persist cookies, authentication challenges or hop-by-hop headers.
function responseHeaders(headers) {
	const link = headers?.get?.("link");
	return link ? { link } : {};
}
// Validators refer to the upstream representation and are stored privately;
// a proxy may return a transformed body, so do not forward them as its ETag.
function cacheResponseHeaders(headers) {
	const result=responseHeaders(headers);
	for(const name of ['etag','last-modified']) {
		const value=headers?.get?.(name);
		if(value && value.length<=1024 && !/[\r\n]/.test(value))result[name]=value;
	}
	return result;
}
function responseFetchedAt(response, fallback = Date.now()) {
	const raw = response?.headers?.get?.("x-fad-proxy-fetched-at");
	const stamp = raw ? Date.parse(raw) : NaN;
	return Number.isFinite(stamp) ? Math.min(stamp, fallback) : fallback;
}
function cveId(value) {
	return /^CVE-\d{4}-\d{4,}$/i.test(String(value || "")) ? String(value).toUpperCase() : null;
}
function encodePath(value) { return String(value).split("/").map(encodeURIComponent).join("/"); }

module.exports = { requestKey, credentialScope, cveId, encodePath, responseHeaders, cacheResponseHeaders, responseFetchedAt };
