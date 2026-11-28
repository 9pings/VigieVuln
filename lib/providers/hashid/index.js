const { requestKey } = require("../common");
module.exports = {
	id: "hashid", ttlMs: 24 * 3600 * 1000,
	key(type, params, scope) { return requestKey("hashid", type,
		type === "circl-sha256" ? { sha256: String(params?.sha256 || "").toLowerCase() } : params, scope); },
	build(type, params) {
		if (type === "depsdev-sha1" && /^[A-Za-z0-9+/=]+$/.test(params?.base64 || ""))
			return { url: `https://api.deps.dev/v3/query?hash.type=SHA1&hash.value=${encodeURIComponent(params.base64)}` };
		if (type === "circl-sha256" && /^[0-9a-f]{64}$/i.test(params?.sha256 || ""))
			return { url: `https://hashlookup.circl.lu/lookup/sha256/${params.sha256.toLowerCase()}` };
		throw new Error("invalid hash identity request");
	},
};
