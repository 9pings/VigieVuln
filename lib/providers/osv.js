const { requestKey } = require("./common");
function normalizedQuery(q) {
	const ecosystem = String(q?.package?.ecosystem || q?.ecosystem || "");
	const name = String(q?.package?.name || q?.name || "");
	const version = String(q?.version || "");
	return ecosystem && name && version ? { ecosystem, name, version,
		...(typeof q?.page_token === "string" && q.page_token ? { page_token: q.page_token } : {}) } : null;
}
module.exports = {
	id: "osv", ttlMs: 12 * 3600 * 1000,
	key(type, params, scope) {
		return requestKey("osv", type, type === "package-version" ? normalizedQuery(params) : params, scope);
	},
	build(operation, params) {
		if (operation === "vuln" && typeof params?.id === "string" && params.id)
			return { url: `https://api.osv.dev/v1/vulns/${encodeURIComponent(params.id)}` };
		if (operation === "packages" || operation === "package-version") {
			const raw = operation === "packages" ? params?.queries : [params];
			if (!Array.isArray(raw) || !raw.length || raw.length > 1000) throw new Error("invalid OSV package request");
			const queries = raw.map(normalizedQuery);
			if (!queries.every(Boolean)) throw new Error("invalid OSV package request");
			return { url: "https://api.osv.dev/v1/querybatch", init: { method: "POST",
				headers: { "content-type": "application/json" }, body: JSON.stringify({ queries: queries.map(q => ({
					package: { ecosystem: q.ecosystem, name: q.name }, version: q.version,
					...(q.page_token ? { page_token: q.page_token } : {}),
				})) }) } };
		}
		throw new Error("invalid OSV request");
	},
	batch(type, params) {
		if (type !== "packages") return null;
		const queries = params?.queries?.map(normalizedQuery);
		if (!Array.isArray(queries) || !queries.length || !queries.every(Boolean)) throw new Error("invalid OSV package request");
		return { items: queries.map(q => ({ type: "package-version", params: q })),
			pack: items => ({ queries: items.map(item => item.params) }),
			split: body => {
				if (!Array.isArray(body?.results) || body.results.length !== queries.length) throw new Error("invalid OSV batch result");
				return body.results.map(result => ({ results: [result] }));
			},
			merge: bodies => ({ results: bodies.map(body => {
				if (!Array.isArray(body?.results) || body.results.length !== 1) throw new Error("invalid OSV package result");
				return body.results[0];
			}) }) };
	},
};
