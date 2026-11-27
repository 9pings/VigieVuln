const { encodePath } = require("./common");
module.exports = {
	id: "maven", ttlMs: 24 * 3600 * 1000,
	build(type, params) {
		if (params?.repository !== undefined && params.repository !== 'google') throw new Error('invalid Maven repository');
		const base=params?.repository==='google' ? 'https://dl.google.com/dl/android/maven2/' : 'https://repo1.maven.org/maven2/';
		if (type === "preflight") return { url: base, init: { method: "HEAD" } };
		if (type === "artifact" && typeof params?.path === "string" && params.path && !params.path.split("/").some(s => s === "." || s === ".."))
			return { url: `${base}${encodePath(params.path.replace(/^\/+/, ""))}`,
				init: { method: params.method === "HEAD" ? "HEAD" : "GET" } };
		if (type === "latest" && params?.group && params?.artifact)
			return { url: `https://search.maven.org/solrsearch/select?q=g:%22${encodeURIComponent(params.group)}%22+AND+a:%22${encodeURIComponent(params.artifact)}%22&core=gav&rows=1&wt=json` };
		throw new Error("invalid Maven request");
	},
};
