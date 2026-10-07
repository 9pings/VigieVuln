const { requestKey } = require("./common");
module.exports = {
	id: "npm", ttlMs: 24 * 3600 * 1000,
	key(type, params, scope) { return requestKey("npm", type, { name: String(params?.name || "").toLowerCase() }, scope); },
	build(operation, params) {
		if (operation !== "package" || !params?.name || typeof params.name !== "string") throw new Error("invalid npm request");
		// Each part encoded: a forged name ("@a/b?x=y") must not reach the registry as a query.
		const scoped = /^@([^/]+)\/([^/]+)$/.exec(params.name);
		if (params.name.startsWith("@") && !scoped) throw new Error("invalid npm request");
		const name = scoped ? `@${encodeURIComponent(scoped[1])}%2F${encodeURIComponent(scoped[2])}` : encodeURIComponent(params.name);
		return { url: `https://registry.npmjs.org/${name}` };
	},
};
