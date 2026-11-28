const { requestKey } = require("../common");
module.exports = {
	id: "pypi", ttlMs: 24 * 3600 * 1000,
	key(type, params, scope) { return requestKey("pypi", type, { name: String(params?.name || "").toLowerCase().replace(/[-_.]+/g, "-") }, scope); },
	build(operation, params) {
		if (operation !== "package" || !params?.name || typeof params.name !== "string") throw new Error("invalid PyPI request");
		return { url: `https://pypi.org/pypi/${encodeURIComponent(params.name)}/json` };
	},
};
