const { requestKey } = require("../common");
module.exports = {
	id: "eol", ttlMs: 7 * 24 * 3600 * 1000,
	key(type, params, scope) { return requestKey("eol", type, { product: String(params?.product || "").toLowerCase() }, scope); },
	build(operation, params) {
		if (operation !== "product" || !params?.product || typeof params.product !== "string") throw new Error("invalid EOL request");
		return { url: `https://endoflife.date/api/${encodeURIComponent(params.product)}.json` };
	},
};
