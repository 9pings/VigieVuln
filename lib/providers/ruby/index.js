const { requestKey } = require("../common");
module.exports = {
	id: "ruby", ttlMs: 24 * 3600 * 1000,
	key(type, params, scope) { return requestKey("ruby", type, { name: String(params?.name || "").toLowerCase() }, scope); },
	build(operation, params) {
		if (operation !== "gem" || !params?.name || typeof params.name !== "string") throw new Error("invalid RubyGems request");
		return { url: `https://rubygems.org/api/v1/gems/${encodeURIComponent(params.name)}.json` };
	},
};
