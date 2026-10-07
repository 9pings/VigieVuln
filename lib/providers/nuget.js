const { requestKey, encodePath } = require("./common");
module.exports = {
	id: "nuget", ttlMs: 24 * 3600 * 1000,
	key(type, params, scope) { return requestKey("nuget", type,
		type === "registration" ? { name: String(params?.name || "").toLowerCase() } : params, scope); },
	build(operation, params) {
		if (operation === "service-index") return { url: "https://api.nuget.org/v3/index.json" };
		if (operation === "registration-page" && /^\/[^?#]+\.json$/.test(params?.path || "") &&
			!String(params.path).split("/").some(s => s === "." || s === ".."))
			return { url: `https://api.nuget.org${encodePath(params.path)}` };
		if (operation !== "registration" || !params?.name || typeof params.name !== "string") throw new Error("invalid NuGet request");
		return { url: `https://api.nuget.org/v3/registration5-gz-semver2/${encodeURIComponent(params.name)}/index.json` };
	},
};
