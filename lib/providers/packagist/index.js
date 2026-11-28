const { encodePath, requestKey } = require("../common");
module.exports = {
	id: "packagist", ttlMs: 24 * 3600 * 1000,
	key(type, params, scope) {
		if (type === "advisory-package" || type === "package" || type === "p2")
			return requestKey("packagist", type, { name: String(params?.name || "").toLowerCase() }, scope);
		return requestKey("packagist", type, params, scope);
	},
	build(operation, params) {
		if ((operation === "advisories" || operation === "advisory-package") &&
			Array.isArray(operation === "advisories" ? params?.packages : [params?.name]) &&
			(operation === "advisories" ? params.packages.length : !!params?.name)) {
			const names = operation === "advisories" ? params.packages : [params.name];
			if (names.some(name => !/^[^/\s]+\/[^/\s]+$/.test(name))) throw new Error("invalid Packagist package name");
			return { url: `https://packagist.org/api/security-advisories/?${names.map(n => `packages[]=${encodeURIComponent(n)}`).join("&")}` };
		}
		if ((operation === "package" || operation === "p2") && /^[^/\s]+\/[^/\s]+$/.test(params?.name || ""))
			return { url: `https://${operation === "p2" ? "repo.packagist.org/p2" : "packagist.org/packages"}/${encodePath(params.name)}.json` };
		throw new Error("invalid Packagist request");
	},
	batch(type, params) {
		if (type !== "advisories") return null;
		const names = params?.packages;
		if (!Array.isArray(names) || !names.length) throw new Error("invalid Packagist advisory request");
		return { items: names.map(name => ({ type: "advisory-package", params: { name } })),
			pack: items => ({ packages: items.map(item => item.params.name) }),
			split: body => {
				if (!body?.advisories || typeof body.advisories !== "object" || Array.isArray(body.advisories)) throw new Error("invalid Packagist batch result");
				return names.map(name => ({ advisories: Object.hasOwn(body.advisories, name)
					? { [name]: body.advisories[name] } : {} }));
			},
			merge: bodies => ({ advisories: Object.assign({}, ...bodies.map(body => {
				if (!body?.advisories || typeof body.advisories !== "object" || Array.isArray(body.advisories))
					throw new Error("invalid Packagist advisory result");
				return body.advisories;
			})) }) };
	},
};
