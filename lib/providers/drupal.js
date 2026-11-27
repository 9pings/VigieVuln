module.exports = {
	id: "drupal", ttlMs: 24 * 3600 * 1000,
	build(type, params) {
		if (type === "extension") {
			if (!/^drupal\/[a-z0-9][a-z0-9_-]{0,198}$/.test(params?.name || "")) throw Error("invalid Drupal catalogue identity");
			return {url:`https://packages.drupal.org/files/packages/8/p2/${params.name}.json`};
		}
		if (type !== "advisories" || !Array.isArray(params?.packages) || !params.packages.length ||
			params.packages.some(name => !/^drupal\/[^/\s]+$/i.test(name))) throw new Error("invalid Drupal advisory request");
		const query = new URLSearchParams();
		for (const name of params.packages) query.append("packages[]", name);
		return { url: `https://packages.drupal.org/8/security-advisories?${query}` };
	},
};
