module.exports = {
	id: "kev", ttlMs: 24 * 3600 * 1000,
	build(operation) {
		if (operation !== "catalog" && operation !== "cves") throw new Error("invalid KEV request");
		return { url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" };
	},
};
