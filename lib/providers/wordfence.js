module.exports = {
	id: "wordfence", ttlMs: 24 * 3600 * 1000,
	build(type, params) {
		if (type === "software") {
			require("../application-providers/wordfence-projection").queriesOf(params?.software, { min: 1, max: 100 });
			return { url: "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production", proxyOnly: true };
		}
		if (type !== "production-feed") throw new Error("invalid Wordfence request");
		return { url: "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production" };
	},
};
