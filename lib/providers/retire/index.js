module.exports = {
	id: "retire", ttlMs: 24 * 3600 * 1000,
	build(type) {
		if (type !== "signatures") throw new Error("invalid retire.js request");
		return { url: "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v5.json" };
	},
};
