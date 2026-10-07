const { cveId, requestKey } = require("./common");
module.exports = {
	id: "epss", ttlMs: 24 * 3600 * 1000,
	key(type, params, scope) {
		return requestKey("epss", type, type === "cve-score" ? { id: cveId(params?.id) } : params, scope);
	},
	build(operation, params) {
		// The whole daily score file (~300 000 CVEs, gzip CSV): fad-service mirrors it.
		if (operation === "current-csv") return { url: "https://epss.cyentia.com/epss_scores-current.csv.gz" };
		const ids = operation === "cve-score" ? [params?.id] : params?.ids;
		if (!["scores", "cve-score"].includes(operation) || !Array.isArray(ids) || !ids.length || ids.some(id => !cveId(id)))
			throw new Error("invalid EPSS request");
		return { url: `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(ids.join(","))}` };
	},
	batch(type, params) {
		if (type !== "scores") return null;
		const ids = params?.ids;
		if (!Array.isArray(ids) || !ids.length || ids.some(id => !cveId(id))) throw new Error("invalid EPSS request");
		return { items: ids.map(id => ({ type: "cve-score", params: { id: cveId(id) } })),
			pack: items => ({ ids: items.map(item => item.params.id) }),
			split: body => {
				if (!Array.isArray(body?.data)) throw new Error("invalid EPSS batch result");
				return ids.map(id => ({ data: body.data.filter(row => row.cve === id) }));
			},
			merge: bodies => ({ data: bodies.flatMap(body => {
				if (!Array.isArray(body?.data)) throw new Error("invalid EPSS result");
				return body.data;
			}) }) };
	},
};
