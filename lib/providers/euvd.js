// ENISA European Vulnerability Database (EUVD). Two bulk reads, no per-CVE call:
// the CVE ↔ EUVD id mapping dump (one CSV) and the exploited catalogue, paged.
module.exports = {
	id: "euvd", ttlMs: 24 * 3600 * 1000,
	build(type, params) {
		const base = "https://euvdservices.enisa.europa.eu/api";
		if (type === "cves") return { url: `${base}/dump/cve-euvd-mapping` };
		if (type === "cve-mapping") return { url: `${base}/dump/cve-euvd-mapping` };
		if (type === "exploited") {
			const page = params?.page;
			if (!Number.isInteger(page) || page < 0 || page > 1000) throw new Error("invalid EUVD request");
			return { url: `${base}/search?exploited=true&size=100&page=${page}` };
		}
		throw new Error("invalid EUVD request");
	},
};
