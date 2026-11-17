const { cveId, requestKey } = require("./common");
module.exports = {
	id: "nvd", ttlMs: 7 * 24 * 3600 * 1000, revalidateTypes: ['cve','cve-mirror'],
	key(type, params, scope) { return requestKey("nvd", type, type === "spip-advisories" ? {} : { id: cveId(params?.id) }, scope); },
	build(operation, params) {
		if (operation === "spip-advisories") return {
			url: "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:spip:spip&resultsPerPage=2000&startIndex=0",
		};
		// fkie-cad/nvd-json-data-feeds: a daily git mirror of the NVD API 2.0, one file per CVE
		// holding the API's own `cve` object, bucketed by the id minus its last two digits
		// (CVE-2021-44228 → CVE-2021-442xx). No key, no 5-per-30s rate limit. lib/nvd.js
		// falls back to it when NVD itself does not answer.
		if (operation === "cve-mirror") {
			const id = cveId(params?.id);
			if (!id) throw new Error("invalid NVD mirror request");
			const [, year, num] = /^CVE-(\d{4})-(\d{4,})$/.exec(id);
			return { url: `https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/CVE-${year}/CVE-${year}-${num.slice(0, -2)}xx/${id}.json` };
		}
		if (operation !== "cve" || !cveId(params?.id)) throw new Error("invalid NVD CVE request");
		return { url: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId(params.id))}` };
	},
};
