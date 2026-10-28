const { encodePath } = require("./common");
module.exports = {
	id: "github", ttlMs: 24 * 3600 * 1000,
	build(type, params) {
		if (type === "publisher-advisories" && /^[^/\s]+\/[^/\s]+$/.test(params?.repo || "")) {
			const page = Number(params.page || 1), perPage = Number(params.perPage || 100);
			if (!Number.isSafeInteger(page) || page < 1 || !Number.isSafeInteger(perPage) || perPage < 1 || perPage > 100)
				throw new Error("invalid GitHub advisory page");
			return { url: `https://api.github.com/repos/${encodePath(params.repo)}/security-advisories?per_page=${perPage}${page > 1 ? `&page=${page}` : ""}` };
		}
		if (type === "cve-maven") return { url: "https://api.github.com/repos/CVEProject/cvelistV5" };
		if (type === "cve-release") return { url: "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest" };
		if (type === "cve-archive" && /^[A-Za-z0-9._-]+$/.test(params?.tag || "") &&
			/^[A-Za-z0-9._-]+\.zip$/i.test(params?.name || ""))
			return { url: `https://github.com/CVEProject/cvelistV5/releases/download/${encodeURIComponent(params.tag)}/${encodeURIComponent(params.name)}` };
		throw new Error("invalid GitHub request");
	},
};
