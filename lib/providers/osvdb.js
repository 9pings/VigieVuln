module.exports = {
	id: "osvdb", ttlMs: 12 * 3600 * 1000,
	build(type, params) {
		if (type !== "ecosystem-archive" || !/^[A-Za-z0-9_.+ -]+$/.test(params?.ecosystem || "")) throw new Error("invalid OSV archive request");
		return { url: `https://osv-vulnerabilities.storage.googleapis.com/${encodeURIComponent(params.ecosystem)}/all.zip` };
	},
};
