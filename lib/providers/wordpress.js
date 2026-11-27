module.exports = {
	id: "wordpress", ttlMs: 24 * 3600 * 1000,
	build(type, params) {
		if (type === "extension") {
			if (!["plugin","theme"].includes(params?.kind) || !/^[a-z0-9][a-z0-9._-]{0,199}$/.test(params.slug)) throw Error("invalid WordPress catalogue identity");
			const query = new URLSearchParams({action:params.kind+"_information","request[slug]":params.slug});
			return {url:`https://api.wordpress.org/${params.kind}s/info/1.2/?${query}`};
		}
		if (type !== "checksums" || !params?.version || typeof params.version !== "string") throw new Error("invalid WordPress checksums request");
		return { url: `https://api.wordpress.org/core/checksums/1.0/?version=${encodeURIComponent(params.version)}&locale=${encodeURIComponent(params.locale || "en_US")}` };
	},
};
