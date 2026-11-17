const { encodePath } = require("./common");
module.exports = {
	id: "go", ttlMs: 24 * 3600 * 1000,
	build(operation, params) {
		// An escaped module path (proxy protocol: upper case as "!x"): no query, fragment or
		// percent-escape can reach the URL, and every segment is encoded on top.
		if (!['module-latest','module-info'].includes(operation) || typeof params?.module !== "string" || !/^[A-Za-z0-9.!_~+-]+(\/[A-Za-z0-9.!_~+-]+)*$/.test(params.module)
			|| params.module.split("/").some(s => s === "." || s === "..")) throw new Error("invalid Go module request");
		if(operation==='module-info') {const version=params.version;if(typeof version!=='string'||!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$/.test(version))throw new Error('invalid Go module version');const escaped=version.replace(/[A-Z]/g,c=>'!'+c.toLowerCase());return {url:`https://proxy.golang.org/${encodePath(params.module)}/@v/${encodeURIComponent(escaped)}.info`};}
		return { url: `https://proxy.golang.org/${encodePath(params.module)}/@latest` };
	},
};
