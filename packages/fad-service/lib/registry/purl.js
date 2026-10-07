/**
 * Package identity in the service: a package-URL without version (pkg:<type>/<name>),
 * from a /v1/resource request or from an OSV `affected.package`. Names are normalised the
 * way each registry does, so one package has one key whoever asked for it.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const OSV_TO_TYPE = { Maven: "maven", npm: "npm", PyPI: "pypi", Packagist: "composer", NuGet: "nuget", Go: "golang", RubyGems: "gem" };
const TYPE_TO_OSV = Object.fromEntries(Object.entries(OSV_TO_TYPE).map(([k, v]) => [v, k]));
const TYPES = new Set(Object.values(OSV_TO_TYPE));

/** PEP 503 normalisation (PyPI is case- and separator-insensitive). */
const pep503 = n => String(n).toLowerCase().replace(/[-_.]+/g, "-");

/** (purl type, registry name) → "pkg:type/name"; null when the name is not well-formed. */
function packageKey(type, name) {
	if (!TYPES.has(type) || typeof name !== "string" || !name || name.length > 300 || /\s/.test(name)) return null;
	switch (type) {
		case "maven": {
			const m = /^([^:/]+)[:/]([^:/]+)$/.exec(name);
			return m ? `pkg:maven/${m[1]}/${m[2]}` : null;
		}
		case "npm": return /^(@[^/]+\/)?[^/@]+$/.test(name) ? `pkg:npm/${name.toLowerCase()}` : null;
		case "pypi": return `pkg:pypi/${pep503(name)}`;
		case "composer": return /^[^/]+\/[^/]+$/.test(name) ? `pkg:composer/${name.toLowerCase()}` : null;
		case "nuget": return /^[A-Za-z0-9_.-]+$/.test(name) ? `pkg:nuget/${name.toLowerCase()}` : null;
		case "gem": return /^[A-Za-z0-9_.-]+$/.test(name) ? `pkg:gem/${name}` : null;
		case "golang": return /^[a-z0-9.-]+\.[a-z]{2,}(\/[^\s]+)?$/i.test(name) ? `pkg:golang/${name}` : null;
	}
	return null;
}

/** "pkg:npm/@types/node" → { type: "npm", name: "@types/node" }. */
function parseKey(key) {
	const m = /^pkg:([a-z]+)\/(.+)$/.exec(String(key || ""));
	if (!m || !TYPES.has(m[1])) return null;
	return { type: m[1], name: m[1] === "maven" ? m[2].replace("/", ":") : m[2] };
}

/** The package a /v1/resource request is about (registry metadata only), or null. */
function packageOfRequest(payload) {
	const p = payload?.params || {};
	switch (`${payload?.provider}/${payload?.type}`) {
		case "npm/package": return packageKey("npm", p.name);
		case "pypi/package": return packageKey("pypi", p.name);
		case "ruby/gem": return packageKey("gem", p.name);
		case "nuget/registration": return packageKey("nuget", p.name);
		case "packagist/package": case "packagist/p2": return packageKey("composer", p.name);
		case "go/module-latest": return packageKey("golang", p.module);
		case "maven/artifact": {
			const m = /^(.+)\/([^/]+)\/(?:maven-metadata\.xml|[^/]+\/[^/]+\.pom)$/.exec(String(p.path || ""));
			if (!m) return null;
			// metadata: g/a/maven-metadata.xml · pom: g/a/v/a-v.pom
			const parts = String(p.path).split("/");
			const isMeta = parts[parts.length - 1] === "maven-metadata.xml";
			const a = isMeta ? parts[parts.length - 2] : parts[parts.length - 3];
			const g = parts.slice(0, isMeta ? -2 : -3).join(".");
			return g && a ? packageKey("maven", `${g}:${a}`) : null;
		}
	}
	return null;
}

/** An OSV `affected.package` → package key. */
function packageOfOsv(pkg) {
	const type = OSV_TO_TYPE[pkg?.ecosystem];
	return type ? packageKey(type, pkg.name) : null;
}

module.exports = { packageKey, parseKey, packageOfRequest, packageOfOsv, pep503, OSV_TO_TYPE, TYPE_TO_OSV };
