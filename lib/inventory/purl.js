/**
 * lib/inventory/purl.js — build Package URL (purl) strings from a depRecord.
 *
 * purl spec: pkg:<type>/<namespace>/<name>@<version>?qualifiers#subpath
 * We only emit type/namespace/name@version — enough for CycloneDX `bom-ref`
 * and CSAF `product_identification_helper.purl`.
 *
 * Pure (no I/O). Shared by lib/reports/sbom-export.js and lib/reports/csaf-export.js.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

// purl type per ecosystem. Maven keeps the dotted groupId as a single namespace
// segment (not slash-separated); npm/composer carry a namespace; pypi/nuget don't.
const TYPE = {
	maven: "maven",
	npm: "npm",
	composer: "composer",
	pypi: "pypi",
	nuget: "nuget",
	go: "golang",
	ruby: "gem",
	wordpress: "generic",
};

// Per the purl spec, each namespace segment and the name are percent-encoded,
// but the dots inside a Maven groupId and the separators are preserved by
// encodeURIComponent (it leaves "." "-" "_" "~" alone), so it is the right tool.
function enc(s) {
	return encodeURIComponent(String(s));
}

// PEP 503 normalisation for PyPI names (purl mandates the canonical form).
function normalizePypi(name) {
	return String(name).toLowerCase().replace(/[-_.]+/g, "-");
}

/**
 * Build a purl for a depRecord. Returns null when the dep lacks a usable
 * ecosystem/name. Version is omitted when absent.
 */
function purlFor(dep) {
	if (!dep || typeof dep !== "object") return null;
	const eco = dep.ecosystem || dep.ecosystemType;
	const type = eco === "system" && /^[a-z][a-z0-9.+-]*$/.test(dep.packageType || "") ? dep.packageType : TYPE[eco];
	if (!type) return null;

	const rawName = dep.name || dep.artifactId;
	if (!rawName) return null;
	let namespace = dep.namespace || dep.groupId || "";
	let name = rawName;

	if (eco === "npm" && !namespace && name.startsWith("@") && name.includes("/")) {
		// Scoped package: "@scope/pkg" → namespace "@scope", name "pkg".
		const slash = name.indexOf("/");
		namespace = name.slice(0, slash);
		name = name.slice(slash + 1);
	} else if (eco === "pypi") {
		name = normalizePypi(name);
		namespace = "";
	} else if (eco === "nuget") {
		namespace = "";
	} else if (eco === "go" && !namespace && name.includes("/")) {
		// Go module path: namespace = everything up to the last "/", name = last segment.
		const slash = name.lastIndexOf("/");
		namespace = name.slice(0, slash);
		name = name.slice(slash + 1);
	}

	// Namespace may itself be slash-separated (Go module paths); encode each
	// segment but keep the separators.
	const nsPart = namespace ? `${String(namespace).split("/").map(enc).join("/")}/` : "";
	const verPart = dep.version ? `@${enc(dep.version)}` : "";
	let qualifiers = "";
	if (eco === "system") {
		const values = {};
		if (dep.architecture) values.arch = dep.architecture;
		if (dep.distribution?.id && dep.distribution?.versionId) values.distro = `${dep.distribution.id}-${dep.distribution.versionId}`;
		const pairs = Object.entries(values).sort(([a],[b]) => a.localeCompare(b)).map(([k,v]) => `${k}=${enc(v)}`);
		if (pairs.length) qualifiers = `?${pairs.join("&")}`;
	}
	return `pkg:${type}/${nsPart}${enc(name)}${verPart}${qualifiers}`;
}

module.exports = { purlFor };
