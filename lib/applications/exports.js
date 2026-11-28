const crypto = require("node:crypto");
const path = require("node:path");
const { purlFor } = require("../inventory/purl");

function relativeLocation(file, srcRoot) {
	if (!file) return null;
	const rel = srcRoot && path.isAbsolute(file) ? path.relative(srcRoot, file) : file;
	return String(rel).split(path.sep).join("/");
}

function variantsFor(dep, srcRoot) {
	if (dep.ecosystem !== "composer" || !dep.occurrences?.length) {
		return [{ dep, location: null, ref: dep.provenance === "embedded" ? dep.coordKey : purlFor(dep) }];
	}
	return dep.occurrences.map(occurrence => {
		const variant = { ...dep, version: occurrence.version, scope: occurrence.scope,
			manifestPaths: [occurrence.manifestPath], occurrences: [occurrence] };
		const location = relativeLocation(occurrence.manifestPath, srcRoot);
		const hash = crypto.createHash("sha256").update(location || "").digest("hex").slice(0, 16);
		return { dep: variant, location, ref: `${purlFor(variant)}#fad-occ-${hash}` };
	});
}

function matchingVariants(match, variants, srcRoot) {
	const file = match.dep?.occurrences?.[0]?.manifestPath || match.dep?.manifestPaths?.[0];
	const location = relativeLocation(file, srcRoot);
	const sameVersion = variants.filter(v => String(v.dep.version) === String(match.dep?.version));
	if (!location || variants.every(v => !v.location)) return sameVersion;
	return sameVersion.filter(v => v.location === location);
}

module.exports = { variantsFor, matchingVariants };
