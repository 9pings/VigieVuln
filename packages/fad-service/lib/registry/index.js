/**
 * The registry layer of the service: what happens when a fad client asks for package
 * metadata through /v1/resource.
 *
 *   transform  the engine hook: a fresh registry answer is projected (lib/registry/project.js),
 *              its package summary written as an asset — PUBLIC only once the publication
 *              rule allows it — and the projection kept and served instead of the raw answer.
 *   demand     every request for a package counts one client (a truncated keyed hash of
 *              its token, never the token or a name); at K distinct clients, or when the
 *              package is seeded, it is published and its demand rows are deleted.
 *
 * A 404 from a registry is never projected, so a private package name never becomes an
 * asset, public or not.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const crypto = require("node:crypto");
const { project } = require("./project");
const { packageOfRequest, parseKey } = require("./purl");

const REGISTRY = {
	npm: { name: "npm registry", page: n => `https://www.npmjs.com/package/${n}` },
	pypi: { name: "PyPI", page: n => `https://pypi.org/project/${n}/` },
	maven: { name: "Maven Central", page: n => `https://central.sonatype.com/artifact/${n.replace(":", "/")}` },
	gem: { name: "RubyGems", page: n => `https://rubygems.org/gems/${n}` },
	composer: { name: "Packagist", page: n => `https://packagist.org/packages/${n}` },
	nuget: { name: "NuGet Gallery", page: n => `https://www.nuget.org/packages/${n}` },
	golang: { name: "Go module proxy", page: n => `https://pkg.go.dev/${n}` },
};

function packageAsset(pkg, published) {
	const reg = REGISTRY[pkg.type];
	const name = pkg.name || parseKey(pkg.key)?.name;
	return {
		type: "package", key: pkg.key, title: name, summary: pkg.description || null,
		aliases: [name, pkg.key, ...(pkg.type === "maven" ? name.split(":") : [])],
		data: { ...pkg, name },
		sources: [{ name: reg.name, licence: "Registry metadata only — no package file is stored", url: reg.page(name) }],
		published,
	};
}

/**
 * opts: { assets, threshold (K, default 5), salt (stable secret for the demand tags) }
 */
function createRegistryLayer({ assets, threshold = 5, salt }) {
	if (!salt) throw new Error("registry layer needs a salt for demand tags");
	const tagOf = principal => crypto.createHmac("sha256", salt).update(principal.hash).digest("hex").slice(0, 8);
	const publishable = key => { const d = assets.demandOf(key); return d.seeded || d.distinct >= threshold; };

	function upsertPackage(pkg) {
		if (pkg.type === "maven") {
			// The metadata gives the versions; keep what a POM already told us.
			const prev = assets.get("package", pkg.key, { includeUnpublished: true });
			if (prev) pkg = { ...prev.data, ...pkg, name: prev.data.name || pkg.name };
		}
		const published = assets.isPublished("package", pkg.key) || publishable(pkg.key);
		assets.upsert(packageAsset(pkg, published));
		if (published) assets.publish("package", pkg.key);
	}

	function upsertPom(pom) {
		assets.upsert({ type: "pom", key: `${pom.key}@${pom.version}`, title: pom.name || null, summary: null, data: pom, sources: [], published: false });
		const prev = assets.get("package", pom.key, { includeUnpublished: true });
		if (prev && (!prev.data.latest || prev.data.latest === pom.version)) {
			upsertPackage({ ...prev.data, key: pom.key, type: "maven", description: pom.description || prev.data.description,
				license: pom.licence || prev.data.license, homepage: pom.url || prev.data.homepage, repository: pom.scm || prev.data.repository,
				dependencies: pom.dependencies });
		}
	}

	/** Engine hook: a fresh upstream answer for `resource`. */
	function transform(resource, buffer) {
		if (!packageOfRequest(resource)) return null;
		const out = project(resource, buffer);
		try {
			if (out.pkg) upsertPackage(out.pkg);
			if (out.pom) upsertPom(out.pom);
		} catch { /* a page is a by-product: never fail the client's request for it */ }
		return out.body;
	}

	/**
	 * One answered /v1/resource request by `principal`; `seed` = an admin seeding it.
	 * Called AFTER the answer, and only for a package a public registry knows: a private
	 * name (404 upstream) never reaches this table.
	 */
	function recordDemand(payload, principal, { seed = false } = {}) {
		const key = packageOfRequest(payload);
		if (!key || !principal || !assets.get("package", key, { includeUnpublished: true })) return null;
		if (assets.isPublished("package", key)) return key;
		const d = assets.demand(key, seed ? "seed" : tagOf(principal));
		if (d.seeded || d.distinct >= threshold) assets.publish("package", key);
		return key;
	}

	return { transform, recordDemand, upsertPackage };
}

module.exports = { createRegistryLayer, packageAsset, REGISTRY };
