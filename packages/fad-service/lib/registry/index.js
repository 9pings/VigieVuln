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
 * opts: { assets, threshold (K, default 5), salt (stable secret for the demand tags),
 *         memoEntries (default 50000) }
 */
function createRegistryLayer({ assets, threshold = 5, salt, memoEntries = 50000 }) {
	if (!salt) throw new Error("registry layer needs a salt for demand tags");
	const tagOf = principal => crypto.createHmac("sha256", salt).update(principal.hash).digest("hex").slice(0, 8);
	const publishable = async key => { const d = await assets.demandOf(key); return d.seeded || d.distinct >= threshold; };

	// recordDemand runs after EVERY answered package request: what it already wrote is
	// remembered here so a repeat costs no SQL. Bounded LRUs, in memory only, and filled
	// only for packages a public registry knows (the asset check comes first) — the same
	// names a public page shows, never a private one. Idempotent writes make a forgotten
	// entry harmless: it is just written again.
	const lru = () => {
		const m = new Map();
		return {
			has(k) { if (!m.has(k)) return false; m.delete(k); m.set(k, 1); return true; },
			add(k) { m.delete(k); m.set(k, 1); while (m.size > memoEntries) m.delete(m.keys().next().value); },
			get size() { return m.size; },
		};
	};
	const recorded = lru(), publishedKeys = lru();

	async function upsertPackage(pkg) {
		if (pkg.type === "maven") {
			// The metadata gives the versions; keep what a POM already told us.
			const prev = await assets.get("package", pkg.key, { includeUnpublished: true });
			if (prev) pkg = { ...prev.data, ...pkg, name: prev.data.name || pkg.name };
		}
		const published = (await assets.isPublished("package", pkg.key)) || (await publishable(pkg.key));
		await assets.upsert(packageAsset(pkg, published));
		if (published) await assets.publish("package", pkg.key);
	}

	async function upsertPom(pom) {
		await assets.upsert({ type: "pom", key: `${pom.key}@${pom.version}`, title: pom.name || null, summary: null, data: pom, sources: [], published: false });
		const prev = await assets.get("package", pom.key, { includeUnpublished: true });
		if (prev && (!prev.data.latest || prev.data.latest === pom.version)) {
			await upsertPackage({ ...prev.data, key: pom.key, type: "maven", description: pom.description || prev.data.description,
				license: pom.licence || prev.data.license, homepage: pom.url || prev.data.homepage, repository: pom.scm || prev.data.repository,
				dependencies: pom.dependencies });
		}
	}

	/** Engine hook: a fresh upstream answer for `resource`. */
	async function transform(resource, buffer) {
		if (!packageOfRequest(resource)) return null;
		const out = project(resource, buffer);
		try {
			if (out.pkg) await upsertPackage(out.pkg);
			if (out.pom) await upsertPom(out.pom);
		} catch { /* a page is a by-product: never fail the client's request for it */ }
		return out.body;
	}

	/**
	 * One answered /v1/resource request by `principal`; `seed` = an admin seeding it.
	 * Called AFTER the answer, and only for a package a public registry knows: a private
	 * name (404 upstream) never reaches this table.
	 */
	async function recordDemand(payload, principal, { seed = false } = {}) {
		const key = packageOfRequest(payload);
		if (!key || !principal) return null;
		const tag = seed ? "seed" : tagOf(principal);
		if (publishedKeys.has(key) || recorded.has(`${key}\0${tag}`)) return key;
		if (!(await assets.get("package", key, { includeUnpublished: true }))) return null;
		if (await assets.isPublished("package", key)) { publishedKeys.add(key); return key; }
		const d = await assets.demand(key, tag);
		if (d.seeded || d.distinct >= threshold) { await assets.publish("package", key); publishedKeys.add(key); }
		else recorded.add(`${key}\0${tag}`);
		return key;
	}

	return { transform, recordDemand, upsertPackage, memo: () => ({ recorded: recorded.size, published: publishedKeys.size }) };
}

module.exports = { createRegistryLayer, packageAsset, REGISTRY };
