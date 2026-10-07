/**
 * Seed: warm and PUBLISH a list of packages (spec §8). Each package goes through exactly
 * the path a client request takes — an in-process server on loopback, the engine, the
 * projection, the publication rule — with an admin token marked as seeding, so a seeded
 * package is public at once. Paced: a few requests in flight, never a registry crawl.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("node:fs");
const { fad } = require("../fad");

/** One spec line ("lodash", "org.slf4j:slf4j-api", "github.com/gin-gonic/gin") → payloads. */
function payloadsFor(type, spec) {
	const s = String(spec).trim();
	if (!s || s.startsWith("#")) return [];
	switch (type) {
		case "npm": return [{ provider: "npm", type: "package", params: { name: s } }];
		case "pypi": return [{ provider: "pypi", type: "package", params: { name: s } }];
		case "gem": return [{ provider: "ruby", type: "gem", params: { name: s } }];
		case "composer": return [{ provider: "packagist", type: "package", params: { name: s } }];
		case "nuget": return [{ provider: "nuget", type: "registration", params: { name: s.toLowerCase() } }];
		case "golang": return [{ provider: "go", type: "module-latest", params: { module: s } }];
		case "maven": {
			const m = /^([^:\s]+):([^:\s]+)$/.exec(s);
			return m ? [{ provider: "maven", type: "artifact", params: { path: `${m[1].replace(/\./g, "/")}/${m[2]}/maven-metadata.xml` } }] : [];
		}
	}
	return [];
}

/** The specs to seed: --list file (one per line) or --popular (fad's curated list). */
function readSpecs(type, { list, popular }) {
	if (list) return fs.readFileSync(list, "utf8").split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#"));
	if (popular) {
		const data = require(require("node:path").join(__dirname, "..", "..", "..", "..", "data", "popular-packages.json"));
		return data[type] || [];
	}
	throw new Error("seed needs --list <file> or --popular");
}

/**
 * opts: { baseUrl, token, type, specs, concurrency, delayMs, assets, log }
 * → { ok, missing, failed }
 */
async function seed({ baseUrl, token, type, specs, concurrency = 4, delayMs = 100, assets, log = () => {} }) {
	const queue = specs.flatMap(s => payloadsFor(type, s));
	let ok = 0, missing = 0, failed = 0, next = 0;
	const post = payload => fetch(`${baseUrl}/v1/resource`, { method: "POST",
		headers: { authorization: `Bearer ${token}`, "x-fad-seed": "1", "content-type": "application/json" }, body: JSON.stringify(payload) });
	const worker = async () => {
		while (next < queue.length) {
			const payload = queue[next++];
			try {
				const r = await post(payload);
				await r.arrayBuffer();
				if (r.status === 200) {
					ok++;
					// Maven: the metadata named the latest version — fetch its POM too.
					if (payload.provider === "maven" && payload.params.path.endsWith("maven-metadata.xml")) {
						const { packageOfRequest } = require("./purl");
						const pkg = await assets.get("package", packageOfRequest(payload), { includeUnpublished: true });
						const v = pkg?.data?.latest;
						if (v) {
							const base = payload.params.path.replace(/maven-metadata\.xml$/, "");
							const a = base.split("/").filter(Boolean).pop();
							const p = await post({ provider: "maven", type: "artifact", params: { path: `${base}${v}/${a}-${v}.pom` } });
							await p.arrayBuffer();
						}
					}
				} else if (r.status === 404) { missing++; log(`not found: ${JSON.stringify(payload.params)}`); }
				else { failed++; log(`HTTP ${r.status}: ${JSON.stringify(payload.params)}`); }
			} catch (e) { failed++; log(`error: ${e.message}`); }
			if (delayMs) await new Promise(ok => setTimeout(ok, delayMs));
		}
	};
	await Promise.all(Array.from({ length: Math.max(1, concurrency) }, worker));
	return { ok, missing, failed, total: queue.length };
}

module.exports = { seed, payloadsFor, readSpecs };
