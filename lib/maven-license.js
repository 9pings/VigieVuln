/**
 * lib/maven-license.js — best-effort Maven license detection, network-free.
 *
 * A declaring POM only lists a dependency's coordinate, not its license — the
 * license lives in the dependency's OWN POM on Maven Central. transitive.js
 * already caches those POMs under ~/.fad-checker/poms-cache/. We read the cached
 * POMs (no network) and scrape the <licenses><license><name> block. Deps whose
 * POM was never cached simply yield no license (→ unknown in the policy view).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { POM_CACHE_DIR } = require("./transitive");

function cachedPomPath(g, a, v, dir) {
	const seg = x => String(x == null ? "" : x).replace(/[^A-Za-z0-9._+-]/g, "%");   // one path segment, always
	return path.join(dir, `${seg(g)}__${seg(a)}__${seg(v)}.pom`);
}

/** Pure: extract license names from a POM's <licenses> block. */
function licensesFromPomXml(xml) {
	if (!xml) return [];
	const block = xml.match(/<licenses>([\s\S]*?)<\/licenses>/i);
	if (!block) return [];
	const names = [];
	const re = /<name>\s*([^<]+?)\s*<\/name>/gi;
	let m;
	while ((m = re.exec(block[1]))) names.push(m[1].trim());
	return names.filter(Boolean);
}

/**
 * Collect license findings for every Maven dep with a cached POM.
 * opts: { cacheDir = POM_CACHE_DIR }
 * Returns [{ dep, licenses: [name…], source: "pom" }].
 */
function collectMavenLicenses(resolved, opts = {}) {
	const cacheDir = opts.cacheDir || POM_CACHE_DIR;
	const out = [];
	for (const dep of resolved.values()) {
		if (dep.ecosystem !== "maven" || !dep.version) continue;
		const p = cachedPomPath(dep.namespace || dep.groupId, dep.name || dep.artifactId, dep.version, cacheDir);
		let xml;
		xml = require('./maven-cache').read(p)?.value;
		if(!xml || xml==='__NOT_FOUND__')continue;
		const names = licensesFromPomXml(xml);
		if (names.length) out.push({ dep, licenses: names, source: "pom" });
	}
	return out;
}

module.exports = { collectMavenLicenses, licensesFromPomXml };
