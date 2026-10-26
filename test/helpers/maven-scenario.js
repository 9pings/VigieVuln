/**
 * Build a Maven scenario on disk + an in-memory Maven Central, and run fad's real Maven
 * pipeline over it (collectResolvedDeps → lib/maven-reactor → settleManagedOnly), wired
 * exactly as vigievuln.js does. Zero network.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const core = require("../../lib/core");
const { collectResolvedDeps, settleManagedOnly } = require("../../lib/cve-match");
const { resolveReactor } = require("../../lib/maven-reactor");

const MC = "https://repo1.maven.org/maven2";
const G = "scratch.test";

function depXml(d) {
	let s = `<dependency><groupId>${d.g || G}</groupId><artifactId>${d.a}</artifactId>`;
	if (d.v != null) s += `<version>${d.v}</version>`;
	if (d.scope) s += `<scope>${d.scope}</scope>`;
	if (d.type) s += `<type>${d.type}</type>`;
	if (d.optional) s += `<optional>true</optional>`;
	if (d.exclusions) s += `<exclusions>${d.exclusions.map(e => `<exclusion><groupId>${e.g || G}</groupId><artifactId>${e.a}</artifactId></exclusion>`).join("")}</exclusions>`;
	return s + `</dependency>`;
}
function pom(p) {
	let s = `<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>`;
	if (p.parent) s += `<parent><groupId>${p.parent.g || G}</groupId><artifactId>${p.parent.a}</artifactId><version>${p.parent.v}</version>${p.parent.relativePath != null ? `<relativePath>${p.parent.relativePath}</relativePath>` : ""}</parent>`;
	if (p.g) s += `<groupId>${p.g}</groupId>`;
	s += `<artifactId>${p.a}</artifactId>`;
	if (p.v) s += `<version>${p.v}</version>`;
	if (p.packaging) s += `<packaging>${p.packaging}</packaging>`;
	if (p.modules) s += `<modules>${p.modules.map(m => `<module>${m}</module>`).join("")}</modules>`;
	if (p.props) s += `<properties>${Object.entries(p.props).map(([k, v]) => `<${k}>${v}</${k}>`).join("")}</properties>`;
	if (p.depMgmt) s += `<dependencyManagement><dependencies>${p.depMgmt.map(depXml).join("")}</dependencies></dependencyManagement>`;
	if (p.deps) s += `<dependencies>${p.deps.map(depXml).join("")}</dependencies>`;
	if (p.profiles) s += `<profiles>${p.profiles.map(pr => `<profile><id>${pr.id}</id>${pr.activeByDefault ? `<activation><activeByDefault>true</activeByDefault></activation>` : ""}${pr.props ? `<properties>${Object.entries(pr.props).map(([k, v]) => `<${k}>${v}</${k}>`).join("")}</properties>` : ""}${pr.deps ? `<dependencies>${pr.deps.map(depXml).join("")}</dependencies>` : ""}</profile>`).join("")}</profiles>`;
	return s + `</project>`;
}
/** Upstream POMs (and optional maven-metadata version lists) → URL → body. */
function upstream(specs, metadata = {}) {
	const R = {};
	for (const p of specs) {
		const g = p.g || p.parent?.g || G, v = p.v || p.parent.v;
		R[`${MC}/${g.replace(/\./g, "/")}/${p.a}/${v}/${p.a}-${v}.pom`] = pom({ g, ...p });
	}
	for (const [ga, versions] of Object.entries(metadata)) {
		const [g, a] = ga.split(":");
		R[`${MC}/${g.replace(/\./g, "/")}/${a}/maven-metadata.xml`] = `<metadata><versioning><versions>${versions.map(v => `<version>${v}</version>`).join("")}</versions></versioning></metadata>`;
	}
	return R;
}
function writeLocal(files) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-scn-"));
	for (const [rel, spec] of Object.entries(files)) {
		const f = path.join(dir, rel);
		fs.mkdirSync(path.dirname(f), { recursive: true });
		fs.writeFileSync(f, pom(spec));
	}
	return dir;
}
async function run(dir, R, { delays = {}, includeTestDeps = true, transitive = true } = {}) {
	const fetcher = async url => {
		if (delays[url]) await new Promise(r => setTimeout(r, delays[url]));
		return R[url] ? { ok: true, status: 200, text: async () => R[url], json: async () => JSON.parse(R[url]) } : { ok: false, status: 404, text: async () => "" };
	};
	const store = core.newMetadataStore();
	for (const p of core.findPomFiles(dir)) await core.parsePom(p, store);
	const propsByPom = {};
	for (const p of Object.keys(store.byPath)) await core.getAllInheritedProps(p, store, propsByPom);
	const resolved = collectResolvedDeps(store, propsByPom, { ignoreTest: !includeTestDeps });
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-scn-cache-"));
	await resolveReactor(resolved, store, propsByPom, { fetcher, cacheDir, includeTestDeps, transitive });
	settleManagedOnly(resolved);
	return resolved;
}
/** "X" → sorted versions of scratch.test:X, or [] when absent. */
const versionsOf = (resolved, a, g = G) => [...(resolved.get(`${g}:${a}`)?.versions || [])].sort();

module.exports = { G, MC, pom, upstream, writeLocal, run, versionsOf };
