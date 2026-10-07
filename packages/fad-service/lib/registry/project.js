/**
 * Registry answers → what the service keeps (spec §5: metadata only).
 *
 * project(resource, buffer) → { body, pkg }:
 *   body  what is stored AND served to fad clients instead of the upstream answer, or null
 *         to keep it as is. A projection keeps the upstream JSON SHAPE and exactly the
 *         fields fad reads (lib/codecs/<eco>/registry.js) plus what a package page shows,
 *         so an existing fad client behind --proxy-cache sees no difference. npm's full
 *         packument (15 MB for typescript) becomes a few hundred KB.
 *   pkg   the package summary for its page and the search: { key, type, name, latest,
 *         latestDate, description, license, homepage, repository, deprecated, versions[],
 *         dependencies[] }, or null.
 *
 * Description, licence and deprecation texts are the registry's own words: evidence, kept
 * as written, escaped when shown.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { packageKey, packageOfRequest } = require("./purl");
const { fad } = require("../fad");

const MAX_VERSIONS = 10000;
const str = (v, n = 500) => (typeof v === "string" && v.trim() ? v.trim().slice(0, n) : null);
const url = v => { const s = typeof v === "string" ? v : v?.url; return /^https?:\/\//i.test(s || "") ? String(s).replace(/^git\+/, "").slice(0, 500) : null; };
const licenceOf = l => typeof l === "string" ? l : Array.isArray(l) ? l.map(x => typeof x === "string" ? x : x?.type).filter(Boolean).join(" OR ") : (l?.type || null);
const deps = (obj, scope) => Object.entries(obj && typeof obj === "object" ? obj : {}).slice(0, 300).map(([name, range]) => ({ name, range: String(range).slice(0, 100), scope }));

function npm(name, j) {
	const latest = j["dist-tags"]?.latest || null;
	const versions = {};
	for (const [v, m] of Object.entries(j.versions || {}).slice(-MAX_VERSIONS)) {
		versions[v] = { version: v,
			...(m?.deprecated ? { deprecated: String(m.deprecated).slice(0, 1000) } : {}),
			...(m?.license !== undefined ? { license: m.license } : {}), ...(m?.licenses !== undefined ? { licenses: m.licenses } : {}),
			...(m?.dependencies ? { dependencies: m.dependencies } : {}), ...(m?.peerDependencies ? { peerDependencies: m.peerDependencies } : {}),
			...(m?.optionalDependencies ? { optionalDependencies: m.optionalDependencies } : {}) };
	}
	const time = {};
	for (const [k, v] of Object.entries(j.time || {})) if (k === "created" || k === "modified" || versions[k]) time[k] = v;
	const body = { name: j.name || name, "dist-tags": j["dist-tags"] || {}, time, versions,
		...(j.license !== undefined ? { license: j.license } : {}), ...(j.licenses !== undefined ? { licenses: j.licenses } : {}),
		...(j.description ? { description: str(j.description, 2000) } : {}), ...(j.homepage ? { homepage: j.homepage } : {}),
		...(j.repository ? { repository: j.repository } : {}), _fadProjection: 1 };
	const lv = versions[latest] || {};
	return {
		body,
		pkg: { type: "npm", name: body.name, latest, latestDate: time[latest] || null, description: str(j.description, 2000),
			license: licenceOf(lv.license ?? lv.licenses ?? j.license ?? j.licenses), homepage: url(j.homepage), repository: url(j.repository),
			deprecated: lv.deprecated || null,
			versions: Object.keys(versions).reverse().map(v => ({ version: v, date: time[v] || null, ...(versions[v].deprecated ? { deprecated: true } : {}) })),
			dependencies: [...deps(lv.dependencies, "runtime"), ...deps(lv.peerDependencies, "peer"), ...deps(lv.optionalDependencies, "optional")] },
	};
}

function pypi(name, j) {
	const info = j.info || {};
	const releases = {};
	for (const [v, files] of Object.entries(j.releases || {}).slice(-MAX_VERSIONS)) {
		const list = Array.isArray(files) ? files : [];
		// One entry per release keeps fad's rule intact: yanked only when EVERY file is.
		releases[v] = list.length ? [{ yanked: list.every(f => f?.yanked), yanked_reason: list.find(f => f?.yanked_reason)?.yanked_reason || null,
			upload_time_iso_8601: list.map(f => f?.upload_time_iso_8601).filter(Boolean).sort()[0] || null }] : [];
	}
	const body = { info: { name: info.name || name, version: info.version || null, summary: str(info.summary, 1000), license: str(info.license, 300),
		classifiers: Array.isArray(info.classifiers) ? info.classifiers.slice(0, 100) : [], home_page: info.home_page || null,
		project_urls: info.project_urls || null, requires_dist: Array.isArray(info.requires_dist) ? info.requires_dist.slice(0, 300) : null },
		releases, _fadProjection: 1 };
	const date = v => releases[v]?.[0]?.upload_time_iso_8601 || null;
	const urls = info.project_urls || {};
	return {
		body,
		pkg: { type: "pypi", name: body.info.name, latest: info.version || null, latestDate: date(info.version), description: str(info.summary, 1000),
			license: str(info.license, 300) || (body.info.classifiers.find(c => c.startsWith("License ::"))?.split(" :: ").pop() || null),
			homepage: url(info.home_page) || url(urls.Homepage), repository: url(urls.Source) || url(urls.Repository),
			deprecated: body.info.classifiers.includes("Development Status :: 7 - Inactive") ? "Inactive" : null,
			versions: Object.keys(releases).reverse().map(v => ({ version: v, date: date(v), ...(releases[v][0]?.yanked ? { yanked: true } : {}) })),
			dependencies: (body.info.requires_dist || []).map(r => ({ name: String(r).split(/[\s;<>=!~[(]/)[0], range: String(r).slice(0, 120), scope: /extra\s*==/.test(r) ? "extra" : "runtime" })) },
	};
}

function gem(name, j) {
	return { body: null, pkg: { type: "gem", name: j.name || name, latest: j.version || null, latestDate: j.version_created_at || null,
		description: str(j.info, 2000), license: Array.isArray(j.licenses) ? j.licenses.join(" OR ") : null,
		homepage: url(j.homepage_uri), repository: url(j.source_code_uri), deprecated: j.yanked ? "yanked" : null,
		versions: j.version ? [{ version: j.version, date: j.version_created_at || null }] : [],
		dependencies: (j.dependencies?.runtime || []).slice(0, 300).map(d => ({ name: d.name, range: d.requirements, scope: "runtime" })) } };
}

function composer(name, j) {
	const list = j.packages?.[name] || j.package?.versions || {};
	const entries = Array.isArray(list) ? list : Object.values(list);
	const stable = entries.filter(e => e?.version && !/dev|alpha|beta|rc/i.test(e.version));
	const latest = stable[0] || entries[0] || {};
	return { body: null, pkg: { type: "composer", name, latest: latest.version || null, latestDate: latest.time || null,
		description: str(latest.description || j.package?.description, 2000), license: licenceOf(latest.license),
		homepage: url(latest.homepage), repository: url(latest.source?.url), deprecated: j.package?.abandoned ? `abandoned${typeof j.package.abandoned === "string" ? " → " + j.package.abandoned : ""}` : null,
		versions: entries.slice(0, MAX_VERSIONS).map(e => ({ version: e.version, date: e.time || null })),
		dependencies: deps(latest.require, "runtime") } };
}

function nuget(name, j) {
	const items = (j.items || []).flatMap(page => page.items || []).map(i => i.catalogEntry || {}).filter(e => e.version);
	const listed = items.filter(e => e.listed !== false);
	const latest = [...listed].reverse().find(e => !/-/.test(e.version)) || listed[listed.length - 1] || {};
	return { body: null, pkg: { type: "nuget", name: latest.id || name, latest: latest.version || null, latestDate: latest.published || null,
		description: str(latest.description, 2000), license: latest.licenseExpression || null, homepage: url(latest.projectUrl), repository: null,
		deprecated: latest.deprecation ? (latest.deprecation.message || (latest.deprecation.reasons || []).join(", ") || "deprecated") : null,
		versions: [...items].reverse().slice(0, MAX_VERSIONS).map(e => ({ version: e.version, date: e.published || null, ...(e.deprecation ? { deprecated: true } : {}) })),
		dependencies: (latest.dependencyGroups || []).flatMap(g => (g.dependencies || []).map(d => ({ name: d.id, range: d.range, scope: g.targetFramework || "runtime" }))).slice(0, 300) } };
}

function golang(name, j) {
	return { body: null, pkg: { type: "golang", name, latest: j.Version || null, latestDate: j.Time || null, description: null, license: null,
		homepage: null, repository: null, deprecated: null, versions: j.Version ? [{ version: j.Version, date: j.Time || null }] : [], dependencies: [] } };
}

/**
 * Maven: maven-metadata.xml → versions (newest first, Maven ordering) and the latest STABLE
 * one — fad's latestStableVersion: Maven's own <release> happily points at a beta.
 */
function mavenMetadata(text) {
	const { compareMavenVersions, latestStableVersion } = fad("maven-version");
	const all = [...new Set([...String(text).matchAll(/<version>\s*([^<\s]+)\s*<\/version>/g)].map(m => m[1]))];
	const tag = t => (new RegExp(`<${t}>\\s*([^<\\s]+)\\s*</${t}>`).exec(text) || [])[1] || null;
	return { versions: [...all].sort(compareMavenVersions), latest: latestStableVersion(all), release: tag("release"), lastUpdated: tag("lastUpdated") };
}
function pomSummary(text) {
	const s = String(text).replace(/<!--[\s\S]*?-->/g, "");
	const noParent = s.replace(/<parent>[\s\S]*?<\/parent>/, "");
	const top = t => (new RegExp(`<${t}>\\s*([\\s\\S]*?)\\s*</${t}>`).exec(noParent.replace(/<(dependencies|dependencyManagement|build|profiles|licenses|developers|scm|distributionManagement)>[\s\S]*?<\/\1>/g, "")) || [])[1] || null;
	const licences = [...(/<licenses>([\s\S]*?)<\/licenses>/.exec(s)?.[1] || "").matchAll(/<name>\s*([^<]+?)\s*<\/name>/g)].map(m => m[1]);
	const depsBlock = (/<dependencies>([\s\S]*?)<\/dependencies>/.exec(noParent.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/, "")) || [])[1] || "";
	const dependencies = [...depsBlock.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)].slice(0, 300).map(([, d]) => {
		const f = t => (new RegExp(`<${t}>\\s*([^<]+?)\\s*</${t}>`).exec(d) || [])[1] || null;
		return { name: `${f("groupId")}:${f("artifactId")}`, range: f("version"), scope: f("scope") || "compile", optional: f("optional") === "true" };
	});
	return { description: str(top("description"), 2000), name: str(top("name"), 300), url: url(top("url")), licence: licences.join(" OR ") || null,
		scm: url((/<scm>[\s\S]*?<url>\s*([^<]+?)\s*<\/url>/.exec(s) || [])[1]), dependencies };
}

/** resource = { provider, type, params } as sent to /v1/resource. */
function project(resource, buffer) {
	const key = packageOfRequest(resource);
	if (!key) return { body: null, pkg: null };
	const name = resource.params?.name || resource.params?.module;
	try {
		if (resource.provider === "maven") {
			const text = buffer.toString("utf8");
			const parts = String(resource.params.path).split("/");
			if (parts[parts.length - 1] === "maven-metadata.xml") {
				const m = mavenMetadata(text);
				return { body: null, pkg: { key, type: "maven", latest: m.latest, versions: [...m.versions].reverse().map(v => ({ version: v })), lastUpdated: m.lastUpdated } };
			}
			return { body: null, pom: { key, version: parts[parts.length - 2], ...pomSummary(text) } };
		}
		const j = JSON.parse(buffer.toString("utf8"));
		const out = { npm: npm, pypi: pypi, ruby: gem, packagist: composer, nuget: nuget, go: golang }[resource.provider]?.(name, j);
		if (!out) return { body: null, pkg: null };
		return { body: out.body ? Buffer.from(JSON.stringify(out.body)) : null, pkg: { key, ...out.pkg } };
	} catch { return { body: null, pkg: null }; }
}

module.exports = { project, mavenMetadata, pomSummary, packageKey };
