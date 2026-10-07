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
 * as written, escaped when shown — but BOUNDED: every string, list and map kept here comes
 * from a registry the service does not control (a 30 MB `license` must not become a 30 MB
 * asset row, search alias or page). Caps sit well above any legitimate value.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { packageKey, packageOfRequest } = require("./purl");
const { fad } = require("../fad");

const MAX_VERSIONS = 10000;
const MAX_DEPS = 1000;          // per dependency map in a served projection
const NAME_MAX = 214;           // npm's own limit; above every other registry's
const VERSION_MAX = 256;
const DATE_MAX = 40;
const str = (v, n = 500) => (typeof v === "string" && v.trim() ? v.trim().slice(0, n) : null);
const clip = (v, n) => (v == null ? null : String(v).slice(0, n));
const url = v => { const s = typeof v === "string" ? v : v?.url; return /^https?:\/\//i.test(s || "") ? String(s).replace(/^git\+/, "").slice(0, 500) : null; };
const licenceOf = l => clip(typeof l === "string" ? l : Array.isArray(l) ? l.slice(0, 20).map(x => typeof x === "string" ? x : x?.type).filter(Boolean).join(" OR ") : (l?.type || null), 300) || null;
/** A free-form upstream value kept in its shape (license objects, repository, project_urls), clamped. */
function bounded(v, { text = 500, items = 20, depth = 3 } = {}) {
	if (typeof v === "string") return v.slice(0, text);
	if (v === null || typeof v !== "object") return typeof v === "number" || typeof v === "boolean" ? v : null;
	if (depth <= 0) return null;
	const next = { text, items, depth: depth - 1 };
	if (Array.isArray(v)) return v.slice(0, items).map(x => bounded(x, next));
	return Object.fromEntries(Object.entries(v).slice(0, items).map(([k, x]) => [k.slice(0, 100), bounded(x, next)]));
}
/** A { name: range } map in the upstream shape: bounded count, name and range. */
const depMap = obj => Object.fromEntries(Object.entries(obj && typeof obj === "object" && !Array.isArray(obj) ? obj : {})
	.filter(([name]) => name.length <= NAME_MAX).slice(0, MAX_DEPS).map(([name, range]) => [name, clip(range, VERSION_MAX)]));
const deps = (obj, scope) => Object.entries(depMap(obj)).slice(0, 300).map(([name, range]) => ({ name, range: clip(range, 100), scope }));
const okVersion = v => typeof v === "string" && v.length > 0 && v.length <= VERSION_MAX;

function npm(name, j) {
	const latest = okVersion(j["dist-tags"]?.latest) ? j["dist-tags"].latest : null;
	const versions = {};
	for (const [v, m] of Object.entries(j.versions || {}).filter(([v]) => okVersion(v)).slice(-MAX_VERSIONS)) {
		versions[v] = { version: v,
			...(m?.deprecated ? { deprecated: String(m.deprecated).slice(0, 1000) } : {}),
			...(m?.license !== undefined ? { license: bounded(m.license, { text: 300 }) } : {}), ...(m?.licenses !== undefined ? { licenses: bounded(m.licenses, { text: 300 }) } : {}),
			...(m?.dependencies ? { dependencies: depMap(m.dependencies) } : {}), ...(m?.peerDependencies ? { peerDependencies: depMap(m.peerDependencies) } : {}),
			...(m?.optionalDependencies ? { optionalDependencies: depMap(m.optionalDependencies) } : {}) };
	}
	const time = {};
	for (const [k, v] of Object.entries(j.time || {})) if (k === "created" || k === "modified" || versions[k]) time[k] = clip(v, DATE_MAX);
	const distTags = Object.fromEntries(Object.entries(j["dist-tags"] && typeof j["dist-tags"] === "object" ? j["dist-tags"] : {})
		.slice(0, 50).filter(([, v]) => okVersion(v)).map(([k, v]) => [k.slice(0, 100), v]));
	const body = { name: clip(j.name || name, NAME_MAX), "dist-tags": distTags, time, versions,
		...(j.license !== undefined ? { license: bounded(j.license, { text: 300 }) } : {}), ...(j.licenses !== undefined ? { licenses: bounded(j.licenses, { text: 300 }) } : {}),
		...(j.description ? { description: str(j.description, 2000) } : {}), ...(j.homepage ? { homepage: clip(j.homepage, 500) } : {}),
		...(j.repository ? { repository: bounded(j.repository) } : {}), _fadProjection: 1 };
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
	for (const [v, files] of Object.entries(j.releases || {}).filter(([v]) => okVersion(v)).slice(-MAX_VERSIONS)) {
		const list = Array.isArray(files) ? files : [];
		// One entry per release keeps fad's rule intact: yanked only when EVERY file is.
		releases[v] = list.length ? [{ yanked: list.every(f => f?.yanked), yanked_reason: clip(list.find(f => f?.yanked_reason)?.yanked_reason, 1000),
			upload_time_iso_8601: clip(list.map(f => f?.upload_time_iso_8601).filter(Boolean).sort()[0], DATE_MAX) }] : [];
	}
	const body = { info: { name: clip(info.name || name, NAME_MAX), version: okVersion(info.version) ? info.version : null, summary: str(info.summary, 1000), license: str(info.license, 300),
		classifiers: Array.isArray(info.classifiers) ? info.classifiers.slice(0, 100).map(c => clip(c, 200)) : [], home_page: clip(info.home_page, 500),
		project_urls: info.project_urls && typeof info.project_urls === "object" ? bounded(info.project_urls, { items: 30, depth: 1 }) : null,
		requires_dist: Array.isArray(info.requires_dist) ? info.requires_dist.slice(0, 300).map(r => clip(r, 300)) : null },
		releases, _fadProjection: 1 };
	const date = v => releases[v]?.[0]?.upload_time_iso_8601 || null;
	const urls = body.info.project_urls || {};
	return {
		body,
		pkg: { type: "pypi", name: body.info.name, latest: body.info.version, latestDate: date(info.version), description: str(info.summary, 1000),
			license: str(info.license, 300) || (body.info.classifiers.find(c => c.startsWith("License ::"))?.split(" :: ").pop() || null),
			homepage: url(info.home_page) || url(urls.Homepage), repository: url(urls.Source) || url(urls.Repository),
			deprecated: body.info.classifiers.includes("Development Status :: 7 - Inactive") ? "Inactive" : null,
			versions: Object.keys(releases).reverse().map(v => ({ version: v, date: date(v), ...(releases[v][0]?.yanked ? { yanked: true } : {}) })),
			dependencies: (body.info.requires_dist || []).map(r => ({ name: clip(String(r).split(/[\s;<>=!~[(]/)[0], NAME_MAX), range: String(r).slice(0, 120), scope: /extra\s*==/.test(r) ? "extra" : "runtime" })) },
	};
}

function gem(name, j) {
	const latest = okVersion(j.version) ? j.version : null, date = clip(j.version_created_at, DATE_MAX);
	return { body: null, pkg: { type: "gem", name: clip(j.name || name, NAME_MAX), latest, latestDate: date,
		description: str(j.info, 2000), license: Array.isArray(j.licenses) ? licenceOf(j.licenses) : null,
		homepage: url(j.homepage_uri), repository: url(j.source_code_uri), deprecated: j.yanked ? "yanked" : null,
		versions: latest ? [{ version: latest, date }] : [],
		dependencies: (Array.isArray(j.dependencies?.runtime) ? j.dependencies.runtime : []).slice(0, 300)
			.map(d => ({ name: clip(d?.name, NAME_MAX), range: clip(d?.requirements, 100), scope: "runtime" })) } };
}

function composer(name, j) {
	const list = j.packages?.[name] || j.package?.versions || {};
	const entries = Array.isArray(list) ? list : Object.values(list);
	const stable = entries.filter(e => e?.version && !/dev|alpha|beta|rc/i.test(e.version));
	const latest = stable[0] || entries[0] || {};
	return { body: null, pkg: { type: "composer", name, latest: okVersion(latest.version) ? latest.version : null, latestDate: clip(latest.time, DATE_MAX),
		description: str(latest.description || j.package?.description, 2000), license: licenceOf(latest.license),
		homepage: url(latest.homepage), repository: url(latest.source?.url), deprecated: j.package?.abandoned ? `abandoned${typeof j.package.abandoned === "string" ? " → " + clip(j.package.abandoned, NAME_MAX) : ""}` : null,
		versions: entries.filter(e => okVersion(e?.version)).slice(0, MAX_VERSIONS).map(e => ({ version: e.version, date: clip(e.time, DATE_MAX) })),
		dependencies: deps(latest.require, "runtime") } };
}

function nuget(name, j) {
	const items = (j.items || []).flatMap(page => page.items || []).map(i => i.catalogEntry || {}).filter(e => okVersion(e.version)).slice(-MAX_VERSIONS);
	const listed = items.filter(e => e.listed !== false);
	const latest = [...listed].reverse().find(e => !/-/.test(e.version)) || listed[listed.length - 1] || {};
	return { body: null, pkg: { type: "nuget", name: clip(latest.id || name, NAME_MAX), latest: latest.version || null, latestDate: clip(latest.published, DATE_MAX),
		description: str(latest.description, 2000), license: clip(latest.licenseExpression, 300), homepage: url(latest.projectUrl), repository: null,
		deprecated: latest.deprecation ? clip(latest.deprecation.message || (Array.isArray(latest.deprecation.reasons) ? latest.deprecation.reasons.slice(0, 10).join(", ") : "") || "deprecated", 1000) : null,
		versions: [...items].reverse().map(e => ({ version: e.version, date: clip(e.published, DATE_MAX), ...(e.deprecation ? { deprecated: true } : {}) })),
		dependencies: (Array.isArray(latest.dependencyGroups) ? latest.dependencyGroups : []).slice(0, 50).flatMap(g => (Array.isArray(g?.dependencies) ? g.dependencies : []).slice(0, 300)
			.map(d => ({ name: clip(d?.id, NAME_MAX), range: clip(d?.range, 100), scope: clip(g.targetFramework || "runtime", 100) }))).slice(0, 300) } };
}

function golang(name, j) {
	const latest = okVersion(j.Version) ? j.Version : null, date = clip(j.Time, DATE_MAX);
	return { body: null, pkg: { type: "golang", name, latest, latestDate: date, description: null, license: null,
		homepage: null, repository: null, deprecated: null, versions: latest ? [{ version: latest, date }] : [], dependencies: [] } };
}

/**
 * Maven: maven-metadata.xml → versions (newest first, Maven ordering) and the latest STABLE
 * one — fad's latestStableVersion: Maven's own <release> happily points at a beta.
 */
function mavenMetadata(text) {
	const { compareMavenVersions, latestStableVersion } = fad("maven-version");
	const all = [...new Set([...String(text).matchAll(/<version>\s*([^<\s]+)\s*<\/version>/g)].map(m => m[1]))].filter(okVersion).slice(-MAX_VERSIONS);
	const tag = t => clip((new RegExp(`<${t}>\\s*([^<\\s]+)\\s*</${t}>`).exec(text) || [])[1], VERSION_MAX);
	return { versions: [...all].sort(compareMavenVersions), latest: latestStableVersion(all), release: tag("release"), lastUpdated: tag("lastUpdated") };
}
function pomSummary(text) {
	const s = String(text).replace(/<!--[\s\S]*?-->/g, "");
	const noParent = s.replace(/<parent>[\s\S]*?<\/parent>/, "");
	const top = t => (new RegExp(`<${t}>\\s*([\\s\\S]*?)\\s*</${t}>`).exec(noParent.replace(/<(dependencies|dependencyManagement|build|profiles|licenses|developers|scm|distributionManagement)>[\s\S]*?<\/\1>/g, "")) || [])[1] || null;
	const licences = [...(/<licenses>([\s\S]*?)<\/licenses>/.exec(s)?.[1] || "").matchAll(/<name>\s*([^<]+?)\s*<\/name>/g)].map(m => m[1]);
	const depsBlock = (/<dependencies>([\s\S]*?)<\/dependencies>/.exec(noParent.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/, "")) || [])[1] || "";
	const dependencies = [...depsBlock.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)].slice(0, 300).map(([, d]) => {
		const f = t => clip((new RegExp(`<${t}>\\s*([^<]+?)\\s*</${t}>`).exec(d) || [])[1], 300);
		return { name: `${f("groupId")}:${f("artifactId")}`, range: f("version"), scope: f("scope") || "compile", optional: f("optional") === "true" };
	});
	return { description: str(top("description"), 2000), name: str(top("name"), 300), url: url(top("url")), licence: licenceOf(licences),
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
