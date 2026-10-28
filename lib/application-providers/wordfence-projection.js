/** Explicit coverage contract shared by the Wordfence proxy and its client. */
const { indexProductionFeed } = require("./wordfence-v3");
const FORMAT = "wordfence-targeted-v1";
const SOURCE_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production";
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const keyOf = q => `${q.type}:${q.slug}`;

function queriesOf(queries, { min = 0, max = 10000 } = {}) {
	if (!Array.isArray(queries) || queries.length < min || queries.length > max)
		throw new Error("invalid Wordfence software query count");
	const unique = new Map();
	for (const q of queries) {
		if (!q || Object.keys(q).some(k => !["type", "slug"].includes(k)) ||
			!["core", "plugin", "theme"].includes(q.type) || typeof q.slug !== "string" ||
			q.slug.length > 200 || !/^[a-z0-9][a-z0-9._-]*$/.test(q.slug) || (q.type === "core" && q.slug !== "wordpress"))
			throw new Error("invalid Wordfence software identity");
		unique.set(keyOf(q), { type: q.type, slug: q.slug });
	}
	return [...unique.values()].sort((a, b) => keyOf(a).localeCompare(keyOf(b)));
}

function componentQueries(components) {
	return queriesOf(components.filter(c => c.visibility !== "private" && c.version &&
		(c.kind === "core" || ["verified", "user-declared"].includes(c.catalogueStatus)) &&
		["core", "plugin", "theme"].includes(c.kind) && (c.kind === "core" || c.slug))
		.map(c => ({ type: c.kind, slug: c.kind === "core" ? "wordpress" : c.slug.toLowerCase() })));
}

function indexProjection(snapshot) {
	if (snapshot?.format !== FORMAT || !snapshot._fadSnapshot || snapshot._fadSnapshot.completeness !== "targeted" ||
		typeof snapshot._fadSnapshot.stale !== "boolean" ||
		typeof snapshot._fadSnapshot.collectedAt !== "string" || !Number.isFinite(Date.parse(snapshot._fadSnapshot.collectedAt)))
		throw new Error("invalid Wordfence projection metadata");
	const queries = queriesOf(snapshot.queriedSoftware);
	if (queries.length !== snapshot.queriedSoftware.length) throw new Error("duplicate Wordfence coverage identity");
	const queried = new Set(queries.map(keyOf));
	const index = indexProductionFeed(snapshot.advisories);
	for (const key of index.keys()) if (!queried.has(key)) throw new Error("Wordfence response contains unrequested software");
	index.queriedSoftware = queried;
	index.sourceSnapshot = snapshot._fadSnapshot;
	return index;
}

function projectFeed(index, queries, fetchedAt, stale = false) {
	queries = queriesOf(queries);
	const advisories = {};
	for (const q of queries) {
		for (const { uuid, record, software } of index.get(keyOf(q)) || []) {
			if (!advisories[uuid]) {
				// Only fields consumed by the matcher; no unrelated software or bulk metadata.
				advisories[uuid] = Object.fromEntries(["id", "title", "cve", "cvss", "description", "published", "updated",
					"cwe", "references", "copyrights"].filter(k => record[k] !== undefined).map(k => [k, record[k]]));
				advisories[uuid].software = [];
			}
			advisories[uuid].software.push(software);
		}
	}
	return { format: FORMAT, queriedSoftware: queries, advisories,
		_fadSnapshot: { collectedAt: new Date(fetchedAt).toISOString(), completeness: "targeted", sourceUrl: SOURCE_URL, stale } };
}

/** Re-querying an identity replaces its old advisories, including removed advisories. */
function mergeProjections(previous, incoming) {
	indexProjection(incoming);
	if (!previous) return incoming;
	const old = indexProjection(previous), fresh = indexProjection(incoming);
	const retained = previous.queriedSoftware.filter(q => !fresh.queriedSoftware.has(keyOf(q)));
	if (!retained.length) return incoming;
	const combined = new Map(retained.map(q => [keyOf(q), old.get(keyOf(q)) || []]));
	for (const [key, entries] of fresh) combined.set(key, entries);
	return projectFeed(combined, [...retained, ...incoming.queriedSoftware],
		Math.min(Date.parse(previous._fadSnapshot.collectedAt), Date.parse(incoming._fadSnapshot.collectedAt)),
		previous._fadSnapshot.stale || incoming._fadSnapshot.stale);
}

module.exports = { FORMAT, SOURCE_URL, MAX_RESPONSE_BYTES, keyOf, queriesOf, componentQueries, indexProjection, projectFeed, mergeProjections };
