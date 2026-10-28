/** Static matcher for a locally supplied Wordfence v3 production-feed snapshot. */
const crypto = require("node:crypto");

const SPECIAL_RANK = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, rc: 3, "#": 4, pl: 5, p: 5 };
function parseVersion(value) {
	const raw = String(value || "").trim().replace(/^v(?=\d)/i, "")
		.replace(/[_+\-]/g, ".")
		.replace(/(\d)([a-z#])/gi, "$1.$2").replace(/([a-z#])(\d)/gi, "$1.$2");
	if (!raw || !/^\d[\da-z.#]*$/i.test(raw)) return null;
	const parts = raw.toLowerCase().split(".");
	if (parts.some(part => !part || (!/^\d+$/.test(part) && !(part in SPECIAL_RANK)))) return null;
	return parts;
}

function compareWordPressVersions(a, b) {
	const left = parseVersion(a), right = parseVersion(b);
	if (!left || !right) return null;
	for (let i = 0; i < Math.max(left.length, right.length); i++) {
		const a = left[i], b = right[i];
		if (a === undefined || b === undefined) {
			const remaining = a === undefined ? b : a;
			const verdict = /^\d+$/.test(remaining) ? -1 : Math.sign(SPECIAL_RANK["#"] - SPECIAL_RANK[remaining]);
			if (verdict) return a === undefined ? verdict : -verdict;
			continue;
		}
		const aNum = /^\d+$/.test(a), bNum = /^\d+$/.test(b);
		if (aNum && bNum) {
			const aa = BigInt(a), bb = BigInt(b);
			if (aa !== bb) return aa > bb ? 1 : -1;
		} else {
			const ar = aNum ? SPECIAL_RANK["#"] : SPECIAL_RANK[a];
			const br = bNum ? SPECIAL_RANK["#"] : SPECIAL_RANK[b];
			if (ar !== br) return Math.sign(ar - br);
		}
	}
	return 0;
}

function rangeVerdict(version, range) {
	if (!range || typeof range !== "object" || typeof range.from_version !== "string" ||
		typeof range.to_version !== "string" || typeof range.from_inclusive !== "boolean" ||
		typeof range.to_inclusive !== "boolean") return "indeterminate";
	if (range.from_version !== "*") {
		const lower = compareWordPressVersions(version, range.from_version);
		if (lower == null) return "indeterminate";
		if (lower < 0 || (lower === 0 && !range.from_inclusive)) return "no-match";
	}
	if (range.to_version !== "*") {
		const upper = compareWordPressVersions(version, range.to_version);
		if (upper == null) return "indeterminate";
		if (upper > 0 || (upper === 0 && !range.to_inclusive)) return "no-match";
	}
	return "affected";
}

function affectedVersion(version, ranges) {
	if (!version || !ranges || typeof ranges !== "object" || Array.isArray(ranges) || !Object.keys(ranges).length)
		return "indeterminate";
	let uncertain = false;
	for (const range of Object.values(ranges)) {
		const verdict = rangeVerdict(version, range);
		if (verdict === "affected") return "affected";
		if (verdict === "indeterminate") uncertain = true;
	}
	return uncertain ? "indeterminate" : "no-match";
}

function indexProductionFeed(feed) {
	if (!feed || typeof feed !== "object" || Array.isArray(feed)) throw new Error("Wordfence v3 feed must be a UUID-keyed object");
	const index = new Map();
	for (const [uuid, record] of Object.entries(feed)) {
		if (uuid === "_fadSnapshot") {
			// Operator-added collection metadata (used by --max-advisory-age); never an advisory record.
			if (!record || typeof record !== "object" || Array.isArray(record))
				throw new Error("invalid Wordfence v3 _fadSnapshot metadata");
			continue;
		}
		if (!/^[a-f0-9-]{36}$/i.test(uuid) || !record || record.id !== uuid || !Array.isArray(record.software))
			throw new Error("invalid Wordfence v3 record identity or software list");
		if (record.references != null && (!Array.isArray(record.references) || record.references.some(v => typeof v !== "string")))
			throw new Error("invalid Wordfence v3 references");
		for (const software of record.software) {
			if (!software || !["core", "plugin", "theme"].includes(software.type) || typeof software.slug !== "string" ||
				!software.affected_versions || typeof software.affected_versions !== "object")
				throw new Error("invalid Wordfence v3 software entry");
			if (software.patched_versions != null && (!Array.isArray(software.patched_versions) || software.patched_versions.some(v => typeof v !== "string")))
				throw new Error("invalid Wordfence v3 patched versions");
			const key = `${software.type}:${software.slug.toLowerCase()}`;
			if (!index.has(key)) index.set(key, []);
			index.get(key).push({ uuid, record, software });
		}
	}
	return index;
}

function indexFeed(feed) {
	if (feed && typeof feed === "object" && ("format" in feed || "queriedSoftware" in feed || "advisories" in feed))
		return require("./wordfence-projection").indexProjection(feed);
	return indexProductionFeed(feed);
}

function assessWordfenceFeed(feed, components = []) {
	const index = feed instanceof Map ? feed : indexFeed(feed);
	const matches = [], coverage = [], diagnostics = [];
	for (const component of components) {
		const appId = component.applicationId;
		const sourceId = component.visibility === "private" ? "internal-advisories" : "wordfence-v3";
		const base = { applicationId: appId, occurrenceId: component.id, capability: "advisories", sourceId,
			expected: 1, executed: 0 };
		if (component.visibility === "private") {
			coverage.push({ ...base, execution: "not-run", result: "indeterminate", diagnostic: "CMS_PRIVATE_COMPONENT" });
			continue;
		}
		if (!component.version || (component.kind !== "core" && !["verified", "user-declared"].includes(component.catalogueStatus))) {
			coverage.push({ ...base, execution: "not-run", result: "indeterminate",
				diagnostic: !component.version ? "CMS_VERSION_UNKNOWN" : "CMS_IDENTITY_UNVERIFIED" });
			continue;
		}
		const slug = component.kind === "core" ? "wordpress" : component.slug;
		if (!slug || !["core", "plugin", "theme"].includes(component.kind)) {
			coverage.push({ ...base, execution: "not-run", result: "indeterminate", diagnostic: "CMS_IDENTITY_UNVERIFIED" });
			continue;
		}
		const key = `${component.kind}:${slug.toLowerCase()}`;
		if (index.queriedSoftware && !index.queriedSoftware.has(key)) {
			coverage.push({ ...base, execution: "not-run", result: "indeterminate", diagnostic: "CMS_PROVIDER_NOT_QUERIED" });
			continue;
		}
		const entries = index.get(key) || [];
		let uncertain = false, affected = false;
		for (const { uuid, record, software } of entries) {
			const verdict = affectedVersion(component.version, software.affected_versions);
			if (verdict === "indeterminate") { uncertain = true; continue; }
			if (verdict !== "affected") continue;
			affected = true;
			const cveId = /^CVE-\d{4}-\d{4,}$/i.test(String(record.cve || "")) ? record.cve : null;
			const score = Number.isFinite(record.cvss?.score) ? record.cvss.score : null;
			const severity = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(String(record.cvss?.rating || "").toUpperCase())
				? record.cvss.rating.toUpperCase() : "UNKNOWN";
			const fixes = (software.patched_versions || []).filter(v => compareWordPressVersions(v, component.version) > 0);
			const dep = { ecosystem: "wordpress", groupId: `wordpress-${component.kind}`, artifactId: slug,
				name: slug, namespace: `wordpress/${component.kind}`, version: component.version,
				coordKey: `wordpress:${component.kind}:${slug}`, scope: "prod", isDev: false, provenance: "application",
				manifestPaths: (component.evidence || []).map(e => e.path).filter(Boolean).slice(0, 1) };
			const findingId = `fad-advisory-${crypto.createHash("sha256").update(`${uuid}\0${component.id}`).digest("hex").slice(0, 24)}`;
			matches.push({ findingId, applicationIds: [appId], ownerComponentIds: [component.id],
				applicationRelation: "direct", attributionStatus: "confirmed", dependencyPaths: [],
				dep, source: "wordfence-v3", confidence: component.kind === "core" ? "verified" :
					component.catalogueStatus === "user-declared" ? "user-declared" : "verified", cve: {
					id: cveId || `WF-${uuid}`, aliases: [uuid, ...(cveId ? [cveId] : [])],
					severity, score, cvssVector: record.cvss?.vector || null, cvssVersion: record.cvss?.vector?.split("/")[0] || null,
					description: record.description || record.title || "", title: record.title || null,
					published: record.published || null, modified: record.updated || null,
					cwes: record.cwe?.id ? [`CWE-${record.cwe.id}`] : [],
					fixVersion: fixes[0] || null,
					osvRefs: (record.references || []).filter(u => /^https?:\/\//i.test(u)).map(url => ({ url, type: "WEB" })),
					copyrightNotice: record.copyrights?.defiant?.notice || null,
				}, advisoryId: uuid });
		}
		const stale = index.sourceSnapshot?.stale === true;
		coverage.push({ ...base, executed: 1, execution: uncertain || stale ? "partial" : "completed",
			result: uncertain || stale ? "indeterminate" : affected ? "affected" : "no-match",
			...(stale ? { diagnostic: "CMS_ADVISORY_STALE" } : uncertain ? { diagnostic: "CMS_VERSION_UNCOMPARABLE" } : {}) });
		if (uncertain) diagnostics.push({ code: "CMS_VERSION_UNCOMPARABLE", applicationId: appId, componentId: component.id,
			message: `Wordfence version range cannot be compared for ${component.kind} ${component.name || slug}` });
	}
	return { matches, coverage, diagnostics };
}

module.exports = { compareWordPressVersions, affectedVersion, indexFeed, indexProductionFeed, assessWordfenceFeed };
