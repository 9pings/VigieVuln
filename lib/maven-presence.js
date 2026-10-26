/**
 * Maven presence is tri-state: found, confirmed absent, or unknown.
 * Old boolean false entries did not distinguish outages from 404s. Never trust
 * them, even after an archive merge. Evidence belongs to each entry, not the
 * file metadata (which can come from a different side of that merge).
 */
const crypto = require("node:crypto");
const core = require("./core");
const { existsInAny } = require("./maven-repo");
const { isAbsentStatus } = require("./private-deps");

const MAX_AGE_MS = 7 * 24 * 3600 * 1000;
const ABSENCE_EVIDENCE = "all-repositories-404-or-410/1";

function repositoryKey(repos) {
	// Hash the scope rather than exporting registry URLs or credentials in the cache.
	const scope = (repos || []).map(r => [r.url, r.auth || "", r.token || ""]);
	scope.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
	return crypto.createHash("sha256").update(JSON.stringify(scope)).digest("hex");
}

function confirmedAbsence(entry) {
	return entry?.found === false && entry.evidence === ABSENCE_EVIDENCE
		&& /^[a-f0-9]{64}$/.test(entry.repositories)
		&& Number.isFinite(entry.checkedAt) && entry.checkedAt > 0;
}

/** Drop legacy negatives without dropping known positive cache hits. */
function discardUnverifiedEntries(cache) {
	let changed = false;
	if (!cache.entries || typeof cache.entries !== "object" || Array.isArray(cache.entries)) {
		cache.entries = {};
		return true;
	}
	for (const [key, entry] of Object.entries(cache.entries)) {
		if (entry === true || confirmedAbsence(entry)) continue;
		delete cache.entries[key];
		changed = true;
	}
	return changed;
}

async function checkMavenLibExist(groupId, artifactId, repos, cache, opts = {}) {
	const g = core.coord(groupId), a = core.coord(artifactId);
	if (!g || !a) return null;
	const key = `${g}:${a}`;
	const scope = opts.configuredRepos || repos;
	const repositories = repositoryKey(scope);
	const now = opts.now ?? Date.now();
	const entry = cache?.entries?.[key];
	if (entry === true) return true;
	if (confirmedAbsence(entry) && entry.repositories === repositories
		&& (opts.offline || (now >= entry.checkedAt && now - entry.checkedAt < MAX_AGE_MS))) return false;
	if (cache?.entries) delete cache.entries[key];
	if (opts.offline) return null;

	const statuses = new Map();
	try {
		const hit = await existsInAny(repos, `${g.replace(/\./g, "/")}/${a}/maven-metadata.xml`, {
			userAgent: "vigievuln-existence",
			...(opts.fetcher ? { fetcher: opts.fetcher } : {}),
			...(opts.health ? { health: opts.health } : {}),
			...(opts.timeoutMs != null ? { timeoutMs: opts.timeoutMs } : {}),
			onMiss(repo, reason) {
				const status = /^HTTP (\d{3})$/.exec(reason);
				statuses.set(repo.url, status ? Number(status[1]) : null);
			},
		});
		if (hit) {
			if (cache?.entries) cache.entries[key] = true;
			return true;
		}
		// A skipped/unreachable repository (including a disabled mirror) is unknown.
		// Checking only the preflight's reachable subset would manufacture absences.
		if (!scope?.length || !scope.every(repo => isAbsentStatus(statuses.get(repo.url)))) return null;
		if (cache?.entries) cache.entries[key] = {
			found: false, evidence: ABSENCE_EVIDENCE, repositories, checkedAt: now,
		};
		return false;
	} catch {
		return null;
	}
}

module.exports = { MAX_AGE_MS, discardUnverifiedEntries, checkMavenLibExist };
