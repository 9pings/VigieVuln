'use strict';
/**
 * The Ruby advisory lane. rubysec/ruby-advisory-db records advisories that GitHub's
 * reviewed database, and therefore OSV, does not carry for RubyGems: project security
 * advisories that were never reviewed, and older OSVDB entries. Measured on Mastodon
 * v4.0.2: 27 advisories (net-ssh, puma, doorkeeper…) found by `bundler-audit` and not by
 * the OSV lane.
 *
 * An advisory names the versions that are NOT vulnerable (`patched_versions`,
 * `unaffected_versions`), as RubyGems requirements: a version is vulnerable when it
 * satisfies none of them. That is the rule `bundler-audit` applies.
 */
const zlib = require('node:zlib');
const { compareRubyVersions } = require('../../codecs/ruby/version');
const { severityFromScore } = require('../../findings/severity');

const NAMESPACE = 'rubysec', DB_KEY = 'advisory-db', FORMAT = 1;
const TTL_MS = 4 * 3600 * 1000;
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024, MAX_ENTRY_BYTES = 512 * 1024, MAX_ADVISORIES = 100000;
const GEM = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;

// ── RubyGems requirements ──────────────────────────────────────────────────────────
const CLAUSE = /^(=|!=|>=|<=|~>|>|<)?\s*([0-9][0-9A-Za-z.-]*)$/;
function parseRequirement(text) {
	const clauses = String(text ?? '').split(',').map(part => CLAUSE.exec(part.trim()));
	return clauses.length && clauses.every(Boolean) ? clauses.map(m => ({ op: m[1] || '=', version: m[2] })) : null;
}
// Gem::Version#bump: "2.3.18" → "2.4", "5.2" → "6"; a prerelease tail is dropped first.
function bump(version) {
	const release = [];
	for (const segment of version.replace(/-/g, '.pre.').split('.')) { if (!/^\d+$/.test(segment)) break; release.push(BigInt(segment)); }
	if (!release.length) return null;
	if (release.length > 1) release.pop();
	release[release.length - 1] += 1n;
	return release.join('.');
}
/** true / false, or null when the version or the requirement cannot be ordered. */
function satisfies(version, requirement) {
	const clauses = parseRequirement(requirement);
	if (!clauses) return null;
	for (const { op, version: bound } of clauses) {
		const c = compareRubyVersions(version, bound);
		if (c === null) return null;
		let ok;
		if (op === '~>') { const upper = bump(bound), below = upper && compareRubyVersions(version, upper); if (below == null) return null; ok = c >= 0 && below < 0; }
		else ok = op === '=' ? c === 0 : op === '!=' ? c !== 0 : op === '>' ? c > 0 : op === '<' ? c < 0 : op === '>=' ? c >= 0 : c <= 0;
		if (!ok) return false;
	}
	return true;
}
/** Vulnerable (true), not vulnerable (false) or undecidable (null) for one advisory. */
function vulnerable(advisory, version) {
	let unknown = false;
	for (const requirement of [...(advisory.patched || []), ...(advisory.unaffected || [])]) {
		const verdict = satisfies(version, requirement);
		if (verdict === true) return false;
		if (verdict === null) unknown = true;
	}
	return unknown ? null : true;
}
// The lowest patched release above the installed version.
function fixVersion(advisory, version) {
	let best = null;
	for (const requirement of advisory.patched || []) for (const { op, version: bound } of parseRequirement(requirement) || []) {
		if (!['>=', '~>', '='].includes(op) || !(compareRubyVersions(bound, version) > 0) || vulnerable(advisory, bound) !== false) continue;
		if (best === null || compareRubyVersions(bound, best) < 0) best = bound;
	}
	return best;
}

// ── Archive → advisories by gem ────────────────────────────────────────────────────
const text = (value, max) => typeof value === 'string' && value.trim() ? value.trim().slice(0, max) : null;
const list = value => (Array.isArray(value) ? value : value == null ? [] : [value]).filter(item => typeof item === 'string' || typeof item === 'number').map(String);
function normalise(doc, file) {
	if (!doc || typeof doc !== 'object' || Array.isArray(doc) || typeof doc.gem !== 'string' || !GEM.test(doc.gem)) return null;
	const cve = /^\d{4}-\d{4,}$/.test(String(doc.cve ?? '')) ? `CVE-${doc.cve}` : null;
	const ghsa = /^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i.test(String(doc.ghsa ?? '')) ? `GHSA-${String(doc.ghsa).toLowerCase()}` : null;
	const osvdb = /^\d+$/.test(String(doc.osvdb ?? '')) ? `OSVDB-${doc.osvdb}` : null;
	const ids = [cve, ghsa, osvdb].filter(Boolean);
	if (!ids.length) return null;
	const score = [doc.cvss_v4, doc.cvss_v3, doc.cvss_v2].map(Number).find(n => Number.isFinite(n) && n >= 0 && n <= 10);
	const date = doc.date instanceof Date ? doc.date.toISOString().slice(0, 10) : /^\d{4}-\d{2}-\d{2}/.test(String(doc.date ?? '')) ? String(doc.date).slice(0, 10) : null;
	const related = doc.related && typeof doc.related === 'object' ? doc.related : {};
	return { gem: doc.gem.toLowerCase(), id: ids[0], aliases: ids.slice(1), file,
		title: text(doc.title, 500), description: text(doc.description, 20000), url: /^https?:\/\//i.test(String(doc.url ?? '')) ? String(doc.url).slice(0, 2000) : null,
		date, score: score ?? null, patched: list(doc.patched_versions), unaffected: list(doc.unaffected_versions),
		related: list(related.url).filter(u => /^https?:\/\//i.test(u)).slice(0, 20) };
}
/** Parse the repository archive (gzip tar). → { gems: { name: [advisory] }, count } */
async function parseArchive(bytes) {
	if (!bytes || bytes.length > MAX_ARCHIVE_BYTES) throw Error('Ruby advisory database archive is missing or exceeds its size limit');
	const yaml = require('js-yaml'), extract = require('tar-stream').extract();
	const gems = Object.create(null); let count = 0, rejected = 0;
	const done = new Promise((resolve, reject) => {
		extract.on('entry', (header, stream, next) => {
			const match = header.type === 'file' && /^[^/]+\/gems\/([^/]+)\/([^/]+\.yml)$/.exec(header.name);
			const chunks = []; let size = 0;
			stream.on('data', chunk => { size += chunk.length; if (match && size <= MAX_ENTRY_BYTES) chunks.push(chunk); });
			stream.on('end', () => {
				if (match && size <= MAX_ENTRY_BYTES) {
					let advisory = null;
					try { advisory = normalise(yaml.load(Buffer.concat(chunks).toString('utf8')), `gems/${match[1]}/${match[2]}`); } catch { /* counted below */ }
					// A file is filed under its gem's directory: anything else is not an advisory for it.
					if (advisory && advisory.gem === match[1].toLowerCase() && count < MAX_ADVISORIES) { (gems[advisory.gem] ||= []).push(advisory); count++; }
					else rejected++;
				}
				next();
			});
			stream.on('error', reject);
		});
		extract.on('finish', resolve); extract.on('error', reject);
	});
	extract.end(zlib.gunzipSync(bytes, { maxOutputLength: 8 * MAX_ARCHIVE_BYTES }));
	await done;
	if (!count) throw Error('Ruby advisory database archive holds no advisory');
	return { gems, count, rejected };
}

// ── Lane ───────────────────────────────────────────────────────────────────────────
function toMatch(dep, advisory) {
	const refs = [advisory.url, ...advisory.related].filter(Boolean).map(url => ({ type: 'ADVISORY', url }));
	return { dep, source: 'rubysec', confidence: 'exact', cve: {
		id: advisory.id, sourceAdvisoryId: advisory.file, aliases: advisory.aliases,
		ghsa: [advisory.id, ...advisory.aliases].find(id => id.startsWith('GHSA-')) || null,
		severity: severityFromScore(advisory.score, 'UNKNOWN'), score: advisory.score,
		summary: advisory.title || '', description: advisory.description || advisory.title || '',
		fixVersion: fixVersion(advisory, dep.version), published: advisory.date, osvRefs: refs } };
}
/** Pure: evaluate the database against the resolved Ruby dependencies. */
function collectRubyMatches(resolvedDeps, gems, onConsulted) {
	const matches = [];
	for (const dep of resolvedDeps ? resolvedDeps.values() : []) {
		if (dep.ecosystem !== 'ruby' || !dep.name) continue;
		const advisories = gems[String(dep.name).toLowerCase()] || [];
		for (const version of dep.versions?.length ? dep.versions : [dep.version]) {
			if (compareRubyVersions(version, version) !== 0) continue;
			let decided = true;
			for (const advisory of advisories) {
				const verdict = vulnerable(advisory, version);
				if (verdict === null) decided = false;
				else if (verdict) matches.push(toMatch({ ...dep, version }, advisory));
			}
			// The database is complete: a gem it does not list has no advisory in it.
			if (decided) onConsulted?.(dep, 'rubysec', version);
		}
	}
	return matches;
}
/**
 * Match the resolved Ruby dependencies against the Ruby advisory database.
 * Online the archive is refreshed when older than 4 hours; `offline` reads the cache only.
 * → matches (source "rubysec"). Throws when no database is available.
 */
async function queryRubyAdvisories(resolvedDeps, opts = {}) {
	const { offline, fetcher, cacheDir, onConsulted, onWarning, forceUpdate } = opts;
	if (![...(resolvedDeps ? resolvedDeps.values() : [])].some(dep => dep.ecosystem === 'ruby')) return [];
	const repository = require('../../cache/repository').createCacheRepository(cacheDir || require('../../cache/directory').getCacheDir());
	let saved = repository.get(NAMESPACE, DB_KEY)?.value;
	if (saved?.format !== FORMAT) saved = null;
	const fresh = saved && Date.now() - saved.fetchedAt < TTL_MS && saved.fetchedAt <= Date.now();
	if (!offline && (!fresh || forceUpdate)) {
		try {
			const response = await require('..').getResource('rubysec', 'advisory-db', {}, { fetcher, noStore: true, streaming: true, headers: { 'User-Agent': 'vigievuln-rubysec' } });
			if (!response.ok) throw Error(`Ruby advisory database HTTP ${response.status}`);
			const parsed = await parseArchive(Buffer.from(await response.arrayBuffer()));
			saved = { format: FORMAT, fetchedAt: Date.now(), count: parsed.count, gems: parsed.gems };
			repository.put(NAMESPACE, DB_KEY, saved, { fetchedAt: saved.fetchedAt });
		} catch (error) {
			if (!saved) throw error;
			onWarning?.({ type: 'source-stale', source: 'rubysec', message: `Ruby advisory database refresh failed (${error.message}); the copy of ${new Date(saved.fetchedAt).toISOString().slice(0, 10)} was used.` });
		}
	}
	if (!saved) throw Error(offline ? 'no cached Ruby advisory database' : 'Ruby advisory database unavailable');
	return collectRubyMatches(resolvedDeps, saved.gems, onConsulted);
}

module.exports = { queryRubyAdvisories, collectRubyMatches, parseArchive, satisfies, vulnerable, fixVersion, bump, NAMESPACE };
