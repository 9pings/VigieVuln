/**
 * lib/merge-sources.js — merge two match arrays into one, deduped per physical finding.
 *
 * Extracted from vigievuln.js so the merge contract is unit-testable: it is the seam
 * where every CVE source (CVEProject index, OSV.dev, OSV local DB, NVD CPE ranges,
 * Packagist advisories) meets every other.
 *
 * The primary key is (coordKey:version | cve.id). The same ADVISORY can arrive under
 * different primary ids though: OSV prefers a CVE alias (CVE-2026-86428) while the
 * Packagist audit record for it may carry no `cve` field at all and only its GHSA
 * remoteId (GHSA-8rr7-cvq3-gmfh) — measured on league/commonmark 2.4.2 in the
 * symfony-demo corpus, where a naive key-only merge emitted the same advisory twice.
 * So the merge is ALIAS-AWARE and SYMMETRIC: a finding carries its aliases and ghsa, and
 * two findings on the same coord+version merge when ANY id of one equals ANY id of the
 * other, whichever side arrived first (test/merge-sources-alias.test.js).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
function mergeBySource(existing, additions) {
	// coordKey keeps embedded-binary findings distinct from a same-g:a:v declared dep
	// (see cve-match dedup). Falls back to g:a for any match lacking a coordKey.
	const coordOf = m => m.dep.coordKey || (m.dep.groupId + ":" + m.dep.artifactId);
	const keyOf = (m, id) => `${coordOf(m)}:${m.dep.version}|${id}`;
	const primary = m => keyOf(m, m.cve.id);
	// Every id a finding answers to: its primary id, its aliases, and its GHSA.
	const idsOf = m => [...new Set([m.cve.id, ...(m.cve.aliases || []), m.cve.ghsa].filter(Boolean))];

	const byKey = new Map();        // slot key → merged record
	const aliasIndex = new Map();   // keyOf(m, id) → slot key, for every id the record answers to
	// The slot key is the record's FIRST primary key and never moves, even when a merge
	// promotes its displayed id (GHSA → CVE below) — so the index points at the slot,
	// not at primary(rec), which may no longer be a byKey key.
	const register = (m, slot) => {
		for (const id of idsOf(m)) if (!aliasIndex.has(keyOf(m, id))) aliasIndex.set(keyOf(m, id), slot);
	};
	// Symmetric lookup: ANY id of the incoming record against ANY id of a registered one.
	// Looking up only the incoming PRIMARY id missed the case where the registered record
	// knew the advisory by its GHSA alone (Packagist: no `cve` field) and the incoming one
	// is CVE-keyed with that GHSA in its aliases — the same advisory emitted twice.
	// The primary id is tried first so an exact-key match always wins over an alias one.
	const findSlot = m => {
		for (const id of idsOf(m)) {
			const k = keyOf(m, id);
			if (byKey.has(k)) return k;
			if (aliasIndex.has(k)) return aliasIndex.get(k);
		}
		return null;
	};
	const isCve = id => /^CVE-/i.test(String(id || ""));

	for (const m of existing || []) {
		const rec = { ...m, source: m.source || "fad" };
		// `existing` is normally the output of a previous merge, but two of its records
		// can still be one advisory (e.g. both came from one lane's alias pair) — fold
		// them the same way as additions rather than overwriting by key.
		const slot = findSlot(rec);
		if (slot) { mergeInto(slot, rec); continue; }
		byKey.set(primary(rec), rec);
		register(rec, primary(rec));
	}
	function mergeInto(targetKey, m) {
		const prev = byKey.get(targetKey);
		// the EXISTING finding keeps its primary id: OSV's CVE preference must not be
		// overridden by a source that keyed the same advisory by GHSA. The one exception
		// is that same preference applied the other way: an existing GHSA-keyed record
		// (Packagist) absorbing a CVE-keyed one takes the CVE, which is what NVD/EPSS/KEV
		// enrichment and the reader key on.
		const id = (!isCve(prev.cve.id) && isCve(m.cve.id)) ? m.cve.id : prev.cve.id;
		// The union is over source TOKENS, not source strings: an existing
		// "osv+packagist" record that absorbs another "packagist" constat must not
		// render as "osv+packagist+packagist".
		const sources = [...new Set([...String(prev.source || "").split("+"),
			...String(m.source || "").split("+")].filter(Boolean))].sort();
		const merged = {
			...prev,
			source: sources.length > 1 ? sources.join("+") : sources[0],
			cve: {
				...prev.cve,
				...m.cve,
				id,
				// an advisory's identity is the UNION of its ids — dropping the
				// previous aliases on merge would unlink the alias index. Both primary
				// ids join it too, so the one not displayed stays an alias.
				aliases: [...new Set([...(prev.cve.aliases || []), ...(m.cve.aliases || []),
					prev.cve.id, m.cve.id].filter(Boolean))].filter(a => a !== id),
				ghsa: prev.cve.ghsa || m.cve.ghsa || null,
				// the fix on the dep's own branch: two sources may state it differently
				// (fixed 5.3.41 vs last affected 5.3.40) — keep the one an upgrade must meet.
				...((prev.cve.branchFix || m.cve.branchFix) ? { branchFix: require("./maven-version").stricterBranchFix(prev.cve.branchFix, m.cve.branchFix) } : {}),
				// keep highest non-null score
				score: Math.max(prev.cve.score ?? 0, m.cve.score ?? 0) || prev.cve.score || m.cve.score,
				// prefer non-UNKNOWN severity
				severity: (prev.cve.severity && prev.cve.severity !== "UNKNOWN") ? prev.cve.severity : m.cve.severity,
				// prefer the longer description
				description: ((prev.cve.description || "").length > (m.cve.description || "").length) ? prev.cve.description : m.cve.description,
			},
		};
		byKey.set(targetKey, merged);
		register(merged, targetKey);
	}
	for (const m of additions || []) {
		const slot = findSlot(m);
		if (slot) { mergeInto(slot, m); continue; }
		const rec = { ...m, source: m.source || "osv" };
		byKey.set(primary(m), rec);
		register(rec, primary(m));
	}
	const merged = [...byKey.values()];
	const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0, UNKNOWN: 0 };
	merged.sort((a, b) => {
		const sa = rank[(a.cve.severity || "UNKNOWN").toUpperCase()] || 0;
		const sb = rank[(b.cve.severity || "UNKNOWN").toUpperCase()] || 0;
		if (sb !== sa) return sb - sa;
		return (a.cve.id || "").localeCompare(b.cve.id || "");
	});
	return merged;
}

module.exports = { mergeBySource };
