/**
 * lib/unmanaged.js — enrich unmanaged (hash-bearing) records with online identity
 * + an integrity classification.
 *
 *   integrity:
 *     "pristine"    — deps.dev matched: file is byte-identical to a PUBLISHED package
 *                     artifact (so it's unmodified, and ought to be a managed dep).
 *     "known-good"  — CIRCL matched: a known OS/distro/CDN/NSRL file.
 *     "unknown"     — no source recognises the hash (suspicious / vendored unknown).
 *
 * Records carrying a declared coordinate (embedded jars) gain a "modified" status in
 * a later refinement; Plan 2 covers the hash-bearing binary records.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { lookupHash, loadCache, saveCache } = require("./hash-id");

async function enrichUnmanaged(resolved, opts = {}) {
	const { fetcher, offline = false, cache, onProgress } = opts;
	const targets = [...resolved.values()].filter(d => d.hashes && (d.hashes.sha1 || d.hashes.sha256));
	const summary = { total: targets.length, identified: 0, pristine: 0, knownGood: 0, unknown: 0, malicious: 0 };
	if (!targets.length) return summary;
	const entries = cache || loadCache({ offline });
	let done = 0;
	for (const d of targets) {
		const id = await lookupHash(d.hashes, { fetcher, offline, cache: entries });
		d.identity = id || null;
		if (!id) d.integrity = "unknown";
		else if (id.source === "deps.dev") d.integrity = "pristine";
		else d.integrity = "known-good";
		if (id) summary.identified++;
		if (d.integrity === "pristine") summary.pristine++;
		else if (d.integrity === "known-good") summary.knownGood++;
		else summary.unknown++;
		if (id?.knownMalicious) summary.malicious++;
		if (onProgress) onProgress(++done, targets.length);
	}
	if (!cache && !offline) saveCache(entries);
	return summary;
}

function normName(s) {
	return String(s || "").toLowerCase()
		.replace(/\.(dll|exe|so|dylib)(\.\d+)*$/, "")  // drop binary extension (+ soname version)
		.replace(/^lib/, "")                            // libssl → ssl
		.replace(/[-_.]?\d[\d.]*$/, "")                 // trailing version
		.replace(/[^a-z0-9]/g, "");
}

/** Lenient compare of a filename to an online identity name (last :/ segment). */
function nameMatches(declared, identityName) {
	const a = normName(declared);
	const b = normName(String(identityName).split(/[:/]/).pop());
	if (!a || !b) return true;        // can't compare → don't raise a false alarm
	return a.includes(b) || b.includes(a);
}

/** Turn the unmanaged (hash-bearing) records into an inventory with derived signals. */
function buildInventory(resolved) {
	const out = [];
	for (const d of resolved.values()) {
		if (!d.hashes || !(d.provenance === "binary" || d.provenance === "embedded")) continue;
		const identity = d.identity || null;
		out.push({
			path: d.manifestPaths?.[0] || d.declaredName || null,
			declaredName: d.declaredName || d.name || null,
			provenance: d.provenance,
			hashes: d.hashes,
			identity,
			integrity: d.integrity || "unknown",
			noOnlineInfo: !identity,
			shouldBeManaged: !!(identity && identity.ecosystem),
			nameMismatch: !!(identity && identity.name && !nameMatches(d.declaredName || d.name, identity.name)),
			knownMalicious: !!(identity && identity.knownMalicious),
		});
	}
	out.sort((a, b) => String(a.path).localeCompare(String(b.path)));
	return out;
}

module.exports = { enrichUnmanaged, buildInventory, nameMatches };
