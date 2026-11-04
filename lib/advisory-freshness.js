/**
 * Freshness control for operator-supplied advisory snapshots (pure).
 * A snapshot's mtime proves nothing about when it was collected; only a date
 * declared inside the snapshot file is accepted as freshness evidence.
 */
const UNITS = { s: 1000, m: 60 * 1000, h: 3600 * 1000, d: 24 * 3600 * 1000 };

function parseMaxAge(value) {
	const match = /^(\d+)(s|m|h|d)$/.exec(String(value || "").trim());
	if (!match || Number(match[1]) < 1) throw new Error(`invalid --max-advisory-age duration: ${value}`);
	return Number(match[1]) * UNITS[match[2]];
}

function declaredCollectedAt(snapshot) {
	const meta = snapshot && typeof snapshot === "object" ? snapshot._fadSnapshot : null;
	const raw = typeof meta?.collectedAt === "string" ? meta.collectedAt
		: typeof snapshot?.collectedAt === "string" ? snapshot.collectedAt
			: typeof snapshot?.generatedAt === "string" ? snapshot.generatedAt : null;
	if (!raw) return null;
	if (!/^\d{4}-\d{2}-\d{2}([T ]|$)/.test(raw.trim()) || !Number.isFinite(Date.parse(raw)))
		throw new Error(`declared collection date is not a valid ISO 8601 timestamp: ${raw}`);
	return new Date(Date.parse(raw));
}

function assertFresh(snapshot, label, maxAgeMs, nowMs = Date.now()) {
	const collectedAt = declaredCollectedAt(snapshot);
	if (!collectedAt) throw new Error(`${label} snapshot does not declare its collection date; `
		+ `add _fadSnapshot.collectedAt (ISO 8601) or a top-level collectedAt/generatedAt to the snapshot file`);
	const ageMs = nowMs - collectedAt.getTime();
	// Allow modest clock skew, consistently with the advisory cache validators.
	if (ageMs < -5 * 60 * 1000) throw new Error(`${label} snapshot collection date ${collectedAt.toISOString()} is in the future; check the snapshot timestamp and system clock`);
	if (ageMs > maxAgeMs) throw new Error(`${label} snapshot collected at ${collectedAt.toISOString()} is stale: `
		+ `age ${Math.round(ageMs / 3600000)}h exceeds --max-advisory-age ${Math.round(maxAgeMs / 3600000)}h`);
	return { collectedAt: collectedAt.toISOString() };
}

module.exports = { parseMaxAge, declaredCollectedAt, assertFresh };
