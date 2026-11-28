'use strict';
// The CVSS v3/v4 qualitative rating scale, in one place.

/** Rating of a base score; `absent` when there is no usable score. */
function severityFromScore(score, absent = null) {
	if (score == null) return absent;
	const n = Number(score);
	if (!Number.isFinite(n)) return absent;
	if (n >= 9) return 'CRITICAL';
	if (n >= 7) return 'HIGH';
	if (n >= 4) return 'MEDIUM';
	if (n > 0) return 'LOW';
	return 'NONE';
}

module.exports = { severityFromScore };
