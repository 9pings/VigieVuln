'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { severityFromScore } = require('../lib/severity');

test('one rating scale for every source', () => {
	assert.deepEqual([10, 9, 8.9, 7, 6.9, 4, 3.9, 0.1, 0].map(n => severityFromScore(n)), ['CRITICAL', 'CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'LOW', 'LOW', 'NONE']);
	assert.equal(severityFromScore('7.5'), 'HIGH');
	for (const none of [null, undefined, NaN, 'n/a']) { assert.equal(severityFromScore(none), null); assert.equal(severityFromScore(none, 'UNKNOWN'), 'UNKNOWN'); }
});
