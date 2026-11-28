'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { foldAccessWarnings } = require('../lib/artifacts/access-warnings');

test('unreadable paths of a collection without root become one notice', () => {
	const warnings = [
		{ type: 'dependency-coverage', reason: 'installed-metadata-error', code: 'EACCES', manifestPath: '/var/spool/cups', message: 'Installed metadata could not be inventoried: /var/spool/cups' },
		{ type: 'dependency-coverage', reason: 'binary-scan-error', manifestPath: '/root', message: "binary scan incomplete for /root: EACCES: permission denied, scandir '/root'" },
		{ type: 'dependency-coverage', reason: 'image-reference-read-error', message: "Cannot inspect image declarations: EACCES: permission denied, scandir '/etc/ssl/private'" },
		{ type: 'dependency-coverage', reason: 'installed-metadata-error', manifestPath: '/opt/app/lib.jar', message: 'installed metadata incomplete for /opt/app/lib.jar: truncated archive' },
	];
	const folded = foldAccessWarnings(warnings);
	assert.equal(folded.length, 2, 'the unrelated warning and one notice');
	assert.equal(folded[0].manifestPath, '/opt/app/lib.jar');
	const notice = folded[1];
	assert.deepEqual([notice.reason, notice.capability, notice.count], ['permission-denied', 'inventory', 3]);
	assert.deepEqual(notice.items.map(i => i.id), ['/etc/ssl/private', '/root', '/var/spool/cups']);
	assert.match(notice.message, /^3 path\(s\) could not be read \(permission denied\).*Run the collection as root/);
	// A later step adds its own warnings: still one notice.
	const again = foldAccessWarnings([...folded, { type: 'dependency-coverage', code: 'EPERM', manifestPath: '/proc/1/root', message: 'x' }, { type: 'dependency-coverage', code: 'EACCES', manifestPath: '/root', message: 'x' }]);
	assert.equal(again.filter(w => w.reason === 'permission-denied').length, 1);
	assert.equal(again.find(w => w.reason === 'permission-denied').count, 4);
	// A single unreadable path keeps its own, more precise, warning.
	assert.deepEqual(foldAccessWarnings(warnings.slice(0, 1)), warnings.slice(0, 1));
});
