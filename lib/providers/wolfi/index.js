'use strict';
// Wolfi and Chainguard OS publish one security database per package repository, in the
// Alpine "secdb" format: for each package, the version that fixed each vulnerability.
const REPOSITORIES = { wolfi: 'https://packages.wolfi.dev/os/security.json', chainguard: 'https://packages.cgr.dev/chainguard/security.json' };

module.exports = { id: 'wolfi', ttlMs: 4 * 3600 * 1000, REPOSITORIES, build(type, params) {
	const url = type === 'secdb' && Object.hasOwn(REPOSITORIES, String(params?.repository)) ? REPOSITORIES[params.repository] : null;
	if (!url) throw Error('invalid Wolfi security database request');
	return { url, init: { headers: { accept: 'application/json' } } };
} };
