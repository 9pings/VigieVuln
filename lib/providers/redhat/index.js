'use strict';
// Red Hat security data. OVAL "including unpatched" definitions, one file per major release
// of Red Hat Enterprise Linux: they state which CVEs affect which packages without a fix.
const MAJORS = new Set(['6', '7', '8', '9']);

module.exports = { id: 'redhat', ttlMs: 24 * 3600 * 1000, MAJORS, build(type, params) {
	const major = String(params?.major ?? '');
	if (type !== 'oval-unpatched' || !MAJORS.has(major)) throw Error('invalid Red Hat OVAL request');
	return { url: `https://security.access.redhat.com/data/oval/v2/RHEL${major}/rhel-${major}-including-unpatched.oval.xml.bz2`, init: { headers: { accept: 'application/x-bzip2' } } };
} };
