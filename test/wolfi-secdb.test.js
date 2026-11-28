'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { recordsFromSecdb, identifiers } = require('../lib/providers/wolfi/secdb');
const { scope, syncSystemAdvisories, assessSystemInventory } = require('../lib/system-inventory/advisories');

const SECDB = { reponame: 'wolfi', packages: [
	{ pkg: { name: 'curl', secfixes: { '0': ['CVE-2023-32001', 'GHSA-c6mx-w98j-fgrj'], '8.11.0-r0': ['CVE-2024-9681', 'GHSA-g337-g667-mjvw'], '8.12.0-r0': ['GHSA-aaaa-bbbb-cccc', 'GO-2025-1234'] } } },
	{ pkg: { name: 'zlib', secfixes: { '1.3.1-r1': ['CVE-2023-45853'] } } },
	{ pkg: { name: '../escape', secfixes: { '1.0-r0': ['CVE-2020-0001'] } } },
	{ pkg: { name: 'odd', secfixes: { 'not a version': ['CVE-2020-0002'], '1.0-r0': ['not-an-id'] } } }] };

test('a security database becomes one record per package, vulnerability and fixed version', () => {
	assert.deepEqual(identifiers(['CVE-2024-9681', 'GHSA-G337-g667-mjvw', 'GO-2024-1']), ['CVE-2024-9681'], 'the CVE speaks for its other identifiers');
	assert.deepEqual(identifiers(['GHSA-aaaa-bbbb-cccc', 'GO-2025-1234']), ['GHSA-aaaa-bbbb-cccc', 'GO-2025-1234']);
	const records = recordsFromSecdb(SECDB, 'Wolfi');
	assert.deepEqual(records.map(r => [r.affected[0].package.name, r.aliases[0], r.affected[0].ranges[0].events[1].fixed]), [
		['curl', 'CVE-2024-9681', '8.11.0-r0'], ['curl', 'GHSA-aaaa-bbbb-cccc', '8.12.0-r0'], ['curl', 'GO-2025-1234', '8.12.0-r0'], ['zlib', 'CVE-2023-45853', '1.3.1-r1']]);
	assert.throws(() => recordsFromSecdb({ packages: [] }, 'Wolfi'), /holds no fix/);
	assert.throws(() => recordsFromSecdb({}, 'Wolfi'), /invalid security database/);
});

test('Wolfi and Chainguard systems are assessed from their security databases, online then offline', async t => {
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-wolfi-'));
	t.after(() => { require('../lib/cache/db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); });
	const wolfi = { id: 'wolfi', versionId: '20230201', name: 'Wolfi' };
	assert.deepEqual([scope(wolfi).ecosystem, scope(wolfi).secdb, scope({ id: 'chainguard' }).secdb, scope(wolfi).fixedOnly], ['Wolfi', ['wolfi'], ['chainguard', 'wolfi'], true]);
	const asked = [];
	const fetcher = async url => { asked.push(String(url)); return Response.json(SECDB); };
	const synced = await syncSystemAdvisories(wolfi, { cacheDir, fetcher });
	assert.deepEqual(asked, ['https://packages.wolfi.dev/os/security.json']); assert.equal(synced.complete, true);
	const apk = (name, version, origin) => ({ name, version, manager: 'apk', ecosystem: 'system', sourceName: origin, sourceVersion: version, architecture: 'x86_64' });
	const inventory = { distribution: wolfi, packages: [apk('libcurl-openssl4', '8.10.0-r0', 'curl'), apk('curl', '8.11.0-r0', 'curl'), apk('zlib', '1.3.1-r50', 'zlib')] };
	const result = await assessSystemInventory(inventory, { cacheDir, offline: true });
	assert.deepEqual(result.matches.map(m => [m.dep.name, m.cve.id, m.cve.fixVersion]).sort(), [
		['curl', 'GHSA-aaaa-bbbb-cccc', '8.12.0-r0'], ['curl', 'GO-2025-1234', '8.12.0-r0'],
		['libcurl-openssl4', 'CVE-2024-9681', '8.11.0-r0'], ['libcurl-openssl4', 'GHSA-aaaa-bbbb-cccc', '8.12.0-r0'], ['libcurl-openssl4', 'GO-2025-1234', '8.12.0-r0']]);
	assert.equal(result.coverage[0].status, 'complete');
	await assert.rejects(syncSystemAdvisories(wolfi, { cacheDir, fetcher: async () => new Response('', { status: 503 }) }), /system advisory download failed: wolfi security database HTTP 503/);
});
