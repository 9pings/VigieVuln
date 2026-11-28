'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const { decompressBlocks } = require('../lib/providers/redhat/bzip2');
const { readUnpatched } = require('../lib/providers/redhat/oval');
const { assessRedHatUnfixed, family } = require('../lib/providers/redhat/unfixed');
const { assessRedHatErrata } = require('../lib/providers/redhat/errata');
const { scope, importSystemAdvisories } = require('../lib/system-inventory/advisories');

const fixture = name => fs.readFileSync(path.join(__dirname, 'fixtures', 'redhat', name));
const OVAL = fixture('rhel-8-mini.oval.xml.bz2');
function cache(t) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-redhat-'));
	t.after(() => { require('../lib/cache/db').closeCacheDbs(); fs.rmSync(dir, { recursive: true, force: true }); });
	return dir;
}
const rpm = (name, version, extra = {}) => ({ name, version, manager: 'rpm', ecosystem: 'system', provenance: 'installed', sourceName: name, sourceVersion: version, architecture: 'x86_64', ...extra });
const RHEL8 = { id: 'rhel', versionId: '8.6', name: 'Red Hat Enterprise Linux 8.6 (Ootpa)' };
const ROCKY8 = { id: 'rocky', versionId: '8.6', name: 'Rocky Linux 8.6 (Green Obsidian)' };

test('bzip2 streams decode to the original bytes, block by block, and corruption is detected', () => {
	const xml = Buffer.concat([...decompressBlocks(OVAL)]);
	assert.ok(xml.equals(fixture('rhel-8-mini.oval.xml')));
	const blocks = [...decompressBlocks(fixture('blocks.bin.bz2'))];
	assert.ok(blocks.length >= 2, 'several blocks');
	assert.equal(crypto.createHash('sha256').update(Buffer.concat(blocks)).digest('hex'), fixture('blocks.sha256').toString().trim());
	assert.equal(Buffer.concat([...decompressBlocks(fixture('two-streams.bz2'))]).length, 2 * xml.length, 'concatenated streams');
	const damaged = Buffer.from(fixture('blocks.bin.bz2')); damaged[4000] ^= 0x55;
	assert.throws(() => [...decompressBlocks(damaged)], /invalid bzip2 data/);
	assert.throws(() => [...decompressBlocks(OVAL.subarray(0, 600))], /invalid bzip2 data: unexpected end of input/);
	assert.throws(() => [...decompressBlocks(Buffer.from('not bzip2 at all'))], /not a bzip2 stream/);
});

test('an OVAL file yields the unpatched vulnerabilities only, by package', () => {
	const data = readUnpatched(OVAL);
	assert.equal(data.timestamp, '2026-11-28T07:28:39');
	assert.deepEqual(Object.keys(data.advisories).sort(), ['CVE-2005-2541', 'CVE-2026-99001', 'CVE-2026-99002'], 'errata and unaffected definitions are other classes');
	assert.deepEqual(data.advisories['CVE-2005-2541'], { title: 'tar: does not warn about setuid & setgid files', severity: 'MEDIUM', score: 7,
		vector: 'CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H', published: '2005-08-04', updated: '2026-03-16' });
	const state = (name, cve) => data.states[data.components[name].find(([id]) => id === cve)[1]];
	assert.deepEqual([state('tar', 'CVE-2005-2541'), state('kernel-core', 'CVE-2026-99001'), state('kernel-rt', 'CVE-2026-99001'), state('python27:2.7/python2', 'CVE-2026-99002'), state('libcurl', 'CVE-2026-99002')],
		['Will not fix', 'Fix deferred', 'Under investigation', 'Out of support scope', 'Affected']);
	assert.equal(data.components.bash, undefined);
});

test('which distributions Red Hat statements describe', () => {
	assert.deepEqual(family(RHEL8), { major: '8', rebuild: null, ownErrata: false });
	assert.deepEqual(family({ id: 'almalinux', versionId: '9.9' }), { major: '9', rebuild: 'AlmaLinux', ownErrata: true });
	assert.deepEqual(family({ id: 'ol', versionId: '8.10' }), { major: '8', rebuild: 'Oracle Linux', ownErrata: false });
	assert.deepEqual(family({ id: 'centos', versionId: '7', name: 'CentOS Linux 7 (Core)' }), { major: '7', rebuild: 'CentOS Linux', ownErrata: false });
	for (const other of [{ id: 'centos', versionId: '9', name: 'CentOS Stream 9' }, { id: 'debian', versionId: '12' }, { id: 'fedora', versionId: '41' }, { id: 'rhel' }]) assert.equal(family(other), null);
});

test('unfixed vulnerabilities are stated once per source package, for the packages of that release only', async t => {
	const cacheDir = cache(t);
	const kernel = v => ['kernel', 'kernel-core', 'kernel-modules'].map(name => rpm(name, v, { sourceName: 'kernel', sourceVersion: v }));
	const inventory = { distribution: RHEL8, packages: [rpm('tar', '2:1.30-5.el8'), ...kernel('4.18.0-372.32.1.el8_6'), rpm('kernel-rt', '4.18.0-372.rt7.el8_6'),
		rpm('python2', '2.7.18-11.module+el8.6.0+1+abc', { modularityLabel: 'python27:2.7:8060020220101:abc' }), rpm('python2', '2.7.18-1.el8'),
		rpm('curl', '7.61.1-22.fc40'), rpm('libcurl', '7.61.1-22.el8', { packageOrigin: { status: 'third-party' } }), rpm('bash', '4.4.20-4.el8_6')] };
	let calls = 0;
	const fetcher = async url => { calls++; assert.match(String(url), /RHEL8\/rhel-8-including-unpatched\.oval\.xml\.bz2$/); return new Response(OVAL); };
	const result = await assessRedHatUnfixed(inventory, { cacheDir, fetcher });
	const found = result.matches.map(m => `${m.dep.name} ${m.cve.id} ${m.cve.distributionStatus.state} [${m.cve.distributionStatus.packages}]`).sort();
	assert.deepEqual(found, ['kernel CVE-2026-99001 Fix deferred [kernel,kernel-core,kernel-modules]',
		'python2 CVE-2026-99002 Out of support scope [python2]', 'tar CVE-2005-2541 Will not fix [tar]']);
	const tar = result.matches.find(m => m.dep.name === 'tar');
	assert.deepEqual([tar.source, tar.cve.severity, tar.cve.score, tar.cve.fixVersion, tar.cve.distributionAdvisory], ['redhat-oval', 'MEDIUM', 7, null, { source: 'Red Hat', release: 'enterprise_linux:8' }]);
	// The module package matches its stream only; a package built elsewhere or of another vendor is not Red Hat's.
	assert.equal(result.matches.filter(m => m.dep.name === 'python2')[0].dep.modularityLabel, 'python27:2.7:8060020220101:abc');
	assert.equal(result.matches.some(m => /curl/.test(m.dep.name)), false);
	assert.deepEqual(result.observations.map(o => [o.dep.name, o.cveId, o.status]), [['kernel-rt', 'CVE-2026-99001', 'possible']]);
	assert.deepEqual([result.coverage[0].execution, result.coverage[0].result, result.coverage[0].skipped], ['completed', 'affected', 1]);
	// Cached for a day, replayed offline, and absent data is a stated gap.
	await assessRedHatUnfixed(inventory, { cacheDir, fetcher }); assert.equal(calls, 1);
	const offline = await assessRedHatUnfixed(inventory, { cacheDir, offline: true, fetcher: () => { throw Error('network used'); } });
	assert.equal(offline.matches.length, 3);
	const missing = await assessRedHatUnfixed(inventory, { cacheDir: cache(t), offline: true });
	assert.deepEqual([missing.coverage[0].execution, missing.matches.length], ['not-run', 0]);
	const failed = await assessRedHatUnfixed(inventory, { cacheDir: cache(t), fetcher: async () => new Response('', { status: 503 }) });
	assert.equal(failed.coverage[0].execution, 'failed'); assert.match(failed.warnings[0].message, /Red Hat OVAL: Red Hat OVAL HTTP 503/);
	// A release without OVAL data is said so, not silently skipped.
	const ten = await assessRedHatUnfixed({ distribution: { id: 'rhel', versionId: '10.1' }, packages: [rpm('tar', '1.35-1.el10')] }, { cacheDir, fetcher });
	assert.match(ten.coverage[0].reason, /no OVAL data for Enterprise Linux 10/);
});

test('a rebuilt distribution takes Red Hat statements, except for the CVEs its own errata mention', async t => {
	const cacheDir = cache(t);
	const record = (id, ecosystem, name, fixed, cves) => ({ id, modified: '2026-01-01T00:00:00Z', related: cves, affected: [{ package: { ecosystem, name }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed }] }] }] });
	// Rocky's own feed: one erratum for tar (mentions CVE-2005-2541), one for curl listing one CVE of two.
	await importSystemAdvisories([record('RLSA-2026:1', 'Rocky Linux:8', 'tar', '2:1.30-9.el8', ['CVE-2005-2541']),
		record('RLSA-2026:2', 'Rocky Linux:8', 'curl', '0:7.61.1-30.el8', ['CVE-2026-0001'])], { cacheDir, distribution: ROCKY8, complete: true });
	// Red Hat's errata: the same curl update with a second CVE, a kernel update Rocky has no erratum for, and one for another major.
	await importSystemAdvisories([record('RHSA-2026:2', 'Red Hat:enterprise_linux:8::baseos', 'curl', '0:7.61.1-30.el8', ['CVE-2026-0001', 'CVE-2026-0002']),
		record('RHSA-2026:3', 'Red Hat:enterprise_linux:8::baseos', 'kernel-core', '0:4.18.0-553.125.1.el8_10', ['CVE-2026-43503']),
		record('RHSA-2026:4', 'Red Hat:enterprise_linux:8::appstream', 'tar', '2:1.30-9.el8', ['CVE-2005-2541']),
		record('RHSA-2026:5', 'Red Hat:enterprise_linux:9::baseos', 'curl', '0:9.9-1.el9', ['CVE-2026-0009'])], { cacheDir, distribution: RHEL8, complete: true });
	const inventory = { distribution: ROCKY8, packages: [rpm('tar', '2:1.30-5.el8'), rpm('curl', '7.61.1-22.el8'), rpm('kernel-core', '4.18.0-372.32.1.el8_6', { sourceName: 'kernel' }), rpm('kernel-core', '4.18.0-553.130.1.el8_10', { sourceName: 'kernel' })] };
	const errata = await assessRedHatErrata(inventory, { cacheDir, offline: true });
	assert.deepEqual(errata.matches.map(m => [m.dep.name, m.dep.version, m.cve.sourceAdvisoryId, m.cve.related, m.cve.fixVersion, m.source]).sort(), [
		['curl', '7.61.1-22.el8', 'RHSA-2026:2', ['CVE-2026-0002'], '0:7.61.1-30.el8', 'redhat-errata'],
		['kernel-core', '4.18.0-372.32.1.el8_6', 'RHSA-2026:3', ['CVE-2026-43503'], '0:4.18.0-553.125.1.el8_10', 'redhat-errata']]);
	assert.deepEqual(errata.matches[0].cve.distributionAdvisory, { source: 'Red Hat', release: 'Red Hat:enterprise_linux:8', appliedTo: 'Rocky Linux' });
	assert.deepEqual([errata.coverage[0].execution, errata.coverage[0].superseded], ['completed', 1]);
	// Unfixed statements follow the same rule: Rocky's erratum for tar mentions the CVE, so Rocky decides.
	const unfixed = await assessRedHatUnfixed(inventory, { cacheDir, fetcher: async () => new Response(OVAL) });
	assert.deepEqual(unfixed.matches.map(m => [m.dep.name, m.dep.version, m.cve.id, m.cve.distributionStatus.appliedTo]).sort(), [
		['curl', '7.61.1-22.el8', 'CVE-2026-99002', 'Rocky Linux'],
		// One statement per installed kernel: two versions are two source packages.
		['kernel-core', '4.18.0-372.32.1.el8_6', 'CVE-2026-99001', 'Rocky Linux'], ['kernel-core', '4.18.0-553.130.1.el8_10', 'CVE-2026-99001', 'Rocky Linux']]);
	assert.equal(unfixed.matches.some(m => m.dep.name === 'tar'), false);
	// Red Hat Enterprise Linux itself has its errata already: the second lane is for rebuilds.
	assert.deepEqual((await assessRedHatErrata({ ...inventory, distribution: RHEL8 }, { cacheDir, offline: true })).coverage, []);
});

test('each distribution maps to the ecosystems that describe its release', () => {
	const name = d => scope(d)?.ecosystem;
	assert.deepEqual([{ id: 'mageia', versionId: '9' }, { id: 'azurelinux', versionId: '3.0' }, { id: 'mariner', versionId: '2.0' }, { id: 'opensuse-leap', versionId: '15.6' },
		{ id: 'opensuse-tumbleweed', versionId: '20261101' }, { id: 'openEuler', versionId: '24.03', name: 'openEuler 24.03 (LTS-SP1)' }, { id: 'openEuler', versionId: '22.03', name: 'openEuler 22.03 LTS' }, { id: 'openEuler', versionId: '25.03', name: 'openEuler 25.03' },
		{ id: 'sle-micro', versionId: '5.5' }, { id: 'rhel', versionId: '9.3' }, { id: 'sles', versionId: '15.5' }, { id: 'gentoo', versionId: '2.15' }].map(name),
	['Mageia:9', 'Azure Linux:3', 'Azure Linux:2', 'openSUSE:Leap 15.6', 'openSUSE:Tumbleweed', 'openEuler:24.03-LTS-SP1', 'openEuler:22.03-LTS', 'openEuler:25.03',
		'SUSE:Linux Enterprise Micro 5.5', 'Red Hat:enterprise_linux:9', 'SUSE:Linux Enterprise 15 SP5', undefined]);
	const accepts = (d, list) => list.filter(scope(d).accepts);
	assert.deepEqual(accepts({ id: 'rhel', versionId: '9.3' }, ['Red Hat:enterprise_linux:9::baseos', 'Red Hat:enterprise_linux:9::appstream', 'Red Hat:enterprise_linux:9', 'Red Hat:enterprise_linux:8::baseos',
		'Red Hat:rhel_eus:9.2::baseos', 'Red Hat:rhel_eus:9.3::appstream', 'Red Hat:enterprise_linux:90::baseos']),
	['Red Hat:enterprise_linux:9::baseos', 'Red Hat:enterprise_linux:9::appstream', 'Red Hat:enterprise_linux:9', 'Red Hat:rhel_eus:9.3::appstream']);
	assert.deepEqual(accepts({ id: 'rhel', versionId: '10.1' }, ['Red Hat:enterprise_linux:10.0', 'Red Hat:enterprise_linux:10.1', 'Red Hat:enterprise_linux:10.2']), ['Red Hat:enterprise_linux:10.0', 'Red Hat:enterprise_linux:10.1']);
	assert.deepEqual(accepts({ id: 'sles', versionId: '15.5' }, ['SUSE:Linux Enterprise Server 15 SP5', 'SUSE:Linux Enterprise Module for Basesystem 15 SP5', 'SUSE:Linux Enterprise Server 15 SP5-LTSS',
		'SUSE:Linux Enterprise Server 15 SP4', 'SUSE:Linux Enterprise Micro 5.5', 'SUSE:Linux Enterprise Server 15', 'openSUSE:Leap 15.5']),
	['SUSE:Linux Enterprise Server 15 SP5', 'SUSE:Linux Enterprise Module for Basesystem 15 SP5', 'SUSE:Linux Enterprise Server 15 SP5-LTSS']);
	// CentOS Linux and Oracle Linux are assessed against the Red Hat errata of the release they rebuild.
	assert.deepEqual([name({ id: 'centos', versionId: '7', name: 'CentOS Linux 7 (Core)' }), name({ id: 'ol', versionId: '8.6' }), name({ id: 'centos', versionId: '9', name: 'CentOS Stream 9' })],
		['Red Hat:enterprise_linux:7', 'Red Hat:enterprise_linux:8', undefined]);
	assert.equal(scope({ id: 'azurelinux', versionId: '3.0' }).fixedOnly, false, 'Azure Linux records unfixed vulnerabilities');
	assert.equal(scope({ id: 'rhel', versionId: '9.3' }).fixedOnly, true);
});

test('a product published under several ecosystems is assessed across all of them', async t => {
	const cacheDir = cache(t);
	const record = (id, ecosystem, name, fixed) => ({ id, modified: '2026-01-01T00:00:00Z', related: ['CVE-2026-000' + id.slice(-1)], affected: [{ package: { ecosystem, name }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed }] }] }] });
	await importSystemAdvisories([record('RHSA-2026:1', 'Red Hat:enterprise_linux:9::baseos', 'openssl-libs', '1:3.0.7-28.el9_4'), record('RHSA-2026:2', 'Red Hat:enterprise_linux:9::appstream', 'git', '0:2.43.5-1.el9_4'),
		record('RHSA-2026:3', 'Red Hat:enterprise_linux:8::baseos', 'git', '0:9.9-1.el8')], { cacheDir, distribution: { id: 'rhel', versionId: '9.3' }, complete: true });
	const { assessSystemInventory } = require('../lib/system-inventory/advisories');
	const result = await assessSystemInventory({ distribution: { id: 'rhel', versionId: '9.3' }, packages: [rpm('openssl-libs', '1:3.0.7-24.el9', { sourceName: 'openssl' }), rpm('git', '2.39.3-1.el9_2')] }, { cacheDir, offline: true });
	assert.deepEqual(result.matches.map(m => [m.dep.name, m.cve.sourceAdvisoryId]).sort(), [['git', 'RHSA-2026:2'], ['openssl-libs', 'RHSA-2026:1']]);
});

test('a version bound published with stray whitespace is still that version', async t => {
	const cacheDir = cache(t), distribution = { id: 'mariner', versionId: '2.0' };
	await importSystemAdvisories([{ id: 'AZL-31332', modified: '2026-01-01T00:00:00Z', upstream: ['CVE-2023-44487'],
		affected: [{ package: { ecosystem: 'Azure Linux:2', name: 'nghttp2' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: ' 1.57.0-1' }] }] }] }], { cacheDir, distribution, complete: true });
	const { assessSystemInventory } = require('../lib/system-inventory/advisories');
	const result = await assessSystemInventory({ distribution, packages: [rpm('nghttp2', '1.46.0-2.cm2')] }, { cacheDir, offline: true });
	assert.deepEqual(result.matches.map(m => [m.cve.sourceAdvisoryId, m.cve.fixVersion]), [['AZL-31332', '1.57.0-1']]);
	assert.equal(result.coverage[0].status, 'complete');
});
