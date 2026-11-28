'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), zlib = require('node:zlib');
const tar = require('tar-stream');
const ruby = require('../lib/providers/rubysec/advisories');

async function archive(files) {
	const pack = tar.pack(), chunks = [];
	const read = (async () => { for await (const chunk of pack) chunks.push(chunk); })();
	for (const [name, text] of Object.entries(files)) pack.entry({ name: `ruby-advisory-db-master/${name}` }, text);
	pack.finalize(); await read;
	return zlib.gzipSync(Buffer.concat(chunks));
}
const FILES = {
	'gems/rack/CVE-2022-30122.yml': "---\ngem: rack\ncve: 2022-30122\nghsa: hxqx-xwvh-44m2\nurl: https://example.test/rack\ntitle: Denial of service in multipart parsing\ndate: 2022-06-27\ndescription: |\n  Crafted multipart requests take too long.\ncvss_v3: 7.5\nunaffected_versions:\n  - \"< 1.2\"\npatched_versions:\n  - \"~> 2.0.9, >= 2.0.9.1\"\n  - \"~> 2.1.4, >= 2.1.4.1\"\n  - \">= 2.2.3.1\"\n",
	'gems/net-ssh/GHSA-vxj5-fg65-x765.yml': "---\ngem: net-ssh\nghsa: vxj5-fg65-x765\ntitle: Host certificate bypass\ndate: 2026-10-04\ncvss_v4: 8.1\npatched_versions:\n  - \">= 7.3.4\"\n",
	'gems/old/OSVDB-1234.yml': "---\ngem: old\nosvdb: 1234\ntitle: Never fixed\n",
	// Filed under another gem's directory: not an advisory for that gem.
	'gems/rack/misfiled.yml': "---\ngem: rails\ncve: 2020-0001\n",
	'rubies/ruby/CVE-2021-1.yml': "---\nengine: ruby\ncve: 2021-1\n",
	'README.md': '# not an advisory',
};

test('RubyGems requirements follow Gem::Requirement, including the pessimistic operator', () => {
	const cases = [['2.3.19', '~> 2.3.18', true], ['2.4.0', '~> 2.3.18', false], ['2.3.17', '~> 2.3.18', false], ['5.9', '~> 5.2', true], ['6.0', '~> 5.2', false],
		['2.4.4', '>= 2.4.4', true], ['1.0', '< 1.2', true], ['2.0.9.1', '~> 2.0.9, >= 2.0.9.1', true], ['2.0.9', '~> 2.0.9, >= 2.0.9.1', false],
		['1.0.0', '1.0.0', true], ['1.0.1', '!= 1.0.0', true], ['2.4.0.rc1', '~> 2.3.18', true]];
	for (const [version, requirement, expected] of cases) assert.equal(ruby.satisfies(version, requirement), expected, `${version} ${requirement}`);
	assert.equal(ruby.satisfies('main', '>= 1.0'), null, 'a branch name cannot be ordered');
	assert.equal(ruby.satisfies('1.0', 'around 1.0'), null);
	assert.deepEqual([ruby.bump('2.3.18'), ruby.bump('5.2'), ruby.bump('3'), ruby.bump('1.2.0.rc1')], ['2.4', '6', '4', '1.3']);
});

test('the archive yields the advisories of each gem and nothing else', async () => {
	const db = await ruby.parseArchive(await archive(FILES));
	assert.deepEqual(Object.keys(db.gems).sort(), ['net-ssh', 'old', 'rack']);
	assert.equal(db.count, 3); assert.equal(db.rejected, 1);
	const rack = db.gems.rack[0];
	assert.deepEqual([rack.id, rack.aliases, rack.score, rack.date, rack.file], ['CVE-2022-30122', ['GHSA-hxqx-xwvh-44m2'], 7.5, '2022-06-27', 'gems/rack/CVE-2022-30122.yml']);
	await assert.rejects(ruby.parseArchive(await archive({ 'README.md': 'empty' })), /holds no advisory/);
});

test('a version is vulnerable when it satisfies no patched or unaffected requirement', async () => {
	const { gems } = await ruby.parseArchive(await archive(FILES));
	const dep = (name, version) => ({ ecosystem: 'ruby', name, version, coordKey: `ruby:${name}` });
	const deps = new Map([['a', dep('rack', '2.1.0')], ['b', dep('rack', '2.2.4')], ['c', dep('rack', '1.1.0')], ['d', dep('net-ssh', '7.0.1')], ['e', dep('old', '9.9')],
		['f', dep('unlisted', '1.0')], ['g', { ecosystem: 'npm', name: 'rack', version: '2.1.0' }], ['h', dep('rack', 'main')]]);
	const consulted = [];
	const matches = ruby.collectRubyMatches(deps, gems, (d, source, version) => consulted.push(`${d.name}@${version}:${source}`));
	assert.deepEqual(matches.map(m => `${m.dep.name}@${m.dep.version} ${m.cve.id} → ${m.cve.fixVersion}`).sort(),
		['net-ssh@7.0.1 GHSA-vxj5-fg65-x765 → 7.3.4', 'old@9.9 OSVDB-1234 → null', 'rack@2.1.0 CVE-2022-30122 → 2.1.4.1']);
	const rack = matches.find(m => m.dep.name === 'rack').cve;
	assert.deepEqual([rack.severity, rack.score, rack.ghsa, rack.published, rack.aliases], ['HIGH', 7.5, 'GHSA-hxqx-xwvh-44m2', '2022-06-27', ['GHSA-hxqx-xwvh-44m2']]);
	assert.equal(matches[0].source, 'rubysec');
	// A gem the database does not list is covered; a version that cannot be ordered is not.
	assert.deepEqual(consulted.sort(), ['net-ssh@7.0.1:rubysec', 'old@9.9:rubysec', 'rack@1.1.0:rubysec', 'rack@2.1.0:rubysec', 'rack@2.2.4:rubysec', 'unlisted@1.0:rubysec']);
});

test('the lane caches the database, replays it offline and keeps a stale copy when a refresh fails', async t => {
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-rubysec-'));
	t.after(() => { require('../lib/cache/db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); });
	const bytes = await archive(FILES), deps = new Map([['a', { ecosystem: 'ruby', name: 'net-ssh', version: '7.0.1' }]]);
	let calls = 0;
	const fetcher = async url => { calls++; assert.match(String(url), /rubysec\/ruby-advisory-db/); return new Response(bytes); };
	assert.equal((await ruby.queryRubyAdvisories(deps, { cacheDir, fetcher })).length, 1);
	assert.equal((await ruby.queryRubyAdvisories(deps, { cacheDir, fetcher })).length, 1);
	assert.equal(calls, 1, 'a fresh copy is not downloaded again');
	const offline = await ruby.queryRubyAdvisories(deps, { cacheDir, offline: true, fetcher: () => { throw Error('network used'); } });
	assert.equal(offline[0].cve.id, 'GHSA-vxj5-fg65-x765');
	const warnings = [];
	const stale = await ruby.queryRubyAdvisories(deps, { cacheDir, forceUpdate: true, fetcher: async () => new Response('', { status: 503 }), onWarning: w => warnings.push(w) });
	assert.equal(stale.length, 1); assert.match(warnings[0].message, /refresh failed \(Ruby advisory database HTTP 503\)/);
	// No Ruby dependency: nothing is fetched. No database at all: the lane fails loudly.
	assert.deepEqual(await ruby.queryRubyAdvisories(new Map([['n', { ecosystem: 'npm', name: 'x', version: '1' }]]), { cacheDir, fetcher: () => { throw Error('network used'); } }), []);
	const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-rubysec-empty-'));
	t.after(() => fs.rmSync(empty, { recursive: true, force: true }));
	await assert.rejects(ruby.queryRubyAdvisories(deps, { cacheDir: empty, offline: true }), /no cached Ruby advisory database/);
});
