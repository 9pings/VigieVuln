const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { configureResourceRoute } = require('../lib/providers');
const { projectFeed } = require('../lib/application-providers/wordfence-projection');
const { indexProductionFeed } = require('../lib/application-providers/wordfence-v3');
const { CACHE_FILE } = require('../lib/application-providers/wordfence-client');
const { runApplicationPlugins } = require('../lib/application-plugins/runner');
const wordpress = require('../lib/application-plugins/wordpress');
const NOW = Date.now() - 1000, HOUR = 3600000;
const ROOT = path.join(__dirname, 'fixtures/wordpress-custom');
const QUERIES = [{ type: 'core', slug: 'wordpress' }, { type: 'theme', slug: 'example' }];
const UUID = '123e4567-e89b-12d3-a456-426614174000';
const FEED = indexProductionFeed({ [UUID]: { id: UUID, title: 'Revalidation fixture', software: [{
	type: 'theme', slug: 'example', affected_versions: { all: {
		from_version: '1', from_inclusive: true, to_version: '2', to_inclusive: true,
	} }, patched_versions: ['2.1'],
}] } });
function fixture(t, { age = 48 * HOUR, stale = false, positive = false } = {}) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-runner-freshness-'));
	const file = path.join(dir, CACHE_FILE);
	const snapshot = projectFeed(positive ? FEED : new Map(), QUERIES, NOW - age, stale);
	fs.writeFileSync(file, JSON.stringify(snapshot));
	const original = fs.readFileSync(file, 'utf8'), calls = [];
	configureResourceRoute({ proxyUrl: 'https://proxy.invalid', hosted: true, token: null, store: null, health: null, fetcher: null });
	t.after(() => {
		configureResourceRoute({ proxyUrl: null, hosted: false, token: null, store: null, health: null, fetcher: null });
		fs.rmSync(dir, { recursive: true, force: true });
	});
	const opts = { plugins: [wordpress], selection: 'wordpress', advisoryCacheDir: dir, now: NOW,
		publicComponents: ['site/wp-content/themes/acme-theme=example'],
		fetchImpl: async (url, init) => {
			assert.equal(url, 'https://proxy.invalid/v1/resource', 'never fetch a direct/bulk catalogue');
			const request = JSON.parse(init.body);
			assert.equal(request.provider, 'wordfence');
			assert.equal(request.type, 'software');
			assert.deepEqual(request.params.software, QUERIES, 'only public identities, no paths or versions');
			calls.push(request);
			return f.respond();
		} };
	const f = { dir, file, original, calls, opts, snapshot,
		respond: () => Response.json(projectFeed(FEED, QUERIES, NOW)),
		run: extra => runApplicationPlugins(ROOT, { ...opts, ...extra }) };
	return f;
}
const covered = result => result.coverage.filter(c => c.sourceId === 'wordfence-v3' && c.executed === 1);
function assertStale(result) {
	assert.equal(covered(result).length, 2);
	assert.ok(covered(result).every(c => c.result === 'indeterminate' && c.execution === 'partial' && c.sourceSnapshot.stale));
	assert.ok(result.diagnostics.some(d => d.code === 'CMS_ADVISORY_STALE'));
}

test('48h stale=false local projection revalidates targeted identities and discovers a missed advisory', async t => {
	const f = fixture(t);
	const result = await f.run();
	assert.equal(f.calls.length, 1);
	assert.equal(result.findings.length, 1);
	assert.deepEqual(covered(result).map(c => c.result), ['no-match', 'affected']);
	assert.ok(covered(result).every(c => c.sourceSnapshot.collectedAt === new Date(NOW).toISOString()));
	assert.equal(JSON.parse(fs.readFileSync(f.file))._fadSnapshot.collectedAt, new Date(NOW).toISOString());
	await f.run();
	assert.equal(f.calls.length, 1, 'fresh cached projection is reused');
});

for (const age of [HOUR - 1, HOUR, HOUR + 1]) test(`Wordfence local freshness threshold: ${age}ms`, async t => {
	const f = fixture(t, { age });
	await f.run();
	assert.equal(f.calls.length, age > HOUR ? 1 : 0);
});

test('explicit stale flag revalidates even a recent projection', async t => {
	const f = fixture(t, { age: 1000, stale: true });
	await f.run();
	assert.equal(f.calls.length, 1);
});

test('failed refresh of a 48h empty projection cannot produce a clean verdict', async t => {
	const f = fixture(t);
	f.respond = () => new Response('', { status: 410 });
	const result = await f.run();
	assert.equal(f.calls.length, 1);
	assert.equal(result.findings.length, 0);
	assertStale(result);
	assert.equal(fs.readFileSync(f.file, 'utf8'), f.original);
});

test('fresh targeted negative replaces an obsolete cached advisory', async t => {
	const f = fixture(t, { positive: true });
	f.respond = () => Response.json(projectFeed(new Map(), QUERIES, NOW));
	const result = await f.run();
	assert.equal(result.findings.length, 0);
	assert.ok(covered(result).every(c => c.result === 'no-match' && !c.sourceSnapshot.stale));
	assert.ok(!result.diagnostics.some(d => d.code === 'CMS_ADVISORY_STALE'));
});

for (const failure of ['http', 'network', 'malformed', 'incomplete']) test(`Wordfence ${failure} failure preserves positives and never reports a stale clean`, async t => {
	const f = fixture(t, { positive: true });
	f.respond = () => {
		if (failure === 'http') return new Response('', { status: 503 });
		if (failure === 'network') throw new Error('fixture network failure');
		if (failure === 'malformed') return new Response('{');
		return Response.json(projectFeed(new Map(), [QUERIES[0]], NOW));
	};
	const result = await f.run();
	assert.equal(f.calls.length, 1);
	assert.equal(result.findings.length, 1);
	assertStale(result);
	assert.match(result.diagnostics.find(d => d.code === 'CMS_ADVISORY_STALE').message, /revalidation failed/);
	assert.equal(fs.readFileSync(f.file, 'utf8'), f.original, 'failure cannot rewrite or restamp the cache');
});

for (const stale of [false, true]) test(`aged proxy response cannot claim clean, stale=${stale}`, async t => {
	const f = fixture(t);
	f.respond = () => Response.json(projectFeed(new Map(), QUERIES, NOW - 48 * HOUR, stale));
	assertStale(await f.run());
	assert.equal(f.calls.length, 1);
});

test('offline uses aged projection without network, including with a live URL, and retains strict max-age', async t => {
	const f = fixture(t, { positive: true });
	const offline = { offline: true, liveWordfenceUrl: 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production' };
	const result = await f.run(offline);
	assert.equal(result.findings.length, 1);
	assertStale(result);
	assert.equal(f.calls.length, 0);
	assert.equal(fs.readFileSync(f.file, 'utf8'), f.original);
	await assert.rejects(f.run({ ...offline, maxAdvisoryAgeMs: HOUR }), /is stale/);
});

test('online revalidation precedes strict max-age check; failed required source still fails', async t => {
	const f = fixture(t);
	await f.run({ maxAdvisoryAgeMs: HOUR });
	assert.equal(f.calls.length, 1);
	fs.writeFileSync(f.file, f.original);
	f.respond = () => new Response('', { status: 503 });
	await assert.rejects(f.run({ requiredProviderIds: ['wordfence-v3'] }), /advisory source failed/);
	const partial = await f.run({ requiredProviderIds: ['wordfence-v3'], reportProviderFailures: true });
	assertStale(partial);
	assert.match(partial.diagnostics.find(d => d.code === 'CMS_ADVISORY_STALE').message, /revalidation failed/);
	assert.equal(fs.readFileSync(f.file, 'utf8'), f.original);
});

test('aged explicit projection revalidates; without a proxy it remains local and indeterminate', async t => {
	const f = fixture(t);
	await f.run({ wordfenceFeedPath: f.file });
	assert.equal(f.calls.length, 1);
	fs.writeFileSync(f.file, f.original);
	configureResourceRoute({ proxyUrl: null, hosted: false });
	assertStale(await f.run({ wordfenceFeedPath: f.file }));
	assert.equal(f.calls.length, 1, 'no implicit direct bulk refresh');
});

function legacyFixture(t, options = {}) {
	const f = fixture(t, options);
	fs.unlinkSync(f.file);
	f.file = path.join(f.dir, 'wordfence-v3.json');
	const snapshot = { ...f.snapshot.advisories, _fadSnapshot: { ...f.snapshot._fadSnapshot, completeness: 'full' } };
	f.original = JSON.stringify(snapshot);
	fs.writeFileSync(f.file, f.original);
	return f;
}

test('automatic legacy full 48h stale=false cache revalidates targeted and creates only a targeted cache', async t => {
	const f = legacyFixture(t);
	const result = await f.run({ maxAdvisoryAgeMs: HOUR });
	assert.equal(f.calls.length, 1);
	assert.equal(result.findings.length, 1);
	assert.deepEqual(covered(result).map(c => c.result), ['no-match', 'affected']);
	assert.ok(covered(result).every(c => c.sourceSnapshot.completeness === 'targeted' && !c.sourceSnapshot.stale));
	assert.equal(fs.readFileSync(f.file, 'utf8'), f.original, 'legacy catalogue is not rewritten');
	assert.ok(fs.existsSync(path.join(f.dir, CACHE_FILE)));
	await f.run();
	assert.equal(f.calls.length, 1, 'next scan prefers the fresh targeted projection');
});

for (const positive of [false, true]) test(`legacy automatic refresh failure is indeterminate, preserves findings=${positive}`, async t => {
	const f = legacyFixture(t, { positive });
	f.respond = () => new Response('', { status: 503 });
	const result = await f.run();
	assert.equal(f.calls.length, 1);
	assert.equal(result.findings.length, positive ? 1 : 0);
	assertStale(result);
	assert.ok(covered(result).every(c => c.sourceSnapshot.collectedAt === f.snapshot._fadSnapshot.collectedAt));
	assert.equal(fs.readFileSync(f.file, 'utf8'), f.original);
	assert.equal(fs.existsSync(path.join(f.dir, CACHE_FILE)), false);
});

for (const age of [1000, HOUR, HOUR + 1]) test(`automatic legacy cache observes 1h threshold: ${age}ms`, async t => {
	const f = legacyFixture(t, { age });
	await f.run();
	assert.equal(f.calls.length, age > HOUR ? 1 : 0);
});

test('explicit legacy file remains authoritative online/offline, including strict max age', async t => {
	const f = legacyFixture(t);
	for (const offline of [false, true]) {
		const result = await f.run({ wordfenceFeedPath: f.file, offline });
		assert.ok(covered(result).every(c => c.result === 'no-match' && c.execution === 'completed'));
		assert.ok(!result.diagnostics.some(d => d.code === 'CMS_ADVISORY_STALE'));
		await assert.rejects(f.run({ wordfenceFeedPath: f.file, offline, maxAdvisoryAgeMs: HOUR }), /is stale/);
	}
	assert.equal(f.calls.length, 0);
	assert.equal(fs.readFileSync(f.file, 'utf8'), f.original);
});

test('automatic legacy cache stays usable offline with warning and zero network', async t => {
	const f = legacyFixture(t, { positive: true });
	const result = await f.run({ offline: true });
	assert.equal(result.findings.length, 1);
	assertStale(result);
	assert.equal(f.calls.length, 0);
	assert.equal(fs.readFileSync(f.file, 'utf8'), f.original);
});

test('legacy false-clean reproduction produces stale warnings in actual CLI JSON and HTML without external network', t => {
	const f = legacyFixture(t);
	const cache = path.join(f.dir, '.fad-checker', 'advisory-snapshots');
	fs.mkdirSync(cache, { recursive: true });
	fs.copyFileSync(f.file, path.join(cache, 'wordfence-v3.json'));
	const callsFile = path.join(f.dir, 'calls.jsonl');
	const hook = path.join(f.dir, 'proxy-only.cjs');
	fs.writeFileSync(hook, `
		const fs=require('node:fs');
		require('node:os').homedir=()=>${JSON.stringify(f.dir)};
		for(const id of ['http','https']){const m=require(id);m.get=m.request=()=>{throw Error('external network forbidden')}}
		globalThis.fetch=async(url,init={})=>{
			if(String(url)==='https://api.vigievuln.fr/v1/proxy/status')return Response.json({ok:true,service:'vigievuln-proxy'});
			if(String(url)!=='https://api.vigievuln.fr/v1/resource')throw Error('unexpected endpoint');
			const q=JSON.parse(init.body);fs.appendFileSync(${JSON.stringify(callsFile)},JSON.stringify(q)+'\\n');
			return new Response('fixture refusal',{status:410});
		};`);
	const output = path.join(f.dir, 'report');
	const args = [path.join(__dirname, '../vigievuln.js'), '-s', ROOT, '--proxy-cache', 'default', '--retries', '0',
		'--no-transitive', '--no-all-libs', '--no-osv', '--no-nvd', '--no-epss', '--no-kev', '--no-euvd', '--no-certfr',
		'--no-eol', '--no-binaries', '--no-jars', '--no-certs', '--no-packagist-audit', '--no-retire',
		'--ecosystem', 'npm', '--app-plugins', 'wordpress', '--public-component', 'site/wp-content/themes/acme-theme=example',
		'--report-html', '--report-json', '-o', output, '--fail-on-incomplete', 'advisories'];
	const run = require('node:child_process').spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 20000,
		env: { ...process.env, HOME: f.dir, USERPROFILE: f.dir, VIGIEVULN_PROXY_CACHE_TOKEN: 'test-key',
			VIGIEVULN_ENV: '', FAD_CHECKER_ENV: '', NODE_OPTIONS: `--require=${hook}`, FORCE_COLOR: '0' } });
	assert.equal(run.status, 2, `${run.error || ''}\n${run.stderr}\n${run.stdout}`);
	const report = JSON.parse(fs.readFileSync(path.join(output, 'findings.json')));
	assert.ok(report.warnings.some(w => w.code === 'CMS_ADVISORY_STALE' && /revalidation failed/.test(w.message)));
	assert.match(fs.readFileSync(path.join(output, 'cve-report.html'), 'utf8'), /Wordfence snapshot is stale/);
	const calls = fs.readFileSync(callsFile, 'utf8').trim().split('\n').map(JSON.parse);
	assert.equal(calls.length, 1, JSON.stringify(calls));
	assert.equal(calls[0].provider, 'wordfence');
	assert.equal(calls[0].type, 'software');
	assert.deepEqual(calls[0].params.software, QUERIES);
});
