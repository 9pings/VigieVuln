const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { configureResourceRoute } = require('../lib/providers');
const { createSourceHealth } = require('../lib/source-health');
const { runApplicationPlugins } = require('../lib/application-plugins/runner');
const drupal = require('../lib/application-plugins/drupal');
const composer = require('../lib/codecs/composer.codec');
const CLI = path.resolve(__dirname, '..');
const NOW = Date.now() - 1000;
const OLD = new Date(NOW - 48 * 3600000).toISOString();
const SNAPSHOT = { queriedPackages: ['drupal/core'], advisories: { 'drupal/core': [{
	advisoryId: 'SA-CORE-2099-001', packageName: 'drupal/core', title: 'Old fixture',
	link: '', cve: null, affectedVersions: '>=10.3.0 <10.3.2',
}] }, _fadSnapshot: { collectedAt: OLD, completeness: 'tool-fetched' } };
const REPO = { widget: { extractors: { filename: ['widget-(§§version§§)\\.js'] },
	vulnerabilities: [{ below: '2.0.0', severity: 'high', cwe: ['CWE-79'],
		identifiers: { CVE: ['CVE-2099-1234'] }, info: ['https://example.test/advisory'] }] } };
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-hosted-snapshots-'));
const resetRoute = () => configureResourceRoute({ hosted: false, proxyUrl: null, token: null, store: null, health: null, fetcher: null });

async function drupalFixture(work) {
	const directory = temp();
	try {
		const file = path.join(directory, 'drupal-security-advisories.json');
		fs.writeFileSync(file, JSON.stringify(SNAPSHOT));
		const root = path.join(__dirname, 'fixtures/drupal-custom');
		const { deps } = await composer.collect(root);
		const opts = { plugins: [drupal], selection: 'drupal', activeCodecIds: ['composer'],
			resolvedDeps: deps, advisoryCacheDir: directory, now: NOW };
		await work({ file, root, opts });
	} finally { resetRoute(); fs.rmSync(directory, { recursive: true, force: true }); }
}

test('hosted Drupal revalidates a 48h implicit snapshot on every scan with only public package identities', async () => {
	await drupalFixture(async ({ file, root, opts }) => {
		const calls = [];
		opts.fetchImpl = configureResourceRoute({ hosted: true, proxyUrl: 'https://proxy.invalid', token: 'fixture', store: null, health: null,
			fetcher: async (url, init) => {
				assert.equal(url, 'https://proxy.invalid/v1/resource');
				const request = JSON.parse(init.body); calls.push(request);
				assert.equal(request.provider, 'drupal');
				assert.equal(request.type, 'advisories');
				assert.deepEqual(request.params.packages, ['drupal/core'], 'private acme/payments must stay local');
				return Response.json({ advisories: { 'drupal/core': [] } }, { headers: { 'x-fad-proxy-fetched-at': new Date(NOW).toISOString() } });
			} }).fetcher;
		for (let i = 1; i <= 2; i++) {
			const result = await runApplicationPlugins(root, opts);
			assert.equal(result.findings.length, 0, 'old local finding is not reused');
			assert.equal(calls.length, i, 'even the newly saved snapshot cannot bypass proxy freshness');
			assert.equal(result.coverage.find(c => c.sourceSnapshot)?.sourceSnapshot.collectedAt, new Date(NOW).toISOString());
		}
		assert.equal(JSON.parse(fs.readFileSync(file))._fadSnapshot.collectedAt, new Date(NOW).toISOString());
		fs.writeFileSync(file, 'invalid old snapshot');
		assert.equal((await runApplicationPlugins(root, opts)).findings.length, 0, 'corrupt implicit cache also goes through the proxy');
		assert.equal(calls.length, 3);
	});
});

test('hosted Drupal keeps proxy stale provenance and does not fall back silently on HTTP failure', async () => {
	await drupalFixture(async ({ file, root, opts }) => {
		const health = createSourceHealth();
		opts.fetchImpl = configureResourceRoute({ hosted: true, proxyUrl: 'https://proxy.invalid', store: null, health,
			fetcher: async () => Response.json({ advisories: SNAPSHOT.advisories }, { headers: {
				'x-fad-proxy': 'stale', 'x-fad-proxy-fetched-at': OLD } }) }).fetcher;
		const result = await runApplicationPlugins(root, opts);
		assert.equal(result.findings.length, 1, 'stale results remain usable with a source warning');
		assert.deepEqual(health.stale(), [{ id: 'drupal', at: Date.parse(OLD) }]);
		assert.equal(result.coverage.find(c => c.sourceSnapshot).sourceSnapshot.collectedAt, OLD);
		assert.equal(JSON.parse(fs.readFileSync(file))._fadSnapshot.collectedAt, OLD, 'never restamp stale data as fresh');
		opts.fetchImpl = configureResourceRoute({ hosted: true, proxyUrl: 'https://proxy.invalid', store: null, health: null,
			fetcher: async () => new Response('', { status: 503 }) }).fetcher;
		const failed = await runApplicationPlugins(root, opts);
		assert.equal(failed.findings.length, 0);
		assert.ok(failed.diagnostics.some(d => d.code === 'CMS_PLUGIN_FAILED'));
		assert.ok(failed.coverage.some(c => c.capability === 'advisories' && c.execution === 'failed'));
		assert.equal(JSON.parse(fs.readFileSync(file))._fadSnapshot.collectedAt, OLD);
	});
});

test('Drupal explicit snapshots and offline replay keep priority and max-age checks without any network', async () => {
	await drupalFixture(async ({ file, root, opts }) => {
		let calls = 0;
		opts.fetchImpl = configureResourceRoute({ hosted: true, proxyUrl: 'https://proxy.invalid', store: null, health: null,
			fetcher: async () => { calls++; throw new Error('offline tripwire'); } }).fetcher;
		assert.equal((await runApplicationPlugins(root, { ...opts, drupalAdvisoriesPath: file })).findings.length, 1);
		const offline = { ...opts, offline: true, liveDrupalAdvisoriesUrl: 'https://packages.drupal.org/8/security-advisories' };
		assert.equal((await runApplicationPlugins(root, offline)).findings.length, 1);
		await assert.rejects(runApplicationPlugins(root, { ...offline, maxAdvisoryAgeMs: 24 * 3600000 }), /stale/);
		await assert.rejects(runApplicationPlugins(root, { ...opts, drupalAdvisoriesPath: file, maxAdvisoryAgeMs: 24 * 3600000 }), /stale/);
		fs.unlinkSync(file);
		const cold = await runApplicationPlugins(root, offline);
		assert.ok(cold.coverage.some(c => c.diagnostic === 'CMS_PROVIDER_UNCONFIGURED'));
		assert.equal(calls, 0);
	});
});

// Each Retire reproduction gets its own HOME and a real Retire subprocess. The preload
// blocks fetch/http/https in both parent and child: no upstream request can escape a stub.
function retireFixture(code) {
	const home = temp();
	try {
		const hook = path.join(home, 'deny-network.cjs');
		fs.writeFileSync(hook, `const deny=()=>{throw Error('unexpected direct network')};globalThis.fetch=deny;for(const id of ['http','https']){const m=require(id);m.request=deny;m.get=deny}`);
		const script = `
		const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
		const R=require(${JSON.stringify(path.join(CLI, 'lib/retire'))});
		const {configureResourceRoute}=require(${JSON.stringify(path.join(CLI, 'lib/providers'))});
		const {createSourceHealth}=require(${JSON.stringify(path.join(CLI, 'lib/source-health'))});
		const repo=${JSON.stringify(REPO)},old=${JSON.stringify(OLD)};
		const src=path.join(process.env.HOME,'source');fs.mkdirSync(src);
		fs.writeFileSync(path.join(src,'widget-1.0.0.js'),'// fixture');
		fs.mkdirSync(R.RETIRE_SIG_DIR,{recursive:true});fs.writeFileSync(R.RETIRE_SIG_FILE,'{}');
		fs.utimesSync(R.RETIRE_SIG_FILE,new Date(Date.now()-2*3600000),new Date(Date.now()-2*3600000));
		fs.mkdirSync(R.RETIRE_CACHE_DIR,{recursive:true});
		const cache=path.join(R.RETIRE_CACHE_DIR,R.cacheKey(src));
		fs.writeFileSync(cache,JSON.stringify({_schema:2,_fetchedAt:Date.now()-2*3600000,body:{data:[]}}));
		(async()=>{${code}})().catch(e=>{console.error(e);process.exitCode=1});`;
		const run = spawnSync(process.execPath, ['-e', script], { cwd: CLI, encoding: 'utf8', timeout: 20000,
			env: { ...process.env, HOME: home, USERPROFILE: home, NODE_OPTIONS: `--require=${hook}` } });
		assert.equal(run.status, 0, `${run.error || ''}\n${run.stderr}\n${run.stdout}`);
	} finally { fs.rmSync(home, { recursive: true, force: true }); }
}

test('hosted Retire bypasses 2h findings/signatures and rescans with proxy signatures on every invocation', () => {
	retireFixture(`
		let calls=0;
		configureResourceRoute({hosted:true,proxyUrl:'https://proxy.invalid',store:null,health:null,fetcher:async(url,init)=>{
			assert.equal(url,'https://proxy.invalid/v1/resource');
			const q=JSON.parse(init.body);assert.equal(q.provider,'retire');assert.equal(q.type,'signatures');assert.deepEqual(q.params,{});
			calls++;return Response.json(repo);
		}});
		for(let i=1;i<=2;i++){
			const result=await R.scanWithRetireFull(src);
			assert.equal(result.error,null);assert.equal(calls,i);
			assert.equal(result.matches[0]?.cve.id,'CVE-2099-1234');assert.equal(result.inventory[0]?.component,'widget');
		}
		assert.deepEqual(JSON.parse(fs.readFileSync(R.RETIRE_SIG_FILE)),repo);
	`);
});

test('hosted Retire records stale proxy responses and cannot hide them behind newly cached findings', () => {
	retireFixture(`
		const health=createSourceHealth();let calls=0;
		configureResourceRoute({hosted:true,proxyUrl:'https://proxy.invalid',store:null,health,fetcher:async()=>{
			calls++;return Response.json(repo,{headers:{'x-fad-proxy':'stale','x-fad-proxy-fetched-at':old}});
		}});
		for(let i=0;i<2;i++)assert.equal((await R.scanWithRetireFull(src)).matches.length,1);
		assert.equal(calls,2);assert.deepEqual(health.stale(),[{id:'retire',at:Date.parse(old)}]);
	`);
});

test('hosted Retire failed or invalid refresh preserves offline signatures and skips without a direct fallback', () => {
	retireFixture(`
		for(const fetcher of [async()=>new Response('',{status:503}),async()=>{throw Error('proxy down')},async()=>new Response('broken JSON'),async()=>Response.json(null)]){
			configureResourceRoute({hosted:true,proxyUrl:'https://proxy.invalid',store:null,health:null,fetcher});
			const result=await R.scanWithRetireFull(src);
			assert.match(result.error,/signatures.*hosted proxy/);assert.equal(result.matches.length,0);
			assert.equal(fs.readFileSync(R.RETIRE_SIG_FILE,'utf8'),'{}');
			assert.deepEqual(JSON.parse(fs.readFileSync(cache)).body,{data:[]});
		}
		fs.unlinkSync(R.RETIRE_SIG_FILE);
		assert.match((await R.scanWithRetireFull(src)).error,/no direct fallback/);
	`);
});

test('Retire offline honors cached findings, forced local scans and cold-cache zero-network even with hosted route', () => {
	retireFixture(`
		let calls=0;configureResourceRoute({hosted:true,proxyUrl:'https://proxy.invalid',store:null,health:null,fetcher:async()=>{calls++;throw Error('network')}});
		fs.writeFileSync(R.RETIRE_SIG_FILE,JSON.stringify(repo));
		assert.equal((await R.scanWithRetireFull(src,{offline:true})).matches.length,0,'findings cache stays available offline');
		assert.equal((await R.warmRetireSignatures({offline:true,force:true})).ok,true);
		assert.equal((await R.scanWithRetireFull(src,{offline:true,force:true})).matches.length,1);
		fs.unlinkSync(R.RETIRE_SIG_FILE);fs.unlinkSync(cache);
		assert.equal((await R.warmRetireSignatures({offline:true,force:true})).ok,false);
		assert.equal(await R.runRetire(src,{offline:true}),null);
		assert.equal(calls,0);
	`);
});

test('non-hosted Retire preserves its existing local cache behavior', () => {
	retireFixture(`
		let calls=0;configureResourceRoute({hosted:false,proxyUrl:'https://private-proxy.invalid',store:null,health:null,fetcher:async()=>{calls++;throw Error('network')}});
		assert.deepEqual(await R.runRetire(src),{data:[]});
		assert.equal(await R.ensureSignatures(),true);
		assert.equal((await R.warmRetireSignatures()).cached,true);assert.equal(calls,0);
	`);
});

test('hosted Drupal/Retire stale warnings reach HTML/JSON and the strict sources gate despite warm local caches', () => {
	const home = temp();
	try {
		const src = path.join(home, 'source');
		fs.mkdirSync(src);
		fs.writeFileSync(path.join(src, 'webform.info.yml'), 'name: Webform\ntype: module\nproject: webform\nversion: 1.0.0\ncore_version_requirement: ^10\n');
		fs.writeFileSync(path.join(src, 'widget-1.0.0.js'), '// fixture');
		const cacheRoot = path.join(home, '.vigie-vuln');
		for (const directory of ['advisory-snapshots', 'retire-signatures', 'retire-cache']) fs.mkdirSync(path.join(cacheRoot, directory), { recursive: true });
		fs.writeFileSync(path.join(cacheRoot, 'advisory-snapshots/drupal-security-advisories.json'), JSON.stringify(SNAPSHOT));
		fs.writeFileSync(path.join(cacheRoot, 'retire-signatures/jsrepository-v5.json'), '{}');
		const key = require('node:crypto').createHash('md5').update(path.resolve(src)).digest('hex');
		fs.writeFileSync(path.join(cacheRoot, 'retire-cache', key + '.json'), JSON.stringify({ _schema: 2, _fetchedAt: Date.now() - 2 * 3600000, body: { data: [] } }));
		const callsFile = path.join(home, 'calls.jsonl');
		const hook = path.join(home, 'proxy-only.cjs');
		fs.writeFileSync(hook, `
		const fs=require('node:fs');
		for(const id of ['http','https']){const m=require(id);m.get=m.request=()=>{throw Error('direct network forbidden')}}
		globalThis.fetch=async(url,init={})=>{
			if(String(url)==='https://api.vigievuln.fr/v1/proxy/status')return Response.json({ok:true,service:'vigievuln-proxy'});
			if(String(url)!=='https://api.vigievuln.fr/v1/resource')throw Error('unexpected endpoint');
			const q=JSON.parse(init.body);fs.appendFileSync(${JSON.stringify(callsFile)},JSON.stringify(q)+'\\n');
			const headers=process.env.VV_STALE==='1'?{'x-fad-proxy':'stale','x-fad-proxy-fetched-at':${JSON.stringify(OLD)}}:{};
			if(q.provider==='drupal' && q.type==='advisories')return Response.json({advisories:{}},{headers});
			if(q.provider==='retire' && q.type==='signatures')return Response.json(${JSON.stringify(REPO)},{headers});
			throw Error('unexpected resource: '+q.provider+'.'+q.type);
		};`);
		const env = { ...process.env, HOME: home, USERPROFILE: home, VIGIEVULN_PROXY_CACHE_TOKEN: 'test-key',
			VIGIEVULN_ENV: '', FAD_CHECKER_ENV: '', NODE_OPTIONS: `--require=${hook}`, FORCE_COLOR: '0' };
		for (const stale of [true, false]) {
			const output = path.join(home, stale ? 'stale-report' : 'fresh-report');
			const args = [path.join(CLI, 'vigievuln.js'), '-s', src, '--proxy-cache', 'default', '--retries', '0',
				'--no-transitive', '--no-all-libs', '--no-osv', '--no-nvd', '--no-epss', '--no-kev', '--no-euvd', '--no-certfr',
				'--no-eol', '--no-binaries', '--no-jars', '--no-certs', '--no-packagist-audit', '--app-plugins', 'drupal', '--scan-context', 'component',
				'--report-html', '--report-json', '-o', output, '--fail-on-incomplete', 'sources'];
			const run = spawnSync(process.execPath, args, { env: { ...env, VV_STALE: stale ? '1' : '0' }, encoding: 'utf8', timeout: 20000 });
			assert.equal(run.status, stale ? 2 : 0, `${run.error || ''}\n${run.stderr}\n${run.stdout}`);
			const report = JSON.parse(fs.readFileSync(path.join(output, 'findings.json')));
			const warnings = report.warnings.filter(w => w.type === 'source-stale');
			if (stale) {
				for (const source of ['drupal', 'retire']) assert.ok(warnings.some(w => w.message.startsWith(source + ':') && w.message.includes(OLD)));
				const html = fs.readFileSync(path.join(output, 'cve-report.html'), 'utf8');
				assert.ok(html.includes(OLD));
				assert.match(html, /drupal: the source could not be refreshed/);
				assert.match(html, /retire: the source could not be refreshed/);
			} else assert.deepEqual(warnings, []);
		}
		const calls = fs.readFileSync(callsFile, 'utf8').trim().split('\n').map(JSON.parse);
		assert.deepEqual(calls.map(q => q.provider + '.' + q.type), ['drupal.advisories', 'retire.signatures', 'drupal.advisories', 'retire.signatures']);
		assert.ok(calls.filter(q => q.provider === 'drupal').every(q => JSON.stringify(q.params.packages) === '["drupal/webform"]'));
	} finally { fs.rmSync(home, { recursive: true, force: true }); }
});
