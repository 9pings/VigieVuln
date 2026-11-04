// Golden answers are explicit fixtures: the online oracle never calls the local
// range evaluator, so a shared matching bug cannot make this comparison pass.
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
// Set the active root BEFORE loading any product module: resolving the default
// cache can migrate legacy directories even when queries later pass cacheDir.
const fallbackCache = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-osv-parity-root-'));
const realHomedir = os.homedir;
os.homedir = () => fallbackCache;
require('../lib/cache-directory').setActiveCacheDir(fallbackCache);
after(() => { os.homedir = realHomedir; require('../lib/cache-db').closeCacheDbs(); fs.rmSync(fallbackCache, { recursive: true, force: true }); });
const { makeDepRecord } = require('../lib/dep-record');
const { queryOsvForDeps, queryBatch } = require('../lib/osv');
const { newOsvIndex, addOsvRecord, matchOsvDbDeps, matchOsvDbRecords } = require('../lib/osv-db');
const { configureResourceRoute } = require('../lib/providers');
const { createResourceEngine } = require('../lib/resource-cache/engine');
const { createCacheStore } = require('../lib/resource-cache/fs-store');

const temporary = t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-osv-parity-'));
  t.after(() => { require('../lib/cache-db').closeCacheDbs(); fs.rmSync(dir, { recursive: true, force: true }); });
  return dir;
};
const resetRoute = () => configureResourceRoute({ proxyUrl: null, hosted: false, token: null,
  store: null, hostedStore: null, health: null, fetcher: null });
const depFor = (version, extra = {}) => makeDepRecord({ ecosystem: 'maven', namespace: 'org.example',
  name: 'widget', version, manifestPath: 'pom.xml', ...extra });
const depMap = (...deps) => new Map(deps.map(dep => [dep.coordKey, dep]));
const advisory = (id, ranges, extra = {}) => ({ id, aliases: [`CVE-2099-${id.slice(-4)}`],
  summary: 'Parity fixture', details: 'Fixture details.', published: '2026-01-01T00:00:00Z',
  modified: '2026-02-01T00:00:00Z', database_specific: { severity: 'HIGH' },
  references: [{ type: 'ADVISORY', url: 'https://example.test/advisory' }],
  affected: [{ package: { ecosystem: 'Maven', name: 'org.example:widget' }, ranges }], ...extra });
const records = [
  advisory('GHSA-parity-1001', [{ type: 'ECOSYSTEM', events: [{ fixed: '2.0' }, { introduced: '1.0' }] }]),
  advisory('GHSA-parity-1002', [{ type: 'ECOSYSTEM', events: [{ last_affected: '3.2' }, { introduced: '3.0' }] }]),
  advisory('GHSA-parity-1003', [{ type: 'ECOSYSTEM', events: [{ limit: '4.5' }, { introduced: '4.0' }] }]),
  advisory('GHSA-parity-1004', [], { affected: [{ package: { ecosystem: 'Maven', name: 'org.example:widget' }, versions: ['5.0'] }] }),
];
const golden = new Map([['0.9', []], ['1.0', ['GHSA-parity-1001']], ['1.7', ['GHSA-parity-1001']],
  ['2.0', []], ['3.0', ['GHSA-parity-1002']], ['3.2', ['GHSA-parity-1002']], ['3.2.1', []],
  ['4.0', ['GHSA-parity-1003']], ['4.4', ['GHSA-parity-1003']], ['4.5', []], ['5.0', ['GHSA-parity-1004']]]);
const normalized = matches => matches.map(m => ({ coordKey: m.dep.coordKey, version: m.dep.version,
  source: m.source, confidence: m.confidence, cve: m.cve })).sort((a, b) =>
  `${a.coordKey}|${a.version}|${a.cve.id}`.localeCompare(`${b.coordKey}|${b.version}|${b.cve.id}`));
function oracle(advisories = records, answers = golden) {
  return async (url, init) => {
    if (url.endsWith('/querybatch')) {
      const queries = JSON.parse(init.body).queries;
      return Response.json({ results: queries.map(q => {
        assert.equal(q.package.ecosystem, 'Maven');
        assert.equal(q.package.name, 'org.example:widget');
        assert.ok(answers.has(q.version), `unexpected queried version ${q.version}`);
        const ids = answers.get(q.version);
        return ids.length ? { vulns: ids.map(id => ({ id })) } : {};
      }) });
    }
    const id = decodeURIComponent(new URL(url).pathname.split('/').pop());
    const record = advisories.find(v => v.id === id);
    assert.ok(record, `unexpected advisory ${id}`);
    return Response.json(record);
  };
}
function seed(dir, ecosystem, advisories) {
  const recordsFile = path.join(dir, `${ecosystem}-records.jsonl`);
  const bytes = Buffer.from(advisories.map(v => JSON.stringify(v)).join('\n') + (advisories.length ? '\n' : ''));
  fs.writeFileSync(recordsFile, bytes);
  return { recordsFile, ecosystem, recordCount: advisories.length,
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'), complete: true, _builtAt: Date.now() };
}
async function proxy(t, dir, fetcher) {
  const engine = createResourceEngine({ store: createCacheStore(path.join(dir, 'proxy')), fetcher });
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk)).on('end', () => {
      engine.handleResource(JSON.parse(Buffer.concat(chunks).toString()), response).catch(error => {
        if (!response.headersSent) response.writeHead(502);
        response.end(error.message);
      });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}

test('OSV golden boundary answers and full findings agree through direct, real proxy, warm cache, index and seed', async t => {
  const dir = temporary(t); resetRoute(); t.after(resetRoute);
  const dep = depFor('5.0'); dep.versions = [...golden.keys()];
  const deps = depMap(dep), fetcher = oracle();
  const directDir = path.join(dir, 'direct');
  const direct = await queryOsvForDeps(deps, { fetcher, cacheDir: directDir, onProgress() {} });
  assert.deepEqual(direct.map(m => [m.dep.version, m.cve.id]).sort(), [...golden].flatMap(([v, ids]) =>
    ids.map(id => [v, `CVE-2099-${id.slice(-4)}`])).sort());
  const tripwire = async () => { assert.fail('offline cache attempted network access'); };
  const warm = await queryOsvForDeps(deps, { offline: true, fetcher: tripwire, cacheDir: directDir });
  assert.deepEqual(normalized(warm), normalized(direct));
  const index = newOsvIndex('Maven'); for (const record of records) addOsvRecord(index, record);
  assert.deepEqual(normalized(matchOsvDbDeps(deps, index)), normalized(direct));
  assert.deepEqual(normalized(await matchOsvDbRecords(deps, seed(dir, 'Maven', records))), normalized(direct));
  const proxyUrl = await proxy(t, dir, fetcher);
  configureResourceRoute({ proxyUrl, hosted: true, token: 'fixture-token' });
  const proxied = await queryOsvForDeps(deps, { cacheDir: path.join(dir, 'proxied'), onProgress() {} });
  assert.deepEqual(normalized(proxied), normalized(direct));
});

test('an advisory learned for version A also evaluates version B never queried online, with or without a seed', async t => {
  const dir = temporary(t); resetRoute(); t.after(resetRoute);
  await queryOsvForDeps(depMap(depFor('1.0')), { fetcher: oracle(), cacheDir: path.join(dir, 'warm'), onProgress() {} });
  const unknown = [], unqueried = depMap(depFor('1.7'));
  const cacheOnly = await queryOsvForDeps(unqueried, { offline: true, cacheDir: path.join(dir, 'warm'), onWarning: w => unknown.push(w),
    fetcher: async () => assert.fail('offline network') });
  const fromSeed = await matchOsvDbRecords(unqueried, seed(dir, 'Maven', records));
  const live = await queryOsvForDeps(unqueried, { fetcher: oracle(), cacheDir: path.join(dir, 'live'), onProgress() {} });
  assert.deepEqual(normalized(cacheOnly), normalized(live), 'stored advisory ranges cover the unseen version');
  assert.ok(unknown.length, 'a finding from known ranges does not prove complete coverage of an unqueried version');
  assert.deepEqual(normalized(fromSeed), normalized(live));
});

test('withdrawn details never become findings through direct, proxy or seed', async t => {
  const dir = temporary(t); resetRoute(); t.after(resetRoute);
  const withdrawn = advisory('GHSA-parity-1999', [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }],
    { withdrawn: '2026-03-01T00:00:00Z' });
  const deps = depMap(depFor('1.7'));
  const fetcher = oracle([withdrawn], new Map([['1.7', [withdrawn.id]]]));
  for (const mode of ['direct', 'proxy']) {
    if (mode === 'proxy') configureResourceRoute({ proxyUrl: await proxy(t, dir, fetcher), hosted: true });
    const matches = await queryOsvForDeps(deps, { fetcher: mode === 'direct' ? fetcher : globalThis.fetch,
      cacheDir: path.join(dir, mode), onProgress() {} });
    assert.deepEqual(matches, [], `${mode}: a withdrawn advisory is not an active vulnerability`);
  }
  assert.deepEqual(await matchOsvDbRecords(deps, seed(dir, 'Maven', [withdrawn])), []);
});

test('embedded JAR coordinates retain their own findings through online, local index and seed', async t => {
  const dir = temporary(t); resetRoute(); t.after(resetRoute);
  const { zipSync, strToU8 } = require('fflate');
  const { scanEmbeddedJars } = require('../lib/codecs/maven/jar-scan');
  const project = path.join(dir, 'project'); fs.mkdirSync(project);
  const jar = zipSync({ 'META-INF/maven/org.example/widget/pom.properties':
    strToU8('groupId=org.example\nartifactId=widget\nversion=1.7\n') });
  fs.writeFileSync(path.join(project, 'app.war'), zipSync({ 'WEB-INF/lib/widget.jar': jar }));
  const inventory = await scanEmbeddedJars(project, { srcRoot: project });
  const embedded = inventory.deps.find(d => d.name === 'widget');
  assert.ok(embedded, 'the nested JAR coordinate must be discovered from pom.properties');
  assert.equal(embedded.provenance, 'embedded');
  assert.match(embedded.coordKey, /app\.war!\/WEB-INF\/lib\/widget\.jar/);
  const deps = depMap(depFor('1.7'), embedded);
  const live = await queryOsvForDeps(deps, { fetcher: oracle(), cacheDir: path.join(dir, 'live'), onProgress() {} });
  assert.equal(live.length, 2);
  const index = newOsvIndex('Maven'); records.forEach(r => addOsvRecord(index, r));
  assert.deepEqual(normalized(matchOsvDbDeps(deps, index)), normalized(live));
  assert.deepEqual(normalized(await matchOsvDbRecords(deps, seed(dir, 'Maven', records))), normalized(live));
});

test('unsupported ranges and version spellings remain explicit unknowns in both offline backends', async t => {
  const dir = temporary(t);
  for (const [ecosystem, name, version, range] of [
    ['PyPI', 'some_pkg', '1.0rc1', { type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.0' }] }],
    ['npm', 'widget', 'not-semver', { type: 'SEMVER', events: [{ introduced: '0' }] }],
    ['Maven', 'org.example:widget', '1.7', { type: 'GIT', repo: 'https://example.test/repo', events: [{ introduced: '0' }] }],
  ]) {
    const codec = { PyPI: 'pypi', npm: 'npm', Maven: 'maven' }[ecosystem];
    const dep = depFor(version, { ecosystem: codec, namespace: codec === 'maven' ? 'org.example' : '', name: codec === 'maven' ? 'widget' : name });
    const record = { id: 'OSV-unsupported', affected: [{ package: { ecosystem, name }, ranges: [range] }] };
    const index = newOsvIndex(ecosystem); addOsvRecord(index, record);
    for (const backend of ['index', 'seed']) {
      const unknown = [], opts = { onUnknown: item => unknown.push(item) };
      const matches = backend === 'index' ? matchOsvDbDeps(depMap(dep), index, opts)
        : await matchOsvDbRecords(depMap(dep), seed(dir, ecosystem, [record]), opts);
      assert.deepEqual(matches, []);
      assert.equal(unknown.length, 1, `${ecosystem}/${backend}: missing semantic support must be visible`);
      assert.equal(unknown[0].advisory, record.id);
    }
  }
});

test('distinct Go package paths cannot overwrite each other in the warmed query cache', async t => {
  const dir = temporary(t); resetRoute(); t.after(resetRoute);
  const names = ['example.org/a/b', 'example.org/a_b'];
  const deps = names.map(name => makeDepRecord({ ecosystem: 'go', name, version: '1.0.0' }));
  const fetcher = async (url, init) => {
    if (url.endsWith('/querybatch')) return Response.json({ results: JSON.parse(init.body).queries.map(q =>
      ({ vulns: [{ id: names.indexOf(q.package.name) === 0 ? 'GO-parity-1' : 'GO-parity-2' }] })) });
    const id = new URL(url).pathname.split('/').pop(), name = names[id.endsWith('1') ? 0 : 1];
    return Response.json({ id, affected: [{ package: { ecosystem: 'Go', name }, versions: ['1.0.0'] }] });
  };
  const live = await queryBatch(deps, { cacheDir: dir, fetcher, onProgress() {} });
  const warm = await queryBatch(deps, { offline: true, cacheDir: dir,
    fetcher: async () => assert.fail('offline network') });
  assert.deepEqual(normalized(warm), normalized(live));
  assert.equal(warm.find(m => m.dep.name === names[0]).cve.id, 'GO-parity-1');
  assert.equal(warm.find(m => m.dep.name === names[1]).cve.id, 'GO-parity-2');
});

test('legacy query files with ambiguous package identity cannot certify a colliding Go name', async t => {
  const dir = temporary(t); resetRoute(); t.after(resetRoute);
  const dep = makeDepRecord({ ecosystem: 'go', name: 'example.org/a/b', version: '1.0.0' });
  // Pre-common-store schema 2 encodes '/' as '_' and records no original tuple.
  // This could equally be the result for the distinct package example.org/a_b.
  const oldKey = 'go____example.org_a_b__1.0.0.json';
  fs.writeFileSync(path.join(dir, oldKey), JSON.stringify({ _schema: 2, _fetchedAt: Date.now(), body: [] }));
  const warnings = [];
  assert.deepEqual(await queryBatch([dep], { cacheDir: dir, offline: true,
    onWarning: warning => warnings.push(warning), fetcher: async () => assert.fail('offline network') }), []);
  assert.ok(warnings.length, 'an empty legacy file without identity is unknown, not evidence that the package is clean');
  let calls = 0;
  assert.deepEqual(await queryBatch([dep], { cacheDir: dir,
    fetcher: async () => { calls++; return Response.json({ results: [{}] }); }, onProgress() {} }), []);
  assert.equal(calls, 1, 'online must establish a new tuple-specific proof');
});

test('npm full findings are identical online and in the seed without Maven-only fix ordering', async t => {
  const dir = temporary(t); resetRoute(); t.after(resetRoute);
  const dep = makeDepRecord({ ecosystem: 'npm', name: '@scope/widget', version: '1.2.0' });
  const record = { id: 'GHSA-npm-parity', affected: [{ package: { ecosystem: 'npm', name: '@scope/widget' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.3.0' }] }] }] };
  const live = await queryBatch([dep], { cacheDir: path.join(dir, 'live'), onProgress() {}, fetcher: async url =>
    Response.json(url.endsWith('/querybatch') ? { results: [{ vulns: [{ id: record.id }] }] } : record) });
  assert.deepEqual(normalized(await matchOsvDbRecords(depMap(dep), seed(dir, 'npm', [record]))), normalized(live));
});
