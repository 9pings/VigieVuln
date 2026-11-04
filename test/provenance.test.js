const fixtureStores = new Set();
function openFixtureStore(options) {
 const store = require('../lib/advisory-store').openAdvisoryStore(options);
 fixtureStores.add(store);
 return store;
}
function closeFixtureStores() {
 for (const store of fixtureStores) store.close();
 fixtureStores.clear();
 require('../lib/cache-db').closeCacheDbs();
}
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { buildScanProvenance, collectDataSources } = require("../lib/provenance");

function tmpCacheDir() {
	return fs.mkdtempSync(path.join(os.tmpdir(), "fad-prov-"));
}

test("buildScanProvenance records tool, mode and the run configuration", () => {
	const dir = tmpCacheDir();
	try {
		const p = buildScanProvenance({
			toolVersion: "2.3.2",
			generatedAt: "2026-06-18T00:00:00.000Z",
			options: { offline: true, transitive: false, transitiveDepth: "6", osv: false, failOn: "high", ecosystem: "maven,npm" },
			cacheDir: dir,
			runtime: { node: "v20.0.0", platform: "linux", arch: "x64" },
		});
		assert.strictEqual(p.tool.name, "VigieVuln");
		assert.strictEqual(p.tool.version, "2.3.2");
		assert.strictEqual(p.generatedAt, "2026-06-18T00:00:00.000Z");
		assert.strictEqual(p.mode, "offline");
		assert.strictEqual(p.runtime.node, "v20.0.0");
		assert.strictEqual(p.configuration.transitive, false);
		assert.strictEqual(p.configuration.failOn, "high");
		assert.ok(Array.isArray(p.dataSources));
	} finally { closeFixtureStores(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("collectDataSources reads each source's freshness marker", () => {
	const dir = tmpCacheDir();
	try {
		const repository=require('../lib/cache-repository').createCacheRepository(dir);
		repository.putSnapshot('cve_lookup',{fetchedAt:Date.parse('2026-06-01T10:00:00.000Z'),complete:true,recordCount:1234});
		repository.put('catalogue','epss',{ meta: { fetchedAt: Date.parse("2026-06-10T00:00:00.000Z") }, entries: { a: 1, b: 2 } });
		repository.put('catalogue','kev',{ _fetchedAt: Date.parse("2026-06-12T00:00:00.000Z"), body: { catalogVersion: "2026.06.12", dateReleased: "2026-06-12", vulnerabilities: [] } });

		const sources = collectDataSources({ cacheDir: dir, options: {} });
		const by = Object.fromEntries(sources.map(s => [s.id, s]));

		assert.strictEqual(by.cve.status, "cached");
		assert.strictEqual(by.cve.asOf, "2026-06-01T10:00:00.000Z");
		assert.match(by.cve.detail, /1234/);

		assert.strictEqual(by.epss.status, "cached");
		assert.strictEqual(by.epss.asOf, "2026-06-10T00:00:00.000Z");

		assert.strictEqual(by.kev.status, "cached");
		assert.match(by.kev.detail || "", /2026\.06\.12/);
	} finally { closeFixtureStores(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("collectDataSources marks a source disabled by its flag and missing when uncached", () => {
	const dir = tmpCacheDir();
	try {
		const sources = collectDataSources({ cacheDir: dir, options: { osv: false } });
		const by = Object.fromEntries(sources.map(s => [s.id, s]));
		assert.strictEqual(by.osv.status, "disabled");
		assert.strictEqual(by.nvd.status, "missing"); // nvd not disabled, but no cache present
	} finally { closeFixtureStores(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a Maven report omits unrelated ecosystem sources from its provenance table', () => {
	const dir = tmpCacheDir();
	try {
		const sources = collectDataSources({ cacheDir: dir, options: {}, ecosystems: new Set(['maven']) });
		const ids = new Set(sources.map(source => source.id));
		assert.ok(ids.has('cve'));
		assert.ok(!ids.has('osvDb-maven'), 'an optional absent catalogue is not a missing source');
		assert.ok(ids.has('mavenCentral'));
		for (const id of ['osvDb-npm', 'osvDb-pypi', 'osvDb-composer', 'npm', 'nuget', 'packagist', 'go', 'rubygems', 'packagistAudit']) assert.ok(!ids.has(id), id);
	} finally { closeFixtureStores(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("collectDataSources reports OSV coverage from SQLite", () => {
	const dir = tmpCacheDir();
	try {
		const store=openFixtureStore({cacheDir:dir});
		store.commit({coverages:[{source:'osv',ecosystem:'Maven',fetchedAt:Date.now()-1000,complete:true},
		 {source:'osv',ecosystem:'npm',fetchedAt:Date.now()-1000,complete:true}]});
		const sources = collectDataSources({ cacheDir: dir, options: {} });
		const osv = sources.find(s => s.id === "osv");
		assert.strictEqual(osv.status, "cached");
		assert.match(osv.detail, /2 ecosystems/);
		assert.ok(osv.asOf, "has a newest-entry date");
	} finally { closeFixtureStores(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("provenance distinguishes source profiles, GCVE index and derived identifiers", () => {
	const dir = tmpCacheDir();
	try {
		require('../lib/cache-repository').createCacheRepository(dir).put('catalogue','gcve',{ builtAt: "2026-01-01T00:00:00Z", coverage: [{ complete: true }, { complete: false }] });
		openFixtureStore({cacheDir:dir}).commit({coverages:[{source:'osv',ecosystem:'npm',fetchedAt:Date.now()-1000,complete:true}]});
		const p = buildScanProvenance({ cacheDir: dir, options: { sourceProfile: "us", disableGcve: true, disableCveProject: true } });
		const by = Object.fromEntries(p.dataSources.map(s => [s.id, s]));
		assert.equal(p.configuration.sourceProfile, "us");
		assert.equal(by.cve.status, "disabled");
		assert.equal(by.gcve.status, "disabled");
		assert.equal(by.gcveDerived.status, "derived");
		assert.equal(by["osvDb-npm"].status, "cached");
		assert.equal(by["osvDb-maven"].status, "missing");
		const gcve = collectDataSources({ cacheDir: dir }).find(s => s.id === "gcve");
		assert.equal(gcve.status, "cached");
		assert.match(gcve.detail, /2 GNA sources; 1 complete/);
	} finally { closeFixtureStores(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('provenance reads shared source coverage and records query TTL', () => {
 const dir=tmpCacheDir();
 try {
  const store=openFixtureStore({cacheDir:dir});const at=Date.now()-1000;
  store.commit({coverages:[{source:'osv',ecosystem:'npm',fetchedAt:at,complete:true},{source:'gcve',ecosystem:'*',fetchedAt:at,complete:false},{source:'cveproject',ecosystem:'*',fetchedAt:at,complete:false}]});
  store.commit({queries:[{source:'osv',ecosystem:'npm',name:'example',version:'1.0.0',ids:[],complete:true,fetchedAt:at}]});
  const p=buildScanProvenance({cacheDir:dir,options:{advisoryQueryTtl:'0'}}), by=Object.fromEntries(p.dataSources.map(s=>[s.id,s]));
  assert.equal(p.configuration.advisoryQueryTtlHours,0);
  assert.match(by.osv.detail,/1 queried versions; 1 stale/);
  assert.equal(by['osvDb-npm'].status,'cached');assert.match(by['osvDb-npm'].detail,/complete; stale/);
  assert.equal(by.gcve.status,'cached');assert.match(by.gcve.detail,/partial/);
  assert.equal(by.cve.status,'cached');assert.equal(by.cve.asOf,new Date(at).toISOString());
 } finally {closeFixtureStores(); fs.rmSync(dir,{recursive:true,force:true});}
});

test('NVD provenance uses SQLite record collection dates', () => {
 const dir=tmpCacheDir();
 try {
  const db=require('../lib/cache-db').getCacheDb(dir),compress=require('../lib/advisory-compression').compress;
  const earlier=Date.now()-86400000, later=earlier+3600000;
  for (const [at,id] of [[earlier,'CVE-2020-1234'],[later,'CVE-2020-5678']]) {
   const body=Buffer.from(JSON.stringify({id,score:5}));
   db.prepare('INSERT INTO nvd_records(cve,kind,fetched_at,revision_ms,body_deflate,body_bytes,metadata_json) VALUES (?,?,?,?,?,?,?)')
    .run(id,'bulk',at,null,compress(body),body.length,'{}');
  }
  const read=()=>collectDataSources({cacheDir:dir}).find(s=>s.id==='nvd');
  assert.equal(read().status,'cached');
  assert.equal(read().asOf,new Date(earlier).toISOString());
  assert.match(read().detail,/2 cached records/);
  assert.equal(collectDataSources({cacheDir:dir,options:{nvd:false}}).find(s=>s.id==='nvd').status,'disabled');
 } finally {closeFixtureStores(); fs.rmSync(dir,{recursive:true,force:true});}
});

test('NVD provenance rejects an invalid compact manifest without trusting directory mtime', () => {
 const dir=tmpCacheDir(), target=path.join(dir,'nvd-cache');
 try {
  const writer=require('../lib/nvd-bulk').createWriter(target,Date.now()-86400000);
  writer.add('CVE-2020-1234',{id:'CVE-2020-1234'});const result=writer.finish();
  fs.writeFileSync(path.join(target,'_bulk',result.generation,'manifest.json'),'{}');
  const source=collectDataSources({cacheDir:dir}).find(s=>s.id==='nvd');
  assert.equal(source.status,'missing');assert.equal(source.asOf,null);
 } finally {closeFixtureStores(); fs.rmSync(dir,{recursive:true,force:true});}
});
