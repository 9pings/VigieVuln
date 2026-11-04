const isolatedTestCache = require('./helpers/isolated-cache')('osv-cache-integrity');
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { queryBatch, cacheKey } = require("../lib/osv");
const { providerKey } = require("../lib/providers");
const { openAdvisoryStore } = require('../lib/advisory-store');
const dep = name => ({ ecosystem: "maven", namespace: "org.example", groupId: "org.example",
	name, artifactId: name, version: "1.0", versions: ["1.0"] });
const response = body => ({ ok: true, json: async () => body });
const advisory = id => ({ id, summary: "Synthetic test advisory", database_specific: { severity: "HIGH" } });
function fixture(t) {
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-osv-integrity-"));
	const store = openAdvisoryStore({ cacheDir });
	t.after(() => { store.close(); require('../lib/cache-db').closeCacheDbs(); fs.rmSync(cacheDir, { recursive: true, force: true }); });
	const tuple = d => ({ source: 'osv', ecosystem: 'Maven', name: `${d.groupId}:${d.name}`, version: d.version });
	const seed = (d, id, fetchedAt = Date.now() - 48 * 3600e3) => store.commit({
		records: [{ source: 'osv', document: advisory(id), fetchedAt }],
		queries: [{ ...tuple(d), ids: [id], fetchedAt, complete: true }],
	});
	const write = (name, body, stamp = Date.now() - 48 * 3600e3) => {
		const file = path.join(cacheDir, 'osv-cache', name);
		fs.mkdirSync(path.dirname(file), { recursive: true });
		fs.writeFileSync(file, JSON.stringify({ _fetchedAt: stamp, body }));
	};
	return { cacheDir, store, tuple, seed, write, read: name => fs.readFileSync(path.join(cacheDir, 'osv-cache', name), "utf8") };
}
test("OSV trims Maven property whitespace before sending a batch", async t => {
	const f = fixture(t), d = { ...dep("demo"), version: "1.0.0.Final\r\n        " };
	let sent;
	await queryBatch([d], { cacheDir: f.cacheDir, fetcher: async (_url, opts) => {
		sent = JSON.parse(opts.body).queries;
		return response({ results: [{}] });
	} });
	assert.equal(sent[0].version, "1.0.0.Final");
});
for (const failure of ["503", "network", "json", "truncated", "null", "bad-id"]) {
	test(`OSV ${failure}: failed refresh preserves the previous package snapshot byte for byte`, async t => {
		const f = fixture(t), d = dep("demo");
		f.seed(d, 'FAD-OLD');
		const before = f.store.getQuery(f.tuple(d));
		const fetcher = async () => {
			if (failure === "503") return { ok: false, status: 503 };
			if (failure === "network") throw new Error("ECONNRESET");
			if (failure === "json") return { ok: true, json: async () => { throw new Error("invalid JSON"); } };
			return response({ results: failure === "truncated" ? [] : failure === "null" ? [null] : [{ vulns: [{ id: "../../outside" }] }] });
		};
		await assert.rejects(queryBatch([d], { cacheDir: f.cacheDir, fetcher }), { code: "OSV_INCOMPLETE" });
		assert.deepEqual(f.store.getQuery(f.tuple(d)), before, 'no partial transaction or timestamp is published');
		const offline = await queryBatch([d], { cacheDir: f.cacheDir, offline: true, fetcher: () => assert.fail("network") });
		assert.equal(offline[0].cve.id, "FAD-OLD");
	});
}
test("OSV missing advisory details cannot replace a complete old snapshot", async t => {
	const f = fixture(t), d = dep("demo");
	f.seed(d, 'FAD-OLD');
	const before = f.store.getQuery(f.tuple(d));
	await assert.rejects(queryBatch([d], { cacheDir: f.cacheDir, onProgress() {},
		fetcher: async url => url.includes("querybatch")
			? response({ results: [{ vulns: [{ id: "FAD-NEW" }] }] }) : { ok: false, status: 404 },
	}), { code: "OSV_INCOMPLETE" });
	assert.deepEqual(f.store.getQuery(f.tuple(d)), before);
	assert.deepEqual(f.store.getQuery(f.tuple(d)).ids, ['FAD-OLD']);
});
test('an old exact OSV consultation remains flagged despite a fresh catalogue', async t => {
	const f = fixture(t), d = dep('demo');
	f.seed(d, 'FAD-OLD');
	f.store.commit({coverages:[{source:'osv',ecosystem:'Maven',fetchedAt:Date.now(),complete:true,provenance:{transport:'seed'}}]});
	const warnings=[];
	const matches=await queryBatch([d],{cacheDir:f.cacheDir,offline:true,onWarning:w=>warnings.push(w),fetcher:()=>assert.fail('network')});
	assert.equal(matches.length,1);
	assert.ok(warnings.some(w=>w.type==='source-stale'));
});
test('multiple stale OSV consultations produce one bounded warning', async t => {
	const f=fixture(t), deps=Array.from({length:8},(_,i)=>dep(`demo${i}`));
	for(const d of deps) f.seed(d,`FAD-${d.name}`);
	const warnings=[];
	const matches=await queryBatch(deps,{cacheDir:f.cacheDir,offline:true,onWarning:w=>warnings.push(w)});
	assert.equal(matches.length,8);
	assert.equal(warnings.filter(w=>w.type==='source-stale').length,1);
	assert.match(warnings[0].message,/8 freshness notices/);
	assert.match(warnings[0].message,/cached advisory data is used offline/);
	assert.match(warnings[0].message,/Oldest saved data: \d{4}-\d\d-\d\dT/);
	assert.doesNotMatch(warnings[0].message,/org\.example:demo/);
});
test("OSV pagination queries only unfinished packages and persists every unique advisory", async t => {
	const f = fixture(t), queries = [];
	const d = dep("demo"), other = dep("other");
	const fetcher = async (url, opts) => {
		if (!url.includes("querybatch")) return response(advisory(decodeURIComponent(url.split("/").at(-1))));
		const q = JSON.parse(opts.body).queries; queries.push(q);
		return response({ results: q[0].page_token
			? [{ vulns: [{ id: "FAD-A" }, { id: "FAD-B" }] }]
			: [{ vulns: [{ id: "FAD-A" }], next_page_token: "page-two" }, {}] });
	};
	const matches = await queryBatch([d, other], { cacheDir: f.cacheDir, fetcher, onProgress() {} });
	assert.deepEqual(matches.map(m => m.cve.id), ["FAD-A", "FAD-B"]);
	assert.equal(queries[0].length, 2);
	assert.equal(queries[1].length, 1);
	assert.equal(queries[1][0].page_token, "page-two");
	assert.deepEqual(f.store.getQuery(f.tuple(d)).ids, ["FAD-A", "FAD-B"]);
	assert.deepEqual(f.store.getQuery(f.tuple(other)).ids, []);
	assert.ok(f.store.getRecord('osv', 'FAD-A'));
	assert.ok(f.store.getRecord('osv', 'FAD-B'));
	const base = { ecosystem: "Maven", name: "org.example:demo", version: "1.0" };
	assert.notEqual(providerKey("osv", "package-version", base),
		providerKey("osv", "package-version", { ...base, page_token: "page-two" }));
});
test("OSV repeated page tokens fail without caching partial results", async t => {
	const f = fixture(t);
	await assert.rejects(queryBatch([dep("demo")], { cacheDir: f.cacheDir,
		fetcher: async () => response({ results: [{ next_page_token: "loop" }] }),
	}), { code: "OSV_INCOMPLETE" });
	assert.equal(f.store.getQuery(f.tuple(dep('demo'))), null);
	assert.equal(f.store.db.prepare('SELECT COUNT(*) count FROM advisory_records').get().count,0,'pagination failure creates no advisory records');
});
test("OSV offline missing package/detail data emits a coverage warning without network", async t => {
	const f = fixture(t), d = dep("demo"), warnings = [];
	f.write(cacheKey(d.groupId, d.name, d.version), ["FAD-MISSING"]);
	const result = await queryBatch([d, dep("cold")], { cacheDir: f.cacheDir, offline: true,
		fetcher: () => assert.fail("network"), onWarning: w => warnings.push(w) });
	assert.deepEqual(result, []);
	assert.equal(warnings.length, 1, 'missing offline consultations are summarized once per ecosystem');
	assert.ok(warnings.every(w => w.type === 'osv-coverage'));
	assert.doesNotMatch(warnings[0].message, /seed/i, 'a seed is optional');
	for (const name of ['demo', 'cold']) assert.ok(warnings.some(w => w.message.includes(`org.example:${name}@1.0`)), `${name} is explicitly unverified`);
});

test("OSV legacy empty lists are unknown offline and refreshed online; new verified empty lists are reusable", async t => {
	const f = fixture(t), d = dep("demo"), ck = cacheKey(d.groupId, d.name, d.version), warnings = [];
	f.write(ck, [], Date.now());
	await queryBatch([d], { cacheDir: f.cacheDir, offline: true, onWarning: w => warnings.push(w) });
	assert.equal(warnings.length, 1);
	let calls = 0;
	await queryBatch([d], { cacheDir: f.cacheDir, fetcher: async () => {
		calls++; return response({ results: [{}] });
	} });
	assert.equal(calls, 1);
	assert.deepEqual(f.store.getQuery(f.tuple(d)).ids, []);
	assert.equal(f.store.getQuery(f.tuple(d)).complete, true);
	assert.equal(JSON.parse(f.read(ck))._schema, undefined, 'an ambiguous legacy file is not promoted into verified evidence');
	await queryBatch([d], { cacheDir: f.cacheDir, offline: true, onWarning: () => assert.fail("verified empty is complete") });
});
