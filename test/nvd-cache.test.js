const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require('node:os');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'vigievuln-nvd-sqlite-test-'));
os.homedir=()=>root;
const N = require("../lib/nvd");
const db=require('../lib/cache-db').getCacheDb(path.dirname(N.NVD_CACHE_DIR));
process.on('exit',()=>{ require('../lib/cache-db').closeCacheDbs(); fs.rmSync(root,{recursive:true,force:true}); });

// Seed an explicit timestamp/schema to exercise online and offline policy.
function withCacheEntry(cveId, { schema, ageMs, body }, fn) {
	const bytes=Buffer.from(JSON.stringify(body));
	db.prepare('INSERT INTO nvd_records(cve,kind,fetched_at,revision_ms,body_deflate,body_bytes,metadata_json) VALUES (?,?,?,?,?,?,?)')
	 .run(cveId,'live',Date.now()-ageMs,null,require('../lib/advisory-compression').compress(bytes),bytes.length,JSON.stringify({schema}));
	const cleanup=()=>db.prepare('DELETE FROM nvd_records WHERE cve=?').run(cveId);
	try { const value=fn(); return value?.then?value.finally(cleanup):(cleanup(),value); }
	catch(error){cleanup();throw error}
}

test('a cached empty NVD answer is distinguishable from missing or corrupt data', () => {
	assert.equal(N.hasCachedAbsence('CVE-2099-99990'), false);
	withCacheEntry('CVE-2099-99991', {schema:3, ageMs:0, body:null}, () => {
		assert.equal(N.hasCachedAbsence('CVE-2099-99991'), true);
	});
	withCacheEntry('CVE-2099-99992', {schema:3, ageMs:0, body:{id:'CVE-2099-99992'}}, () => {
		assert.equal(N.hasCachedAbsence('CVE-2099-99992'), false);
	});
	withCacheEntry('CVE-2099-99993', {schema:3, ageMs:8 * 24 * 3600000, body:null}, () => {
		assert.equal(N.hasCachedAbsence('CVE-2099-99993'), false, 'old negative answers do not certify a current absence');
	});
});

test("readCache OFFLINE returns a TTL-expired warmed body (never drops enrichment); ONLINE rejects it to re-fetch", () => {
	const cveId = "CVE-0000-OFFLINE-TTL-" + process.pid;
	const body = { id: cveId, description: "x", cwes: ["CWE-79", "CWE-89"], severity: "HIGH", score: 7.5 };
	withCacheEntry(cveId, { schema: 2, ageMs: 30 * 24 * 3600 * 1000, body }, () => {
		// online: an entry older than the 7-day TTL is a miss → re-fetch to refresh
		assert.equal(N.readCache(cveId), null, "online must reject a TTL-expired entry");
		// offline: the warmed cache is all we have — return it, CWEs intact
		const got = N.readCache(cveId, true);
		assert.ok(got, "offline must return the stale warmed body, not null");
		assert.deepEqual(got.cwes, ["CWE-79", "CWE-89"], "offline keeps the cached CWE enrichment");
	});
});

test("readCache OFFLINE returns an older-schema warmed body (partial enrichment beats none); ONLINE rejects it", () => {
	const cveId = "CVE-0000-OFFLINE-SCHEMA-" + process.pid;
	// A pre-cwes (schema 1) entry: has description/score but no cwes field.
	const body = { id: cveId, description: "legacy", severity: "MEDIUM", score: 5 };
	withCacheEntry(cveId, { schema: 1, ageMs: 1000, body }, () => {
		assert.equal(N.readCache(cveId), null, "online rejects an older schema so it re-fetches the new fields");
		const got = N.readCache(cveId, true);
		assert.ok(got, "offline returns the older-schema body rather than dropping ALL enrichment");
		assert.equal(got.description, "legacy");
	});
});

test("enrichMatches OFFLINE restores CWEs from a TTL-expired warmed cache (the air-gapped bug)", async () => {
	const cveId = "CVE-0000-OFFLINE-ENRICH-" + process.pid;
	const body = { id: cveId, description: "d", cwes: ["CWE-502"], severity: "CRITICAL", score: 9.8, references: [], cpes: [], configurations: [] };
	await withCacheEntry(cveId, { schema: 2, ageMs: 30 * 24 * 3600 * 1000, body }, async () => {
		const matches = [{ dep: { artifactId: "x" }, cve: { id: cveId, severity: "CRITICAL" }, source: "osv" }];
		await N.enrichMatches(matches, { offline: true });
		assert.deepEqual(matches[0].cve.cwes, ["CWE-502"], "offline enrichment surfaces the warmed CWEs");
	});
});
