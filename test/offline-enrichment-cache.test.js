const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { execFileSync } = require("node:child_process");

for (const kind of ["kev", "hash-id"]) {
	test(`${kind}: stale offline cache retains evidence without network or timestamp changes`, t => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-enrichment-age-"));
		t.after(() => fs.rmSync(root, { recursive: true, force: true }));
		execFileSync(process.execPath, ["-e", `
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
require("node:os").homedir = () => process.argv[2];
const kind = process.argv[1], mod = require(path.resolve("lib", kind));
const id = "CVE-2099-99999", hash = "a".repeat(64);
const identity = { name: "synthetic-test-binary", source: "circl:test", knownMalicious: true };
const stamp = Date.now() - 72 * 3600e3;
const body = kind === "kev"
	? { _fetchedAt: stamp, body: { byId: { [id]: { dateAdded: "2099-01-01", dueDate: "2099-02-01", ransomware: true } } } }
	: { _fetchedAt: stamp, entries: { [hash]: identity } };
const repo=require(path.resolve('lib/cache-repository')).createCacheRepository(path.join(process.argv[2],'.vigie-vuln'));
const namespace=kind==='kev'?'catalogue':'auxiliary',key=kind==='kev'?'kev':'hash-id';
repo.put(namespace,key,body,{fetchedAt:stamp});
const before=repo.get(namespace,key);
let calls = 0;
const fetcher = async () => {
	calls++;
	return new Response(JSON.stringify(kind === "kev"
		? { vulnerabilities: [{ cveID: id, dateAdded: "2099-03-01" }] }
		: { FileName: "refreshed-binary" }), { status: 200 });
};
(async () => {
	if (kind === "kev") {
		const matches = [{ cve: { id } }, { cve: { id: "CVE-2099-88888" } }];
		await mod.enrichKev(matches, { offline: true, fetcher });
		assert.equal(matches[0].cve.kev, true);
		assert.equal(matches[0].cve.kevRansomware, true);
		assert.equal(matches[0].cve.kevDateAdded, "2099-01-01");
		assert.equal(matches[0].cve.kevDueDate, "2099-02-01");
		assert.equal(matches[1].cve.kev, undefined);
	} else {
		assert.deepEqual(await mod.lookupHash({ sha256: hash }, { offline: true, fetcher }), identity);
		assert.equal(await mod.lookupHash({ sha256: "b".repeat(64) }, { offline: true, fetcher }), null);
		const deps = new Map([["binary", { hashes: { sha256: hash } }]]);
		const summary = await require(path.resolve("lib/unmanaged")).enrichUnmanaged(deps, { offline: true, fetcher });
		assert.equal(summary.identified, 1);
		assert.equal(summary.malicious, 1);
		assert.deepEqual(deps.get("binary").identity, identity);
	}
	assert.equal(calls, 0);
	assert.deepEqual(repo.get(namespace,key),before);
	if (kind === "kev") {
		const matches = [{ cve: { id } }];
		await mod.enrichKev(matches, { fetcher });
		assert.equal(matches[0].cve.kevDateAdded, "2099-03-01");
	} else {
		const value = await mod.lookupHash({ sha256: hash }, { fetcher });
		assert.equal(value.name, "refreshed-binary");
	}
	assert.equal(calls, 1, "online still refreshes expired snapshots");
	assert.ok(repo.get(namespace,key).value._fetchedAt > stamp);
	repo.delete(namespace,key);
	if (kind === "kev") {
		const matches = [{ cve: { id } }];
		await mod.enrichKev(matches, { offline: true, fetcher });
		assert.equal(matches[0].cve.kev, undefined);
	} else {
		assert.equal(await mod.lookupHash({ sha256: hash }, { offline: true, fetcher }), null);
	}
	assert.equal(calls, 1);
	assert.equal(repo.get(namespace,key), null, "cold offline reads never create a cache entry");
})().catch(error => { console.error(error); process.exitCode = 1; });
`, kind, root], { cwd: path.resolve(__dirname, ".."), encoding: "utf8" });
		assert.equal(fs.existsSync(path.join(root, ".vigie-vuln", `${kind}-cache.json`)), false);
	});
}
