const isolatedTestCache = require('./helpers/isolated-cache')('maven-presence-cli');
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const CLI = path.resolve(__dirname, "../vigievuln.js");
const key = "org.slf4j:slf4j-api";
const flags = ["--cve-offline", "--no-transitive", "--no-osv", "--no-osv-db", "--no-nvd",
	"--no-gcve", "--no-epss", "--no-kev", "--no-euvd", "--no-certfr", "--no-eol", "--no-retire",
	"--no-jars", "--no-binaries", "--no-certs", "--retries", "0"];
const write = (file, data) => {
	fs.mkdirSync(path.dirname(file), { recursive: true });
	fs.writeFileSync(file, typeof data === "string" ? data : JSON.stringify(data));
};
const read = file => JSON.parse(fs.readFileSync(file, "utf8"));

function scenario(t) {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-presence-cli-"));
	const stores = [];
	t.after(() => { for (const store of stores) store.close(); require('../lib/cache-db').closeCacheDbs(); fs.rmSync(root, { recursive: true, force: true }); });
	const home = path.join(root, "home"), src = path.join(root, "project");
	const preload = path.join(root, "preload.cjs"), calls = path.join(root, "calls.jsonl");
	const report = path.join(root, "report.json");
	const cache = (...parts) => path.join(home, ".vigie-vuln", ...parts);
	const presence=()=>require('../lib/json-cache').load(cache(),'maven-exists-cache.json',{meta:{fetchedAt:0},entries:{}});
	const savePresence=value=>require('../lib/json-cache').save(cache(),'maven-exists-cache.json',value);
	write(path.join(src, "pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId>" +
		"<artifactId>demo</artifactId><version>1.0</version><dependencies><dependency>" +
		"<groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.18</version>" +
		"</dependency></dependencies></project>");
	write(preload, `
require("node:os").homedir = () => process.env.FAD_PRESENCE_TEST_HOME;
globalThis.fetch = async (url, init) => {
	const mode = process.env.FAD_PRESENCE_TEST_MODE, u = String(url);
	require("node:fs").appendFileSync(process.env.FAD_PRESENCE_TEST_CALLS, JSON.stringify({ url: u, method: init?.method }) + "\\n");
	if (mode === "offline") throw new Error("unexpected offline request");
	if (mode === "unreachable") throw new Error("ENETUNREACH");
	if (u.startsWith("https://api.osv.dev/")) {
		if (mode === "osv-503") return new Response(null, { status: 503 });
		return new Response(JSON.stringify({ results: [] }), { status: 200 });
	}
	if (u.endsWith("/maven2/")) return new Response(null, { status: 200 });
	if (init?.method === "HEAD") {
		const status = mode === "public" || mode.startsWith("osv-") ? 200 : mode === "absent" ? 404
			: mode === "mixed" && u.includes("repo1.maven.org") ? 404 : 503;
		return new Response(null, { status });
	}
	return new Response("<metadata><versioning><release>2.0.18</release><versions><version>2.0.18</version></versions></versioning></metadata>", { status: 200 });
};
`);
	const run = (args, mode = "offline") => {
		fs.rmSync(report, { force: true });
		fs.rmSync(calls, { force: true });
		const result = spawnSync(process.execPath, ["--require", preload, CLI, ...args], {
			cwd: root, encoding: "utf8", timeout: 20000,
			env: { ...process.env, FAD_PRESENCE_TEST_HOME: home, FAD_PRESENCE_TEST_MODE: mode,
				FAD_PRESENCE_TEST_CALLS: calls },
		});
		assert.ifError(result.error);
		if (mode === "offline") assert.equal(fs.existsSync(calls), false, result.stdout + result.stderr);
		return result;
	};
	const scan = (mode = "offline", extra = [], enabledFlags = flags) => run([
		"-s", src, ...enabledFlags, ...(mode === "offline" ? ["--offline"] : []),
		"--report-json", report, ...extra,
	], mode);
	const warmOsv = (id, fetchedAt = Date.now()) => {
		const store = require('../lib/advisory-store').openAdvisoryStore({ cacheDir: cache() });
		stores.push(store);
		store.commit({ records: [{ source: 'osv', fetchedAt, document: {
			id, summary: 'Synthetic test advisory, not a real vulnerability', database_specific: { severity: 'HIGH' },
			affected: [{ package: { ecosystem: 'Maven', name: key }, versions: ['2.0.18'] }],
		} }], queries: [{ source: 'osv', ecosystem: 'Maven', name: key, version: '2.0.18',
			ids: [id], fetchedAt, complete: true }] });
		return store;
	};
	return { root, cache, report, run, scan, warmOsv, presence, savePresence };
}

for (const mode of ["unreachable", "503", "mixed"]) {
	test(`CLI: ${mode} cannot poison the next offline scan with false private packages`, t => {
		const s = scenario(t);
		const online = s.scan(mode);
		assert.equal(online.status, 0, online.stdout + online.stderr);
		if (mode !== "mixed") assert.ok(read(s.report).warnings.some(w => w.type === "source-unavailable"));
		assert.equal(s.presence().entries[key], undefined);
		const offline = s.scan();
		assert.equal(offline.status, 0, offline.stdout + offline.stderr);
		assert.deepEqual(read(s.report).warnings.filter(w => w.type === "private-libs"), []);
	});
}

test("CLI: legacy false entries are removed offline without discarding known positives", t => {
	const s = scenario(t);
	s.savePresence({
		meta: { fetchedAt: Date.now() }, entries: { [key]: false, "other:public": true },
	});
	const result = s.scan();
	assert.equal(result.status, 0, result.stdout + result.stderr);
	assert.deepEqual(s.presence().entries, { "other:public": true });
	assert.deepEqual(read(s.report).warnings.filter(w => w.type === "private-libs"), []);
});

test("CLI: descriptor import warms presence; an archive merge cannot revive an unrelated legacy false", t => {
	const s = scenario(t);
	const descriptor = path.join(s.root, "deps.json");
	write(descriptor, { schema: "fad-deps/1", deps: [
		{ ecosystem: "maven", namespace: "org.slf4j", name: "slf4j-api", version: "2.0.18" },
	] });
	const warmed = s.run(["--import-anonymized", descriptor, ...flags], "public");
	assert.equal(warmed.status, 0, warmed.stdout + warmed.stderr);
	assert.equal(s.presence().entries[key], true);
	const archive = path.join(s.root, "cache.tar.gz");
	assert.equal(s.run(["--export-cache", archive]).status, 0);
	// Simulate an enclave with old negative entries absent from the incoming archive.
	s.savePresence({
		meta: { fetchedAt: Date.now() - 1000 }, entries: { [key]: false, "legacy:missing": false, "local:public": true },
	});
	assert.equal(s.run(["--import-cache", archive]).status, 0);
	const offline = s.scan();
	assert.equal(offline.status, 0, offline.stdout + offline.stderr);
	assert.deepEqual(s.presence().entries, { [key]: true, "local:public": true });
	assert.deepEqual(read(s.report).warnings.filter(w => w.type === "private-libs"), []);
});

test("CLI: an absence warning does not suppress OSV findings or the fail-on gate", t => {
	const s = scenario(t);
	const initial = s.scan("absent");
	assert.equal(initial.status, 0, initial.stdout + initial.stderr);
	const id = "FAD-TEST-SENTINEL";
	s.warmOsv(id);
	const result = s.scan("offline", ["--fail-on", "high"], flags.filter(f => f !== "--no-osv"));
	assert.equal(result.status, 1, result.stdout + result.stderr);
	const doc = read(s.report);
	assert.equal(doc.warnings.filter(w => w.type === "private-libs").length, 1);
	assert.equal(doc.cve.length, 1);
	assert.equal(doc.cve[0].id, id);
	assert.ok(!doc.warnings.find(w => w.type === "private-libs").message.includes("cannot be detected"));
});

for (const mode of ["osv-503", "osv-truncated", "unreachable"]) {
	test(`CLI: ${mode} warns in the online report and preserves cached findings for the next offline scan`, t => {
		const s = scenario(t), id = "FAD-TEST-SENTINEL";
		const stamp = Date.now() - 48 * 3600e3;
		const store = s.warmOsv(id, stamp);
		const before = store.getQuery({ source: 'osv', ecosystem: 'Maven', name: key, version: '2.0.18' });
		const osvFlags = flags.filter(f => f !== "--no-osv");
		const online = s.scan(mode, [], osvFlags);
		assert.equal(online.status, 0, online.stdout + online.stderr);
		assert.ok(read(s.report).warnings.some(w => w.type === "source-unavailable" && /OSV/.test(w.message)));
		assert.equal(read(s.report).cve[0].id, id, 'source failure retains known findings in the online report');
		const strict = s.scan(mode, ["--fail-on-incomplete", "sources"], osvFlags);
		assert.equal(strict.status, 2, strict.stdout + strict.stderr);
		assert.ok(read(s.report).warnings.some(w => w.type === "source-unavailable" && /OSV/.test(w.message)));
		assert.deepEqual(store.getQuery({ source: 'osv', ecosystem: 'Maven', name: key, version: '2.0.18' }), before);
		const proof = store.getQuery({ source: 'osv', ecosystem: 'Maven', name: key, version: '2.0.18' });
		assert.equal(proof.fetchedAt, stamp, 'a failed network refresh cannot mint a fresh consultation');
		assert.equal(proof.fresh, false);
		const offline = s.scan("offline", ["--fail-on", "high"], osvFlags);
		assert.equal(offline.status, 1, offline.stdout + offline.stderr);
		assert.equal(read(s.report).cve[0].id, id);
	});
}

test('CLI rejects a corrupt SQLite advisory body instead of reporting a clean scan',t=>{
 const s=scenario(t),store=s.warmOsv('FAD-CORRUPTION-SENTINEL');
 store.db.prepare('UPDATE advisory_records SET envelope_deflate=? WHERE source=? AND id=?').run(
  Buffer.from('corrupt'),'osv','FAD-CORRUPTION-SENTINEL');
 const result=s.scan('offline',['--fail-on-incomplete','sources'],flags.filter(f=>f!=='--no-osv'));
 assert.notEqual(result.status,0,'corrupted advisory must not pass as a clean scan');
});

test("CLI: anonymized export strips unrelated Maven properties and retains a custom dependency version pin", t => {
	const s = scenario(t);
	const src = path.join(s.root, "project"), descriptor = path.join(s.root, "deps.json");
	write(path.join(src, "pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId>" +
		"<artifactId>demo</artifactId><version>1.0</version><properties><customPin>2.0.18</customPin>" +
		"<server.password>DO_NOT_EXPORT</server.password><sonar.sources>/home/private/src</sonar.sources>" +
		"<internal.url>https://internal.invalid/</internal.url></properties><dependencies><dependency>" +
		"<groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>${customPin}</version>" +
		"</dependency></dependencies></project>");
	const result = s.run(["-s", src, "--export-anonymized", descriptor]);
	assert.equal(result.status, 0, result.stdout + result.stderr);
	assert.deepEqual(read(descriptor).maven.propertyOverrides, { customPin: "2.0.18" });
	assert.equal(read(descriptor).deps[0].version, "2.0.18");
	assert.ok(!/DO_NOT_EXPORT|\/home\/private|internal.invalid/.test(fs.readFileSync(descriptor, "utf8")));
	assert.match(result.stdout, /3 Maven property value\(s\) omitted/);
});

test("CLI: --fail-on kev still fails offline with a catalogue older than 24 hours", t => {
	const s = scenario(t), id = "CVE-2099-99999";
	const stamp = Date.now() - 72 * 3600e3;
	s.warmOsv(id, stamp);
	const repo=require('../lib/cache-repository').createCacheRepository(s.cache());
	repo.put('catalogue','kev',{ _fetchedAt: stamp, body: { byId: {
		[id]: { dateAdded: "2099-01-01", dueDate: "2099-02-01", ransomware: true },
	} } });
	const before = repo.get('catalogue','kev');
	const result = s.scan("offline", ["--fail-on", "kev"],
		flags.filter(f => !["--no-osv", "--no-kev"].includes(f)));
	assert.equal(result.status, 1, result.stdout + result.stderr);
	assert.equal(read(s.report).cve[0].id, id);
	assert.equal(read(s.report).cve[0].kev, true);
	assert.deepEqual(repo.get('catalogue','kev'), before);
});

test('CLI offline signals a missing transitive POM and strict completeness fails', t => {
 const s=scenario(t), enabled=flags.filter(f=>f!=='--no-transitive');
 for(const category of ['inventory','sources']) {
  const result=s.scan('offline',['--fail-on-incomplete',category],enabled);
  assert.equal(result.status,2,result.stdout+result.stderr);
  assert.ok(read(s.report).warnings.some(w=>w.type==='dependency-coverage' && /POM/.test(w.message)));
 }
 require('../lib/maven-cache').write(s.cache('poms-cache','org.slf4j__slf4j-api__2.0.18.pom'),'<project><modelVersion>4.0.0</modelVersion><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.18</version></project>');
 const complete=s.scan('offline',[],enabled);
 assert.equal(complete.status,0,complete.stdout+complete.stderr);
 assert.deepEqual(read(s.report).warnings.filter(w=>w.type==='dependency-coverage'),[]);
});

test('CLI warns and fails strict inventory on colliding Maven classifiers', t => {
 const s=scenario(t),pom=path.join(s.root,'project','pom.xml');
 write(pom,'<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>demo</artifactId><version>1</version><dependencies>'+
 '<dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>1</version></dependency>'+
 '<dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>2</version><classifier>tests</classifier></dependency>'+
 '</dependencies></project>');
 const result=s.scan('offline',['--fail-on-incomplete','inventory']);
 assert.equal(result.status,2,result.stdout+result.stderr);
 assert.ok(read(s.report).warnings.some(w=>w.type==='dependency-coverage' && /classifiers/.test(w.message)));
});
