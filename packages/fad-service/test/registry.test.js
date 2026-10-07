// fad-service milestone 4: package metadata — identity, projections (fad reads the same
// findings from a projection as from the raw registry answer), the publication rule,
// Maven mirrors, package pages, seed. Zero network: mock upstreams.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

let sqlite = true;
try { require("node:sqlite"); } catch { sqlite = false; }
const opts = { skip: !sqlite && "node:sqlite unavailable" };
const FAD = path.join(__dirname, "..", "..", "..", "lib");
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const PACKUMENT = {
	name: "left-pad", "dist-tags": { latest: "1.3.0" }, description: "String left pad", license: "WTFPL",
	readme: "x".repeat(50000), maintainers: [{ name: "a" }], users: { a: true },
	time: { created: "2014-03-01T00:00:00Z", modified: "2020-01-01T00:00:00Z", "1.1.0": "2015-01-01T00:00:00Z", "1.3.0": "2018-04-01T00:00:00Z", "9.9.9-unlisted": "2020-01-01T00:00:00Z" },
	versions: {
		"1.1.0": { version: "1.1.0", license: "WTFPL", deprecated: "use String.prototype.padStart()", dist: { tarball: "https://x/y.tgz", integrity: "sha512-…" }, readme: "big" },
		"1.3.0": { version: "1.3.0", license: "WTFPL", dist: { tarball: "https://x/z.tgz" }, dependencies: { "a-dep": "^1.0.0" } },
	},
};
const PYPI = {
	info: { name: "Requests", version: "2.32.0", summary: "HTTP for Humans.", license: "Apache 2.0", classifiers: ["License :: OSI Approved :: Apache Software License"],
		description: "y".repeat(40000), requires_dist: ["charset-normalizer<4,>=2", "PySocks!=1.5.7,>=1.5.6; extra == \"socks\""] },
	releases: {
		"2.31.0": [{ yanked: true, yanked_reason: "bad", upload_time_iso_8601: "2023-05-22T00:00:00Z", url: "https://files/x.whl", digests: {} }, { yanked: true }],
		"2.32.0": [{ yanked: false, upload_time_iso_8601: "2024-05-20T00:00:00Z" }, { yanked: true }],
	},
};

test("identity: one key per package whoever asks, from requests and from OSV", () => {
	const { packageKey, packageOfRequest, packageOfOsv, parseKey } = require("../lib/registry/purl");
	assert.equal(packageKey("pypi", "Django_REST.framework"), "pkg:pypi/django-rest-framework");
	assert.equal(packageKey("npm", "@Types/Node"), "pkg:npm/@types/node");
	assert.equal(packageKey("npm", "a/b/c"), null);
	assert.equal(packageOfRequest({ provider: "maven", type: "artifact", params: { path: "org/apache/logging/log4j/log4j-core/maven-metadata.xml" } }), "pkg:maven/org.apache.logging.log4j/log4j-core");
	assert.equal(packageOfRequest({ provider: "maven", type: "artifact", params: { path: "org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.pom" } }), "pkg:maven/org.apache.logging.log4j/log4j-core");
	assert.equal(packageOfRequest({ provider: "maven", type: "artifact", params: { path: "org/x/a/1.0/a-1.0.jar" } }), null, "a binary is never a package page");
	assert.equal(packageOfRequest({ provider: "nvd", type: "cve", params: { id: "CVE-2021-1" } }), null);
	assert.equal(packageOfOsv({ ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" }), "pkg:maven/org.apache.logging.log4j/log4j-core");
	assert.equal(packageOfOsv({ ecosystem: "PyPI", name: "Requests" }), "pkg:pypi/requests");
	assert.deepEqual(parseKey("pkg:maven/g/a"), { type: "maven", name: "g:a" });
});

test("versions: SemVer 2.0 precedence; verdicts only where the ordering is exact", () => {
	const { compareSemver, versionAffected } = require("../lib/registry/versions");
	const order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0"];
	for (let i = 1; i < order.length; i++) assert.equal(compareSemver(order[i - 1], order[i]), -1, `${order[i - 1]} < ${order[i]}`);
	const npmRange = [{ ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.3.0" }] }] }];
	assert.equal(versionAffected("npm", "1.1.0", npmRange), true);
	assert.equal(versionAffected("npm", "1.3.0", npmRange), false);
	assert.equal(versionAffected("npm", "1.3.0-rc.1", npmRange), true, "a prerelease is below its release");
	assert.equal(versionAffected("pypi", "1.0", [{ ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0" }] }] }]), null, "no exact PEP 440 ordering here: no verdict");
	assert.equal(versionAffected("pypi", "1.0", [{ versions: ["1.0"], ranges: [] }]), true, "an explicit version list is exact");
	assert.equal(versionAffected("maven", "2.12.2", [{ ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.0-beta9" }, { fixed: "2.15.0" }] }] }]), true);
	assert.equal(versionAffected("maven", "2.15.0", [{ ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.0-beta9" }, { fixed: "2.15.0" }] }] }]), false);
});

test("projections: fad finds exactly the same things in the projection as in the raw answer", () => {
	const { project } = require("../lib/registry/project");
	const { packumentToFindings } = require(path.join(FAD, "codecs", "npm", "registry.js"));
	const { pypiToFindings } = require(path.join(FAD, "codecs", "pypi", "registry.js"));
	const raw = Buffer.from(JSON.stringify(PACKUMENT));
	const npm = project({ provider: "npm", type: "package", params: { name: "left-pad" } }, raw);
	const projected = JSON.parse(npm.body.toString());
	for (const version of ["1.1.0", "1.3.0", "0.0.1"]) {
		const dep = { artifactId: "left-pad", version, ecosystem: "npm" };
		assert.deepEqual(packumentToFindings(projected, dep), packumentToFindings(PACKUMENT, dep), version);
	}
	assert.ok(npm.body.length < raw.length / 10, "readme, tarballs, maintainers dropped");
	assert.ok(!npm.body.toString().includes("tarball"));
	assert.equal(npm.pkg.key, "pkg:npm/left-pad");
	assert.equal(npm.pkg.latest, "1.3.0");
	assert.deepEqual(npm.pkg.dependencies, [{ name: "a-dep", range: "^1.0.0", scope: "runtime" }]);

	const py = project({ provider: "pypi", type: "package", params: { name: "requests" } }, Buffer.from(JSON.stringify(PYPI)));
	const pyProjected = JSON.parse(py.body.toString());
	for (const version of ["2.31.0", "2.32.0", "1.0"]) assert.deepEqual(pypiToFindings(pyProjected, { version }), pypiToFindings(PYPI, { version }), version);
	assert.equal(py.pkg.key, "pkg:pypi/requests");
	assert.deepEqual(py.pkg.versions.map(v => [v.version, !!v.yanked]), [["2.32.0", false], ["2.31.0", true]], "yanked only when every file is");
});

test("maven: metadata gives the versions, a POM its description, licence and dependencies", () => {
	const { mavenMetadata, pomSummary } = require("../lib/registry/project");
	const m = mavenMetadata("<metadata><versioning><latest>2.15.0</latest><release>2.15.0</release><versions><version>2.14.1</version><version>2.15.0</version></versions><lastUpdated>20211214</lastUpdated></versioning></metadata>");
	assert.deepEqual(m, { versions: ["2.14.1", "2.15.0"], latest: "2.15.0", release: "2.15.0", lastUpdated: "20211214" });
	const beta = mavenMetadata("<metadata><versioning><release>3.0.0-beta3</release><versions><version>2.25.1</version><version>3.0.0-beta3</version><version>2.9.0</version></versions></versioning></metadata>");
	assert.equal(beta.latest, "2.25.1", "Maven's <release> may be a beta; the page names the latest stable");
	assert.deepEqual(beta.versions, ["2.9.0", "2.25.1", "3.0.0-beta3"], "Maven ordering, not lexical");
	const pom = pomSummary(`<project><parent><groupId>p</groupId><artifactId>parent</artifactId><description>NOT ME</description></parent>
		<artifactId>log4j-core</artifactId><name>Apache Log4j Core</name><description>The Apache Log4j Implementation</description>
		<licenses><license><name>Apache-2.0</name></license></licenses>
		<dependencyManagement><dependencies><dependency><groupId>m</groupId><artifactId>managed</artifactId></dependency></dependencies></dependencyManagement>
		<dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-api</artifactId><version>2.15.0</version></dependency>
		<dependency><groupId>junit</groupId><artifactId>junit</artifactId><scope>test</scope></dependency></dependencies></project>`);
	assert.equal(pom.description, "The Apache Log4j Implementation");
	assert.equal(pom.licence, "Apache-2.0");
	assert.deepEqual(pom.dependencies.map(d => `${d.name}:${d.scope}`), ["org.apache.logging.log4j:log4j-api:compile", "junit:junit:test"], "managed entries are not dependencies");
});

test("maven mirrors: the EU mirror first, Central when the mirror lacks the file or fails", async () => {
	const { createUpstreamFetcher } = require("../lib/upstream");
	const calls = [];
	let mirrorStatus = 200;
	const f = createUpstreamFetcher(async url => { calls.push(url); return new Response("x", { status: url.includes("googleapis") ? mirrorStatus : 200 }); });
	const path = "org/x/a/maven-metadata.xml";
	await f(`https://repo1.maven.org/maven2/${path}`);
	assert.deepEqual(calls, [`https://maven-central-eu.storage-download.googleapis.com/maven2/${path}`]);
	calls.length = 0; mirrorStatus = 404;
	assert.equal((await f(`https://repo1.maven.org/maven2/${path}`)).status, 200);
	assert.deepEqual(calls.map(u => new URL(u).host), ["maven-central-eu.storage-download.googleapis.com", "repo1.maven.org"]);
	calls.length = 0;
	await f("https://registry.npmjs.org/lodash");
	assert.deepEqual(calls, ["https://registry.npmjs.org/lodash"], "other registries untouched");
});

async function service({ threshold = 2, upstream, target = ":memory:" }) {
	const { createServiceServer } = require("../lib/server");
	const { createRegistryLayer } = require("../lib/registry");
	const { db, assets, tokens, store } = await require("./helpers/db").open(target);
	const registry = createRegistryLayer({ assets, threshold, salt: "s" });
	const server = createServiceServer({ store, tokens, assets, registry, fetcher: upstream });
	await new Promise(ok => server.listen(0, "127.0.0.1", ok));
	const base = `http://127.0.0.1:${server.address().port}`;
	const ask = (token, payload, extra = {}) => fetch(`${base}/v1/resource`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...extra }, body: JSON.stringify(payload) });
	return { db, assets, tokens, base, ask, get: p => fetch(base + p), close: () => new Promise(ok => server.close(ok)) };
}

const npmUpstream = calls => async url => {
	calls.push(url);
	if (url === "https://registry.npmjs.org/left-pad") return json(PACKUMENT);
	return json({ error: "Not found" }, 404);
};

test("publication: cached ≠ published — public after K distinct clients; a private name never stored", opts, async () => {
	const calls = [];
	const s = await service({ threshold: 2, upstream: npmUpstream(calls) });
	try {
		const a = (await s.tokens.add({ role: "client" })).token, b = (await s.tokens.add({ role: "client" })).token;
		const LP = { provider: "npm", type: "package", params: { name: "left-pad" } };
		const first = await s.ask(a, LP);
		const body = await first.json();
		assert.equal(body["dist-tags"].latest, "1.3.0");
		assert.equal(body._fadProjection, 1, "the client gets the projection");
		assert.equal((await s.get("/pkg/npm/left-pad")).status, 404, "one client: cached, not public");
		assert.deepEqual((await s.assets.search("left-pad")), []);
		await (await s.ask(a, LP)).text();
		assert.equal((await s.get("/pkg/npm/left-pad")).status, 404, "the same client twice is still one client");
		await (await s.ask(b, LP)).text();
		assert.equal((await s.get("/pkg/npm/left-pad")).status, 200, "two distinct clients: public");
		assert.equal((await s.assets.search("left-pad"))[0].key, "pkg:npm/left-pad");
		assert.equal((await s.db.get("SELECT COUNT(*) AS n FROM package_demand")).n, 0, "who asked is forgotten once published");
		assert.equal(calls.length, 1, "one upstream fetch for all of it");

		const PRIVATE = { provider: "npm", type: "package", params: { name: "@acme/internal-billing" } };
		assert.equal((await s.ask(a, PRIVATE)).status, 404);
		await (await s.ask(b, PRIVATE)).text();
		const dump = JSON.stringify(await s.db.all("SELECT * FROM assets")) + JSON.stringify(await s.db.all("SELECT * FROM package_demand"));
		assert.ok(!dump.includes("internal-billing"), "a name the registry does not know is never written");
	} finally { await s.close(); }
});

test("seed: an admin seeding a package publishes it at once; package page with advisory verdicts", opts, async () => {
	const { seed } = require("../lib/registry/seed");
	const { osvAsset } = require("../lib/jobs/osv");
	const s = await service({ threshold: 5, upstream: npmUpstream([]) });
	try {
		const vuln = osvAsset({ id: "GHSA-aaaa-bbbb-cccc", summary: "Prototype pollution in left-pad", aliases: ["CVE-2099-0001"],
			affected: [{ package: { ecosystem: "npm", name: "left-pad" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.0" }] }] }] });
		(await s.assets.transaction(async () => { (await s.assets.upsert(vuln.asset)); (await s.assets.linkAdvisory(vuln.asset.key, vuln.cves)); (await s.assets.linkAdvisoryPackages(vuln.asset.key, vuln.packages)); }));
		const admin = (await s.tokens.add({ role: "admin" })).token;
		const r = await seed({ baseUrl: s.base, token: admin, type: "npm", specs: ["left-pad", "@acme/does-not-exist"], assets: s.assets, delayMs: 0 });
		assert.deepEqual(r, { ok: 1, missing: 1, failed: 0, total: 2 });
		const page = await (await s.get("/pkg/npm/left-pad?lang=en")).text();
		assert.match(page, /String left pad/);
		assert.match(page, /GHSA-aaaa-bbbb-cccc/);
		assert.match(page, /introduced 0, fixed 1\.2\.0/);
		// The versions panel: each version, its date, how many advisories affect it.
		assert.match(page, /<li><a href="\/pkg\/npm\/left-pad\?version=1\.1\.0&amp;lang=en">1\.1\.0<\/a> <span class="badge">deprecated<\/span><span class="v-meta"><time[^>]*>2015-01-01<\/time> <span class="flag"[^>]*>1<\/span>/);
		assert.match(page, /<li><a href="\/pkg\/npm\/left-pad\?version=1\.3\.0&amp;lang=en">1\.3\.0<\/a><span class="v-meta"><time[^>]*>2018-04-01<\/time> <span class="ok"[^>]*>✓<\/span>/);
		assert.match(page, /No known advisory affects it/, "the latest version is fixed");
		assert.match(page, /Registry metadata only — no package file is stored/);
		const cve = await (await s.get("/search?q=pkg%3Anpm%2Fleft-pad")).url;
		assert.match(cve, /\/pkg\/npm\/left-pad/);
	} finally { await s.close(); }
});
