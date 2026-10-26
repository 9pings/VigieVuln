const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { configureResourceRoute, getResource, providerKey } = require("../lib/providers");
const { createCacheStore, startProxyCacheServer } = require("../lib/proxy-cache");

const nvdId = "CVE-2024-31210";
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-provider-"));

test("the router builds a provider request for direct access", async () => {
	configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
	let requested;
	const response = await getResource("nvd", "cve", { id: nvdId }, { fetcher: async (url, init) => {
		requested = { url, init };
		return new Response(JSON.stringify({ id: nvdId }), { status: 200, headers: { "content-type": "application/json" } });
	} });
	assert.match(requested.url, /cveId=CVE-2024-31210$/);
	assert.equal((await response.json()).id, nvdId);
});

test("the server receives provider parameters, deduplicates concurrent requests and persists results", async () => {
	const dir = tmp();
	let hits = 0, online = true;
	const fetcher = async (url) => {
		hits++;
		if (!online) throw new Error("upstream offline");
		assert.match(url, /services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0\?cveId=CVE-2024-31210/);
		await new Promise(ok => setTimeout(ok, 30));
		return new Response(JSON.stringify({ id: nvdId }), { status: 200,
			headers: { "content-type": "application/json" } });
	};
	const first = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(dir), fetcher });
	try {
		configureResourceRoute({ proxyUrl: first.url, store: null, health: null, fetcher: globalThis.fetch });
		const results = await Promise.all(Array.from({ length: 12 }, () => getResource("nvd", "cve", { id: nvdId })));
		assert.deepEqual(await Promise.all(results.map(r => r.json())), Array(12).fill({ id: nvdId }));
		assert.equal(hits, 1);
		assert.equal(first.server.fadStore.size(), 1);
		assert.equal(first.server.fadStore.get(providerKey("nvd", "cve", { id: nvdId })).bytes > 0, true);
	} finally { await new Promise(ok => first.server.close(ok)); }
	online = false;
	const second = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(dir),
		overrideTtlMs: 1, fetcher });
	try {
		configureResourceRoute({ proxyUrl: second.url, store: null, health: null, fetcher: globalThis.fetch });
		const response = await getResource("nvd", "cve", { id: nvdId });
		assert.equal(response.status, 200);
		assert.equal((await response.json()).id, nvdId);
		const cold = await getResource("nvd", "cve", { id: "CVE-2024-99999" });
		assert.equal(cold.status, 502);
	} finally {
		await new Promise(ok => second.server.close(ok));
		configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
		fs.rmSync(dir, { recursive: true, force: true });
	}
});

test("overlapping OSV batches share package-version work and survive a source outage", async () => {
	const dir = tmp();
	const seen = new Map();
	let online = true;
	const fetcher = async (url, init) => {
		assert.match(url, /api\.osv\.dev\/v1\/querybatch/);
		if (!online) throw new Error("OSV offline");
		const queries = JSON.parse(init.body).queries;
		for (const q of queries) seen.set(q.package.name, (seen.get(q.package.name) || 0) + 1);
		await new Promise(ok => setTimeout(ok, 30));
		return new Response(JSON.stringify({ results: queries.map(q => ({ vulns: [{ id: q.package.name }] })) }),
			{ headers: { "content-type": "application/json" } });
	};
	const { server, url } = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(dir), fetcher,
		overrideTtlMs: 1, swr: false });
	const query = name => ({ package: { ecosystem: "npm", name }, version: "1.2.3" });
	try {
		configureResourceRoute({ proxyUrl: url, store: null, health: null, fetcher: globalThis.fetch });
		const batches = Array.from({ length: 30 }, (_, i) => i % 2 ? [query("b"), query("c")] : [query("a"), query("b")]);
		const responses = await Promise.all(batches.map(queries => getResource("osv", "packages", { queries })));
		const bodies = await Promise.all(responses.map(response => response.json()));
		for (let i = 0; i < bodies.length; i++) assert.deepEqual(
			bodies[i].results.map(row => row.vulns[0].id), batches[i].map(row => row.package.name));
		assert.deepEqual(Object.fromEntries(seen), { a: 1, b: 1, c: 1 });
		assert.equal(server.fadStore.size(), 3);
		await new Promise(ok => setTimeout(ok, 5));
		online = false;
		const stale = await getResource("osv", "packages", { queries: [query("b"), query("a")] });
		assert.deepEqual((await stale.json()).results.map(row => row.vulns[0].id), ["b", "a"]);
		const cold = await getResource("osv", "packages", { queries: [query("never-seen")] });
		assert.equal(cold.status, 502);
		assert.equal(server.fadStore.size(), 3);
	} finally {
		await new Promise(ok => server.close(ok));
		configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
		fs.rmSync(dir, { recursive: true, force: true });
	}
});

test("Packagist and EPSS batches deduplicate by package and CVE identity", async () => {
	const dir = tmp(), seen = new Map();
	const fetcher = async url => {
		const source = new URL(url);
		const items = source.hostname === "packagist.org"
			? source.searchParams.getAll("packages[]") : source.searchParams.get("cve").split(",");
		for (const item of items) seen.set(item, (seen.get(item) || 0) + 1);
		await new Promise(ok => setTimeout(ok, 25));
		return new Response(JSON.stringify(source.hostname === "packagist.org"
			? { advisories: Object.fromEntries(items.filter(item => item !== "b/b").map(item => [item, []])) }
			: { data: items.map(cve => ({ cve, epss: "0.1", percentile: "0.2" })) }),
		{ headers: { "content-type": "application/json" } });
	};
	const { server, url } = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(dir), fetcher });
	try {
		configureResourceRoute({ proxyUrl: url, store: null, health: null, fetcher: globalThis.fetch });
		const ids = ["CVE-2024-10001", "CVE-2024-10002", "CVE-2024-10003"];
		const results = await Promise.all([
			getResource("packagist", "advisories", { packages: ["a/a", "b/b"] }),
			getResource("packagist", "advisories", { packages: ["b/b", "c/c"] }),
			getResource("epss", "scores", { ids: ids.slice(0, 2) }),
			getResource("epss", "scores", { ids: ids.slice(1) }),
		]);
		const bodies = await Promise.all(results.map(r => r.json()));
		assert.deepEqual(Object.keys(bodies[0].advisories), ["a/a"]);
		assert.deepEqual(Object.keys(bodies[1].advisories), ["c/c"]);
		assert.deepEqual(bodies[2].data.map(row => row.cve), ids.slice(0, 2));
		assert.deepEqual(bodies[3].data.map(row => row.cve), ids.slice(1));
		assert.equal(server.fadStore.size(), 6);
		for (const item of ["a/a", "b/b", "c/c", ...ids]) assert.equal(seen.get(item), 1, `${item} fetched once`);
		assert.equal(providerKey("nvd", "cve", { id: "cve-2024-31210" }),
			providerKey("nvd", "cve", { id: "CVE-2024-31210" }));
	} finally {
		await new Promise(ok => server.close(ok));
		configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
		fs.rmSync(dir, { recursive: true, force: true });
	}
});

test("the client keeps its semantic entry if the proxy is unreachable and fails a cold lookup", async () => {
	const serverDir = tmp(), clientDir = tmp(), local = createCacheStore(clientDir);
	const running = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(serverDir),
		fetcher: async () => new Response(JSON.stringify({ id: nvdId }), { headers: { "content-type": "application/json" } }) });
	try {
		configureResourceRoute({ proxyUrl: running.url, store: local, health: null, fetcher: globalThis.fetch });
		assert.equal((await (await getResource("nvd", "cve", { id: nvdId })).json()).id, nvdId);
		const key = providerKey("nvd", "cve", { id: nvdId });
		const metaPath = local.metaPath(local.hash(key));
		const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
		meta.fetchedAt = 0;
		fs.writeFileSync(metaPath, JSON.stringify(meta));
		await new Promise(ok => running.server.close(ok));
		const stale = await getResource("nvd", "cve", { id: nvdId });
		assert.equal(stale.headers.get("x-fad-proxy"), "stale");
		assert.equal((await stale.json()).id, nvdId);
		await assert.rejects(getResource("nvd", "cve", { id: "CVE-2024-99999" }));
		assert.ok(local.get(key), "an outage never deletes the local entry");
	} finally {
		if (running.server.listening) await new Promise(ok => running.server.close(ok));
		configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
		fs.rmSync(serverDir, { recursive: true, force: true });
		fs.rmSync(clientDir, { recursive: true, force: true });
	}
});

test("publisher pagination survives both proxy and local cache hits", async () => {
	const { fetchGithubAdvisories } = require("../lib/application-providers/live-snapshot");
	const dir = tmp(), localDir = tmp();
	let calls = 0;
	const running = await startProxyCacheServer({ port: 0, store: createCacheStore(dir), fetcher: async url => {
		calls++;
		const second = new URL(url).searchParams.get("page") === "2";
		return new Response(JSON.stringify([{ ghsa_id: second ? "GHSA-second" : "GHSA-first", vulnerabilities: [] }]), {
			headers: { "content-type": "application/json", ...(second ? {} : {
				link: '<https://api.github.com/repos/TYPO3/typo3/security-advisories?per_page=100&page=2>; rel="next"' }) },
		});
	} });
	try {
		configureResourceRoute({ proxyUrl: running.url, store: createCacheStore(localDir), health: null, fetcher: null });
		for (let i = 0; i < 3; i++) {
			if (i === 2) configureResourceRoute({ proxyUrl: running.url, store: null });
			const result = await fetchGithubAdvisories("TYPO3/typo3");
			assert.deepEqual(result.snapshot.advisories.map(a => a.ghsa_id), ["GHSA-first", "GHSA-second"]);
		}
		assert.equal(calls, 2);
	} finally {
		await new Promise(ok => running.server.close(ok));
		configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
		fs.rmSync(dir, { recursive: true, force: true });
		fs.rmSync(localDir, { recursive: true, force: true });
	}
});

test("a batch in failure backoff does not strand preceding reservations", async () => {
	const dir = tmp();
	const running = await startProxyCacheServer({ port: 0, store: createCacheStore(dir), fetcher: async (url, init) => {
		const queries = JSON.parse(init.body).queries;
		if (queries.some(q => q.package.name === "broken")) throw new Error("upstream unavailable");
		return new Response(JSON.stringify({ results: queries.map(() => ({})) }));
	} });
	const query = name => ({ package: { ecosystem: "npm", name }, version: "1.0.0" });
	const call = names => fetch(running.url + "/v1/resource", { method: "POST",
		headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(1500),
		body: JSON.stringify({ provider: "osv", type: "packages", params: { queries: names.map(query) } }) });
	try {
		assert.equal((await call(["broken"])).status, 502);
		assert.equal((await call(["healthy", "broken"])).status, 502);
		assert.equal((await call(["healthy"])).status, 200);
	} finally {
		running.server.closeAllConnections();
		await new Promise(ok => running.server.close(ok));
		fs.rmSync(dir, { recursive: true, force: true });
	}
});

test("SPIP NVD snapshots use the shared provider route and server credentials", async () => {
	const { fetchSpipAdvisories } = require("../lib/application-providers/spip-advisories");
	const dir = tmp();
	let calls = 0;
	const running = await startProxyCacheServer({ port: 0, store: createCacheStore(dir), keys: { nvd: "server-key" },
		fetcher: async (url, init) => {
			calls++;
			assert.equal(new URL(url).searchParams.get("virtualMatchString"), "cpe:2.3:a:spip:spip");
			assert.equal(init.headers.apiKey, "server-key");
			return new Response(JSON.stringify({ totalResults: 0, vulnerabilities: [] }));
		} });
	try {
		configureResourceRoute({ proxyUrl: running.url, store: null, health: null, fetcher: null });
		const fetchImpl = (url, init) => {
			assert.ok(url.startsWith(running.url), "SPIP must not bypass the proxy");
			return fetch(url, init);
		};
		await fetchSpipAdvisories({ fetchImpl });
		await fetchSpipAdvisories({ fetchImpl });
		assert.equal(calls, 1);
	} finally {
		await new Promise(ok => running.server.close(ok));
		configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
		fs.rmSync(dir, { recursive: true, force: true });
	}
});

test("a stale proxy snapshot keeps its original collection date through local caching", async () => {
	const { fetchDrupalAdvisories } = require("../lib/application-providers/live-snapshot");
	const dir = tmp(), localDir = tmp(), store = createCacheStore(dir);
	const stamp = Date.parse("2020-01-01T00:00:00Z");
	const params = { packages: ["drupal/core"] };
	const bytes = Buffer.from(JSON.stringify({ advisories: {} }));
	const seed = path.join(dir, "seed");
	fs.writeFileSync(seed, bytes);
	store.commit(providerKey("drupal", "advisories", params), seed,
		{ fetchedAt: stamp, ttlMs: 1, bytes: bytes.length, contentType: "application/json" });
	const running = await startProxyCacheServer({ port: 0, store, fetcher: async () => { throw new Error("offline upstream"); } });
	try {
		configureResourceRoute({ proxyUrl: running.url, store: createCacheStore(localDir), health: null, fetcher: null });
		for (let i = 0; i < 2; i++) {
			const result = await fetchDrupalAdvisories(params.packages);
			assert.equal(Date.parse(result.snapshot._fadSnapshot.collectedAt), stamp);
		}
	} finally {
		await new Promise(ok => running.server.close(ok));
		configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
		fs.rmSync(dir, { recursive: true, force: true });
		fs.rmSync(localDir, { recursive: true, force: true });
	}
});

test("Wordfence live scan and anonymized warming accept only the server key", async () => {
	const { fetchWordfenceFeed, WORDFENCE_PRODUCTION_URL } = require("../lib/application-providers/live-snapshot");
	const { warmCmsAdvisorySnapshots } = require("../lib/cms-snapshot-warm");
	const dir = tmp(), snapshots = tmp();
	let calls = 0;
	const running = await startProxyCacheServer({ port: 0, store: createCacheStore(dir), keys: { wordfence: "server-secret" },
		fetcher: async (url, init) => {
			assert.equal(init.headers.authorization, "Bearer server-secret"); calls++;
			return new Response("{}");
		} });
	try {
		configureResourceRoute({ proxyUrl: running.url, store: null, health: null, fetcher: null });
		await fetchWordfenceFeed(WORDFENCE_PRODUCTION_URL);
		const warmed = await warmCmsAdvisorySnapshots([], { advisoryCacheDir: snapshots,
			applications: [{ type: "wordpress" }], wordfenceLive: true });
		assert.equal(warmed.wordfence, true);
		assert.equal(calls, 1);
		assert.equal(fs.readFileSync(path.join(snapshots, "wordfence-v3.json"), "utf8").includes("server-secret"), false);
		await assert.rejects(fetchWordfenceFeed("https://custom.invalid/feed"), /requires an API key/);
	} finally {
		await new Promise(ok => running.server.close(ok));
		configureResourceRoute({ proxyUrl: null, store: null, health: null, fetcher: null });
		fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(snapshots, { recursive: true, force: true });
	}
});

test("Wordfence with no server or client key is refused before reaching upstream", async () => {
	const dir = tmp();
	const running = await startProxyCacheServer({ port: 0, store: createCacheStore(dir), fetcher: () => { throw new Error("must not fetch"); } });
	try {
		const response = await fetch(running.url + "/v1/resource", { method: "POST", headers: { "content-type": "application/json" },
			body: JSON.stringify({ provider: "wordfence", type: "production-feed", params: {} }) });
		assert.equal(response.status, 503);
		assert.match((await response.json()).error, /--wordfence-key/);
		assert.equal(running.server.fadStats.upstream, 0);
	} finally { await new Promise(ok => running.server.close(ok)); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("CLI --wordfence-live works without a client key through the shared server", async () => {
	const { execFile } = require("node:child_process");
	const { promisify } = require("node:util");
	const dir = tmp(), source = tmp(), output = path.join(source, "findings.json");
	fs.mkdirSync(path.join(source, "wp-admin")); fs.mkdirSync(path.join(source, "wp-includes"));
	fs.writeFileSync(path.join(source, "wp-load.php"), "<?php");
	fs.writeFileSync(path.join(source, "wp-admin/index.php"), "<?php");
	fs.writeFileSync(path.join(source, "wp-includes/version.php"), "<?php $wp_version = '6.4.2';");
	const running = await startProxyCacheServer({ port: 0, store: createCacheStore(dir), keys: { wordfence: "server-secret" },
		fetcher: async (url, init) => {
			assert.match(url, /wordfence.com/); assert.equal(init.headers.authorization, "Bearer server-secret");
			return new Response("{}");
		} });
	const isolate = path.join(source, "isolate.cjs");
	fs.writeFileSync(isolate, 'require("node:os").homedir = () => __dirname;');
	const env = { ...process.env, FORCE_COLOR: "0" }; delete env.WORDFENCE_API_KEY;
	try {
		await promisify(execFile)(process.execPath, ["--require", isolate, path.join(__dirname, "..", "vigievuln.js"),
			"-s", source, "--ecosystem", "composer", "--app-plugins", "wordpress", "--wordfence-live",
			"--proxy-cache", running.url, "-d", "osv,packagist-audit,nvd,eol,epss,kev,retire,transitive",
			"--report-json", output, "--no-checksums"], { env, timeout: 15000 });
		const report = JSON.parse(fs.readFileSync(output, "utf8"));
		assert.ok(report.coverage.some(row => row.sourceId === "wordfence-v3" && row.execution === "completed"));
		assert.equal(JSON.stringify(report).includes("server-secret"), false);
	} finally { await new Promise(ok => running.server.close(ok)); fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(source, { recursive: true, force: true }); }
});
