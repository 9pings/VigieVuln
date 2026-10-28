const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { startProxyCacheServer, createCacheStore } = require("../lib/proxy-cache");
const { configureResourceRoute, getResource, providerKey } = require("../lib/providers");
const { indexFeed, indexProductionFeed, assessWordfenceFeed } = require("../lib/application-providers/wordfence-v3");
const { projectFeed, indexProjection, componentQueries, mergeProjections, SOURCE_URL, MAX_RESPONSE_BYTES } = require("../lib/application-providers/wordfence-projection");
const { fetchWordfenceFeed } = require("../lib/application-providers/live-snapshot");
const { cacheProjection, CACHE_FILE } = require("../lib/application-providers/wordfence-client");
const { runApplicationPlugins } = require("../lib/application-plugins/runner");
const wordpress = require("../lib/application-plugins/wordpress");

const uuid = "123e4567-e89b-12d3-a456-426614174000";
const software = (type, slug) => ({ type, slug, affected_versions: {
	all: { from_version: "1", from_inclusive: true, to_version: "2", to_inclusive: true },
}, patched_versions: ["2.1"] });
const feed = { [uuid]: { id: uuid, title: "Fixture", cve: null, references: ["https://example.test/advisory"],
	copyrights: { defiant: { notice: "Fixture copyright" } },
	software: [software("plugin", "example"), software("theme", "example"), software("plugin", "unrelated")] } };
const q = (type = "plugin", slug = "example") => ({ type, slug });
const component = (kind = "plugin", slug = "example", extra = {}) => ({ id: `${kind}:${slug}`, applicationId: "wordpress:site",
	kind, slug, version: "1.5", visibility: "public", catalogueStatus: "verified", ...extra });
const cacheKey = key => providerKey("wordfence", "projection-feed-v1", {}, { authorization: `Bearer ${key}` });
const payload = software => ({ provider: "wordfence", type: "software", params: { software } });

function temp(t) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wordfence-projection-"));
	t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
	return dir;
}
async function proxy(t, opts = {}) {
	const store = opts.store || createCacheStore(temp(t));
	const { server, url } = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store,
		keys: { wordfence: "server-key" }, fetcher: async () => Response.json(feed), ...opts });
	const close = () => server.listening ? new Promise(resolve => server.close(resolve)) : Promise.resolve();
	t.after(close);
	return { store, server, url, close, ask: (software, extra = {}) => fetch(`${url}/v1/resource`, { method: "POST",
		headers: { "content-type": "application/json" }, body: JSON.stringify({ ...payload(software), ...extra }) }) };
}
function route(t, url = "https://proxy.invalid") {
	configureResourceRoute({ proxyUrl: url, hosted: true, store: null, health: null, token: null, fetcher: null });
	t.after(() => configureResourceRoute({ proxyUrl: null, hosted: false, store: null, health: null, token: null, fetcher: null }));
}

test("Wordfence projections distinguish explicit negatives, unqueried identities, kind and stale evidence", () => {
	const snapshot = projectFeed(indexProductionFeed(feed), [q(), q("plugin", "absent")], Date.now());
	assert.deepEqual(snapshot.advisories[uuid].software.map(s => s.slug), ["example"]);
	const components = [component(), component("theme"), component("plugin", "absent"),
		component("plugin", "private", { visibility: "private" }), component("plugin", "unverified", { catalogueStatus: "not-queried" })];
	const result = assessWordfenceFeed(snapshot, components);
	assert.equal(result.matches[0].cve.id, `WF-${uuid}`);
	assert.equal(result.matches[0].cve.copyrightNotice, "Fixture copyright");
	assert.deepEqual(result.coverage.map(c => c.result), ["affected", "indeterminate", "no-match", "indeterminate", "indeterminate"]);
	assert.equal(result.coverage[1].diagnostic, "CMS_PROVIDER_NOT_QUERIED");
	snapshot._fadSnapshot.stale = true;
	const stale = assessWordfenceFeed(snapshot, components);
	assert.equal(stale.matches.length, 1, "known positives survive an outage");
	assert.equal(stale.coverage[0].diagnostic, "CMS_ADVISORY_STALE");
	assert.equal(stale.coverage[2].result, "indeterminate", "a stale absence is never a clean verdict");
});

test("Wordfence server coalesces different queries on one feed and projects only requested software", async t => {
	let calls = 0;
	const s = await proxy(t, { fetcher: async (url, init) => {
		calls++;
		assert.equal(url, SOURCE_URL);
		assert.equal(init.headers.authorization, "Bearer server-key");
		await new Promise(resolve => setImmediate(resolve));
		return Response.json(feed);
	} });
	const responses = await Promise.all([s.ask([q()]), s.ask([q("theme")]), s.ask([q("plugin", "absent")])]);
	const snapshots = await Promise.all(responses.map(r => { assert.equal(r.status, 200); return r.json(); }));
	assert.equal(calls, 1);
	assert.deepEqual(snapshots.map(s => s.queriedSoftware), [[q()], [q("theme")], [q("plugin", "absent")]]);
	assert.equal(snapshots[0].advisories[uuid].software.length, 1);
	assert.deepEqual(snapshots[2].advisories, {});
	assert.ok(snapshots.every(s => !JSON.stringify(s).includes("unrelated")));
	assert.equal(s.store.size(), 1, "one server-only compressed catalogue, no per-client feed copies");
	assert.equal((await s.ask([q()])).status, 200);
	assert.equal(calls, 1);
});

test("Wordfence server refuses malformed requests, missing keys and oversize responses without bulk fallback", async t => {
	let calls = 0;
	const fetcher = async () => { calls++; return Response.json(feed); };
	const s = await proxy(t, { fetcher });
	for (const queries of [[], Array(101).fill(q()), [q("plugin", "../secret")], [q("core", "wrong")], [{ ...q(), version: "1" }]])
		assert.equal((await s.ask(queries)).status, 400);
	assert.equal(calls, 0);
	const noKey = await proxy(t, { keys: {}, fetcher });
	assert.equal((await noKey.ask([q()])).status, 503);
	assert.equal(calls, 0);
	const bounded = await proxy(t, { maxBodyBytes: 100, fetcher });
	const denied = await bounded.ask([q()]);
	assert.equal(denied.status, 502);
	assert.match(await denied.text(), /upstream request failed/);
});

for (const broken of ["outage", "schema", "empty", "truncated"]) {
	test(`Wordfence: ${broken} refresh preserves the previous complete catalogue and its original date`, async t => {
		const store = createCacheStore(temp(t));
		const first = await proxy(t, { store });
		assert.equal((await first.ask([q()])).status, 200);
		const key = cacheKey("server-key"), entry = store.get(key);
		const old = Date.now() - 2 * 86400000;
		store.put(key, store.readBody(entry), { ...entry, fetchedAt: old });
		await first.close();
		let calls = 0;
		const restarted = await proxy(t, { store, fetcher: async () => {
			calls++;
			if (broken === "outage") return new Response("unavailable", { status: 503 });
			if (broken === "truncated") return new Response('{"broken":');
			return Response.json(broken === "schema" ? { error: "not a feed" } : {});
		} });
		for (let i = 0; i < 2; i++) {
			const response = await restarted.ask([q(), q("plugin", "absent")]);
			assert.equal(response.status, 200);
			assert.equal(response.headers.get("x-fad-proxy"), "stale");
			assert.equal(Date.parse(response.headers.get("x-fad-proxy-fetched-at")), old);
			const snapshot = await response.json();
			assert.equal(Date.parse(snapshot._fadSnapshot.collectedAt), old);
			assert.equal(snapshot._fadSnapshot.stale, true);
			assert.ok(assessWordfenceFeed(snapshot, [component(), component("plugin", "absent")]).coverage.every(c => c.result === "indeterminate"));
		}
		assert.equal(calls, 1, "failed refreshes have a cooldown");
		assert.equal(store.get(key).fetchedAt, old);
	});
}

test("Wordfence: invalid cold catalogue and corrupt cache cannot establish negative coverage", async t => {
	const s = await proxy(t, { fetcher: async () => Response.json({}) });
	assert.equal((await s.ask([q("plugin", "absent")])).status, 502);
	assert.equal(s.store.size(), 0);
	const body = Buffer.from("not gzip");
	s.store.put(cacheKey("server-key"), body, { fetchedAt: Date.now(), ttlMs: 86400000, bytes: body.length });
	await s.close();
	const restarted = await proxy(t, { store: s.store, fetcher: async () => new Response("down", { status: 503 }) });
	assert.equal((await restarted.ask([q("plugin", "absent")])).status, 502);
});

for (const type of ["software", "production-feed"]) {
	const request = (s, headers) => s.ask([q()], { type,
		params: type === "software" ? { software: [q()] } : {}, headers });
	const title = body => (type === "software" ? body.advisories : body)[uuid].title;
	const keyedFeed = authorization => ({ [uuid]: { ...feed[uuid], title: authorization } });

	test(`Wordfence ${type}: irrelevant API keys share the effective server credential cache`, async t => {
		let calls = 0;
		const s = await proxy(t, { fetcher: async (url, init) => {
			calls++;
			assert.equal(init.headers.authorization, "Bearer server-key");
			await new Promise(resolve => setImmediate(resolve));
			return Response.json(feed);
		} });
		const variants = [
			{ apikey: "irrelevant-one", authorization: "Bearer overridden-one" },
			{ apikey: "irrelevant-two", authorization: "Bearer overridden-two" },
			{ apiKey: "irrelevant-three" },
		];
		const responses = await Promise.all(variants.map(headers => request(s, headers)));
		for (const response of responses) {
			assert.equal(response.status, 200);
			assert.equal(title(await response.json()), "Fixture");
		}
		assert.equal(calls, 1, "one complete feed download for concurrent requests");
		assert.equal(s.store.size(), 1);
		assert.equal((await request(s, {})).status, 200);
		assert.equal(calls, 1);
		await s.close();
		const restarted = await proxy(t, { store: s.store, fetcher: async () => {
			calls++;
			throw new Error("the persisted feed should be reused");
		} });
		const cached = await request(restarted, { apikey: "irrelevant-four" });
		assert.equal(cached.status, 200);
		assert.equal(title(await cached.json()), "Fixture");
		assert.equal(calls, 1, "cache identity survives a restart");
	});

	test(`Wordfence ${type}: client credentials isolate concurrent downloads and cached content`, async t => {
		const credentials = [];
		const s = await proxy(t, { keys: {}, fetcher: async (url, init) => {
			credentials.push(init.headers.authorization);
			await new Promise(resolve => setImmediate(resolve));
			return Response.json(keyedFeed(init.headers.authorization));
		} });
		const ask = key => request(s, { apikey: "same-irrelevant-key", authorization: `Bearer ${key}` });
		const responses = await Promise.all([ask("one"), ask("two")]);
		for (const [i, response] of responses.entries()) {
			assert.equal(response.status, 200);
			assert.equal(title(await response.json()), `Bearer ${["one", "two"][i]}`);
		}
		for (const key of ["two", "one"]) {
			const response = await ask(key);
			assert.equal(response.status, 200);
			assert.equal(title(await response.json()), `Bearer ${key}`);
		}
		assert.deepEqual(credentials.sort(), ["Bearer one", "Bearer two"]);
		assert.equal(s.store.size(), 2);
	});

	test(`Wordfence ${type}: distinct server credentials isolate a shared store`, async t => {
		const store = createCacheStore(temp(t)), credentials = [];
		for (const key of ["one", "two", "one"]) {
			const s = await proxy(t, { store, keys: { wordfence: key }, fetcher: async (url, init) => {
				credentials.push(init.headers.authorization);
				return Response.json(keyedFeed(init.headers.authorization));
			} });
			const response = await request(s, { apikey: "same-irrelevant-key", authorization: "Bearer overridden" });
			assert.equal(response.status, 200);
			assert.equal(title(await response.json()), `Bearer ${key}`);
			await s.close();
		}
		assert.deepEqual(credentials, ["Bearer one", "Bearer two"]);
		assert.equal(store.size(), 2);
	});
}

test("Wordfence refresh cooldown expires under sustained reads and strict stale policy is respected", async t => {
	const { createWordfenceProjection } = require("../lib/resource-cache/wordfence");
	const store = createCacheStore(temp(t));
	let now = Date.now(), online = true, calls = 0;
	const opts = { store, ttlMs: 1, allowStale: true, maxEntries: 10, now: () => now,
		stats: { hits: 0, misses: 0, stale: 0, coalesced: 0, errors: 0 },
		loadFeed: async () => { calls++; if (!online) throw new Error("offline"); return feed; } };
	const query = createWordfenceProjection(opts);
	await query([q()], "catalogue", {});
	now += 100; online = false;
	assert.equal((await query([q()], "catalogue", {})).stale, true);
	now += 20000;
	assert.equal((await query([q()], "catalogue", {})).stale, true);
	assert.equal(calls, 2);
	now += 10001; online = true;
	assert.equal((await query([q()], "catalogue", {})).stale, false);
	assert.equal(calls, 3);
	now += 100; online = false;
	await assert.rejects(createWordfenceProjection({ ...opts, allowStale: false })([q()], "catalogue", {}), /offline/);
});

test("Wordfence server transfer limit and admission policy cannot publish a partial catalogue", async t => {
	const bounded = await proxy(t, { maxTransferBytes: 100 });
	const result = await bounded.ask([q()]);
	assert.equal(result.status, 502);
	assert.match(await result.text(), /upstream request failed/);
	assert.equal(bounded.store.size(), 0);
	let upstream = 0;
	const denied = await proxy(t, { admit: () => ({ retryAfterS: 60 }), fetcher: async () => { upstream++; return Response.json(feed); } });
	assert.equal((await denied.ask([q()])).status, 502);
	assert.equal(upstream, 0);
});

test("Wordfence warming queries only explicit descriptor identities and writes a targeted snapshot", async t => {
	route(t);
	const dir = temp(t), asked = [];
	const { warmCmsAdvisorySnapshots } = require("../lib/cms-snapshot-warm");
	const result = await warmCmsAdvisorySnapshots([], { advisoryCacheDir: dir, wordfenceLive: true,
		applications: [{ type: "wordpress", components: ["wordpress:theme:example", "composer:private/internal"] }],
		fetchImpl: async (url, init) => {
			const body = JSON.parse(init.body);
			assert.equal(body.type, "software");
			asked.push(...body.params.software);
			return Response.json(projectFeed(indexProductionFeed(feed), body.params.software, Date.now()));
		} });
	assert.equal(result.wordfence, true);
	assert.deepEqual(asked, [q("core", "wordpress"), q("theme")]);
	const cached = JSON.parse(fs.readFileSync(path.join(dir, CACHE_FILE), "utf8"));
	assert.equal(indexProjection(cached).queriedSoftware.size, 2);
	assert.equal(fs.existsSync(path.join(dir, "wordfence-v3.json")), false);
});

test("Wordfence anonymized export carries public software identities without private names or network access", t => {
	const dir = temp(t), output = path.join(dir, "descriptor.json"), preload = path.join(dir, "offline.cjs");
	fs.writeFileSync(preload, 'require("node:os").homedir = () => __dirname; globalThis.fetch = () => { throw new Error("network forbidden"); };');
	require("node:child_process").execFileSync(process.execPath, ["--require", preload,
		path.join(__dirname, "../vigievuln.js"), "-s", path.join(__dirname, "fixtures/wordpress-custom"),
		"--ecosystem", "composer", "--app-plugins", "wordpress", "--export-anonymized", output,
		"--public-component", "site/wp-content/themes/acme-theme=example"], { timeout: 15000, stdio: "pipe" });
	const descriptor = JSON.parse(fs.readFileSync(output, "utf8"));
	assert.deepEqual(descriptor.applications[0].components, ["wordpress:core:wordpress", "wordpress:theme:example"]);
});

test("Wordfence client sends no paths, versions or private/unverified identities; batches and explicit coverage are checked", async t => {
	route(t);
	const components = [...Array.from({ length: 101 }, (_, i) => component("plugin", `example-${i}`)),
		component("theme", "private", { visibility: "private" }), component("theme", "unknown", { catalogueStatus: "not-queried" })];
	const calls = [];
	const fetched = await fetchWordfenceFeed(SOURCE_URL, { components, fetchImpl: async (url, init) => {
		assert.equal(url, "https://proxy.invalid/v1/resource");
		const request = JSON.parse(init.body);
		assert.equal(request.type, "software");
		calls.push(request.params.software);
		return Response.json(projectFeed(indexProductionFeed(feed), request.params.software, Date.now()));
	} });
	assert.deepEqual(calls.map(c => c.length), [100, 1]);
	assert.equal(indexProjection(fetched.snapshot).queriedSoftware.size, 101);
	assert.equal(JSON.stringify(calls).includes("private"), false);
	assert.ok(calls.flat().every(q => Object.keys(q).sort().join() === "slug,type"));
	await assert.rejects(fetchWordfenceFeed(SOURCE_URL, { components: [component()],
		fetchImpl: async () => Response.json(projectFeed(new Map(), [], Date.now())) }), /explicitly cover/);
	await assert.rejects(fetchWordfenceFeed(SOURCE_URL, { components: [component()],
		fetchImpl: async () => Response.json(feed) }), /projection metadata/);
	let network = 0;
	await fetchWordfenceFeed(SOURCE_URL, { components: [component("plugin", "private", { visibility: "private" })],
		fetchImpl: async () => { network++; } });
	assert.equal(network, 0);
});

test("Wordfence targeted requests cannot fall back to direct or a custom bulk URL", async t => {
	configureResourceRoute({ proxyUrl: null, hosted: false, store: null });
	await assert.rejects(getResource("wordfence", "software", { software: [q()] }), /requires a proxy/);
	route(t);
	await assert.rejects(getResource("wordfence", "software", { software: [q()] }, { direct: true }), /requires a proxy/);
	await assert.rejects(fetchWordfenceFeed("https://custom.invalid/feed", { components: [component()], apiKey: "key" }), /direct bulk fallback/);
	await assert.rejects(fetchWordfenceFeed(SOURCE_URL, { components: [component()],
		fetchImpl: async () => new Response("", { headers: { "content-length": String(MAX_RESPONSE_BYTES + 1) } }) }), /response limit/);
});

test("Wordfence projection merges replace old evidence, retain other identities and never upgrade the collection date", () => {
	const old = projectFeed(indexProductionFeed(feed), [q(), q("theme")], Date.now() - 86400000, true);
	const fresh = projectFeed(new Map(), [q()], Date.now());
	const merged = mergeProjections(old, fresh);
	assert.equal(indexFeed(merged).get("plugin:example"), undefined, "removed advisory stays removed");
	assert.equal(indexFeed(merged).get("theme:example").length, 1);
	assert.equal(merged._fadSnapshot.collectedAt, old._fadSnapshot.collectedAt);
	assert.equal(merged._fadSnapshot.stale, true);
	assert.equal(mergeProjections(old, projectFeed(new Map(), [q(), q("theme")], Date.now()))._fadSnapshot.stale, false);
});

test("Wordfence plugin uses targeted cache offline, preserves stale coverage and enforces max age", async t => {
	const dir = temp(t);
	const snapshot = projectFeed(indexProductionFeed(feed), [q("core", "wordpress")], Date.now() - 2 * 86400000, true);
	cacheProjection(dir, snapshot);
	assert.equal(fs.existsSync(path.join(dir, "wordfence-v3.json")), false);
	assert.ok(fs.existsSync(path.join(dir, CACHE_FILE)));
	const opts = { plugins: [wordpress], selection: "wordpress", advisoryCacheDir: dir, offline: true,
		publicComponents: ["site/wp-content/themes/acme-theme=example"], fetchImpl: async () => { throw new Error("offline network"); } };
	const root = path.join(__dirname, "fixtures", "wordpress-custom");
	const result = await runApplicationPlugins(root, opts);
	const coverage = result.coverage.filter(c => c.sourceId === "wordfence-v3");
	assert.ok(coverage.some(c => c.diagnostic === "CMS_ADVISORY_STALE" && c.sourceSnapshot.stale));
	assert.ok(coverage.some(c => c.diagnostic === "CMS_PROVIDER_NOT_QUERIED"));
	assert.ok(coverage.every(c => c.result === "indeterminate"));
	await assert.rejects(runApplicationPlugins(root, { ...opts, maxAdvisoryAgeMs: 3600000 }), /is stale/);
});

test("Wordfence plugin live scan is end-to-end targeted and the next offline scan agrees", async t => {
	const s = await proxy(t);
	route(t, s.url);
	const dir = temp(t), calls = [];
	const root = path.join(__dirname, "fixtures", "wordpress-custom");
	const opts = { plugins: [wordpress], selection: "wordpress", advisoryCacheDir: dir,
		publicComponents: ["site/wp-content/themes/acme-theme=example"] };
	const online = await runApplicationPlugins(root, { ...opts, liveWordfenceUrl: SOURCE_URL,
		fetchImpl: async (url, init) => { calls.push(JSON.parse(init.body)); return fetch(url, init); } });
	assert.equal(calls.length, 1);
	assert.deepEqual(calls[0].params.software, [q("core", "wordpress"), q("theme")]);
	assert.equal(online.findings.length, 1);
	assert.equal(online.findings[0].cve.id, `WF-${uuid}`);
	const offline = await runApplicationPlugins(root, { ...opts, offline: true,
		fetchImpl: async () => { throw new Error("offline network"); } });
	assert.deepEqual(offline.findings, online.findings);
	assert.deepEqual(offline.coverage.map(c => [c.sourceId, c.result]), online.coverage.map(c => [c.sourceId, c.result]));
});
