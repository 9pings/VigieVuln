const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { configureResourceRoute } = require("../lib/providers");
const { fetchWordfenceFeed, WORDFENCE_PRODUCTION_URL } = require("../lib/application-providers/live-snapshot");
const { runApplicationPlugins } = require("../lib/application-plugins/runner");
const wordpress = require("../lib/application-plugins/wordpress");

function refusedProxy(t) {
	configureResourceRoute({ proxyUrl: "https://proxy.invalid", hosted: true, token: "proxy-token",
		store: null, health: null, fetcher: null });
	t.after(() => configureResourceRoute({ proxyUrl: null, hosted: false, token: null,
		store: null, health: null, fetcher: null }));
	const calls = [];
	const fetchImpl = async (url, init) => {
		calls.push({ url, init });
		assert.equal(url, "https://proxy.invalid/v1/resource", "no direct Wordfence fallback");
		assert.equal(init.method, "POST");
		assert.equal(init.redirect, "error");
		assert.equal(init.headers["x-fad-proxy-token"], "proxy-token");
		const body = JSON.parse(init.body);
		assert.equal(body.provider, "wordfence");
		assert.equal(body.type, "software");
		return Response.json({ error: "bulk data downloads are unavailable through the hosted proxy; update VigieVuln" },
			{ status: 410 });
	};
	return { calls, fetchImpl };
}

for (const apiKey of [undefined, "client-key"]) {
	test(`Wordfence: proxy 410 rejects without downloading a feed, ${apiKey ? "with" : "without"} a client key`, async t => {
		const { calls, fetchImpl } = refusedProxy(t);
		await assert.rejects(fetchWordfenceFeed(WORDFENCE_PRODUCTION_URL, { fetchImpl, apiKey,
			components: [{ kind: "core", version: "6.6.2" }] }), /HTTP 410/);
		assert.equal(calls.length, 1, "no retry or direct fallback after a definitive refusal");
	});
}

test("Wordfence: a refused live source fails the scan and leaves no complete-looking snapshot", async t => {
	const { calls, fetchImpl } = refusedProxy(t);
	const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "wordfence-refused-"));
	t.after(() => fs.rmSync(cacheDir, { recursive: true, force: true }));
	// An old local snapshot must not hide failure of an explicitly requested live source.
	const cachedFile = path.join(cacheDir, "wordfence-v3.json");
	const previous = JSON.stringify({ _fadSnapshot: { collectedAt: "2020-01-01T00:00:00Z", completeness: "tool-fetched" } });
	fs.writeFileSync(cachedFile, previous);
	await assert.rejects(runApplicationPlugins(path.join(__dirname, "fixtures", "wordpress-custom"), {
		plugins: [wordpress], selection: "wordpress", liveWordfenceUrl: WORDFENCE_PRODUCTION_URL,
		advisoryCacheDir: cacheDir, fetchImpl,
	}), /wordpress advisory source failed: .*HTTP 410/);
	assert.equal(calls.length, 1);
	assert.equal(fs.readFileSync(cachedFile, "utf8"), previous);
	assert.deepEqual(fs.readdirSync(cacheDir), ["wordfence-v3.json"]);
});
