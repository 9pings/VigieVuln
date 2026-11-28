/**
 * Maven Central mirrors: spreading the load, and dropping a dead one for the run.
 *
 * The outdated/metadata lookups are one request per dependency — hundreds on a real
 * reactor, all at the same host. The officially listed mirrors (the three Google buckets
 * in repo.maven.apache.org/maven2/.meta/repository-metadata.xml) give that some headroom.
 * Two properties matter for an audit tool: the spread must be DETERMINISTIC, so a re-run
 * queries the same host for the same coordinate, and a mirror that stops answering must be
 * dropped for the rest of the scan rather than re-timing-out on every remaining coordinate.
 */
const test = require("node:test");
const assert = require("node:assert");
const {
	buildRepoList, orderRepos, createRepoHealth, tryRepos, DEFAULT_CENTRAL_MIRRORS,
} = require("../lib/providers/maven/repo");

const urls = list => list.map(r => r.url);

test("the default list carries Central plus the officially listed mirrors", () => {
	const repos = buildRepoList([]);
	assert.ok(repos.some(r => r.url === "https://repo1.maven.org/maven2/"), "canonical Central");
	for (const m of DEFAULT_CENTRAL_MIRRORS) {
		assert.ok(repos.some(r => r.url === m.url), `mirror ${m.url}`);
	}
	assert.ok(repos.every(r => !r.central || r.url.includes("maven")), "central block tagged");
});

test("a private repo always stays ahead of Central and its mirrors", () => {
	// Private-first is the documented contract: an internal artifact must resolve from
	// the internal Nexus, never from whatever a public mirror happens to hold.
	const repos = buildRepoList([{ name: "nexus", url: "https://nexus.acme/repo/" }]);
	assert.strictEqual(repos[0].url, "https://nexus.acme/repo/");
	for (const key of ["a:b", "c:d", "e:f", "g:h", "zzz:yyy"]) {
		assert.strictEqual(orderRepos(repos, key)[0].url, "https://nexus.acme/repo/");
	}
});

test("the central block rotates by coordinate, so load spreads", () => {
	const repos = buildRepoList([]);
	const firsts = new Set();
	for (let i = 0; i < 60; i++) firsts.add(orderRepos(repos, `g${i}:a${i}`)[0].url);
	assert.ok(firsts.size > 1, "every coordinate hit the same host — no spread");
});

test("the rotation is deterministic — a re-run must query the same host", () => {
	const repos = buildRepoList([]);
	assert.deepStrictEqual(
		urls(orderRepos(repos, "org.apache.commons:commons-lang3")),
		urls(orderRepos(repos, "org.apache.commons:commons-lang3")));
});

test("ordering never loses or duplicates a repo", () => {
	const repos = buildRepoList([{ name: "nexus", url: "https://nexus.acme/repo/" }]);
	const out = orderRepos(repos, "x:y");
	assert.strictEqual(out.length, repos.length);
	assert.deepStrictEqual(new Set(urls(out)), new Set(urls(repos)));
});

test("a mirror that errors is dropped for the rest of the scan", async () => {
	const health = createRepoHealth();
	const repos = [
		{ name: "dead", url: "https://dead.example/maven2/", central: true, mirror: true },
		{ name: "live", url: "https://live.example/maven2/", central: true, mirror: true },
	];
	const hits = [];
	const fetcher = async url => {
		hits.push(url);
		if (url.startsWith("https://dead.")) throw new Error("ETIMEDOUT");
		return { ok: true, status: 200, text: async () => "<metadata/>" };
	};
	const first = await tryRepos(repos, "g/a/maven-metadata.xml", { fetcher, health, readBody: true });
	assert.strictEqual(first.repo.name, "live");
	assert.strictEqual(health.isDown("https://dead.example/maven2/"), true);

	hits.length = 0;
	await tryRepos(repos, "g/b/maven-metadata.xml", { fetcher, health, readBody: true });
	assert.ok(hits.every(u => !u.startsWith("https://dead.")), "dead mirror queried again");
});

test("a 404 does NOT condemn a repo — it just does not hold that artifact", async () => {
	const health = createRepoHealth();
	const repos = [
		{ name: "partial", url: "https://partial.example/maven2/", central: true, mirror: true },
		{ name: "live", url: "https://live.example/maven2/", central: true, mirror: true },
	];
	const fetcher = async url => url.startsWith("https://partial.")
		? { ok: false, status: 404 }
		: { ok: true, status: 200, text: async () => "<metadata/>" };
	await tryRepos(repos, "g/a/maven-metadata.xml", { fetcher, health });
	assert.strictEqual(health.isDown("https://partial.example/maven2/"), false);
});

test("rate limiting and server errors do condemn it for the run", async () => {
	for (const status of [429, 503]) {
		const health = createRepoHealth();
		const repos = [{ name: "x", url: "https://x.example/maven2/", central: true, mirror: true },
			{ name: "ok", url: "https://ok.example/maven2/", central: true, mirror: true }];
		const fetcher = async url => url.startsWith("https://x.")
			? { ok: false, status }
			: { ok: true, status: 200, text: async () => "ok" };
		await tryRepos(repos, "p", { fetcher, health });
		assert.strictEqual(health.isDown("https://x.example/maven2/"), true, `status ${status}`);
	}
});

test("everything down means null, not a throw — the scan carries on without the check", async () => {
	const health = createRepoHealth();
	const repos = [{ name: "a", url: "https://a.example/m2/", central: true, mirror: true }];
	const fetcher = async () => { throw new Error("ENETUNREACH"); };
	assert.strictEqual(await tryRepos(repos, "p", { fetcher, health }), null);
	assert.strictEqual(await tryRepos(repos, "q", { fetcher, health }), null);
});

test("Maven Central itself is never condemned, however it fails", () => {
	// A mirror is redundant by construction — Central sits behind it — so dropping one
	// costs nothing. Dropping Central, or a private repo, would silently turn a transient
	// blip into a coverage hole for the whole scan. Only mirrors are eligible.
	const health = createRepoHealth();
	health.markDown({ name: "central", url: "https://repo1.maven.org/maven2/", central: true }, "ETIMEDOUT");
	assert.strictEqual(health.isDown("https://repo1.maven.org/maven2/"), false);
});

test("a private repo is never condemned either", () => {
	const health = createRepoHealth();
	health.markDown({ name: "nexus", url: "https://nexus.acme/repo/" }, "ETIMEDOUT");
	assert.strictEqual(health.isDown("https://nexus.acme/repo/"), false);
});

test("a condemned mirror is reported, so the run can say what it lost", () => {
	const health = createRepoHealth();
	health.markDown({ name: "gcs-eu", url: "https://eu.example/m2/", central: true, mirror: true }, "HTTP 429");
	assert.deepStrictEqual(health.downList(), [{ name: "gcs-eu", url: "https://eu.example/m2/", reason: "HTTP 429" }]);
});

test("the release-date HEAD skips mirrors but keeps private repos", async () => {
	// maven-metadata.xml is small and constantly re-requested, so the mirrors serve it hot.
	// An individual .pom is a unique deep path, cold in their buckets: measured 9.2s via the
	// rotation against 1.7s via Central, zero misses either way. Private repos must stay —
	// a private artifact's POM exists nowhere else.
	const { pomLastModifiedRepos } = require("../lib/maintenance/outdated");
	const repos = [
		{ name: "nexus", url: "https://nexus.acme/repo/" },
		{ name: "central", url: "https://repo1.maven.org/maven2/", central: true },
		{ name: "gcs", url: "https://mirror.example/maven2/", central: true, mirror: true },
	];
	assert.deepStrictEqual(pomLastModifiedRepos(repos).map(r => r.name), ["nexus", "central"]);
});

test("if somehow only mirrors are configured, use them rather than give up", () => {
	const { pomLastModifiedRepos } = require("../lib/maintenance/outdated");
	const only = [{ name: "gcs", url: "https://mirror.example/maven2/", central: true, mirror: true }];
	assert.deepStrictEqual(pomLastModifiedRepos(only).map(r => r.name), ["gcs"]);
});
