const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
	buildRepoList,
	splitUrlAuth,
	authHeader,
	tryRepos,
	fetchPomFromRepos,
	fetchMavenMetadata,
	MAVEN_CENTRAL,
} = require("../lib/maven-repo");

test('hosted Maven Central uses the proxy for preflight and artifact requests; private repos stay direct', async () => {
	const {configureResourceRoute}=require('../lib/providers');
	const {reachableRepos}=require('../lib/maven-repo');
	const calls=[];
	const fetcher=async (url,init)=>{calls.push({url:String(url),body:init?.body ? JSON.parse(init.body) : null});return new Response('ok',{status:200});};
	configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null,health:null,token:'test',fetcher});
	try {
		const repos=buildRepoList([{name:'private',url:'https://private.invalid/'}]);
		assert.equal(repos.length,2);
		await reachableRepos(repos,{fetcher});
		await tryRepos([repos[1]],'org/example/demo/maven-metadata.xml',{fetcher,readBody:true});
		assert.ok(calls.some(c=>c.url==='https://private.invalid/'));
		assert.deepEqual(calls.filter(c=>c.url==='https://proxy.invalid/v1/resource').map(c=>c.body.type),['preflight','artifact']);
		assert.equal(calls.some(c=>c.url.includes('repo1.maven.org') || c.url.includes('storage-download.googleapis.com')),false);
	} finally {configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null});}
});

test("splitUrlAuth pulls user:pass out of a URL", () => {
	const { url, auth } = splitUrlAuth("https://alice:s3cr3t@nexus.acme.com/repository/maven-public/");
	assert.equal(auth, "alice:s3cr3t");
	assert.ok(!/alice:s3cr3t/.test(url));
	assert.ok(url.startsWith("https://nexus.acme.com/"));
});

test("splitUrlAuth no-op when URL has no auth", () => {
	const { url, auth } = splitUrlAuth("https://repo1.maven.org/maven2/");
	assert.equal(auth, null);
	assert.equal(url, "https://repo1.maven.org/maven2/");
});

test("authHeader returns Basic <base64>", () => {
	assert.equal(authHeader("alice:s3cr3t"), "Basic " + Buffer.from("alice:s3cr3t").toString("base64"));
	assert.equal(authHeader(null), null);
});

test("Maven Bearer tokens survive configuration and are used by preflight and artifact requests only on their own repo", async () => {
	const { reachableRepos } = require("../lib/maven-repo");
	const repos = buildRepoList([{ name: "private", url: "https://private.invalid/", token: "test-token", auth: "user:password" }], [], { mirrors: false });
	assert.equal(repos[0].token, "test-token");
	const calls = [];
	const fetcher = async (url, init) => {
		calls.push({ url, authorization: init.headers.Authorization });
		return { ok: false, status: 404 };
	};
	await reachableRepos(repos, { fetcher });
	await tryRepos(repos, "g/a/maven-metadata.xml", { fetcher });
	assert.equal(calls.length, 4);
	for (const call of calls) {
		assert.equal(call.authorization, call.url.startsWith("https://private.invalid/") ? "Bearer test-token" : undefined);
	}
});

test("buildRepoList puts user repos first, then Central ahead of its mirrors, dedupes by URL, normalises trailing slash", () => {
	const list = buildRepoList(
		[
			{ name: "nexus", url: "https://nexus.acme.com/repository/maven-public" },          // no trailing /
			{ name: "jboss", url: "https://repository.jboss.org/nexus/content/groups/public/" },
		],
		[
			{ url: "https://nexus.acme.com/repository/maven-public/" },                          // dup, with trailing /
			{ url: "https://maven.atlassian.com/" },
		],
	);
	assert.equal(list[0].name, "nexus");
	assert.equal(list[0].url, "https://nexus.acme.com/repository/maven-public/");
	assert.equal(list[1].name, "jboss");
	// The dup of "nexus" is dropped
	assert.equal(list.filter(r => r.name === "nexus").length, 1);
	// atlassian is in the middle (extra repo, before Central)
	assert.ok(list.some(r => r.url === "https://maven.atlassian.com/"));
	// Central closes the configured repos and leads the mirror block that follows it. Every
	// user-supplied repo must still come first: private artifacts resolve privately.
	const centralAt = list.findIndex(r => r.url === MAVEN_CENTRAL.url);
	assert.ok(centralAt >= 0, "Central present");
	assert.ok(list.slice(0, centralAt).every(r => !r.central), "a mirror jumped ahead of Central");
	assert.ok(list.slice(centralAt + 1).every(r => r.mirror), "only mirrors follow Central");
});

test("buildRepoList strips and stores embedded user:pass auth", () => {
	const list = buildRepoList([
		{ name: "private", url: "https://bob:hunter2@nexus.acme.com/repository/private/" },
	]);
	assert.equal(list[0].url, "https://nexus.acme.com/repository/private/");
	assert.equal(list[0].auth, "bob:hunter2");
});

test("tryRepos returns the first 2xx, skipping 404s", async () => {
	const calls = [];
	const fetcher = async (url) => {
		calls.push(url);
		if (url.startsWith("https://nexus.acme/")) return { ok: false, status: 404 };
		if (url.startsWith("https://repo1.maven.org/")) return { ok: true, status: 200, text: async () => "<project/>" };
		return { ok: false, status: 500 };
	};
	const repos = buildRepoList([{ name: "nexus", url: "https://nexus.acme/" }]);
	const hit = await tryRepos(repos, "log4j/log4j/1.2.17/log4j-1.2.17.pom", { fetcher, readBody: true });
	assert.ok(hit, "should hit Central after Nexus 404");
	assert.equal(hit.repo.url, MAVEN_CENTRAL.url);
	assert.equal(hit.body, "<project/>");
	assert.equal(calls.length, 2);
});

test("tryRepos returns null when no repo answers 2xx", async () => {
	const fetcher = async () => ({ ok: false, status: 404 });
	const repos = buildRepoList([{ name: "a", url: "https://a.example/" }, { name: "b", url: "https://b.example/" }]);
	const hit = await tryRepos(repos, "g/a/1/a-1.pom", { fetcher });
	assert.equal(hit, null);
});

test("tryRepos sends Basic auth header for repos with creds", async () => {
	let seenAuth = null;
	const fetcher = async (url, init) => {
		seenAuth = init?.headers?.Authorization || null;
		return { ok: true, status: 200, text: async () => "ok" };
	};
	const repos = buildRepoList([{ name: "p", url: "https://x:y@nexus.acme/" }]);
	await tryRepos(repos, "g/a/1/a-1.pom", { fetcher });
	assert.equal(seenAuth, "Basic " + Buffer.from("x:y").toString("base64"));
});

test("fetchPomFromRepos constructs the standard Maven path", async () => {
	const seen = [];
	const fetcher = async (url) => { seen.push(url); return { ok: false, status: 404 }; };
	const repos = buildRepoList([{ name: "a", url: "https://a.example/" }]);
	await fetchPomFromRepos(repos, "org.apache.logging.log4j", "log4j-core", "2.17.0", { fetcher });
	assert.ok(seen[0].endsWith("org/apache/logging/log4j/log4j-core/2.17.0/log4j-core-2.17.0.pom"),
		`unexpected URL: ${seen[0]}`);
});

test("fetchMavenMetadata hits the maven-metadata.xml path", async () => {
	const seen = [];
	const fetcher = async (url) => { seen.push(url); return { ok: false, status: 404 }; };
	const repos = buildRepoList([{ name: "a", url: "https://a.example/" }]);
	await fetchMavenMetadata(repos, "org.apache.logging.log4j", "log4j-core", { fetcher });
	assert.ok(seen[0].endsWith("org/apache/logging/log4j/log4j-core/maven-metadata.xml"),
		`unexpected URL: ${seen[0]}`);
});

// ---- fail-fast on an unreachable network (offline VM without --offline) ----
// A HEAD against a blackholed route hangs until the OS TCP timeout; with 100+
// existence probes that is minutes of silence. Every request carries an abort
// signal bounded by opts.timeoutMs.
test("tryRepos gives up on a hung request after timeoutMs", async () => {
	let gotSignal = false;
	const fetcher = (url, init) => {
		// No abort signal = no way to interrupt a hung socket. Answer at once so the
		// test fails on the assertion below instead of hanging the suite.
		if (!init || !init.signal) return Promise.resolve({ ok: false, status: 599 });
		gotSignal = true;
		return new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted"))));
	};
	const repos = buildRepoList([{ name: "blackhole", url: "https://10.255.255.1/" }]);
	const t0 = Date.now();
	const hit = await tryRepos(repos, "g/a/maven-metadata.xml", { fetcher, method: "HEAD", timeoutMs: 50 });
	assert.equal(hit, null);
	assert.ok(gotSignal, "every request must carry an AbortSignal bounded by timeoutMs");
	assert.ok(Date.now() - t0 < 2000, "bounded by timeoutMs, not the OS TCP timeout");
});

test("reachableRepos keeps repos that answer ANY HTTP status and drops network errors/timeouts", async () => {
	const { reachableRepos } = require("../lib/maven-repo");
	const fetcher = (url, init) => {
		if (url.startsWith("https://nexus.acme/")) return Promise.resolve({ ok: false, status: 401 });   // auth wall, but alive
		if (url.startsWith("https://dead.acme/")) return Promise.reject(new Error("ENETUNREACH"));
		return new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted")))); // Central blackholed
	};
	const repos = buildRepoList([{ name: "nexus", url: "https://nexus.acme/" }, { name: "dead", url: "https://dead.acme/" }]);
	const live = await reachableRepos(repos, { fetcher, timeoutMs: 50 });
	assert.deepEqual(live.map(r => r.name), ["nexus"]);
});
