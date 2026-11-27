const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
	SOURCES, sourceForUrl, classifyResponse, retryDelaysMs, RETRY_ATTEMPTS,
	createSourceHealth, formatAbort, guardedFetch,
} = require("../lib/source-health");

/* ---------------- attribution ---------------- */

test("every source in the registry declares a disable flag and a host", () => {
	for (const [id, s] of Object.entries(SOURCES)) {
		assert.ok(s.label, `${id}: label`);
		assert.ok(s.flag, `${id}: flag`);
		assert.ok(Array.isArray(s.hosts) && s.hosts.length, `${id}: hosts`);
	}
	// endoflife.date had no disable flag before this; the abort message needs one to offer.
	assert.equal(SOURCES.eol.flag, "--no-eol");
});

test("sourceForUrl maps a URL to its source by host, including subdomains and mirrors", () => {
	const m = u => sourceForUrl(u)?.id ?? null;
	assert.equal(m("https://endoflife.date/api/php.json"), "eol");
	assert.equal(m("https://api.first.org/data/v1/epss?cve=CVE-1"), "epss");
	assert.equal(m("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"), "kev");
	assert.equal(m("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1"), "nvd");
	assert.equal(m("https://api.osv.dev/v1/querybatch"), "osv");
	assert.equal(m("https://repo1.maven.org/maven2/org/x/1.0/x-1.0.pom"), "maven");
	assert.equal(m("https://maven-central-eu.storage-download.googleapis.com/maven2/x.pom"), "maven");
	assert.equal(m("https://registry.npmjs.org/lodash"), "npm");
	assert.equal(m("https://pypi.org/pypi/django/json"), "pypi");
	assert.equal(m("https://api.nuget.org/v3/registration5-gz-semver2/x/index.json"), "nuget");
	assert.equal(m("https://repo.packagist.org/p2/symfony/console.json"), "composer");
	assert.equal(m("https://rubygems.org/api/v1/gems/rails.json"), "ruby");
	assert.equal(m("https://proxy.golang.org/github.com/x/@latest"), "go");
	assert.equal(m("https://api.deps.dev/v3alpha/query"), "binary");
	assert.equal(m("https://hashlookup.circl.lu/sha256/ABC"), "binary");
	assert.equal(m("https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"), "wordfence");
	assert.equal(m("https://api.wordpress.org/core/checksums/1.0/"), "wordpress");
	assert.equal(m("https://api.github.com/repos/TYPO3/typo3/security-advisories"), "githubApi");
	assert.equal(m("https://example.invalid/whatever"), null, "an unknown host is not attributed");
	assert.equal(m("not a url"), null);
});

/* ---------------- what counts as a failure ---------------- */

test("classifyResponse: a definitive 404/410 is an ANSWER, not an outage", () => {
	// This is load-bearing: an absent coordinate is how private/internal packages are
	// detected. Treating it as an outage would abort every scan of a normal monorepo.
	assert.equal(classifyResponse({ ok: false, status: 404 }, null), "answered");
	assert.equal(classifyResponse({ ok: false, status: 410 }, null), "answered");
	assert.equal(classifyResponse({ ok: true, status: 200 }, null), "answered");
	assert.equal(classifyResponse({ ok: false, status: 400 }, null), "answered");
});

test("classifyResponse: throttling, auth walls, server errors and transport errors are outages", () => {
	for (const status of [403, 429, 500, 502, 503, 504]) {
		assert.equal(classifyResponse({ ok: false, status }, null), "unavailable", `HTTP ${status}`);
	}
	assert.equal(classifyResponse(null, new Error("getaddrinfo ENOTFOUND")), "unavailable");
	assert.equal(classifyResponse(null, new Error("ECONNREFUSED")), "unavailable");
	assert.equal(classifyResponse(null, new Error("The operation was aborted")), "unavailable");
});

/* ---------------- retry policy ---------------- */

test("retry policy is 5 attempts waiting 5+n seconds", () => {
	assert.equal(RETRY_ATTEMPTS, 5);
	assert.deepEqual(retryDelaysMs(), [6000, 7000, 8000, 9000, 10000]);
});

/* ---------------- the ledger ---------------- */

test("a source is only degraded once its retries are exhausted; a recovery clears nothing but records no outage", async () => {
	const h = createSourceHealth();
	assert.deepEqual(h.degraded(), []);
	h.markOutage("epss", { url: "https://api.first.org/x", code: "HTTP 503" });
	assert.deepEqual(h.degraded().map(d => d.id), ["epss"]);
});

test("the ledger keeps every distinct error code and the first failing URL, deduped and ordered", () => {
	const h = createSourceHealth();
	h.markOutage("nvd", { url: "https://services.nvd.nist.gov/a", code: "HTTP 429" });
	h.markOutage("nvd", { url: "https://services.nvd.nist.gov/b", code: "HTTP 429" });
	h.markOutage("nvd", { url: "https://services.nvd.nist.gov/c", code: "HTTP 503" });
	const [d] = h.degraded();
	assert.equal(d.id, "nvd");
	assert.deepEqual(d.codes, ["HTTP 429", "HTTP 503"]);
	assert.equal(d.url, "https://services.nvd.nist.gov/a", "the FIRST failing URL is the reproducible one");
	assert.equal(d.attempts, 3);
});

test("a host that is already down is reported as down so callers stop querying it", () => {
	const h = createSourceHealth();
	assert.equal(h.isDown("epss"), false);
	h.markOutage("epss", { url: "https://api.first.org/x", code: "HTTP 503" });
	assert.equal(h.isDown("epss"), true);
	assert.equal(h.isDown("kev"), false);
});

/* ---------------- the message ---------------- */

test("formatAbort names the source, the domain, the codes, the failing URL and the disable flag", () => {
	const h = createSourceHealth();
	h.markOutage("eol", { url: "https://endoflife.date/api/symfony.json", code: "HTTP 403" });
	const msg = formatAbort(h.degraded());
	assert.match(msg, /endoflife\.date/, "the domain");
	assert.match(msg, /HTTP 403/, "the code");
	assert.match(msg, /https:\/\/endoflife\.date\/api\/symfony\.json/, "the failing URL");
	assert.match(msg, /--no-eol/, "the flag that disables this source");
	assert.match(msg, /--offline/, "the one-shot escape");
	assert.match(msg, /5 attempts/, "says the retries happened");
	// This block is the operator's diagnostic, printed in the terminal's own language. It
	// was the single French block in an otherwise English CLI.
	assert.doesNotMatch(msg, /injoignable|tentative|aucune réponse|Relancer|zéro réseau|ignorer/,
		"the abort block is English, like the rest of the terminal");
});

test("formatAbort lists every degraded source, so one re-run can disable them all", () => {
	const h = createSourceHealth();
	h.markOutage("epss", { url: "https://api.first.org/x", code: "HTTP 503" });
	h.markOutage("kev", { url: "https://www.cisa.gov/y", code: "ETIMEDOUT" });
	const msg = formatAbort(h.degraded());
	assert.match(msg, /--no-epss/);
	assert.match(msg, /--no-kev/);
});

/* ---------------- the guard ---------------- */

test("guardedFetch passes a good response straight through and records nothing", async () => {
	const h = createSourceHealth();
	const f = guardedFetch({ health: h, fetch: async () => ({ ok: true, status: 200 }), sleep: async () => {} });
	const r = await f("https://api.first.org/data");
	assert.equal(r.status, 200);
	assert.deepEqual(h.degraded(), []);
});

test("guardedFetch retries 5 times with the 5+n schedule, logs each one, then marks the outage", async () => {
	const h = createSourceHealth();
	const waits = [], logged = [];
	let calls = 0;
	const f = guardedFetch({
		health: h,
		fetch: async () => { calls++; return { ok: false, status: 429 }; },
		sleep: async ms => { waits.push(ms); },
		onRetry: e => logged.push(e),
	});
	const r = await f("https://api.first.org/data/v1/epss");
	assert.equal(calls, 6, "the first call plus 5 retries");
	assert.deepEqual(waits, [6000, 7000, 8000, 9000, 10000]);
	assert.equal(logged.length, 5);
	assert.equal(logged[0].attempt, 1);
	assert.equal(logged[0].code, "HTTP 429");
	assert.equal(logged[0].source, "epss");
	assert.equal(logged[4].attempt, 5);
	assert.equal(r.ok, false, "the last response is still handed back — callers keep their own fallbacks");
	assert.deepEqual(h.degraded().map(d => d.id), ["epss"]);
});

test("guardedFetch stops retrying as soon as the host answers", async () => {
	const h = createSourceHealth();
	let calls = 0;
	const f = guardedFetch({
		health: h,
		fetch: async () => { calls++; return calls < 3 ? { ok: false, status: 503 } : { ok: true, status: 200 }; },
		sleep: async () => {},
	});
	const r = await f("https://api.osv.dev/v1/query");
	assert.equal(calls, 3);
	assert.equal(r.ok, true);
	assert.deepEqual(h.degraded(), [], "a blip that recovered is not a coverage hole");
});

test("guardedFetch never retries a 404 — it is an answer", async () => {
	const h = createSourceHealth();
	let calls = 0;
	const f = guardedFetch({ health: h, fetch: async () => { calls++; return { ok: false, status: 404 }; }, sleep: async () => {} });
	const r = await f("https://registry.npmjs.org/@acme/internal");
	assert.equal(calls, 1);
	assert.equal(r.status, 404);
	assert.deepEqual(h.degraded(), []);
});

test("guardedFetch short-circuits a host already known to be down, without sleeping again", async () => {
	const h = createSourceHealth();
	h.markOutage("nvd", { url: "https://services.nvd.nist.gov/first", code: "HTTP 503" });
	let calls = 0, slept = 0;
	const f = guardedFetch({ health: h, fetch: async () => { calls++; return { ok: true, status: 200 }; }, sleep: async () => { slept++; } });
	await assert.rejects(() => f("https://services.nvd.nist.gov/again"), /already unreachable/i);
	assert.equal(calls, 0, "a dead host is not queried 400 more times");
	assert.equal(slept, 0);
});

test("an unattributed host is left completely alone — no retries, no ledger", async () => {
	const h = createSourceHealth();
	let calls = 0;
	const f = guardedFetch({ health: h, fetch: async () => { calls++; return { ok: false, status: 503 }; }, sleep: async () => {} });
	const r = await f("https://something.else.invalid/x");
	assert.equal(calls, 1);
	assert.equal(r.status, 503);
	assert.deepEqual(h.degraded(), []);
});

test("a transport error is retried and then rethrown, so existing catch blocks still see it", async () => {
	const h = createSourceHealth();
	let calls = 0;
	const f = guardedFetch({ health: h, fetch: async () => { calls++; throw new Error("ECONNREFUSED"); }, sleep: async () => {} });
	await assert.rejects(() => f("https://endoflife.date/api/php.json"), /ECONNREFUSED/);
	assert.equal(calls, 6);
	assert.deepEqual(h.degraded().map(d => d.id), ["eol"]);
});

test("concurrent requests to one dead source share a single retry loop", async () => {
	// Without this, a 400-dependency reactor starts 400 retry schedules before any of them
	// declares the host down: minutes of sleeping and a flooded log for one dead domain.
	const h = createSourceHealth();
	let calls = 0, retries = 0;
	const f = guardedFetch({
		health: h,
		fetch: async () => { calls++; return { ok: false, status: 503 }; },
		sleep: async () => {},
		onRetry: () => retries++,
	});
	const urls = Array.from({ length: 6 }, (_, i) => `https://api.osv.dev/v1/q${i}`);
	await Promise.all(urls.map(u => f(u).catch(() => null)));
	assert.equal(retries, 5, "one schedule, not six");
	assert.ok(calls <= 6 + 5, `first attempts plus one retry loop, got ${calls}`);
	assert.deepEqual(h.degraded().map(d => d.id), ["osv"]);
	assert.equal(h.degraded()[0].codes.join(","), "HTTP 503");
});

test("a source that recovers lets the waiting callers through", async () => {
	const h = createSourceHealth();
	let n = 0;
	const f = guardedFetch({
		health: h,
		fetch: async () => { n++; return n <= 3 ? { ok: false, status: 503 } : { ok: true, status: 200 }; },
		sleep: async () => {},
	});
	const rs = await Promise.all([f("https://pypi.org/pypi/a/json"), f("https://pypi.org/pypi/b/json")]);
	assert.ok(rs.every(r => r.ok), "both callers got a real answer after the recovery");
	assert.deepEqual(h.degraded(), [], "a recovered blip is not a coverage hole");
});

test("a caller that owns a deadline is never retried behind its back", async () => {
	// lib/maven-repo.js wraps each mirror attempt in withDeadline(5s) and fails over to the
	// next mirror; lib/registries.js and the npm registry do the same with
	// AbortSignal.timeout. Retrying inside that budget is both futile — the signal is
	// already aborted, so every retry fails instantly — and ruinous: 40s of sleeping per
	// dead mirror instead of an immediate failover. Measured at 40.0s before this rule.
	const h = createSourceHealth();
	let calls = 0, slept = 0;
	const f = guardedFetch({
		health: h,
		fetch: async (url, init) => { calls++; if (init?.signal?.aborted) throw new Error("aborted"); throw new Error("timeout after 5000 ms"); },
		sleep: async () => { slept++; },
	});
	const ac = new AbortController(); ac.abort();
	await assert.rejects(() => f("https://repo1.maven.org/maven2/x/maven-metadata.xml", { signal: ac.signal }), /aborted/);
	assert.equal(calls, 1, "one attempt, then straight back to the caller's own failover");
	assert.equal(slept, 0, "no backoff inside someone else's budget");
	assert.deepEqual(h.degraded(), [], "one mirror failing is not a source outage — the next mirror may answer");
});

test("a live signal is respected too: still one attempt, no schedule", async () => {
	const h = createSourceHealth();
	let calls = 0, slept = 0;
	const f = guardedFetch({
		health: h,
		fetch: async () => { calls++; return { ok: false, status: 429 }; },
		sleep: async () => { slept++; },
	});
	const r = await f("https://registry.npmjs.org/lodash", { signal: AbortSignal.timeout(5000) });
	assert.equal(r.status, 429);
	assert.equal(calls, 1);
	assert.equal(slept, 0);
});

test("single-endpoint sources, which have no failover of their own, still get the schedule", async () => {
	const h = createSourceHealth();
	let calls = 0;
	const f = guardedFetch({ health: h, fetch: async () => { calls++; return { ok: false, status: 429 }; }, sleep: async () => {} });
	await f("https://api.first.org/data/v1/epss");
	assert.equal(calls, 6, "EPSS passes no signal, so the retry schedule applies");
	assert.deepEqual(h.degraded().map(d => d.id), ["epss"]);
});

/* ---------------- fan-out exhaustion (Maven mirrors, registry bases) ---------------- */

const { classifyMissReason, noteFanoutExhausted, setActiveLedger } = require("../lib/source-health");

test("classifyMissReason: a 404/410 from a mirror is an answer; throttling and transport are not", () => {
	assert.equal(classifyMissReason("HTTP 404"), "answered");
	assert.equal(classifyMissReason("HTTP 410"), "answered");
	assert.equal(classifyMissReason("HTTP 401"), "answered", "an auth-walled private repo still answered");
	assert.equal(classifyMissReason("HTTP 429"), "unavailable");
	assert.equal(classifyMissReason("HTTP 503"), "unavailable");
	assert.equal(classifyMissReason("network: timeout after 5000 ms"), "unavailable");
	assert.equal(classifyMissReason(""), "unavailable");
});

test("a lookup where EVERY host was unavailable is a coverage hole", () => {
	const h = createSourceHealth();
	setActiveLedger(h);
	noteFanoutExhausted("https://repo1.maven.org/maven2/g/a/maven-metadata.xml",
		["network: timeout after 5000 ms", "HTTP 503", "HTTP 429"]);
	assert.deepEqual(h.degraded().map(d => d.id), ["maven"]);
	assert.equal(h.degraded()[0].url, "https://repo1.maven.org/maven2/g/a/maven-metadata.xml");
	setActiveLedger(null);
});

test("a lookup that 404s everywhere is a private package, NOT an outage", () => {
	// This is the whole point: an internal coordinate absent from every configured repo is
	// the finding fad exists to produce. Aborting the run on it would break every monorepo.
	const h = createSourceHealth();
	setActiveLedger(h);
	noteFanoutExhausted("https://registry.npmjs.org/@acme/internal", ["HTTP 404", "HTTP 404"]);
	assert.deepEqual(h.degraded(), []);
	setActiveLedger(null);
});

test("one host answering 404 while another times out is still an answer", () => {
	const h = createSourceHealth();
	setActiveLedger(h);
	noteFanoutExhausted("https://repo1.maven.org/maven2/x", ["network: ECONNREFUSED", "HTTP 404"]);
	assert.deepEqual(h.degraded(), [], "the rotation reached a host that knew the answer");
	setActiveLedger(null);
});

test("with no ledger registered (offline, or a unit test) the hook is inert", () => {
	setActiveLedger(null);
	assert.doesNotThrow(() => noteFanoutExhausted("https://api.osv.dev/x", ["HTTP 503"]));
	assert.doesNotThrow(() => noteFanoutExhausted("not-a-url", []));
});

/* ---------------- --retries ---------------- */
const { setRetryAttempts, getRetryAttempts, describeSchedule } = require("../lib/source-health");

test("--retries: guardedFetch honours a configured retry count (schedule stays 5+n)", async () => {
	const h = createSourceHealth();
	const waits = [];
	let calls = 0;
	const f = guardedFetch({ health: h, retries: 2, fetch: async () => { calls++; return { ok: false, status: 503 }; }, sleep: async ms => { waits.push(ms); } });
	await f("https://api.first.org/data/v1/epss");
	assert.equal(calls, 3, "the first call plus 2 retries");
	assert.deepEqual(waits, [6000, 7000]);
	assert.deepEqual(h.degraded().map(d => d.id), ["epss"]);
});

test("--retries 0: the first failed answer declares the source down, without sleeping", async () => {
	const h = createSourceHealth();
	let calls = 0, slept = 0;
	const f = guardedFetch({ health: h, retries: 0, fetch: async () => { calls++; return { ok: false, status: 503 }; }, sleep: async () => { slept++; } });
	await f("https://api.first.org/data/v1/epss");
	assert.equal(calls, 1);
	assert.equal(slept, 0);
	assert.equal(h.isDown("epss"), true);
});

test("--retries: the run-wide setting reaches guards built without an explicit count, and the abort message", async () => {
	try {
		assert.equal(getRetryAttempts(), 5, "default is 5");
		setRetryAttempts("3");
		const h = createSourceHealth();
		let calls = 0;
		const f = guardedFetch({ health: h, fetch: async () => { calls++; return { ok: false, status: 503 }; }, sleep: async () => {} });
		await f("https://api.first.org/data/v1/epss");
		assert.equal(calls, 4);
		assert.match(formatAbort(h.degraded()), /3 attempts, 6→8 s/);
		assert.equal(describeSchedule(0), "no retry");
		assert.equal(describeSchedule(1), "1 attempt, 6 s");
	} finally { setRetryAttempts(5); }
});

test("--retries: a value that is not a non-negative integer is refused, never clamped", () => {
	for (const bad of ["five", "-1", "2.5", "", null]) assert.throws(() => setRetryAttempts(bad), /non-negative integer/);
	assert.equal(getRetryAttempts(), 5, "a refused value leaves the setting untouched");
});
test('refresh failure summary is omitted only when every failed cache request is already described',()=>{
 const health=require('../lib/source-health').createSourceHealth();
 health.markStale('euvd',new Date().toISOString(),{reason:'refresh-failed',requestKey:'detail-a'});
 assert.equal(health.unreportedStale(['detail-a']).length,0);
 health.markStale('euvd',new Date().toISOString(),{reason:'refresh-failed',requestKey:'detail-b'});
 assert.equal(health.unreportedStale(['detail-a']).length,1);
 health.markStale('euvd',new Date().toISOString(),{reason:'refresh-failed'});
 assert.equal(health.unreportedStale(['detail-a','detail-b']).length,1);
 assert.equal(health.stale()[0].blocking,true);
});

test('stale filtering retains unrelated nonblocking and unkeyed observations without inheriting covered failure severity',()=>{
 const h=createSourceHealth();
 h.markStale('nvd','2024-01-01T00:00:00Z',{reason:'refresh-failed',requestKey:'cve-a'});
 h.markStale('nvd','2025-01-01T00:00:00Z',{requestKey:'spip'});
 assert.deepEqual(h.unreportedStale(['cve-a']),[{id:'nvd',at:Date.parse('2025-01-01T00:00:00Z')}]);
 assert.deepEqual(h.unreportedStale(['cve-a','spip']),[]);
 h.markStale('nvd','2025-02-01T00:00:00Z');
 assert.equal(h.unreportedStale(['cve-a','spip']).length,1);
});

test('request keys are stripped before fetch and concurrent failures remain independently attributable',async()=>{
 const {REQUEST_KEY}=require('../lib/source-health'),h=createSourceHealth(),seen=[];
 const f=guardedFetch({health:h,retries:0,fetch:async(url,init)=>{seen.push(Object.getOwnPropertySymbols(init));await Promise.resolve();return {status:503}},sleep:async()=>{}});
 await Promise.all(['a','b'].map(k=>f('https://services.nvd.nist.gov/rest/json/cves/2.0',{[REQUEST_KEY]:k})));
 assert.deepEqual(seen,[[],[]]);
 assert.equal(h.unreportedOutages(['a']).length,1);
 assert.equal(h.unreportedOutages(['a','b']).length,0);
});

test('fanout preserves each request key and unrelated unkeyed outages',()=>{
 const h=createSourceHealth();setActiveLedger(h);
 try {
  noteFanoutExhausted('https://services.nvd.nist.gov/x',['HTTP 429'],{requestKey:'cve'});
  noteFanoutExhausted('https://services.nvd.nist.gov/y',['HTTP 503'],{requestKey:'spip'});
  assert.equal(h.unreportedOutages(['cve']).length,1);
	  assert.deepEqual(h.unreportedOutages(['cve'])[0].codes,['HTTP 503']);
  assert.equal(h.unreportedOutages(['cve','spip']).length,0);
  noteFanoutExhausted('https://services.nvd.nist.gov/z',['HTTP 503']);
  assert.equal(h.unreportedOutages(['cve','spip']).length,1);
 } finally {setActiveLedger(null)}
});

test('direct 429 respects Retry-After and retains the last failure when the budget expires', async () => {
	const health = createSourceHealth(), delays = [], notices = [];
	const replies = [
		new Response(null,{status:429,headers:{'retry-after':'15'}}),
		new Response('unavailable',{status:503,headers:{'retry-after':'3600'}}),
	];
	const fetch = guardedFetch({health,retries:2,fetch:async()=>replies.shift(),sleep:async ms=>delays.push(ms),onRetry:e=>notices.push(e)});
	const res = await fetch('https://api.osv.dev/test');
	assert.deepEqual(delays,[15000]);
	assert.deepEqual(notices.map(n=>[n.code,!!n.exhausted]),[['HTTP 429',false],['HTTP 503',true]]);
	assert.equal(res.status,503);
	assert.equal(await res.text(),'unavailable');
	assert.deepEqual(health.degraded()[0].codes,['HTTP 503']);
});

test('self-hosted proxy announces source retries for transient failures', async t => {
	const {configureResourceRoute,getResource} = require('../lib/providers');
	const notices = [], waits = [];
	let calls = 0;
	configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:false,health:createSourceHealth(),store:null,
		fetcher:async()=>++calls===1 ? new Response(null,{status:503}) : Response.json({id:'CVE-2024-12345'}),
		sleep:async ms=>waits.push(ms),onRetry:notice=>notices.push(notice)});
	t.after(()=>configureResourceRoute({proxyUrl:null,hosted:false,health:null,store:null,fetcher:null,sleep:null,onRetry:null}));
	const response = await getResource('osv','vuln',{id:'CVE-2024-12345'});
	assert.equal(response.status,200);
	assert.deepEqual(waits,[6000]);
	assert.deepEqual(notices.map(e=>[e.source,e.code,e.attempt]),[['osv','HTTP 503',1]]);
});
