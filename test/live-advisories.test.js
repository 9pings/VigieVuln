const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { DRUPAL_ADVISORIES_URL, fetchDrupalAdvisories, fetchWordfenceFeed, fetchGithubAdvisories, writeSnapshotAtomically } = require("../lib/application-providers/live-snapshot");
const { indexFeed } = require("../lib/application-providers/wordfence-v3");
const { validateSnapshot: validateGithub } = require("../lib/application-providers/github-advisories");
const drupal = require("../lib/application-plugins/drupal");
const wordpress = require("../lib/application-plugins/wordpress");
const prestashop = require("../lib/application-plugins/prestashop");
const typo3 = require("../lib/application-plugins/typo3");
const { runApplicationPlugins } = require("../lib/application-plugins/runner");

const NOW = Date.parse("2026-09-23T12:00:00Z");
const jsonResponse = body => ({ ok: true, status: 200, text: async () => JSON.stringify(body), json: async () => body });

test("the Drupal live client queries the official per-package endpoint and stamps an honest snapshot", async () => {
	assert.equal(DRUPAL_ADVISORIES_URL, "https://packages.drupal.org/8/security-advisories");
	const calls = [];
	const entry = { advisoryId: "SA-CORE-2018-002", packageName: "drupal/core", title: "Drupal core - Fixture",
		link: "https://www.drupal.org/sa-core-2018-002", cve: "CVE-2018-7600", affectedVersions: ">=7.0 <7.58" };
	const fetched = await fetchDrupalAdvisories(["drupal/core", "Drupal/Webform", "drupal/core"],
		{ fetchImpl: async url => { calls.push(url); return jsonResponse({ advisories: { "drupal/core": [entry] } }); }, now: NOW });
	assert.equal(calls.length, 1);
	assert.equal(calls[0].startsWith(`${DRUPAL_ADVISORIES_URL}?`), true);
	assert.ok(calls[0].includes("packages%5B%5D=drupal%2Fcore"));
	assert.ok(calls[0].includes("packages%5B%5D=drupal%2Fwebform"));
	assert.deepEqual(fetched.snapshot.queriedPackages, ["drupal/core", "drupal/webform"]);
	assert.deepEqual(fetched.snapshot.advisories, { "drupal/core": [entry] });
	assert.equal(fetched.snapshot._fadSnapshot.collectedAt, "2026-09-23T12:00:00.000Z");
	assert.equal(fetched.snapshot._fadSnapshot.completeness, "tool-fetched");
	assert.equal(fetched.snapshot._fadSnapshot.sourceUrl, DRUPAL_ADVISORIES_URL);
	assert.match(fetched.sourceSnapshot.sha256, /^[a-f0-9]{64}$/);
	assert.equal(fetched.sourceSnapshot.completeness, "tool-fetched");
});

test("the Drupal live client surfaces API errors and skips the network without packages", async () => {
	let called = 0;
	await assert.rejects(fetchDrupalAdvisories(["drupal/core"],
		{ fetchImpl: async () => jsonResponse({ status: "error", message: "Missing array of package names" }) }),
		/Missing array of package names/);
	await assert.rejects(fetchDrupalAdvisories(["drupal/core"],
		{ fetchImpl: async () => ({ ok: false, status: 503, text: async () => "Service Unavailable" }) }),
		/503/);
	const empty = await fetchDrupalAdvisories([], { fetchImpl: async () => { called++; return jsonResponse({}); }, now: NOW });
	assert.equal(called, 0, "no packages means no request, and an honest empty snapshot");
	assert.deepEqual(empty.snapshot, { queriedPackages: [], advisories: {},
		_fadSnapshot: { collectedAt: "2026-09-23T12:00:00.000Z", completeness: "tool-fetched", sourceUrl: DRUPAL_ADVISORIES_URL } });
});

test("the Wordfence live client validates the feed and stamps collection metadata", async () => {
	const uuid = "123e4567-e89b-12d3-a456-426614174000";
	const record = { id: uuid, title: "Fixture advisory", cve: null, software: [{ type: "theme", slug: "acme-theme",
		affected_versions: { a: { from_version: "1", from_inclusive: true, to_version: "2", to_inclusive: true } } }] };
	const urls = [];
	const fetched = await fetchWordfenceFeed("https://operator.invalid/production.json",
		{ fetchImpl: async (url, init) => { urls.push([url, init.headers.Authorization]); return jsonResponse({ [uuid]: record }); },
			apiKey: "test-token", now: NOW });
	assert.deepEqual(urls, [["https://operator.invalid/production.json", "Bearer test-token"]]);
	assert.equal(indexFeed(fetched.snapshot).get("theme:acme-theme").length, 1, "the fetched feed stays matchable with its metadata");
	assert.equal(fetched.snapshot._fadSnapshot.sourceUrl, "https://operator.invalid/production.json");
	await assert.rejects(fetchWordfenceFeed("https://operator.invalid/broken.json",
		{ fetchImpl: async () => jsonResponse({ notAFeed: true }), apiKey: "test-token" }), /Wordfence v3/);
	await assert.rejects(fetchWordfenceFeed("https://operator.invalid/down.json",
		{ fetchImpl: async () => ({ ok: false, status: 403, text: async () => "Forbidden" }), apiKey: "test-token" }), /403/);
	await assert.rejects(fetchWordfenceFeed("https://operator.invalid/production.json",
		{ fetchImpl: async () => { throw new Error("should not fetch without a key"); } }), /requires an API key/);
});

test("the Github live client pages the publisher's advisory feed and stamps collection metadata", async () => {
	const record = page => ({ ghsa_id: `GHSA-page${page}`, cve_id: null, summary: `Fixture ${page}`, severity: "low",
		cvss: null, vulnerabilities: [{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
			vulnerable_version_range: ">= 1.0.0", patched_versions: "", vulnerable_functions: [] }],
		published_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", html_url: "https://example.invalid/" + page });
	const urls = [];
	const paged = (url, page) => ({ ok: true, status: 200, text: async () => JSON.stringify([record(page)]),
		headers: { get: name => name.toLowerCase() === "link" ? (page === 1 ? `<${url}&page=2>; rel="next", <${url}>; rel="first"` : null) : null } });
	const fetched = await fetchGithubAdvisories("PrestaShop/PrestaShop",
		{ fetchImpl: async (url, init) => { urls.push([url, init?.headers?.Accept]); return paged(url, urls.length); }, now: NOW });
	assert.equal(urls.length, 2, "both pages are fetched");
	assert.match(urls[0][0], /^https:\/\/api\.github\.com\/repos\/PrestaShop\/PrestaShop\/security-advisories\?per_page=100$/);
	assert.equal(urls[0][1], "application/vnd.github+json");
	assert.deepEqual(fetched.snapshot.advisories.map(a => a.ghsa_id), ["GHSA-page1", "GHSA-page2"]);
	assert.equal(fetched.snapshot._fadSnapshot.collectedAt, "2026-09-23T12:00:00.000Z");
	assert.equal(fetched.snapshot._fadSnapshot.completeness, "tool-fetched");
	assert.equal(fetched.snapshot._fadSnapshot.sourceUrl, "https://api.github.com/repos/PrestaShop/PrestaShop/security-advisories?per_page=100");
	assert.match(fetched.sourceSnapshot.sha256, /^[a-f0-9]{64}$/);
	assert.equal(validateGithub(fetched.snapshot, { fallbackCoord: "prestashop/prestashop" }).index.get("prestashop/prestashop").length, 2,
		"the fetched snapshot stays matchable");
});

test("the Github live client refuses broken feeds and runaway pagination", async () => {
	await assert.rejects(fetchGithubAdvisories("typo3/typo3",
		{ fetchImpl: async () => jsonResponse({ notAnArray: true }) }), /must return a JSON array/);
	await assert.rejects(fetchGithubAdvisories("typo3/typo3",
		{ fetchImpl: async () => ({ ok: false, status: 403, text: async () => "Forbidden" }) }), /403/);
	await assert.rejects(fetchGithubAdvisories("typo3/typo3",
		{ fetchImpl: async url => ({ ok: true, status: 200, text: async () => "[]",
			headers: { get: () => `<${url}>; rel="next"` } }), maxPages: 2 }), /more than 2 page/);
	await assert.rejects(fetchGithubAdvisories("not-a-repo", { fetchImpl: async () => jsonResponse([]) }), /owner\/repo/);
});

test("snapshot cache writes are atomic and leave no temporary residue", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-live-cache-"));
	try {
		const file = path.join(temp, "drupal-security-advisories.json");
		writeSnapshotAtomically(file, { queriedPackages: [], advisories: {}, _fadSnapshot: { collectedAt: "2026-09-23T12:00:00.000Z" } });
		assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")).queriedPackages, []);
		assert.equal(fs.readdirSync(temp).length, 1, "only the final file remains after the atomic rename");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("the Drupal plugin queries live advisories for its inventoried public packages", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-drupal-live-"));
	try {
		const cacheDir = path.join(temp, "cache");
		const calls = [];
		const entry = { advisoryId: "SA-CORE-2099-001", packageName: "drupal/core", title: "Drupal core - Critical - Fixture",
			link: "https://www.drupal.org/sa-core-2099-001", cve: null, affectedVersions: ">=10.3.0 <10.3.2" };
		const root = path.join(__dirname, "fixtures", "drupal-custom");
		const { deps } = await require("../lib/codecs/composer.codec").collect(root);
		const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal",
			resolvedDeps: deps, activeCodecIds: ["composer"], liveDrupalAdvisoriesUrl: "https://example.invalid/security-advisories",
			advisoryCacheDir: cacheDir, fetchImpl: async url => { calls.push(url);
				return jsonResponse({ advisories: { "drupal/core": [entry] } }); }, now: NOW,
			requiredProviderIds: ["drupal-security-advisories"] });
		assert.equal(result.findings.length, 1);
		assert.equal(result.findings[0].cve.id, "SA-CORE-2099-001");
		assert.deepEqual(calls, ["https://example.invalid/security-advisories?packages%5B%5D=drupal%2Fcore"],
			"only the public core identity is queried; the private custom module is not");
		const advisories = result.coverage.find(c => c.capability === "advisories");
		assert.equal(advisories.sourceSnapshot.completeness, "tool-fetched");
		assert.equal(advisories.sourceSnapshot.collectedAt, "2026-09-23T12:00:00.000Z");
		const cached = JSON.parse(fs.readFileSync(path.join(cacheDir, "drupal-security-advisories.json"), "utf8"));
		assert.equal(cached._fadSnapshot.sourceUrl, "https://example.invalid/security-advisories");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("a failing live Drupal source stops the scan like any required provider", async () => {
	const root = path.join(__dirname, "fixtures", "drupal-custom");
	const { deps } = await require("../lib/codecs/composer.codec").collect(root);
	await assert.rejects(runApplicationPlugins(root, { plugins: [drupal], selection: "drupal",
		resolvedDeps: deps, activeCodecIds: ["composer"], liveDrupalAdvisoriesUrl: "https://example.invalid/security-advisories",
		fetchImpl: async () => ({ ok: false, status: 500, text: async () => "boom" }),
		requiredProviderIds: ["drupal-security-advisories"] }), /500/);
});

test("the WordPress plugin assesses a live feed for a user-declared public theme", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wp-live-"));
	try {
		const uuid = "123e4567-e89b-12d3-a456-426614174000";
		const record = { id: uuid, title: "Fixture theme advisory", cve: null,
			software: [{ type: "theme", slug: "acme-theme", affected_versions: { a: { from_version: "1", from_inclusive: true,
				to_version: "2", to_inclusive: true } }, patched_versions: ["2.1"] }],
			copyrights: { defiant: { notice: "Fixture copyright" } } };
		const root = path.join(__dirname, "fixtures", "wordpress-custom");
		const result = await runApplicationPlugins(root, { plugins: [wordpress], selection: "wordpress",
			activeCodecIds: [], publicComponents: ["site/wp-content/themes/acme-theme=acme-theme"],
			liveWordfenceUrl: "https://operator.invalid/production.json",
			wordfenceApiKey: "test-token",
			advisoryCacheDir: path.join(temp, "cache"),
			fetchImpl: async () => jsonResponse({ [uuid]: record }), now: NOW,
			requiredProviderIds: ["wordfence-v3"] });
		assert.equal(result.findings.length, 1);
		assert.equal(result.findings[0].cve.id, `WF-${uuid}`);
		assert.equal(result.findings[0].cve.copyrightNotice, "Fixture copyright");
		assert.equal(result.coverage.find(c => c.capability === "advisories").sourceSnapshot.completeness, "tool-fetched");
		assert.ok(fs.existsSync(path.join(temp, "cache", "wordfence-v3.json")));
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

// Builds a scan root holding two independent Drupal instances. The instance discovered
// first ("alpha") carries only drupal/core; whether the second instance ("beta") carries
// the extra public module drupal/foo is controlled by `fooInSecond`. Swapping the flag
// inverts which instance is discovered first with the extra package.
function twoInstanceRoot(dir, fooInSecond) {
	const mkSite = (name, withFoo) => {
		const site = path.join(dir, name);
		fs.mkdirSync(path.join(site, "web", "core", "lib"), { recursive: true });
		fs.mkdirSync(path.join(site, "web", "modules"), { recursive: true });
		fs.writeFileSync(path.join(site, "composer.json"), JSON.stringify({ name: `example/${name}`,
			require: { "drupal/core": "^10.3" } }, null, "\t"));
		fs.writeFileSync(path.join(site, "composer.lock"), JSON.stringify({ packages: [
			{ name: "drupal/core", version: "10.3.1", type: "drupal-core" }], "packages-dev": [] }, null, "\t"));
		fs.writeFileSync(path.join(site, "web", "core", "core.services.yml"), "services: {}\n");
		fs.writeFileSync(path.join(site, "web", "core", "lib", "Drupal.php"),
			"<?php\n// Reduced structural marker.\nclass Drupal { const VERSION = '10.3.1'; }\n");
		if (withFoo) {
			fs.mkdirSync(path.join(site, "web", "modules", "foo"), { recursive: true });
			fs.writeFileSync(path.join(site, "web", "modules", "foo", "foo.info.yml"),
				"name: Foo\ntype: module\nversion: '1.0.0'\nproject: foo\ncore_version_requirement: ^10\n");
		}
	};
	mkSite("alpha", !fooInSecond);
	mkSite("beta", fooInSecond);
	return dir;
}

const drupalFakeEndpoint = calls => async url => {
	calls.push(url);
	const requested = [...new URL(url).searchParams.getAll("packages[]")];
	const advisories = {};
	for (const pkg of requested) advisories[pkg] = [{
		advisoryId: `SA-CONTRIB-2099-${pkg === "drupal/foo" ? "002" : "001"}`, packageName: pkg,
		title: `${pkg} - Moderately critical - Fixture`, link: "https://www.drupal.org/sa-contrib-2099",
		cve: null, affectedVersions: pkg === "drupal/foo" ? ">=1.0.0 <1.0.1" : ">=10.3.0 <10.3.2" }];
	return jsonResponse({ advisories });
};

test("the Drupal live source queries the union of every instance's public packages, in any discovery order", async () => {
	for (const fooInSecond of [true, false]) {
		const temp = fs.mkdtempSync(path.join(os.tmpdir(), `fad-drupal-union-${fooInSecond ? "b" : "a"}-`));
		try {
			const cacheDir = path.join(temp, "cache");
			const calls = [];
			const root = twoInstanceRoot(path.join(temp, "src"), fooInSecond);
			const { deps } = await require("../lib/codecs/composer.codec").collect(root);
			const result = await runApplicationPlugins(root, { plugins: [drupal], selection: "drupal",
				resolvedDeps: deps, activeCodecIds: ["composer"],
				liveDrupalAdvisoriesUrl: "https://example.invalid/security-advisories",
				advisoryCacheDir: cacheDir, fetchImpl: drupalFakeEndpoint(calls), now: NOW,
				requiredProviderIds: ["drupal-security-advisories"] });
			// Every public identity of every instance is matched against a response that
			// covered it: no CMS_PACKAGE_NOT_QUERIED, in either discovery order.
			assert.ok(!result.coverage.some(c => c.diagnostic === "CMS_PACKAGE_NOT_QUERIED"),
				`coverage must never report CMS_PACKAGE_NOT_QUERIED (order fooInSecond=${fooInSecond})`);
			const advisoryIds = result.findings.map(f => f.cve.id).sort();
			assert.deepEqual(advisoryIds, ["SA-CONTRIB-2099-001", "SA-CONTRIB-2099-001", "SA-CONTRIB-2099-002"],
				`core matches in both instances and foo in its own (order fooInSecond=${fooInSecond})`);
			const fooCoverage = result.coverage.find(c => (c.occurrenceId || "").includes("web/modules/foo"));
			assert.ok(fooCoverage, "the foo module keeps its own coverage row");
			assert.equal(fooCoverage.execution, "completed");
			assert.equal(fooCoverage.result, "affected");
			// The reusable disk snapshot holds the exact union of packages actually queried.
			const cached = JSON.parse(fs.readFileSync(path.join(cacheDir, "drupal-security-advisories.json"), "utf8"));
			assert.deepEqual([...cached.queriedPackages].sort(), ["drupal/core", "drupal/foo"],
				`disk cache holds the queried union (order fooInSecond=${fooInSecond})`);
			assert.ok(Object.keys(cached.advisories).includes("drupal/foo"));
			for (const call of calls) for (const pkg of new URL(call).searchParams.getAll("packages[]"))
				assert.match(pkg, /^drupal\/(core|foo)$/, "private or already-covered packages are never re-sent");
		} finally { fs.rmSync(temp, { recursive: true, force: true }); }
	}
});

test("the CLI refuses live advisory sources under --offline", () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-live-offline-"));
	try {
		const src = path.join(__dirname, "fixtures", "drupal-custom");
		for (const extra of [["--drupal-advisories-live"], ["--wordfence-feed-url", "https://operator.invalid/feed.json"],
			["--prestashop-advisories-live"], ["--typo3-advisories-live"], ["--wp-checksums-live"]]) {
			const run = spawnSync(process.execPath, [path.join(__dirname, "..", "vigievuln.js"), "-s", src,
				"--ecosystem", "composer", "--app-plugins", "drupal", "--offline", ...extra,
				"-d", "eol,nvd,epss,kev,retire,transitive"], { encoding: "utf8", timeout: 30000, env: { ...process.env, FORCE_COLOR: "0" } });
			assert.equal(run.status, 2, `${run.stdout}\n${run.stderr}`);
			assert.match(run.stderr, /--offline/);
		}
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

const githubPage = (records, next = null) => ({ ok: true, status: 200,
	text: async () => JSON.stringify(records),
	headers: { get: name => name.toLowerCase() === "link" ? next : null } });
const GH_RECORD = { ghsa_id: "GHSA-live-fixture", cve_id: "CVE-2026-11111", summary: "Fixture advisory",
	severity: "high", cvss: { vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
	vulnerabilities: [{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
		vulnerable_version_range: ">= 8.0.0, < 8.2.8", patched_versions: "8.2.8", vulnerable_functions: [] }],
	published_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z",
	html_url: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-live-fixture" };
const prestashopSite = (dir, version) => {
	fs.mkdirSync(path.join(dir, "config"), { recursive: true });
	fs.writeFileSync(path.join(dir, "composer.json"), JSON.stringify({ name: "prestashop/prestashop", type: "project" }));
	fs.writeFileSync(path.join(dir, "config", "config.inc.php"), "<?php // marker\n");
	fs.writeFileSync(path.join(dir, "config", "settings.inc.php"), `<?php define('_PS_VERSION_', '${version}');\n`);
};

test("the PrestaShop live lane fetches the publisher feed once per scan and reuses it for every instance", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-ps-live-"));
	try {
		const calls = [];
		prestashopSite(path.join(temp, "src", "shop-a"), "8.2.1");
		prestashopSite(path.join(temp, "src", "shop-b"), "8.2.4");
		const { deps } = await require("../lib/codecs/composer.codec").collect(path.join(temp, "src"));
		const result = await runApplicationPlugins(path.join(temp, "src"), { plugins: [prestashop], selection: "prestashop",
			resolvedDeps: deps, activeCodecIds: ["composer"], livePrestashopAdvisoriesUrl: "https://api.github.com/repos/PrestaShop/PrestaShop/security-advisories",
			advisoryCacheDir: path.join(temp, "cache"), now: NOW,
			fetchImpl: async url => { calls.push(url); return githubPage([GH_RECORD]); } });
		assert.equal(calls.length, 1, "one feed fetch serves both instances");
		assert.match(calls[0], /\/security-advisories\?per_page=100$/);
		assert.deepEqual(result.findings.map(f => f.dep.version).sort(), ["8.2.1", "8.2.4"]);
		assert.ok(result.findings.every(f => f.cve.id === "CVE-2026-11111" && f.cve.fixVersion === "8.2.8"));
		assert.ok(result.coverage.filter(c => c.capability === "advisories")
			.every(c => c.sourceSnapshot.completeness === "tool-fetched" && c.sourceSnapshot.collectedAt));
		const cached = JSON.parse(fs.readFileSync(path.join(temp, "cache", "github-prestashop-advisories.json"), "utf8"));
		assert.deepEqual(cached.advisories.map(a => a.ghsa_id), ["GHSA-live-fixture"]);
		assert.equal(cached._fadSnapshot.collectedAt, "2026-09-23T12:00:00.000Z");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("a configured live Github lane whose plugin is not selected fails the scan", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-ps-unselected-"));
	try {
		prestashopSite(path.join(temp, "src"), "8.2.1");
		const { deps } = await require("../lib/codecs/composer.codec").collect(path.join(temp, "src"));
		await assert.rejects(runApplicationPlugins(path.join(temp, "src"), { plugins: [prestashop], selection: "none",
			resolvedDeps: deps, activeCodecIds: ["composer"],
			livePrestashopAdvisoriesUrl: "https://api.github.com/repos/PrestaShop/PrestaShop/security-advisories" }),
			/github-prestashop-advisories source configured but its application plugin is not selected/);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("a failing live Github source stops the scan like any required provider", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-ps-fail-"));
	try {
		prestashopSite(path.join(temp, "src"), "8.2.1");
		const { deps } = await require("../lib/codecs/composer.codec").collect(path.join(temp, "src"));
		await assert.rejects(runApplicationPlugins(path.join(temp, "src"), { plugins: [prestashop], selection: "prestashop",
			resolvedDeps: deps, activeCodecIds: ["composer"],
			livePrestashopAdvisoriesUrl: "https://api.github.com/repos/PrestaShop/PrestaShop/security-advisories",
			fetchImpl: async () => ({ ok: false, status: 429, text: async () => "Too Many Requests" }) }),
			/PrestaShop advisory source failed|HTTP 429/);
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("the TYPO3 live lane fetches once and matches system extensions per coordinate", async () => {
	const temp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-typo3-live-"));
	try {
		const calls = [];
		const src = path.join(temp, "src");
		fs.mkdirSync(src, { recursive: true });
		fs.writeFileSync(path.join(src, "composer.json"), JSON.stringify({ name: "example/site", require: { "typo3/cms-core": "^14.3" } }));
		fs.writeFileSync(path.join(src, "composer.lock"), JSON.stringify({ packages: [
			{ name: "typo3/cms-core", version: "14.3.6" },
			{ name: "typo3/cms-lowlevel", version: "14.3.6", type: "typo3-cms-framework" }], "packages-dev": [] }));
		fs.mkdirSync(path.join(src, "public"), { recursive: true });
		fs.writeFileSync(path.join(src, "public", "index.php"), "<?php // marker\n");
		const { deps } = await require("../lib/codecs/composer.codec").collect(src);
		const result = await runApplicationPlugins(src, { plugins: [typo3], selection: "typo3",
			resolvedDeps: deps, activeCodecIds: ["composer"], liveTypo3AdvisoriesUrl: "https://api.github.com/repos/TYPO3/typo3/security-advisories",
			advisoryCacheDir: path.join(temp, "cache"), now: NOW,
			fetchImpl: async url => { calls.push(url); return githubPage([GH_RECORD]); } });
		assert.equal(calls.length, 1);
		// the PrestaShop-scoped fixture record has no typo3 coordinate: honest no-match, no findings
		assert.deepEqual(result.findings, []);
		const rows = result.coverage.filter(c => c.capability === "advisories");
		assert.ok(rows.length >= 2 && rows.every(r => r.execution === "completed" && r.result === "no-match"));
		assert.ok(fs.existsSync(path.join(temp, "cache", "github-typo3-advisories.json")), "the fetched feed is cached for offline reuse");
	} finally { fs.rmSync(temp, { recursive: true, force: true }); }
});
