const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const { enrichEpss, parseEpssResponse, CACHE_PATH } = require("../lib/providers/epss/enrich");

// Sentinel CVE ids that never collide with real cached entries. Purge them from
// the shared cache before exercising the mock fetcher (enrichEpss persists a
// per-CVE cache that would otherwise self-poison on a second run).
const SENT_A = "CVE-9999-44228";
const SENT_B = "CVE-9999-00001";
function purgeSentinels() {
	try {
		const c = JSON.parse(fs.readFileSync(CACHE_PATH, "utf8"));
		delete c.entries[SENT_A];
		delete c.entries[SENT_B];
		fs.writeFileSync(CACHE_PATH, JSON.stringify(c));
	} catch { /* no cache yet */ }
}

test("parseEpssResponse maps cve → {score, percentile}", () => {
	const m = parseEpssResponse({
		status: "OK",
		data: [
			{ cve: "CVE-2021-44228", epss: "0.97565", percentile: "0.99998" },
			{ cve: "CVE-2020-0001", epss: "0.00042", percentile: "0.12" },
		],
	});
	assert.equal(m.get("CVE-2021-44228").score, 0.97565);
	assert.equal(m.get("CVE-2021-44228").percentile, 0.99998);
	assert.equal(m.get("CVE-2020-0001").score, 0.00042);
});

test("enrichEpss attaches score/percentile to matches via a mocked fetcher", async () => {
	purgeSentinels();
	const matches = [
		{ cve: { id: SENT_A, severity: "CRITICAL" } },
		{ cve: { id: SENT_B, severity: "LOW" } },
	];
	let calls = 0;
	const fetcher = async (url) => {
		calls++;
		assert.ok(url.includes(SENT_A));
		return {
			ok: true,
			json: async () => ({ data: [{ cve: SENT_A, epss: "0.9", percentile: "0.99" }] }),
		};
	};
	await enrichEpss(matches, { fetcher, offline: false, verbose: false });
	assert.equal(calls, 1);
	assert.equal(matches[0].cve.epssScore, 0.9);
	assert.equal(matches[0].cve.epssPercentile, 0.99);
	// CVE not in the response → no fields set.
	assert.equal(matches[1].cve.epssScore, undefined);
	purgeSentinels();
});

test("enrichEpss in offline mode makes no network call", async () => {
	purgeSentinels();
	const matches = [{ cve: { id: SENT_A } }];
	let calls = 0;
	const fetcher = async () => { calls++; return { ok: true, json: async () => ({ data: [] }) }; };
	await enrichEpss(matches, { fetcher, offline: true });
	assert.equal(calls, 0);
});

test("enrichEpss with no CVE matches is a no-op", async () => {
	let calls = 0;
	const fetcher = async () => { calls++; return { ok: true, json: async () => ({ data: [] }) }; };
	await enrichEpss([{ cve: { id: "GHSA-xxxx" } }], { fetcher });
	assert.equal(calls, 0);
});
