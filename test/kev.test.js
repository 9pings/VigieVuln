const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const { enrichKev, indexKevCatalog, CACHE_PATH } = require("../lib/kev");

const SAMPLE = {
	title: "CISA KEV",
	vulnerabilities: [
		{ cveID: "CVE-2021-44228", dateAdded: "2021-12-10", dueDate: "2021-12-24", knownRansomwareCampaignUse: "Known" },
		{ cveID: "CVE-2017-5638", dateAdded: "2021-11-03", dueDate: "2021-11-17", knownRansomwareCampaignUse: "Unknown" },
	],
};

test("indexKevCatalog builds a cveID → metadata map", () => {
	const { byId } = indexKevCatalog(SAMPLE);
	assert.equal(byId["CVE-2021-44228"].ransomware, true);
	assert.equal(byId["CVE-2021-44228"].dueDate, "2021-12-24");
	assert.equal(byId["CVE-2017-5638"].ransomware, false);
	assert.equal(byId["CVE-9999-0000"], undefined);
});

// enrichKev reads a TTL'd cache file. Back it up so a real cache doesn't shadow
// the mock fetcher, and restore it afterwards (non-destructive to the user).
function withFreshCache(fn) {
	const repository=require('../lib/cache-repository').createCacheRepository(require('node:path').dirname(CACHE_PATH));
	const backup=repository.get('catalogue','kev');
	repository.delete('catalogue','kev');
	return Promise.resolve()
		.then(fn)
		.finally(() => {
			repository.delete('catalogue','kev');
			if(backup)repository.put('catalogue','kev',backup.value,{fetchedAt:backup.fetchedAt});
		});
}

test("enrichKev flags matches present in the catalogue (mock fetcher)", () => withFreshCache(async () => {
	const matches = [
		{ cve: { id: "CVE-2021-44228" } },
		{ cve: { id: "CVE-2099-0001" } },
	];
	let calls = 0;
	const fetcher = async () => { calls++; return { ok: true, json: async () => SAMPLE }; };
	await enrichKev(matches, { fetcher });
	assert.equal(calls, 1);
	assert.equal(matches[0].cve.kev, true);
	assert.equal(matches[0].cve.kevRansomware, true);
	assert.equal(matches[0].cve.kevDueDate, "2021-12-24");
	assert.equal(matches[1].cve.kev, undefined); // not in catalogue
}));

test("enrichKev offline with no cache makes no call and flags nothing", () => withFreshCache(async () => {
	const matches = [{ cve: { id: "CVE-2021-44228" } }];
	let calls = 0;
	const fetcher = async () => { calls++; return { ok: true, json: async () => SAMPLE }; };
	await enrichKev(matches, { fetcher, offline: true });
	assert.equal(calls, 0);
	assert.equal(matches[0].cve.kev, undefined);
}));
