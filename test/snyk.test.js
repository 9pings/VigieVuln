const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseSnykResults, parseSnykStdout, mergeWithFadResults, snykOutputError } = require("../lib/snyk");

const snykSample = {
	vulnerabilities: [
		{
			id: "SNYK-JAVA-LOG4J-2314720",
			packageName: "org.apache.logging.log4j:log4j-core",
			version: "2.14.0",
			severity: "critical",
			cvssScore: 10,
			title: "Remote Code Execution",
			fixedIn: ["2.15.0", "2.16.0"],
			identifiers: { CVE: ["CVE-2021-44228"] },
		},
		{
			id: "SNYK-JAVA-JACKSON-2421244",
			packageName: "com.fasterxml.jackson.core:jackson-databind",
			version: "2.13.0",
			severity: "high",
			cvssScore: 7.5,
			title: "Denial of Service",
			fixedIn: ["2.13.5"],
			identifiers: { CVE: ["CVE-2022-42003"] },
		},
	],
};

test("parseSnykStdout accepts a JSON object or array", () => {
	assert.deepEqual(parseSnykStdout(""), []);
	const arr = parseSnykStdout(JSON.stringify([snykSample]));
	assert.equal(arr.length, 1);
	const obj = parseSnykStdout(JSON.stringify(snykSample));
	assert.equal(obj.length, 1);
});

test("parseSnykResults normalises to vigievuln match shape", () => {
	const out = parseSnykResults(snykSample);
	assert.equal(out.length, 2);
	assert.equal(out[0].dep.groupId, "org.apache.logging.log4j");
	assert.equal(out[0].dep.artifactId, "log4j-core");
	assert.equal(out[0].cve.id, "CVE-2021-44228");
	assert.equal(out[0].cve.severity, "CRITICAL");
	assert.equal(out[0].cve.fixVersion, "2.15.0");
	assert.equal(out[0].source, "snyk");
});

test("snykOutputError surfaces snyk's error-shaped JSON instead of a silent '0 findings'", () => {
	// exit 2 — genuine failure (e.g. auth), single error object on stdout
	const authErr = { ok: false, error: "Authentication failed. Please run `snyk auth`.", path: "/x" };
	assert.match(snykOutputError(authErr), /Authentication failed/);

	// exit 3 — no supported projects (array form, as --all-projects emits)
	const noProj = [{ ok: false, error: "Could not detect supported target files", path: "/x" }];
	assert.match(snykOutputError(noProj), /supported target files/);

	// multiple distinct errors → joined, deduped
	const multi = [
		{ ok: false, error: "boom" },
		{ ok: false, error: "boom" },
		{ ok: false, error: "kaboom" },
	];
	assert.equal(snykOutputError(multi), "boom; kaboom");

	// real findings (exit 1) → NOT an error
	assert.equal(snykOutputError([snykSample]), null);
	assert.equal(snykOutputError(snykSample), null);

	// clean project (ok:true, empty vulns) → NOT an error
	assert.equal(snykOutputError([{ ok: true, vulnerabilities: [] }]), null);

	// partial --all-projects: one project errored, one has findings → usable, no hard error
	assert.equal(snykOutputError([{ ok: false, error: "boom" }, snykSample]), null);

	// nothing parsed → no error
	assert.equal(snykOutputError([]), null);
	assert.equal(snykOutputError(null), null);
});

test("mergeWithFadResults tags overlap as 'both' and keeps Snyk-only as 'snyk'", () => {
	const fadMatches = [
		{
			dep: { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.14.0" },
			cve: { id: "CVE-2021-44228", severity: "CRITICAL" },
			confidence: "exact",
		},
	];
	const snykMatches = parseSnykResults(snykSample);
	const merged = mergeWithFadResults(fadMatches, snykMatches);
	assert.equal(merged.length, 2);
	const log4j = merged.find(m => m.cve.id === "CVE-2021-44228");
	assert.equal(log4j.source, "both");
	const jackson = merged.find(m => m.cve.id === "CVE-2022-42003");
	assert.equal(jackson.source, "snyk");
});
