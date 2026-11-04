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
	assert.throws(() => parseSnykStdout('invalid Snyk output'), /invalid JSON/);
});

test('offline mode refuses Snyk before starting a scan',()=>{
	const {spawnSync}=require('node:child_process'),path=require('node:path');
	for(const args of [['--snyk'],['-a','snyk']]){
		const r=spawnSync(process.execPath,[path.join(__dirname,'../vigievuln.js'),'--offline',...args],{encoding:'utf8'});
		assert.notEqual(r.status,0);assert.match(r.stderr,/snyk requires network access/i);
	}
});

test('Snyk command failure and empty output cannot look like a clean scan',{skip:process.platform==='win32'},async t=>{
	const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
	const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-snyk-command-')),binary=path.join(dir,'snyk'),old=process.env.PATH;
	t.after(()=>{process.env.PATH=old;fs.rmSync(dir,{recursive:true,force:true})});
	process.env.PATH=dir+path.delimiter+old;
	fs.writeFileSync(binary,'#!/bin/sh\nexit 0\n',{mode:0o755});
	await assert.rejects(require('../lib/snyk').runSnykTest(dir),/no project results/);
	fs.writeFileSync(binary,'#!/bin/sh\nprintf \'{"ok":false,"error":"authentication failed"}\'\nexit 0\n');
	await assert.rejects(require('../lib/snyk').runSnykTest(dir),/authentication failed/);
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

test("mergeWithFadResults retains original sources and adds Snyk on overlap", () => {
	const fadMatches = [
		{
			dep: { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.14.0" },
			cve: { id: "CVE-2021-44228", severity: "CRITICAL" },
			source: "CVEProject+osv",
			confidence: "exact",
		},
	];
	const snykMatches = parseSnykResults(snykSample);
	const merged = mergeWithFadResults(fadMatches, snykMatches);
	assert.equal(merged.length, 2);
	const log4j = merged.find(m => m.cve.id === "CVE-2021-44228");
	assert.equal(log4j.source, "CVEProject+osv+snyk");
	const jackson = merged.find(m => m.cve.id === "CVE-2022-42003");
	assert.equal(jackson.source, "snyk");
});

test('Snyk npm findings keep their ecosystem, version and project attribution',()=>{
	const {makeDepRecord}=require('../lib/dep-record');
	const existing=makeDepRecord({ecosystem:'npm',name:'@scope/pkg',version:'1.0.0',manifestPath:'/project/package-lock.json'});
	const newer=makeDepRecord({ecosystem:'npm',name:'@scope/pkg',version:'2.0.0',manifestPath:'/project/other/package-lock.json'});
	const document={packageManager:'npm',vulnerabilities:[{id:'SNYK-JS-1',packageName:'@scope/pkg',version:'1.0.0',severity:'high',identifiers:{CVE:['CVE-2026-10001']}},{id:'SNYK-JS-2',packageName:'@scope/pkg',version:'2.0.0',severity:'high',identifiers:{CVE:['CVE-2026-10001']}}]};
	const parsed=parseSnykResults(document);
	assert.equal(parsed[0].dep.coordKey,'npm:@scope/pkg');
	const base=[{dep:existing,cve:{id:'CVE-2026-10001',severity:'HIGH'},source:'osv'},{dep:newer,cve:{id:'CVE-2026-10001',severity:'HIGH'},source:'osv'}];
	const merged=mergeWithFadResults(base,parsed,new Map([[existing.coordKey,existing]]));
	assert.equal(merged.length,2);assert.deepEqual(merged.map(x=>x.dep.version).sort(),['1.0.0','2.0.0']);
	assert.ok(merged.every(x=>x.source==='osv+snyk'));
	const only=mergeWithFadResults([],parsed.slice(0,1),new Map([[existing.coordKey,existing]]));
	assert.deepEqual(only[0].dep.manifestPaths,['/project/package-lock.json']);
});

test('Snyk integration preserves separate existing findings and ecosystems',()=>{
	const {makeDepRecord}=require('../lib/dep-record');
	const maven=makeDepRecord({ecosystem:'maven',namespace:'example',name:'pkg',version:'1.0'});
	const npm=makeDepRecord({ecosystem:'npm',name:'pkg',version:'1.0'});
	const base=[{dep:maven,cve:{id:'CVE-2026-10001',severity:'HIGH'},source:'osv'},
		{dep:{...maven,provenance:'embedded',coordKey:'embedded:a.jar'},cve:{id:'CVE-2026-10001',severity:'HIGH'},source:'osv'},
		{dep:npm,cve:{id:'CVE-2026-10001',severity:'HIGH'},source:'osv'}];
	const snyk=parseSnykResults({packageManager:'npm',vulnerabilities:[{id:'SNYK-JS-1',packageName:'pkg',version:'1.0',identifiers:{CVE:['CVE-2026-10001']}}]});
	const merged=mergeWithFadResults(base,snyk);
	assert.equal(merged.length,3);assert.equal(merged.find(x=>x.dep.ecosystem==='npm').source,'osv+snyk');
	assert.equal(merged.filter(x=>x.dep.ecosystem==='maven' && x.source==='osv').length,2);
});

test('Snyk Ruby and Composer coordinates match their native ecosystems',()=>{
	for(const [packageManager,packageName,key] of [['rubygems','rails','ruby:rails'],['composer','vendor/package','composer:vendor/package']]){
		const [match]=parseSnykResults({packageManager,vulnerabilities:[{id:'SNYK-test',packageName,version:'1.0'}]});
		assert.equal(match.dep.coordKey,key);
	}
});
