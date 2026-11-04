const { test } = require("node:test");
const assert = require("node:assert");
const { generateHtmlReport, generateWordReport } = require("../lib/cve-report");
const { makeDepRecord } = require("../lib/dep-record");

test("report renders a Part C inventory chapter for unmanaged binaries", () => {
	const resolved = new Map();
	const d = makeDepRecord({ ecosystem: "binary", name: "libssl.so.1.1", manifestPath: "/p/libssl.so.1.1", provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) }, declaredName: "libssl.so.1.1" });
	d.identity = { ecosystem: null, name: "openssl", version: "3.0", source: "circl:nsrl_modern" }; d.integrity = "known-good";
	resolved.set("binary:/p/libssl.so.1.1", d);
	const html = generateHtmlReport({ cveMatches: [], devCveMatches: [], embeddedMatches: [], retireMatches: [], eolResults: [], obsoleteResults: [], outdatedResults: [], licenseResults: null, resolvedDeps: resolved, projectInfo: { name: "t", src: "/p" }, warnings: [] });
	assert.match(html, /Unmanaged/);
	assert.match(html, /libssl\.so\.1\.1/);
	assert.match(html, /openssl/);
});

test("binary metadata is escaped in HTML and Word, with executables first", () => {
	const resolved = new Map();
	for (const name of ["a.dll", "z.exe"]) {
		const d = makeDepRecord({ ecosystem: "binary", name, manifestPath: `/p/${name}`, provenance: "binary", hashes: { sha256: "b".repeat(64) }, declaredName: name });
		d.binaryMetadata = { versionStrings: [{ ProductName: '</details><script>alert("xss")</script>', CompanyName: '<img src=x onerror=alert(1)>', FileVersion: "1.2.3", OriginalFilename: 'safe.exe', '<svg onload=alert(1)>': 'other metadata' }] };
		resolved.set(name, d);
	}
	const payload = { cveMatches: [], devCveMatches: [], embeddedMatches: [], retireMatches: [], eolResults: [], obsoleteResults: [], outdatedResults: [], licenseResults: null, resolvedDeps: resolved, projectInfo: { name: "t", src: "/p" }, warnings: [], locale: "fr" };
	for (const html of [generateHtmlReport(payload), generateWordReport(payload)]) {
		assert.match(html, /Limite d’analyse/);
		assert.match(html, /ne font pas l’objet d’une corrélation automatique avec les CVE/);
		assert.match(html, /<details class="binary-metadata"(?: open)?><summary>Métadonnées PE non vérifiées<\/summary>/);
		assert.match(html, /&lt;\/details&gt;&lt;script&gt;alert\(&quot;xss&quot;\)&lt;\/script&gt;/);
		assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
		assert.match(html, /&lt;svg onload=alert\(1\)&gt;:<\/strong> other metadata/);
		assert.doesNotMatch(html, /<script>alert\("xss"\)<\/script>|<img src=x onerror=/);
		assert.match(html, /Version du fichier:<\/strong> 1\.2\.3/);
		assert.ok(html.indexOf('z.exe') < html.indexOf('a.dll'));
	}
	assert.match(generateWordReport(payload), /<details class="binary-metadata" open>/);
});
