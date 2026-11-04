const { test } = require("node:test");
const assert = require("node:assert/strict");
const os = require("os");
const fs = require("fs");
const path = require("path");

const { packumentToFindings } = require("../lib/codecs/npm/registry");
const { pypiToFindings, pypiLicense } = require("../lib/codecs/pypi/registry");
const { packagistToFindings } = require("../lib/codecs/composer/registry");
const { nugetRegistrationToFindings } = require("../lib/codecs/nuget/registry");
const { licensesFromPomXml, collectMavenLicenses } = require("../lib/maven-license");

test("npm packumentToFindings extracts the resolved version's license", () => {
	const pk = { "dist-tags": { latest: "2.0.0" }, license: "ISC", versions: { "1.0.0": { license: "MIT" } } };
	assert.equal(packumentToFindings(pk, { version: "1.0.0" }).license, "MIT");
	// falls back to root license when the version has none
	assert.equal(packumentToFindings(pk, { version: "9.9.9" }).license, "ISC");
});

test("pypi license prefers trove classifiers over free-form info.license", () => {
	const data = { info: { version: "1.0", license: "see LICENSE file for the full multi-paragraph text ".repeat(5), classifiers: ["License :: OSI Approved :: MIT License"] } };
	assert.deepEqual(pypiLicense(data.info), ["MIT License"]);
	assert.deepEqual(pypiToFindings(data, { version: "1.0" }).license, ["MIT License"]);
	// short info.license, no classifier
	assert.equal(pypiLicense({ license: "BSD-3-Clause", classifiers: [] }), "BSD-3-Clause");
});

test("composer packagistToFindings reads the version's license array", () => {
	const pkg = { versions: { "5.4.0": { license: ["MIT"] }, "v5.4.0": { license: ["MIT"] } } };
	assert.deepEqual(packagistToFindings(pkg, { version: "5.4.0" }).license, ["MIT"]);
});

test("nuget reads licenseExpression from the matching catalog entry", () => {
	const reg = { items: [{ items: [{ catalogEntry: { version: "13.0.1", licenseExpression: "MIT" } }] }] };
	assert.equal(nugetRegistrationToFindings(reg, { version: "13.0.1" }).license, "MIT");
});

test("licensesFromPomXml scrapes the <licenses> block", () => {
	const xml = `<project><licenses>
		<license><name>Apache License, Version 2.0</name><url>x</url></license>
		<license><name>MIT</name></license>
	</licenses></project>`;
	assert.deepEqual(licensesFromPomXml(xml), ["Apache License, Version 2.0", "MIT"]);
	assert.deepEqual(licensesFromPomXml("<project></project>"), []);
});

test("collectMavenLicenses reads cached POMs from a given cache dir", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pom-"));
	require('../lib/maven-cache').write(path.join(dir, "org.apache.commons__commons-lang3__3.12.0.pom"),
		"<project><licenses><license><name>Apache-2.0</name></license></licenses></project>");
	const resolved = new Map([
		["org.apache.commons:commons-lang3", { ecosystem: "maven", namespace: "org.apache.commons", name: "commons-lang3", version: "3.12.0" }],
		["com.x:nocache", { ecosystem: "maven", namespace: "com.x", name: "nocache", version: "1.0" }],
	]);
	const out = collectMavenLicenses(resolved, { cacheDir: dir });
	assert.equal(out.length, 1);
	assert.deepEqual(out[0].licenses, ["Apache-2.0"]);
	assert.equal(out[0].source, "pom");
});
