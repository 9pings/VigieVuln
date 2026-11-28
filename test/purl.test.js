const { test } = require("node:test");
const assert = require("node:assert/strict");
const { purlFor } = require("../lib/inventory/purl");

test("maven purl keeps groupId as a dotted namespace segment", () => {
	const dep = { ecosystem: "maven", namespace: "org.apache.commons", name: "commons-lang3", version: "3.12.0" };
	assert.equal(purlFor(dep), "pkg:maven/org.apache.commons/commons-lang3@3.12.0");
});

test("npm scoped package splits scope into the purl namespace (encoded @)", () => {
	const dep = { ecosystem: "npm", namespace: "", name: "@angular/core", version: "12.0.0" };
	assert.equal(purlFor(dep), "pkg:npm/%40angular/core@12.0.0");
});

test("npm unscoped package has no namespace", () => {
	const dep = { ecosystem: "npm", namespace: "", name: "lodash", version: "4.17.21" };
	assert.equal(purlFor(dep), "pkg:npm/lodash@4.17.21");
});

test("composer uses vendor/package", () => {
	const dep = { ecosystem: "composer", namespace: "symfony", name: "console", version: "5.4.0" };
	assert.equal(purlFor(dep), "pkg:composer/symfony/console@5.4.0");
});

test("pypi normalizes the name (lowercase, runs of separators → hyphen)", () => {
	const dep = { ecosystem: "pypi", namespace: "", name: "Flask_SQLAlchemy", version: "2.5.1" };
	assert.equal(purlFor(dep), "pkg:pypi/flask-sqlalchemy@2.5.1");
});

test("nuget keeps the package name verbatim", () => {
	const dep = { ecosystem: "nuget", namespace: "", name: "Newtonsoft.Json", version: "13.0.1" };
	assert.equal(purlFor(dep), "pkg:nuget/Newtonsoft.Json@13.0.1");
});

test("version is omitted when null", () => {
	const dep = { ecosystem: "npm", namespace: "", name: "lodash", version: null };
	assert.equal(purlFor(dep), "pkg:npm/lodash");
});

test("falls back to groupId/artifactId aliases when namespace/name absent", () => {
	const dep = { ecosystem: "maven", groupId: "com.google.guava", artifactId: "guava", version: "31.0-jre" };
	assert.equal(purlFor(dep), "pkg:maven/com.google.guava/guava@31.0-jre");
});

test("returns null for an unusable dep", () => {
	assert.equal(purlFor(null), null);
	assert.equal(purlFor({ ecosystem: "npm" }), null);
});
