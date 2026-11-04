const { test } = require("node:test");
const assert = require("node:assert/strict");
const { webjarToNpm } = require("../lib/codecs/npm/collect");

test("webjarToNpm derives the npm name from org.webjars.npm (deterministic mirror)", () => {
	assert.deepEqual(
		webjarToNpm({ groupId: "org.webjars.npm", artifactId: "react", version: "18.2.0" }),
		{ name: "react", version: "18.2.0" },
	);
	// Scoped packages encode "@scope/name" as "scope__name".
	assert.deepEqual(
		webjarToNpm({ groupId: "org.webjars.npm", artifactId: "angular__core", version: "17.2.3" }),
		{ name: "@angular/core", version: "17.2.3" },
	);
});

test("webjarToNpm passes classic org.webjars artifactIds through as-is", () => {
	// Classic WebJars are hand-curated; the artifactId is the JS lib name.
	assert.deepEqual(
		webjarToNpm({ groupId: "org.webjars", artifactId: "angularjs", version: "1.8.3" }),
		{ name: "angularjs", version: "1.8.3" },
	);
	assert.equal(webjarToNpm({ groupId: "org.webjars", artifactId: "jquery", version: "3.7.1" }).name, "jquery");
});

test("webjarToNpm handles bower webjars too", () => {
	assert.equal(webjarToNpm({ groupId: "org.webjars.bowergithub.foo", artifactId: "bar", version: "1.0.0" }).name, "bar");
});

test("webjarToNpm returns null for non-webjar coordinates", () => {
	assert.equal(webjarToNpm({ groupId: "org.springframework", artifactId: "spring-core", version: "6.0.0" }), null);
	assert.equal(webjarToNpm({ ecosystem: "npm", groupId: "", artifactId: "react", version: "18.0.0" }), null);
});

test("WebJars Java locator modules are not npm packages", () => {
	for (const artifactId of ["webjars-locator", "webjars-locator-lite", "webjars-locator-core"]) {
		assert.equal(webjarToNpm({ groupId: "org.webjars", artifactId, version: "1.0" }), null);
	}
	assert.equal(webjarToNpm({ groupId: "org.webjars.npm", artifactId: "webjars-locator-lite", version: "1.0" }).name, "webjars-locator-lite");
});
