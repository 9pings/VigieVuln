const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const composer = require("../lib/codecs/composer.codec");
const symfony = require("../lib/applications/plugins/symfony");
const { runApplicationPlugins } = require("../lib/applications/plugins/runner");

test("Symfony application inventory keeps exact framework and independent bundle versions", async () => {
	const root = path.join(__dirname, "fixtures", "php-symfony54");
	const { deps } = await composer.collect(root);
	const result = await runApplicationPlugins(root, { plugins: [symfony], selection: "symfony", resolvedDeps: deps, activeCodecIds: ["composer"] });
	assert.deepEqual(result.applications.map(a => a.id), ["symfony:."]);
	const byCoord = Object.fromEntries(result.inventory.map(c => [c.coord, c]));
	assert.equal(byCoord["symfony/framework-bundle"].version, "5.4.45");
	assert.equal(byCoord["symfony/framework-bundle"].kind, "framework");
	assert.equal(byCoord["symfony/framework-bundle"].symfonyRequireConstraint, "5.4.*");
	assert.equal(byCoord["symfony/console"].version, "5.4.47");
	assert.equal(byCoord["symfony/monolog-bundle"].version, "3.10.0");
	assert.equal(byCoord["symfony/monolog-bundle"].kind, "bundle");
	assert.deepEqual(byCoord["symfony/framework-bundle"].recipe, { version: "5.2", files: ["config/packages/framework.yaml"] });
	assert.equal(byCoord["symfony/framework-bundle"].version, "5.4.45", "symfony.lock recipe version is not the installed package version");
	assert.equal(byCoord["symfony/old-bundle"], undefined, "orphaned recipe is not an installed package");
	assert.ok(result.diagnostics.some(d => d.code === "CMS_RECIPE_ORPHANED" && d.package === "symfony/old-bundle"));
	assert.equal(result.coverage.find(c => c.capability === "recipes").execution, "completed");
	assert.equal(result.coverage.find(c => c.capability === "inventory").execution, "completed");
	// No Symfony publisher feed exists: the components are Composer deps, so the
	// advisories capability reads as covered by the dependency lanes, not as a gap.
	const advisories = result.coverage.find(c => c.capability === "advisories");
	assert.equal(advisories.execution, "completed");
	assert.equal(advisories.sourceId, "dependency-lanes");
	assert.equal(advisories.expected, result.inventory.length);
	assert.equal(advisories.executed, result.inventory.length);
	assert.ok(!advisories.diagnostic, "no fake CMS_ADVISORY_NOT_QUALIFIED gap");
});

test("a library using Symfony Console is not classified as a Symfony application", async () => {
	const root = path.join(__dirname, "fixtures", "php-app");
	const { deps } = await composer.collect(root);
	const result = await runApplicationPlugins(root, { plugins: [symfony], selection: "symfony", resolvedDeps: deps, activeCodecIds: ["composer"] });
	assert.deepEqual(result.applications, []);
});
