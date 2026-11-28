const { test } = require("node:test");
const assert = require("node:assert/strict");
const { findEolProduct, COMPOSER_FRAMEWORKS } = require("../lib/maintenance/outdated");

const c = (ns, name) => ({ ecosystem: "composer", namespace: ns, name, groupId: ns, artifactId: name });

test("composer_frameworks data: symfony/laravel core lists carry their anchors and the monorepo package", () => {
	const sf = COMPOSER_FRAMEWORKS.symfony;
	assert.equal(sf.product, "symfony");
	assert.equal(sf.label, "Symfony");
	for (const n of ["symfony/framework-bundle", "symfony/http-kernel", "symfony/console", "symfony/security-guard", "symfony/yaml", "symfony/monolog-bridge", "symfony/symfony"]) {
		assert.ok(sf.components.includes(n), `${n} must be a symfony core component`);
	}
	for (const a of sf.anchors) assert.ok(sf.components.includes(a), `anchor ${a} must itself be a component`);
	assert.deepEqual(sf.components, [...sf.components].sort(), "components are sorted (stable diffs)");

	const lv = COMPOSER_FRAMEWORKS.laravel;
	assert.equal(lv.product, "laravel");
	for (const n of ["laravel/framework", "illuminate/support", "illuminate/database", "illuminate/contracts"]) {
		assert.ok(lv.components.includes(n), `${n} must be a laravel core component`);
	}
	for (const a of lv.anchors) assert.ok(lv.components.includes(a), `anchor ${a} must itself be a component`);
});

test("zero-FP guard: independently-versioned symfony/* packages are NOT framework components and map to NO product", () => {
	// Each of these ships its own version line (monolog-bundle 3.x, phpunit-bridge 6.4 inside a
	// 5.4 app, contracts 2.x/3.x, polyfills 1.x, flex 1.x/2.x). Mapping any of them to the
	// "symfony" product would match a wrong endoflife cycle — a false positive.
	for (const n of [
		"symfony/monolog-bundle", "symfony/phpunit-bridge", "symfony/deprecation-contracts", "symfony/service-contracts",
		"symfony/event-dispatcher-contracts", "symfony/http-client-contracts", "symfony/translation-contracts", "symfony/cache-contracts",
		"symfony/polyfill-mbstring", "symfony/polyfill-php80", "symfony/flex", "symfony/maker-bundle", "symfony/webpack-encore-bundle",
		"symfony/runtime", "symfony/apache-pack", "symfony/ux-twig-component",
	]) {
		assert.ok(!COMPOSER_FRAMEWORKS.symfony.components.includes(n), `${n} must not be a core component`);
		const [ns, name] = n.split("/");
		assert.equal(findEolProduct(c(ns, name)), null, `${n} must not map to any EOL product`);
	}
});

test("findEolProduct: a framework component maps via composer-framework and carries frameworkId", () => {
	const r = findEolProduct(c("symfony", "framework-bundle"));
	assert.equal(r.product, "symfony");
	assert.equal(r.label, "Symfony");
	assert.equal(r.via, "composer-framework");
	assert.equal(r.viaKey, "symfony/framework-bundle");
	assert.equal(r.frameworkId, "symfony");
	assert.equal(findEolProduct(c("Symfony", "Security-Guard")).frameworkId, "symfony", "case-insensitive");
	assert.equal(findEolProduct(c("illuminate", "support")).frameworkId, "laravel");
	assert.equal(findEolProduct(c("laravel", "framework")).frameworkId, "laravel");
});

test("findEolProduct: by_composer_name still serves non-framework entries (drupal/core) without frameworkId", () => {
	const r = findEolProduct(c("drupal", "core"));
	assert.equal(r.product, "drupal");
	assert.equal(r.via, "composer-name");
	assert.equal(r.frameworkId, undefined);
});

const { computeCoreComponents, FRAMEWORKS } = require("../scripts/gen-composer-eol-map");

test("computeCoreComponents: last NON-EMPTY replace per major, unioned, monorepo included, lowercased + sorted", () => {
	// Packagist p2 lists versions newest-first. v7.3.1 has no replace (the map is absent on
	// some patch releases) → the rule must fall through to v7.2.9 for the 7.x majors we track.
	const versions = [
		{ version: "v7.3.1", replace: {} },
		{ version: "v7.2.9", replace: { "symfony/asset": "self.version", "symfony/type-info": "self.version" } },
		{ version: "v6.4.45", replace: { "symfony/asset": "self.version", "symfony/Templating": "self.version" } },
		{ version: "v5.4.53", replace: { "symfony/asset": "self.version", "symfony/security-guard": "self.version", "symfony/not-core": "1.2.3" } },
		{ version: "v5.4.0", replace: { "symfony/monolog-bundle": "self.version" } },   // older patch of the same major: ignored
	];
	const out = computeCoreComponents(versions, ["5.4", "6.4", "7.2"], "symfony/symfony");
	assert.deepEqual(out, ["symfony/asset", "symfony/security-guard", "symfony/symfony", "symfony/templating", "symfony/type-info"]);
});

test("computeCoreComponents: a major with no version carrying replace contributes nothing (no crash)", () => {
	const out = computeCoreComponents([{ version: "v8.0.1", replace: {} }], ["8.0"], "symfony/symfony");
	assert.deepEqual(out, ["symfony/symfony"]);
});

test("generator config: every configured anchor is present in the committed data", () => {
	for (const [id, fw] of Object.entries(FRAMEWORKS)) {
		for (const a of fw.anchors) assert.ok(COMPOSER_FRAMEWORKS[id].components.includes(a), `${id}: anchor ${a}`);
		assert.deepEqual(COMPOSER_FRAMEWORKS[id].anchors, fw.anchors, `${id}: anchors in data == anchors in generator config`);
	}
});
