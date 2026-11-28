const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { parseGemfileLock } = require("../lib/codecs/ruby/parse");
const { gemToFindings } = require("../lib/codecs/ruby/registry");
const { purlFor } = require("../lib/inventory/purl");
const ruby = require("../lib/codecs/ruby.codec");

test("parseGemfileLock reads 4-space specs, skips nested deps, strips platform", () => {
	const { deps } = parseGemfileLock(`GEM
  remote: https://rubygems.org/
  specs:
    actionpack (6.1.4)
      actionview (= 6.1.4)
    rack (2.2.3)
    nokogiri (1.13.0-x86_64-linux)

DEPENDENCIES
  rails
`);
	const names = deps.map(d => d.name).sort();
	assert.deepEqual(names, ["actionpack", "nokogiri", "rack"]);
	assert.equal(deps.find(d => d.name === "actionpack").version, "6.1.4");
	assert.equal(deps.find(d => d.name === "nokogiri").version, "1.13.0"); // platform stripped
});

test("gemToFindings extracts latest + licenses", () => {
	const f = gemToFindings({ version: "7.0.0", licenses: ["MIT"] });
	assert.equal(f.latest, "7.0.0");
	assert.deepEqual(f.license, ["MIT"]);
});

test("ruby purl uses the gem type", () => {
	assert.equal(purlFor({ ecosystem: "ruby", namespace: "", name: "rails", version: "6.1.4" }), "pkg:gem/rails@6.1.4");
});

test("ruby codec collects + detects the fixture", async () => {
	const dir = path.join(__dirname, "fixtures", "ruby-app");
	assert.equal(ruby.detect(dir), true);
	const { deps } = await ruby.collect(dir);
	assert.ok(deps.has("ruby:rails"));
	assert.equal(deps.get("ruby:rails").version, "6.1.4");
	assert.equal(ruby.osvPackageName(deps.get("ruby:rails")), "rails");
});
