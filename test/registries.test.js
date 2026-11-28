const { test } = require("node:test");
const assert = require("node:assert");
const os = require("os"); const fs = require("fs"); const path = require("path");
const R = require("../lib/providers/registries");

test("SUPPORTED lists the registry-backed ecosystems", () => {
	assert.deepStrictEqual([...R.SUPPORTED].sort(), ["composer", "go", "maven", "npm", "nuget", "pypi", "ruby"]);
});

test("authHeaderFor: token → Bearer, auth → Basic, none → null", () => {
	assert.strictEqual(R.authHeaderFor({ token: "abc" }), "Bearer abc");
	assert.strictEqual(R.authHeaderFor({ auth: "u:p" }), "Basic " + Buffer.from("u:p").toString("base64"));
	assert.strictEqual(R.authHeaderFor({}), null);
});

test("buildRegistryList: unions layers, dedups by URL, splits inline auth, public NOT appended", () => {
	const list = R.buildRegistryList("npm", [
		[{ name: "a", url: "https://r1/" }],
		[{ name: "b", url: "https://u:p@r2" }, { name: "dup", url: "https://r1" }],
	]);
	assert.strictEqual(list.length, 2);
	assert.strictEqual(list[0].url, "https://r1/");
	assert.strictEqual(list[1].url, "https://r2/");
	assert.strictEqual(list[1].auth, "u:p");
});

test("withPublic appends the ecosystem public base last", () => {
	const bases = R.withPublic("npm", [{ name: "a", url: "https://r1/" }]);
	assert.strictEqual(bases.length, 2);
	assert.strictEqual(bases[1].url, R.PUBLIC_BASES.npm);
	assert.strictEqual(bases[1].name, "public");
});

test("config registries CRUD round-trips via a temp HOME", () => {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-cfg-"));
	const prev = os.homedir; os.homedir = () => tmp;
	delete require.cache[require.resolve("../lib/config")];
	const config = require("../lib/config");
	try {
		config.addRegistry("npm", "verda", "https://npm.acme/", { token: "t" });
		config.addRegistry("maven", "nexus", "https://nexus.acme/m2/", { auth: "u:p" });
		assert.strictEqual(config.getRegistries("npm")[0].token, "t");
		assert.strictEqual(config.getRegistryMap().maven[0].auth, "u:p");
		assert.strictEqual(config.removeRegistry("npm", "verda"), true);
		assert.strictEqual(config.getRegistries("npm").length, 0);
	} finally { os.homedir = prev; delete require.cache[require.resolve("../lib/config")]; fs.rmSync(tmp, { recursive: true, force: true }); }
});

const { buildRepoList } = require("../lib/providers/maven/repo");
test("maven buildRepoList still appends Central after the user repos, and dedups", () => {
	const repos = buildRepoList([{ name: "nexus", url: "https://nexus/m2" }], [{ url: "https://nexus/m2" }]);
	const centralAt = repos.findIndex(r => r.name === "central");
	assert.ok(centralAt > 0, "Central sits behind the user repos");
	// After Central: the Central mirrors, then the Google Android repository as the last-resort
	// fallback (it hosts artifacts Central does not, so it is neither a mirror nor an authority).
	const after = repos.slice(centralAt + 1);
	assert.ok(after.slice(0, -1).every(r => r.mirror), "only mirrors sit between Central and the fallback");
	assert.strictEqual(after.at(-1).name, "google-android");
	assert.strictEqual(after.at(-1).mirror, false);
	assert.strictEqual(after.at(-1).fallback, true);
	assert.strictEqual(repos.filter(r => r.name === "nexus").length, 1);
});

test("mirrors can be turned off, which restores the pre-mirror list exactly", () => {
	const repos = buildRepoList([{ name: "nexus", url: "https://nexus/m2" }], [], { mirrors: false });
	// No mirror at all; the Google Android fallback is not a mirror and stays after Central.
	assert.deepStrictEqual(repos.map(r => r.name), ["nexus", "central", "google-android"]);
	assert.ok(repos.every(r => !r.mirror));
});
