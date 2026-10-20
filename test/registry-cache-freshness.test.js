const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { execFileSync } = require("node:child_process");

const cases = [
	["npm", "lib/codecs/npm/registry", "checkNpmRegistryDeps", "npm-registry-cache.json", "demo@1.0.0"],
	["composer", "lib/codecs/composer/registry", "checkComposerRegistryDeps", "packagist-cache.json", "acme/demo@1.0.0"],
	["ruby", "lib/codecs/ruby/registry", "checkRubyRegistryDeps", "rubygems-cache.json", "demo@1.0.0"],
	["pypi", "lib/codecs/pypi/registry", "checkPypiRegistryDeps", "pypi-cache.json", "demo@1.0.0"],
	["nuget", "lib/codecs/nuget/registry", "checkNugetRegistryDeps", "nuget-cache.json", "demo@1.0.0"],
	["go", "lib/codecs/go/registry", "checkGoRegistryDeps", "go-proxy-cache.json", "demo@1.0.0"],
	["maven", "lib/outdated", "checkOutdatedDeps", "version-cache.json", "org.example:demo"],
];

for (const spec of cases) {
	test(`${spec[0]}: offline and cache-only reads do not extend TTL; the next stale online run refetches`, t => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-registry-age-"));
		t.after(() => fs.rmSync(root, { recursive: true, force: true }));
		// Each module captures homedir at load time; isolate it in a child rather
		// than touching the operator's cache or racing other test files.
		const output = execFileSync(process.execPath, ["-e", `
const fs = require("node:fs"), path = require("node:path"), assert = require("node:assert/strict");
require("node:os").homedir = () => process.argv[2];
const [eco, mod, method, filename, key] = JSON.parse(process.argv[1]);
const check = require(path.resolve(mod))[method];
const dir = path.join(process.argv[2], ".fad-checker"), file = path.join(dir, filename);
fs.mkdirSync(dir, { recursive: true });
const dep = { ecosystem: eco, name: "demo", artifactId: "demo", version: "1.0.0", scope: "compile",
	namespace: eco === "maven" ? "org.example" : eco === "composer" ? "acme" : "",
	groupId: eco === "maven" ? "org.example" : eco === "composer" ? "acme" : "" };
const deps = new Map([["demo", dep]]);
let calls = 0;
globalThis.fetch = async () => {
	calls++;
	return new Response(JSON.stringify({
		info: { version: "3.0.0" }, releases: {}, version: "3.0.0", Version: "v3.0.0",
		"dist-tags": { latest: "3.0.0" }, versions: { "3.0.0": {} },
		package: { versions: { "3.0.0": {} } },
		items: [{ items: [{ catalogEntry: { version: "3.0.0" } }] }],
		response: { docs: [{ v: "3.0.0" }] },
	}), { status: 200, headers: { "content-type": "application/json" } });
};
const seed = stamp => fs.writeFileSync(file, JSON.stringify({ meta: { fetchedAt: stamp }, entries: { [key]: { latest: "2.0.0" } } }));
(async () => {
	const stale = Date.now() - 72 * 3600e3;
	seed(stale);
	const bytes = fs.readFileSync(file, "utf8"), modified = fs.statSync(file).mtimeMs;
	await check(deps, { offline: true });
	assert.equal(calls, 0);
	assert.equal(fs.readFileSync(file, "utf8"), bytes);
	assert.equal(fs.statSync(file).mtimeMs, modified);
	await check(deps, { offline: false });
	assert.ok(calls > 0, "offline must not hide expiration from the next online scan");
	assert.equal(JSON.parse(fs.readFileSync(file)).entries[key].latest, "3.0.0");
	const fresh = Date.now() - 3600e3;
	seed(fresh); calls = 0;
	await check(deps, { offline: false });
	assert.equal(calls, 0);
	assert.equal(JSON.parse(fs.readFileSync(file)).meta.fetchedAt, fresh, "a cache-only online run must not renew untouched data either");
	fs.unlinkSync(file);
	await check(deps, { offline: true });
	assert.equal(calls, 0);
	assert.equal(fs.existsSync(file), false, "cold offline scan must not create a fresh-looking empty cache");
})().catch(error => { console.error(error); process.exitCode = 1; });
`, JSON.stringify(spec), root], { cwd: path.resolve(__dirname, ".."), encoding: "utf8" });
		assert.ok(typeof output === "string");
	});
}
