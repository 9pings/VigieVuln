const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const {
	parsePackageJson,
	parsePackageLock,
	parseYarnLockV1,
	parseYarnBerry,
	parsePnpmLock,
	findJsManifests,
} = require("../lib/codecs/npm/parse");
const { collectNpmDeps } = require("../lib/codecs/npm/collect");

const FIX = path.join(__dirname, "fixtures", "monorepo-mixed");
const F = n => path.join(__dirname, "fixtures", n);

test("parsePackageJson extracts dependencies + dev + peer scopes", () => {
	const res = parsePackageJson(path.join(FIX, "packages", "web-app", "package.json"));
	assert.equal(res.packageName, "@acme/web-app");
	assert.equal(res.packageVersion, "1.0.0");
	const byName = Object.fromEntries(res.deps.map(d => [d.name, d]));
	assert.equal(byName.axios.scope, "prod");
	assert.equal(byName.jest.scope, "dev");
	assert.equal(byName.react.scope, "peer");
});

test("parsePackageLock v3 enumerates direct + transitive deps with correct scopes", () => {
	const res = parsePackageLock(path.join(FIX, "packages", "web-app", "package-lock.json"));
	assert.equal(res.lockfileVersion, 3);
	const byName = Object.fromEntries(res.deps.map(d => [d.name, d]));
	// direct prod
	assert.equal(byName.axios.scope, "prod");
	assert.equal(byName.axios.version, "0.21.0");
	// transitive (depth via nested node_modules) — flat in v3, but here axios's "follow-redirects" lives at the top, depth 0
	assert.equal(byName["follow-redirects"].version, "1.13.0");
	// dev
	assert.equal(byName.jest.scope, "dev");
	assert.equal(byName.eslint.scope, "dev");
	// peer
	assert.equal(byName.react.scope, "peer");
});

test("parseYarnLockV1 picks up versions and dedupes by (name, version)", () => {
	const res = parseYarnLockV1(path.join(FIX, "packages", "cli", "yarn.lock"));
	assert.equal(res.lockfileVersion, 1);
	const byName = Object.fromEntries(res.deps.map(d => [d.name, d]));
	assert.equal(byName.chalk.version, "4.1.2");
	assert.equal(byName["ansi-styles"].version, "4.3.0");
	assert.equal(byName["@acme/private-utils"].version, "1.0.0");
	assert.equal(byName.mocha.version, "9.0.0");
});

test("findJsManifests discovers both packages, skips node_modules and Maven dirs", () => {
	const groups = findJsManifests(FIX);
	const dirs = groups.map(g => path.relative(FIX, g.dir)).sort();
	assert.ok(dirs.includes(path.join("packages", "web-app")));
	assert.ok(dirs.includes(path.join("packages", "cli")));
	// No Maven dir should appear
	assert.ok(!dirs.some(d => d.startsWith("services" + path.sep)));
});

test("collectNpmDeps merges both packages and namespaces keys with 'npm:'", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	assert.ok(map.has("npm:axios"));
	assert.ok(map.has("npm:lodash"));
	assert.ok(map.has("npm:chalk"));
	assert.ok(map.has("npm:@acme/private-utils"));
	const axios = map.get("npm:axios");
	assert.equal(axios.ecosystem, "npm");
	assert.equal(axios.artifactId, "axios");
	assert.equal(axios.groupId, "");
	assert.equal(axios.version, "0.21.0");
	assert.equal(axios.scope, "prod");
});

test("collectNpmDeps --ignore-test skips devDependencies (jest, eslint, mocha)", () => {
	const map = collectNpmDeps(FIX, { ignoreTest: true, verbose: false });
	assert.equal(map.has("npm:jest"), false);
	assert.equal(map.has("npm:eslint"), false);
	assert.equal(map.has("npm:mocha"), false);
	// prod deps still present
	assert.ok(map.has("npm:axios"));
	assert.ok(map.has("npm:chalk"));
});

test("collectNpmDeps deps2Exclude regex strips @acme/private-utils", () => {
	const map = collectNpmDeps(FIX, { deps2Exclude: /^@acme\//, verbose: false });
	assert.equal(map.has("npm:@acme/private-utils"), false);
	// public deps still present
	assert.ok(map.has("npm:axios"));
	assert.ok(map.has("npm:chalk"));
});

test("collectNpmDeps prefers lockfile (resolved) version over package.json range", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	// In web-app, package.json pins "0.21.0" and lockfile says "0.21.0" — verify
	// concrete resolved version is the one kept.
	const axios = map.get("npm:axios");
	assert.equal(/^\d/.test(axios.version), true);
});

test("collectNpmDeps skips package.json when a lockfile is present in the same dir", () => {
	// web-app has both package.json and package-lock.json. Only the lockfile
	// should source dep entries; the package.json (which carries ranges like
	// "^1.0.0" we can't query OSV with) must be ignored as a source.
	const map = collectNpmDeps(FIX, { verbose: false });
	const axios = map.get("npm:axios");
	assert.ok(axios.lockType?.startsWith("package-lock-v"), `axios should come from lockfile, got lockType=${axios.lockType}`);
	// And the only manifestPaths recorded for axios should be the lockfile
	for (const p of axios.manifestPaths) {
		assert.ok(p.endsWith("package-lock.json") || p.endsWith("yarn.lock"),
			`expected only lockfile manifestPaths for axios, got ${p}`);
	}
});

test("collectNpmDeps no-lockfile fallback: warns + scans pinned, skips ranges", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	assert.ok(Array.isArray(map.warnings), "warnings array should be present");
	const w = map.warnings.find(x => x.type === "no-lockfile" && x.manifestPath.includes("no-lock"));
	assert.ok(w, "expected a no-lockfile warning for packages/no-lock/package.json");
	assert.match(w.message, /best-effort/, "warning should mention best-effort/partial results");
	// Range-only deps must NOT leak into the Map (can't query OSV with "^1.0.0").
	assert.equal(map.has("npm:left-pad"), false, "left-pad ^1.0.0 must not be collected (unresolved range)");
	// Pinned exact versions ARE now collected best-effort (changed contract).
	assert.ok(map.has("npm:semver"), "semver 7.5.0 (pinned) should be collected from no-lock package.json");
	assert.equal(map.get("npm:semver").version, "7.5.0");
});

test("parsePackageLock tags flattened-transitive entries as scope='transitive'", () => {
	// follow-redirects is pulled in by axios but is not in the root's direct
	// dependency lists — even though npm v3 places it at depth 0 in node_modules,
	// it must be reported as transitive.
	const res = parsePackageLock(path.join(FIX, "packages", "web-app", "package-lock.json"));
	const byName = Object.fromEntries(res.deps.map(d => [d.name, d]));
	assert.equal(byName["follow-redirects"].scope, "transitive");
	assert.equal(byName.qs.scope, "transitive");
	// direct deps stay direct
	assert.equal(byName.axios.scope, "prod");
	assert.equal(byName.express.scope, "prod");
});

test("collectNpmDeps sets ecosystemType=npm for package-lock and yarn for yarn.lock", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	assert.equal(map.get("npm:axios").ecosystemType, "npm");      // from package-lock.json
	assert.equal(map.get("npm:chalk").ecosystemType, "yarn");     // from yarn.lock
});

test("collectNpmDeps captures peerDependencies (react@17 in web-app)", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	const react = map.get("npm:react");
	assert.ok(react, "react peer dep should be present");
	assert.equal(react.scope, "peer");
});

/* ---- pnpm-lock.yaml ---- */
test("parsePnpmLock v9: importers + packages + snapshots, dev classification preserved", () => {
	const r = parsePnpmLock(F("pnpm-v9/pnpm-lock.yaml"));
	assert.equal(r.lockfileVersion, "9.0");
	const m = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.equal(m["lodash"].version, "4.17.21");
	assert.equal(m["@babel/core"].version, "7.23.0");     // scoped name parsed correctly
	assert.equal(m["ms"].version, "2.1.3");                // transitive from snapshots
	assert.equal(m["typescript"].scope, "dev");           // importers devDeps wins over packages
});

test("parsePnpmLock v6: /name@version(peers) keys + top-level deps, dev flag honored", () => {
	const r = parsePnpmLock(F("pnpm-v6/pnpm-lock.yaml"));
	assert.equal(r.lockfileVersion, "6.0");
	const m = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.equal(m["axios"].version, "1.6.0");
	assert.equal(m["follow-redirects"].version, "1.15.3");  // transitive
	assert.equal(m["jest"].scope, "dev");                   // dev: true in packages
	// scoped + dev. No importer reaches it in this fixture (an orphan): like the
	// package-lock path, a package nothing declares is a "transitive", and the lock's
	// own `dev: true` flag is what keeps it out of production.
	assert.equal(m["@types/node"].scope, "transitive");
	assert.equal(m["@types/node"].isDev, true);
});

test("collectNpmDeps: pnpm-lock.yaml collected, ecosystemType stays npm, ignoreTest drops dev", () => {
	const all = collectNpmDeps(F("pnpm-v9"), { verbose: false });
	assert.ok(all.has("npm:lodash"));
	assert.ok(all.has("npm:ms"));
	assert.equal(all.get("npm:lodash").ecosystemType, "npm");   // pnpm pkgs are npm-registry
	assert.equal(all.get("npm:lodash").lockType, "pnpm");
	const noTest = collectNpmDeps(F("pnpm-v9"), { ignoreTest: true, verbose: false });
	assert.equal(noTest.has("npm:typescript"), false);          // dev dropped
});

test("hasJsManifests / detect finds a pnpm-only project", () => {
	const { hasJsManifests } = require("../lib/codecs/npm/collect");
	assert.equal(hasJsManifests(F("pnpm-v9")), true);
});

test("parsePnpmLock v5: slash-format keys (/name/version, /@scope/name/version)", () => {
	const r = parsePnpmLock(F("pnpm-v5/pnpm-lock.yaml"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d.version]));
	assert.equal(m["lodash"], "4.17.21");
	assert.equal(m["@babel/core"], "7.0.0");      // scoped slash form parsed
});

test("parsePnpmLock: malformed YAML throws (so safeParse skips it, no crash)", () => {
	const fs = require("fs"), os = require("os");
	const tmp = path.join(os.tmpdir(), `fad-pnpm-bad-${process.pid}.yaml`);
	fs.writeFileSync(tmp, "lockfileVersion: '9.0'\npackages:\n  - [unbalanced\n");
	assert.throws(() => parsePnpmLock(tmp), /pnpm-lock parse failed/);
	fs.unlinkSync(tmp);
});

/* ---- yarn.lock v2+ (Berry) ---- */
test("parseYarnBerry: parses YAML, multi-descriptor keys, skips @workspace local", () => {
	const fs = require("fs");
	const raw = fs.readFileSync(F("yarn-berry/yarn.lock"), "utf8");
	const r = parseYarnBerry(raw, F("yarn-berry/yarn.lock"));
	assert.equal(r.lockfileVersion, "berry");
	assert.ok(!r.parseError);
	const m = Object.fromEntries(r.deps.map(d => [d.name, d.version]));
	assert.equal(m["lodash"], "4.17.21");
	assert.equal(m["@babel/core"], "7.23.0");      // from "@babel/core@npm:^7.0.0, @babel/core@npm:^7.23.0"
	assert.equal(m["@babel/types"], "7.23.0");
	assert.equal(m["jest"], "29.7.0");
	assert.ok(!("my-app" in m), "the @workspace local package must be skipped");
});

test("parseYarnBerry: malformed YAML sets parseError instead of throwing", () => {
	const r = parseYarnBerry("__metadata:\n  version: 8\n\"a@npm:1\":\n  - [bad\n", "/tmp/yarn.lock");
	assert.equal(r.lockfileVersion, "berry");
	assert.ok(r.parseError, "parseError should be set");
	assert.deepEqual(r.deps, []);
});

test("parseYarnLockV1 dispatches Berry lockfiles to the YAML parser (no longer unsupported)", () => {
	const r = parseYarnLockV1(F("yarn-berry/yarn.lock"));
	assert.equal(r.lockfileVersion, "berry");
	assert.equal(r.unsupported, undefined);        // contract changed: now parsed
	assert.ok(r.deps.length >= 4);
});

test("collectNpmDeps: Berry yarn.lock collected with ecosystemType=yarn", () => {
	const map = collectNpmDeps(F("yarn-berry"), { verbose: false });
	assert.ok(map.has("npm:lodash"));
	assert.ok(map.has("npm:@babel/core"));
	assert.equal(map.get("npm:lodash").ecosystemType, "yarn");
	assert.equal(map.get("npm:lodash").lockType, "yarn-berry");
	// no "yarn-berry-unsupported" warning anymore
	assert.ok(!(map.warnings || []).find(w => w.type === "yarn-berry-unsupported"));
});

// Regression: every DISTINCT concrete version of a package must be scanned, not
// just the highest. A nested node_modules pin (lower version) used to be dropped,
// missing CVEs that only affect that lower version. (audit fix #2)
test("collectNpmDeps accumulates every distinct nested version", () => {
	const { collectNpmDeps } = require("../lib/codecs/npm/collect");
	const fs = require("fs");
	const os = require("os");
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-npm-"));
	fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "t", version: "1.0.0", dependencies: { lodash: "^4.0.0", a: "^1.0.0" } }));
	fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({
		name: "t", version: "1.0.0", lockfileVersion: 3,
		packages: {
			"": { name: "t", version: "1.0.0", dependencies: { lodash: "^4.0.0", a: "^1.0.0" } },
			"node_modules/lodash": { version: "4.17.21" },
			"node_modules/a": { version: "1.0.0", dependencies: { lodash: "^3.0.0" } },
			"node_modules/a/node_modules/lodash": { version: "3.10.1" },
		},
	}));
	const deps = collectNpmDeps(dir); // returns the resolved-deps Map directly
	const lodash = deps.get("npm:lodash");
	assert.ok(lodash, "lodash collected");
	assert.deepEqual([...lodash.versions].sort(), ["3.10.1", "4.17.21"]);
	fs.rmSync(dir, { recursive: true, force: true });
});

test('npm representative version uses full SemVer precedence and retains all observed versions', () => {
 const {semverCompare}=require('../lib/codecs/npm/collect');
 const chain=['1.0.0-alpha','1.0.0-alpha.1','1.0.0-alpha.beta','1.0.0-beta','1.0.0-beta.2','1.0.0-beta.11','1.0.0-rc.1','1.0.0'];
 for(let i=1;i<chain.length;i++) {
  assert.equal(semverCompare(chain[i-1],chain[i]),-1);
  assert.equal(semverCompare(chain[i],chain[i-1]),1);
 }
 assert.equal(semverCompare('1.0.0+build.2','1.0.0+build.1'),0);
 assert.equal(semverCompare('9007199254740993.0.0','9007199254740992.0.0'),1);
 for(const invalid of ['latest','^1.0.0','1.0.0-01','1.0.0-'])assert.equal(semverCompare(invalid,'1.0.0'),null);
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'vv-npm-precedence-'));
 try {
  for(const [name,version] of [['a','1.0.0-rc.1'],['b','1.0.0']]) {
   const dir=path.join(temp,name);fs.mkdirSync(dir);fs.writeFileSync(path.join(dir,'package.json'),JSON.stringify({name,dependencies:{lib:version}}));
  }
  const dep=collectNpmDeps(temp).get('npm:lib');
  assert.equal(dep.version,'1.0.0');assert.deepEqual([...dep.versions].sort(),['1.0.0','1.0.0-rc.1']);
 } finally {fs.rmSync(temp,{recursive:true,force:true});}
});
