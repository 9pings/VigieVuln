const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { parseGoMod, parseGoSum } = require("../lib/codecs/go/parse");
const { escapeModule } = require("../lib/codecs/go/registry");
const { purlFor } = require("../lib/purl");
const go = require("../lib/codecs/go.codec");

test("parseGoMod reads require blocks, strips v, flags indirect as transitive", () => {
	const { module, deps } = parseGoMod(`module github.com/acme/app
go 1.21
require (
	github.com/gin-gonic/gin v1.9.1
	github.com/bytedance/sonic v1.9.1 // indirect
)
require github.com/stretchr/testify v1.8.4
`);
	assert.equal(module, "github.com/acme/app");
	const gin = deps.find(d => d.name === "github.com/gin-gonic/gin");
	assert.equal(gin.version, "1.9.1");       // v stripped
	assert.equal(gin.scope, "compile");
	const sonic = deps.find(d => d.name === "github.com/bytedance/sonic");
	assert.equal(sonic.scope, "transitive");  // // indirect
	assert.ok(deps.find(d => d.name === "github.com/stretchr/testify"));
});

test("parseGoSum dedups module → version", () => {
	const { deps } = parseGoSum(`github.com/gin-gonic/gin v1.9.1 h1:abc=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def=
`);
	assert.equal(deps.length, 1);
	assert.equal(deps[0].version, "1.9.1");
});

test("escapeModule case-encodes uppercase per the proxy protocol", () => {
	assert.equal(escapeModule("github.com/BurntSushi/toml"), "github.com/!burnt!sushi/toml");
});

test("go purl splits the module path into namespace + name", () => {
	const dep = { ecosystem: "go", namespace: "", name: "github.com/gin-gonic/gin", version: "1.9.1" };
	assert.equal(purlFor(dep), "pkg:golang/github.com/gin-gonic/gin@1.9.1");
});

test("go codec collects from the fixture (go.mod authoritative)", async () => {
	const { deps } = await go.collect(path.join(__dirname, "fixtures", "go-app"));
	assert.ok(deps.has("go:github.com/gin-gonic/gin"));
	assert.equal(deps.get("go:github.com/gin-gonic/gin").version, "1.9.1");
	assert.equal(deps.get("go:github.com/bytedance/sonic").scope, "transitive");
	assert.equal(go.osvPackageName(deps.get("go:github.com/gin-gonic/gin")), "github.com/gin-gonic/gin");
});

test("go codec detects the fixture dir", () => {
	assert.equal(go.detect(path.join(__dirname, "fixtures", "go-app")), true);
});

// Regression: go.sum lists every version in the module graph — keep the HIGHEST,
// not the first encountered (the comment promised highest, the code kept first). (#E)
test("parseGoSum keeps the highest version per module", () => {
	const out = parseGoSum("ex.com/m v1.0.0 h1:a=\nex.com/m v1.5.0 h1:b=\nex.com/m v1.2.0 h1:c=\n");
	assert.equal(out.deps.length, 1);
	assert.equal(out.deps[0].version, "1.5.0");
});

// `replace` changes the EFFECTIVE build: a downgrade pin must be scanned at the
// replacement version (scanning the require line missed it entirely).
test("parseGoMod applies module→module replace directives (block and single-line)", () => {
	const { deps } = parseGoMod(`module ex.com/app
go 1.21
require (
	golang.org/x/text v0.3.9
	github.com/foo/bar v2.0.0
)
replace golang.org/x/text => golang.org/x/text v0.3.5
replace (
	github.com/foo/bar v2.0.0 => github.com/foo/bar-fork v2.0.1
)
`);
	const text = deps.find(d => d.name === "golang.org/x/text");
	assert.equal(text.version, "0.3.5", "versionless old matches every version — downgrade applied");
	assert.equal(text.replaced, true);
	const fork = deps.find(d => d.name === "github.com/foo/bar-fork");
	assert.equal(fork.version, "2.0.1");
	assert.equal(deps.find(d => d.name === "github.com/foo/bar"), undefined);
});

test("parseGoMod versioned replace only rewrites that exact version", () => {
	const { deps } = parseGoMod(`module ex.com/app
require ex.com/lib v1.0.0
replace ex.com/lib v9.9.9 => ex.com/lib v1.0.1
`);
	assert.equal(deps.find(d => d.name === "ex.com/lib").version, "1.0.0", "non-matching old version untouched");
});

test("parseGoMod drops directory-replaced deps and reports them", () => {
	const { deps, dropped } = parseGoMod(`module ex.com/app
require ex.com/internal v1.2.3
replace ex.com/internal => ../internal
`);
	assert.equal(deps.length, 0);
	assert.equal(dropped.length, 1);
	assert.equal(dropped[0].name, "ex.com/internal");
	assert.equal(dropped[0].path, "../internal");
});

test("parseGoMod captures the go directive", () => {
	assert.equal(parseGoMod("module m\ngo 1.16\n").goVersion, "1.16");
	assert.equal(parseGoMod("module m\n").goVersion, null);
});

// Pre-1.17 go.mod lists DIRECT deps only — the go.sum graph must be merged or
// every transitive dep of the module is invisible to the scan.
test("go codec merges go.sum transitives for a pre-1.17 module", async () => {
	const fs = require("fs");
	const os = require("os");
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-go116-"));
	fs.writeFileSync(path.join(dir, "go.mod"), "module ex.com/app\ngo 1.16\nrequire ex.com/direct v1.0.0\n");
	fs.writeFileSync(path.join(dir, "go.sum"),
		"ex.com/direct v1.0.0 h1:a=\nex.com/direct v1.0.0/go.mod h1:b=\nex.com/transitive v0.9.0 h1:c=\n");
	const { deps, warnings } = await go.collect(dir);
	assert.equal(deps.get("go:ex.com/direct").version, "1.0.0", "go.mod's selected version wins");
	assert.equal(deps.get("go:ex.com/direct").scope, "compile");
	assert.ok(deps.has("go:ex.com/transitive"), "go.sum-only transitive merged");
	assert.equal(deps.get("go:ex.com/transitive").scope, "transitive");
	assert.equal(warnings.filter(w => w.type === 'go-coverage').length, 1);
	assert.match(warnings.find(w => w.type === 'go-coverage').message, /checksums rather than selected build dependencies/);
	fs.rmSync(dir, { recursive: true, force: true });
});

test("go codec does NOT merge go.sum for a >=1.17 module (pruned graph in go.mod)", async () => {
	const fs = require("fs");
	const os = require("os");
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-go121-"));
	fs.writeFileSync(path.join(dir, "go.mod"), "module ex.com/app\ngo 1.21\nrequire ex.com/direct v1.0.0\n");
	fs.writeFileSync(path.join(dir, "go.sum"),
		"ex.com/direct v1.0.0 h1:a=\nex.com/stale-candidate v0.1.0 h1:c=\n");
	const { deps, warnings } = await go.collect(dir);
	assert.ok(deps.has("go:ex.com/direct"));
	assert.equal(deps.has("go:ex.com/stale-candidate"), false, "go.sum candidates not in the pruned graph stay out");
	assert.equal(warnings.some(w => w.type === 'go-coverage'), false);
	fs.rmSync(dir, { recursive: true, force: true });
});

// go.sum records TWO kinds of line per module:
//   mod ver h1:...          the module ZIP checksum
//   mod ver/go.mod h1:...   only its go.mod was read, during minimal version selection
// Neither kind proves current build membership. Metadata-only records are not
// included by the fallback, whose incomplete coverage is now made explicit.
test("parseGoSum keeps only modules that were actually downloaded (zip hash present)", () => {
	const sum = [
		"example.com/used v1.2.0 h1:aaa=",
		"example.com/used v1.2.0/go.mod h1:bbb=",
		"example.com/considered v9.9.9/go.mod h1:ccc=",   // MVS-only, never downloaded
		"example.com/alsoused v0.1.0 h1:ddd=",
	].join("\n");
	const names = parseGoSum(sum).deps.map(d => d.name).sort();
	assert.deepEqual(names, ["example.com/alsoused", "example.com/used"],
		"a metadata-only checksum does not establish a downloaded dependency");
});

test("parseGoSum picks the version that was downloaded, not the highest considered", () => {
	const sum = [
		"example.com/lib v1.0.0 h1:aaa=",
		"example.com/lib v1.0.0/go.mod h1:bbb=",
		"example.com/lib v2.5.0/go.mod h1:ccc=",   // considered by MVS, not selected
	].join("\n");
	const deps = parseGoSum(sum).deps;
	assert.equal(deps.length, 1);
	assert.equal(deps[0].version, "1.0.0",
		"v2.5.0 was only weighed during selection — reporting it invents a dependency");
});

test("parseGoSum still keeps the highest version when several were downloaded", () => {
	const sum = [
		"example.com/lib v1.0.0 h1:aaa=",
		"example.com/lib v1.4.0 h1:bbb=",
	].join("\n");
	assert.equal(parseGoSum(sum).deps[0].version, "1.4.0");
});
