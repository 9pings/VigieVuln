'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const go = require('../lib/codecs/go.codec');
const nuget = require('../lib/codecs/nuget.codec');
const python = require('../lib/codecs/pypi.codec');

function fixture(t, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-parser-regression-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}
function goEnv(t, value) {
  const old = process.env.GOWORK;
  if (value === undefined) delete process.env.GOWORK; else process.env.GOWORK = value;
  t.after(() => { if (old === undefined) delete process.env.GOWORK; else process.env.GOWORK = old; });
}
const mod = 'module example.com/app\ngo 1.24\nrequire golang.org/x/net v0.40.0\nreplace golang.org/x/net => golang.org/x/net v0.30.0\n';

test('workspace replacements override go.mod and coverage remains explicitly incomplete', async t => {
  goEnv(t, undefined);
  const dir = fixture(t, { 'go.mod': mod, 'go.work': 'go 1.24\nuse .\nreplace (\n golang.org/x/net => golang.org/x/net v0.7.0\n)\n' });
  const r = await go.collect(dir);
  assert.deepEqual(r.deps.get('go:golang.org/x/net').versions, ['0.7.0']);
  assert.ok(r.warnings.some(w => w.reason === 'workspace-graph-not-resolved'));
  assert.ok(r.parsedManifests.includes(path.join(dir, 'go.work')));
});

test('GOWORK off disables workspace discovery; explicit GOWORK chooses that file', async t => {
  const dir = fixture(t, { 'go.mod': mod, 'go.work': 'replace golang.org/x/net => golang.org/x/net v0.7.0\n', 'custom.work': 'replace golang.org/x/net => golang.org/x/net v0.8.0\n' });
  goEnv(t, 'off');
  let r = await go.collect(dir);
  assert.deepEqual(r.deps.get('go:golang.org/x/net').versions, ['0.30.0']);
  assert.ok(!r.warnings.some(w => w.reason === 'workspace-graph-not-resolved'));
  process.env.GOWORK = path.join(dir, 'custom.work');
  r = await go.collect(dir);
  assert.deepEqual(r.deps.get('go:golang.org/x/net').versions, ['0.8.0']);
});

test('local workspace replacement is not incorrectly scanned as the public version', async t => {
  goEnv(t, undefined);
  const dir = fixture(t, { 'go.mod': mod, 'go.work': 'replace golang.org/x/net => ./fork\n' });
  const r = await go.collect(dir);
  assert.equal(r.deps.size, 0);
  assert.ok(r.warnings.some(w => w.type === 'local-replace'));
});

test('NuGet retains conditional CPM alternatives in either declaration order and respects VersionOverride', async t => {
  const pins = [`<PackageVersion Include="Newtonsoft.Json" Version="12.0.1" Condition="'$(TargetFramework)' == 'net48'"/>`, `<PackageVersion Include="Newtonsoft.Json" Version="13.0.3" Condition="'$(TargetFramework)' == 'net8.0'"/>`];
  const dir = fixture(t, { 'app.csproj': '<Project><PropertyGroup><TargetFrameworks>net48;net8.0</TargetFrameworks></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json"/></ItemGroup></Project>' });
  for (const entries of [pins, [...pins].reverse()]) {
    fs.writeFileSync(path.join(dir, 'Directory.Packages.props'), `<Project><ItemGroup>${entries.join('')}</ItemGroup></Project>`);
    const r = await nuget.collect(dir);
    assert.deepEqual(r.deps.get('nuget:newtonsoft.json').versions.sort(), ['12.0.1', '13.0.3']);
    assert.ok(r.warnings.some(w => w.type === 'dependency-coverage' && w.reason === 'conditional-versions'));
  }
  fs.writeFileSync(path.join(dir, 'app.csproj'), '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" VersionOverride="14.0.0"/></ItemGroup></Project>');
  const r = await nuget.collect(dir);
  assert.deepEqual(r.deps.get('nuget:newtonsoft.json').versions, ['14.0.0']);
  assert.ok(!r.warnings.some(w => w.type === 'dependency-coverage' && w.reason === 'conditional-versions'));
});

test('Python conditional constraint alternatives survive line order and unused constraints stay excluded', async t => {
  const pins = ['django==2.2.0; python_version < "3.10"', 'django==5.1.0; python_version >= "3.10"'];
  const dir = fixture(t, { 'requirements.txt': '-c constraints.txt\ndjango>=2\n' });
  for (const lines of [pins, [...pins].reverse()]) {
    fs.writeFileSync(path.join(dir, 'constraints.txt'), [...lines, 'unused==1.0'].join('\n'));
    const r = await python.collect(dir);
    assert.deepEqual(r.deps.get('pypi:django').versions.sort(), ['2.2.0', '5.1.0']);
    assert.equal(r.deps.size, 1);
    assert.ok(r.warnings.some(w => w.type === 'dependency-coverage' && w.reason === 'conditional-versions'));
  }
});

test('Python dependency groups resolve normalized includes, preserve shared prod scope and report invalid groups', async t => {
  const dir = fixture(t, { 'pyproject.toml': '[dependency-groups]\ntest=["django==2.2.0", {include-group="shared_group"}]\nshared-group=["requests==2.31.0"]\nruntime=[{include-group="test"}]\ncycle=[{include-group="cycle"}]\nbroken=[{include-group="absent"}]\n' });
  const r = await python.collect(dir, { ignoreTest: true });
  assert.deepEqual(r.deps.get('pypi:django').versions, ['2.2.0']);
  assert.equal(r.deps.get('pypi:django').isDev, false);
  assert.ok(r.deps.has('pypi:requests'));
  assert.ok(r.warnings.some(w => w.type === 'parse-error' && /cycle/.test(w.message)));
  assert.ok(r.warnings.some(w => w.type === 'parse-error' && /absent/.test(w.message)));
});

test('Python test-only dependency group is scanned by default and honors ignoreTest', async t => {
  const dir = fixture(t, { 'pyproject.toml': '[dependency-groups]\ntest=["django==2.2.0"]\n' });
  assert.ok((await python.collect(dir)).deps.has('pypi:django'));
  assert.equal((await python.collect(dir, { ignoreTest: true })).deps.size, 0);
});


test('Go replacement precedence is file priority then exact version, independent of line order', () => {
  const { parseGoMod } = require('../lib/codecs/go/parse');
  const source = 'module example.com/app\ngo 1.24\nrequire golang.org/x/net v0.40.0\nreplace golang.org/x/net v0.40.0 => golang.org/x/net v0.30.0\n';
  const wildcard = 'replace golang.org/x/net => golang.org/x/net v0.7.0\n';
  const exact = 'replace golang.org/x/net v0.40.0 => golang.org/x/net v0.8.0\n';
  const workspace = text => parseGoMod(text, { replacementsOnly: true });
  assert.equal(parseGoMod(source, { workspaceReplaces: workspace(wildcard) }).deps[0].version, '0.7.0');
  for (const text of [wildcard + exact, exact + wildcard]) {
    assert.equal(parseGoMod(source, { workspaceReplaces: workspace(text) }).deps[0].version, '0.8.0');
    assert.equal(parseGoMod('require golang.org/x/net v0.40.0\n' + text).deps[0].version, '0.8.0');
  }
});
