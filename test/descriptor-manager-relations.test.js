const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { buildProjectDescriptor } = require('../lib/project-descriptor');
const fixture = eco => path.join(__dirname, 'fixtures', 'descriptor-relations', eco);
async function descriptor(eco) {
 const { deps } = await require(`../lib/codecs/${eco}.codec`).collect(fixture(eco), { offline: true });
 const result = buildProjectDescriptor(deps);
 assert.ok(!JSON.stringify(result).includes(fixture(eco)), 'no local paths in descriptor');
 return { deps, rows: result.deps, relation: (name, v) => result.deps.find(d => d.name.toLowerCase() === name.toLowerCase() && d.version === v)?.relation };
}
test('Go descriptor: per-module versions, indirect marker, sums and replacements', async () => {
 const x = await descriptor('go');
 assert.equal(x.relation('example.com/shared', '1.0.0'), 'direct');
 assert.equal(x.relation('example.com/shared', '2.0.0'), 'transitive');
 assert.equal(x.relation('example.com/shared', '3.0.0'), 'unknown');
 assert.equal(x.relation('example.com/shared', '9.0.0'), undefined, 'go.sum cannot override same-module require');
 assert.equal(x.relation('example.com/indirect', '1.0.0'), 'direct', 'direct evidence from another module survives');
 assert.equal(x.relation('example.com/fork', '2.0.0'), 'unknown', 'replacement identity is not a root declaration');
 assert.equal(x.relation('example.com/sum', '1.0.0'), 'unknown');
 assert.equal(x.relation('example.com/sum-b', '1.0.0'), 'unknown');
 assert.equal(x.relation('example.com/local', '1.0.0'), undefined);
 const shared = x.deps.get('go:example.com/shared');
 assert.equal(Object.keys(shared.versionPaths).length, 3);
});
test('NuGet descriptor: explicit lock types, multi-TFM evidence, unknown legacy list', async () => {
 const x = await descriptor('nuget');
 assert.equal(x.relation('shared', '1.0.0'), 'direct');
 assert.equal(x.relation('shared', '2.0.0'), 'transitive');
 assert.equal(x.relation('mixed', '1.0.0'), 'direct');
 assert.equal(x.relation('pinned', '2.0.0'), 'transitive');
 assert.equal(x.relation('weird', '1.0.0'), 'unknown');
 assert.equal(x.relation('legacy', '1.0.0'), 'unknown');
 assert.equal(x.relation('local', '1.0.0'), undefined);
 assert.equal(Object.keys(x.deps.get('nuget:shared').versionPaths).length, 2);
});
test('Bundler descriptor: root section, reachable edges, unknown sources and orphans', async () => {
 const x = await descriptor('ruby');
 assert.equal(x.relation('shared', '1.0.0'), 'direct');
 assert.equal(x.relation('shared', '2.0.0'), 'transitive');
 assert.equal(x.relation('child', '1.0.0'), 'transitive');
 assert.equal(x.relation('orphan', '1.0.0'), 'unknown');
 assert.equal(x.relation('local', '1.0.0'), 'unknown');
 assert.equal(Object.keys(x.deps.get('ruby:shared').versionPaths).length, 2);
});

test('Go ambiguous markers, unclosed blocks, excludes and malformed replaces remain unknown', () => {
 const { parseGoMod } = require('../lib/codecs/go/parse');
 for (const text of [
  'require example.com/lib v1.0.0 // indirectly required',
  'require (\n example.com/lib v1.0.0\n',
  'require example.com/lib v1.0.0\nexclude example.com/lib v1.0.0\n',
  'require example.com/lib v1.0.0\nreplace example.com/lib =>\n',
  'require example.com/lib v1.0.0\nreplace (\n invalid\n)\n',
 ]) assert.deepEqual(parseGoMod(text).deps[0].managerRelations, ['unknown'], text);
 assert.deepEqual(parseGoMod('require example.com/lib v1.0.0 // indirect').deps[0].managerRelations, ['transitive']);
 assert.deepEqual(parseGoMod('require example.com/lib v1.0.0 // application dependency').deps[0].managerRelations, ['direct']);
});

test('Go workspace does not claim module-local requirements are resolved direct versions', async t => {
 const fs = require('node:fs'), os = require('node:os');
 const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-relations-workspace-'));
 t.after(() => fs.rmSync(root, { recursive: true, force: true }));
 fs.writeFileSync(path.join(root, 'go.work'), 'go 1.21\nuse ./app\n');
 fs.mkdirSync(path.join(root, 'app'));
 fs.writeFileSync(path.join(root, 'app', 'go.mod'), 'module example.com/app\ngo 1.21\nrequire example.com/lib v1.0.0\n');
 const { deps } = await require('../lib/codecs/go.codec').collect(root, { offline: true });
 assert.equal(buildProjectDescriptor(deps).deps[0].relation, 'unknown');
});

test('Bundler missing/malformed roots, conflicting sources and multi-version locks stay unknown', () => {
 const { parseGemfileLock } = require('../lib/codecs/ruby/parse');
 const gem = 'GEM\n  remote: https://rubygems.org/\n  specs:\n    lib (1.0.0)\n';
 for (const text of [
  gem,
  gem + '\nDEPENDENCIES\n malformed root\n',
  gem + '\nDEPENDENCIES\n  lib\n\nDEPENDENCIES\n  lib\n',
  gem + '\nGIT\n  remote: https://example.test/repo\n  specs:\n    lib (1.0.0)\n\nDEPENDENCIES\n  lib\n',
  gem + '    lib (2.0.0)\n\nDEPENDENCIES\n  lib\n',
 ]) assert.ok(parseGemfileLock(text).deps.every(d => d.managerRelations[0] === 'unknown'), text);
});

test('Bundler cycles terminate and development root remains direct independently of scope', () => {
 const { parseGemfileLock } = require('../lib/codecs/ruby/parse');
 const text = 'GEM\n  specs:\n    rspec (3.0.0)\n      child\n    child (1.0.0)\n      rspec\n\nDEPENDENCIES\n  rspec\n';
 const rows = parseGemfileLock(text).deps;
 assert.deepEqual(rows.map(d => [d.name, d.managerRelations[0]]), [['rspec', 'direct'], ['child', 'transitive']]);
});

test('NuGet PackageReference without lock stays unknown, even with explicit version', async t => {
 const fs = require('node:fs'), os = require('node:os');
 const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-relations-nuget-'));
 t.after(() => fs.rmSync(root, { recursive: true, force: true }));
 fs.writeFileSync(path.join(root, 'App.csproj'), '<Project><ItemGroup><PackageReference Include="Library" Version="1.0.0" /></ItemGroup></Project>');
 const { deps } = await require('../lib/codecs/nuget.codec').collect(root, { offline: true });
 assert.equal(buildProjectDescriptor(deps).deps[0].relation, 'unknown', 'bare NuGet version is a minimum, not a resolved lock version');
});

test('empty or unrecognized relation evidence never invents transitivity', () => {
 for (const evidence of [[], ['unexpected'], ['transitive', 'unexpected'], ['unknown', 'transitive']]) {
  const out = buildProjectDescriptor(new Map([['x', { ecosystem: 'npm', name: 'lib', version: '1.0.0', versionRelations: { '1.0.0': evidence } }]]));
  assert.equal(out.deps[0].relation, 'unknown');
 }
});
