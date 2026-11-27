const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const CLI = path.resolve(__dirname, '../vigievuln.js');

test('Go unresolved inventory fails inventory and sources gates after exporting unchanged findings', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-go-coverage-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const project = path.join(root, 'project'), home = path.join(root, 'home');
  const report = path.join(root, 'report.json'), preload = path.join(root, 'preload.cjs');
  const calls = path.join(root, 'unexpected-network');
  fs.mkdirSync(project); fs.mkdirSync(home);
  // Application plugins are disabled here. Their separate empty-coverage gate
  // must not mask whether the real CLI enforces the Go collection warning.
  fs.writeFileSync(preload, `require('node:os').homedir = () => process.env.VV_GO_TEST_HOME;
require(${JSON.stringify(path.resolve(__dirname, '../lib/scan-coverage.js'))}).requiredCoverageComplete = () => true;
// Isolate the inventory gate from the independently tested native-source availability gate.
require(${JSON.stringify(path.resolve(__dirname, '../lib/native-source-prepare.js'))}).prepareNativeSources = async () => ({sources:[],coverage:[],warnings:[]});
globalThis.fetch = async () => { require('node:fs').writeFileSync(process.env.VV_GO_TEST_CALLS, 'called'); throw new Error('unexpected offline network'); };`);
  fs.writeFileSync(path.join(project, 'go.sum'), 'example.org/lib v1.0.0 h1:fixture=\n');
  const setManifest = version => fs.writeFileSync(path.join(project, 'go.mod'),
    `module example.org/app\ngo ${version}\nrequire example.org/lib v1.0.0\n`);
  const run = category => {
    fs.rmSync(report, { force: true });
    const result = spawnSync(process.execPath, ['--require', preload, CLI, 'scan', project,
      '--offline', '--ecosystem', 'go', '--app-plugins', 'none', '--no-osv', '--no-osv-db',
      '--no-gcve', '--no-nvd', '--no-epss', '--no-kev', '--no-certfr', '--no-euvd',
      '--no-eol', '--no-retire', '--no-packagist-audit', '--no-all-libs', '--no-binaries',
      '--no-jars', '--no-certs', '--report-json', report, '--report-output', path.join(root, 'audit'),
      ...(category ? ['--fail-on-incomplete', category] : [])], {
      cwd: root, encoding: 'utf8', timeout: 20000,
      env: { ...process.env, VV_GO_TEST_HOME: home, VV_GO_TEST_CALLS: calls, FORCE_COLOR: '0' },
    });
    assert.ifError(result.error);
    assert.equal(fs.existsSync(calls), false, 'offline test must not attempt network');
    return require('./helpers/cancelled-scan')(result,[report]);
  };
  setManifest('1.14');
  for(const category of [null,'inventory','sources']) assert.match(run(category),/go-coverage|go.sum.*version/i);
  setManifest('1.21');
  for(const category of ['inventory','sources']) assert.doesNotMatch(run(category),/\[go-coverage\]/);
});
