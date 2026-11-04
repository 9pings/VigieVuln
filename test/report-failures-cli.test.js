const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const CLI = path.join(__dirname, '..', 'vigievuln.js');
function fixture(t) {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-report-failures-'));
	t.after(() => fs.rmSync(root, { recursive: true, force: true }));
	const src = path.join(root, 'src'); fs.mkdirSync(src);
	fs.writeFileSync(path.join(src, 'package-lock.json'), JSON.stringify({ name: 'fixture', lockfileVersion: 3, packages: { '': { name: 'fixture', version: '1.0.0' } } }));
	const preload = path.join(root, 'preload.cjs');
	fs.writeFileSync(preload, `require('node:os').homedir = () => ${JSON.stringify(root)}; globalThis.fetch = async () => { throw new Error('unexpected network'); };`);
	const run = args => {
		const r = spawnSync(process.execPath, ['--require', preload, CLI, ...args], {
			cwd: root, encoding: 'utf8', timeout: 20000,
			env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, FORCE_COLOR: '0' },
		});
		assert.ifError(r.error); return r;
	};
	const flags = ['scan', src, '--offline', '--ecosystem', 'npm', '--app-plugins', 'none', '--no-retire', '--no-gcve', '--no-eol', '--no-certs', '--no-binaries'];
	return { root, src, run, flags, preload };
}
test('baseline gates fail closed for missing, malformed, wrong-shaped and absent baselines', t => {
	const { root, run, flags } = fixture(t);
	const baseline = path.join(root, 'baseline.json');
	for (const content of [undefined, '{', '{}', 'null', '{"cve":{}}']) {
		if (content !== undefined) fs.writeFileSync(baseline, content);
		const r = run([...flags, '--no-report', '--fail-on-new', '--baseline', baseline]);
		assert.equal(r.status, 2, r.stdout + r.stderr);
		assert.match(r.stderr, /cannot read baseline/);
	}
	const missing = run([...flags, '--no-report', '--fail-on-new']);
	assert.equal(missing.status, 2); assert.match(missing.stderr, /requires --baseline/);
	fs.writeFileSync(baseline, '{"schema":"fad-findings/1","cve":[]}');
	const valid = run([...flags, '--no-report', '--fail-on-new', '--baseline', baseline]);
	assert.equal(valid.status, 0, valid.stdout + valid.stderr);
});
test('each requested machine export failure returns code 2 while successful sibling exports remain usable', t => {
	const { root, src, run, flags } = fixture(t);
	for (const format of ['json', 'sbom', 'csaf', 'sarif', 'xlsx']) {
		const sibling = path.join(root, 'successful.html');
		const r = run([...flags, '--report-' + format, src, '--report-html', sibling]);
		assert.equal(r.status, 2, r.stdout + r.stderr);
		assert.match(r.stdout + r.stderr, /export failed/);
		assert.ok(fs.statSync(sibling).size > 0);
	}
});
test('direct scan hint is localized on stderr and absent from proxy, descriptor and help flows', t => {
	const { root, run, flags } = fixture(t);
	const en = 'For faster scans with the VigieVuln DB or a seed → vigievuln setup';
	const fr = 'Pour des scans plus rapides avec la DB VigieVuln ou un seed → vigievuln setup';
	for (const [lang, hint] of [['en', en], ['fr', fr]]) {
		const r = run([...flags, '--no-report', '--lang', lang]);
		assert.equal(r.status, 0, r.stdout + r.stderr);
		assert.ok(r.stderr.includes(hint), r.stderr);
		assert.ok(!r.stdout.includes(hint));
	}
	for (const args of [
		[...flags, '--no-report', '--proxy-cache', 'https://cache.example.test'],
		[...flags, '--export-anonymized', path.join(root, 'descriptor.json')],
		['--help'],
	]) {
		const r = run(args);
		assert.equal(r.status, 0, r.stdout + r.stderr);
		assert.ok(!r.stderr.includes(en) && !r.stderr.includes(fr));
	}
});

test('standalone diff validates report input and does not gate on dev-only changes', t => {
	const { root, run } = fixture(t);
	const baseline = path.join(root, 'baseline.json'), current = path.join(root, 'current.json');
	fs.writeFileSync(baseline, JSON.stringify({ cve: [] }));
	fs.writeFileSync(current, JSON.stringify({ cve: [{ id: 'CVE-2026-12345', dep: { ecosystem: 'npm', coord: 'dev', version: '1', isDev: true } }] }));
	const ok = run(['diff', baseline, current, '--fail-on-new']);
	assert.equal(ok.status, 0, ok.stdout + ok.stderr);
	assert.match(ok.stdout, /New production CVE findings:\s+0/);
	fs.writeFileSync(current, '{}');
	assert.equal(run(['diff', baseline, current, '--fail-on-new']).status, 2);
});

test('human report failures return code 2 without a stack and preserve sibling exports', t => {
	const { root, src, run, flags } = fixture(t);
	for (const format of ['html', 'doc']) {
		const other = format === 'html' ? 'doc' : 'html';
		const sibling = path.join(root, `successful.${other}`), json = path.join(root, 'successful.json');
		const r = run([...flags, '--report-' + format, src, '--report-' + other, sibling, '--report-json', json]);
		assert.equal(r.status, 2, r.stdout + r.stderr);
		assert.match(r.stdout + r.stderr, /export failed/);
		assert.doesNotMatch(r.stderr, /\n\s+at |Node\.js v/);
		assert.ok(fs.statSync(sibling).size > 0);
		assert.ok(Array.isArray(JSON.parse(fs.readFileSync(json, 'utf8')).cve));
	}
});

test('unexpected main rejection has a concise error and exit 2', t => {
	const { preload, run, flags } = fixture(t);
	fs.appendFileSync(preload, `require(${JSON.stringify(path.join(__dirname, '../lib/ui'))}).banner = () => { throw new Error('injected startup failure'); };`);
	const r = run([...flags, '--no-report']);
	assert.equal(r.status, 2, r.stdout + r.stderr);
	assert.match(r.stderr, /scan failed: injected startup failure/);
	assert.doesNotMatch(r.stderr, /\n\s+at |Node\.js v/);
});

test('standalone diff output failure has context and exit 2 without a stack', t => {
	const { root, src, run } = fixture(t);
	const baseline = path.join(root, 'base.json');
	fs.writeFileSync(baseline, JSON.stringify({ cve: [] }));
	const r = run(['diff', baseline, baseline, '--report-json', src]);
	assert.equal(r.status, 2, r.stdout + r.stderr);
	assert.match(r.stderr, /cannot write diff report/);
	assert.doesNotMatch(r.stderr, /\n\s+at |Node\.js v/);
});

test('global ignore and mismatched project baselines are visible in terminal and reports', t => {
	const { root, run, flags } = fixture(t);
	const ignore = path.join(root, '.fadignore'), baseline = path.join(root, 'base.json'), output = path.join(root, 'findings.json');
	fs.writeFileSync(ignore, '* # intentional acceptance');
	fs.writeFileSync(baseline, JSON.stringify({ project: { name: 'another-project' }, cve: [] }));
	const r = run([...flags, '--ignore', ignore, '--baseline', baseline, '--report-json', output]);
	assert.equal(r.status, 0, r.stdout + r.stderr);
	assert.match(r.stdout + r.stderr, /global wildcard/);
	assert.match(r.stdout + r.stderr, /another-project/);
	const doc = JSON.parse(fs.readFileSync(output, 'utf8'));
	assert.ok(doc.warnings.some(w => w.type === 'global-ignore'));
	assert.ok(doc.warnings.some(w => w.type === 'baseline-project-mismatch'));
	const standalone = run(['diff', baseline, output, '--report-json', path.join(root, 'diff.json')]);
	assert.equal(standalone.status, 0, standalone.stdout + standalone.stderr);
	assert.match(standalone.stderr, /another-project/);
});
