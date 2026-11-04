const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

for (const ecosystem of ['maven', 'npm']) test(`offline ${ecosystem} missing advisory source fails the sources gate`, t => {
 const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-offline-sources-'));
 t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
 const src = path.join(dir, 'src'); fs.mkdirSync(src);
 if (ecosystem === 'maven') fs.writeFileSync(path.join(src, 'pom.xml'), '<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version></dependency></dependencies></project>');
 else fs.writeFileSync(path.join(src, 'package.json'), JSON.stringify({name:'example',version:'1.0.0',dependencies:{example:'1.0.0'}}));
 const hook = path.join(dir, 'hook.cjs'); fs.writeFileSync(hook, `require('node:os').homedir = () => ${JSON.stringify(dir)};`);
 const output = path.join(dir, 'out');
 const args = ['--require', hook, path.join(__dirname, '../vigievuln.js'), '-s', src, '--ecosystem', ecosystem, '--offline', '-d', 'nvd,eol,epss,kev,euvd,certfr,retire,transitive,all-libs,gcve', '--no-binaries', '--no-certs', '--report-json', '-o', output, '--fail-on-incomplete', 'sources'];
 if (ecosystem === 'maven') args.push('--no-osv');
 const run = spawnSync(process.execPath, args, {cwd:dir, env:{PATH:process.env.PATH, FORCE_COLOR:'0'}, encoding:'utf8', timeout:30000});
 assert.equal(run.status, 2, run.stdout + run.stderr);
 const report = JSON.parse(fs.readFileSync(path.join(output, 'findings.json'), 'utf8'));
 assert.ok(report.warnings.some(w => ecosystem === 'maven' ? w.type === 'source-unavailable' && /CVEProject/.test(w.message) : w.type === 'osv-coverage'), JSON.stringify(report.warnings));
});
