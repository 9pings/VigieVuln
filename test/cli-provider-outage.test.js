const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

for (const hosted of [true, false]) {
  for (const strict of [null, 'advisories', 'sources']) {
    test(`CLI Wordfence 503 writes warning reports: hosted=${hosted}, strict=${strict}`, t => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-source-outage-'));
      t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
      const src = path.join(dir, 'source');
      fs.mkdirSync(path.join(src, 'wp-admin'), { recursive: true });
      fs.mkdirSync(path.join(src, 'wp-includes'));
      fs.writeFileSync(path.join(src, 'wp-load.php'), '<?php');
      fs.writeFileSync(path.join(src, 'wp-admin/index.php'), '<?php');
      fs.writeFileSync(path.join(src, 'wp-includes/version.php'), "<?php $wp_version = '6.4.2';");
      const hook = path.join(dir, 'fixture.cjs');
      fs.writeFileSync(hook, `
        require('node:os').homedir = () => __dirname;
        globalThis.fetch = async (url, init) => {
          const u = new URL(url);
          if (u.pathname === '/v1/proxy/status') return Response.json({ok:true, service:'vigievuln-proxy'});
          if (u.pathname === '/v1/resource') {
            const q = JSON.parse(init.body);
            require('node:assert/strict').equal(q.provider, 'wordfence');
            require('node:assert/strict').equal(q.type, 'software');
          } else require('node:assert/strict').equal(u.hostname, 'www.wordfence.com');
          require('node:fs').appendFileSync(__dirname + '/requests', 'wordfence\\n');
          return Response.json({error:'Wordfence unavailable'}, {status:503});
        };
      `);
      const out = path.join(dir, 'report');
      const args = ['--require', hook, path.join(__dirname, '../vigievuln.js'), '-s', src,
        '--wordfence-live', '--retries', '0', '--report-html', '--report-json', '-o', out];
      if (hosted) args.push('--proxy-cache', 'default');
      if (strict) args.push('--fail-on-incomplete', strict);
      const env = { PATH: process.env.PATH, FORCE_COLOR:'0',
        ...(hosted ? {VIGIEVULN_PROXY_CACHE_TOKEN:'fixture-proxy-token'} : {WORDFENCE_API_KEY:'fixture-wordfence-key'}) };
      const run = spawnSync(process.execPath, args, { env, cwd:dir, encoding:'utf8', timeout:30000 });
      assert.equal(run.status, strict ? 2 : 0, `${run.error || ''}\n${run.stdout}\n${run.stderr}`);
      assert.match(fs.readFileSync(path.join(dir, 'requests'), 'utf8'), /wordfence/);
      const report = JSON.parse(fs.readFileSync(path.join(out, 'findings.json'), 'utf8'));
      const failed = report.coverage.find(c => c.sourceId === 'wordfence-v3' && c.capability === 'advisories');
      assert.equal(failed.execution, 'failed');
      assert.equal(failed.result, 'indeterminate');
      assert.ok(report.warnings.some(w => /assessment failed.*503/i.test(w.message)));
      assert.match(fs.readFileSync(path.join(out, 'cve-report.html'), 'utf8'), /503/);
      assert.equal(report.coverage.some(c => c.sourceId === 'wordfence-v3' && c.result === 'no-match'), false);
    });
  }
}

for (const strict of [false, true]) test(`CLI Packagist 503 writes partial reports, strict=${strict}`, t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-packagist-outage-'));
  t.after(() => fs.rmSync(dir, {recursive:true,force:true}));
  const src = path.join(dir,'source'); fs.mkdirSync(src);
  fs.writeFileSync(path.join(src,'composer.json'), JSON.stringify({require:{'monolog/monolog':'1.0.0'}}));
  fs.writeFileSync(path.join(src,'composer.lock'), JSON.stringify({packages:[{name:'monolog/monolog',version:'1.0.0'}]}));
  const hook = path.join(dir,'fixture.cjs');
  fs.writeFileSync(hook, `require('node:os').homedir=()=>__dirname;
    globalThis.fetch=async()=>Response.json({error:'Unavailable'},{status:503});`);
  const out = path.join(dir,'report');
  const args = ['--require',hook,path.join(__dirname,'../vigievuln.js'),'-s',src,'--ecosystem','composer',
    '-d','osv,nvd,eol,epss,kev,euvd,certfr,retire,transitive,all-libs',
    '--retries','0','--report-html','--report-json','-o',out];
  if(strict) args.push('--fail-on-incomplete','sources');
  const run=spawnSync(process.execPath,args,{cwd:dir,env:{PATH:process.env.PATH,FORCE_COLOR:'0'},encoding:'utf8',timeout:30000});
  assert.equal(run.status,strict?2:0,run.stdout+run.stderr);
  const report=JSON.parse(fs.readFileSync(path.join(out,'findings.json'),'utf8'));
  assert.ok(report.warnings.some(w=>w.type==='source-unavailable' && /Packagist:.*coverage is incomplete/i.test(w.message)), JSON.stringify(report.warnings));
  assert.match(fs.readFileSync(path.join(out,'cve-report.html'),'utf8'),/503/);
});
