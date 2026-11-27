const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

for (const hosted of [true, false]) {
  for (const strict of [null, 'advisories', 'sources']) {
    test(`CLI Wordfence 503 ${strict ? 'cancels publication' : 'publishes an incomplete report'}: hosted=${hosted}, strict=${strict}`, t => {
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
      const args = ['--require', hook, path.join(__dirname, '../vigievuln.js'), 'scan', src,
        '--wordfence-live', '--retries', '0', '--report-html', '--report-json', '-o', out];
      if (hosted) args.push('--proxy-cache', 'default');
      if (strict) args.push('--fail-on-incomplete', strict);
      const env = { PATH: process.env.PATH, FORCE_COLOR:'0',
        ...(hosted ? {VIGIEVULN_PROXY_CACHE_TOKEN:'fixture-proxy-token'} : {WORDFENCE_API_KEY:'fixture-wordfence-key'}) };
      const run = spawnSync(process.execPath, args, { env, cwd:dir, encoding:'utf8', timeout:30000 });
      assert.match(fs.readFileSync(path.join(dir, 'requests'), 'utf8'), /wordfence/);
      assert.match(run.stdout+run.stderr,/wordfence.*503/is);
      // The Wordfence outage names the failed WordPress advisory check on stderr in both outcomes.
      assert.match(run.stderr,/Incomplete advisories check for wordpress:.*\(wordfence-v3\).*HTTP 503/);
      if (strict) {
        // --fail-on-incomplete advisories|sources keeps the strict behaviour.
        assert.equal(run.status, 2, `${run.error || ''}\n${run.stdout}\n${run.stderr}`);
        assert.match(run.stderr,/Scan cancelled/);
        assert.deepEqual(fs.existsSync(out)?fs.readdirSync(out):[],[]);
      } else {
        const { doc } = require('./helpers/incomplete-scan')(run, path.join(out, 'findings.json'));
        assert.deepEqual(fs.readdirSync(out).sort(),['SHA256SUMS','cve-report.html','findings.json']);
        assert.ok(doc.warnings.some(w => w.type === 'scan-reliability' && /Incomplete advisories check for wordpress:.*\(wordfence-v3\).*HTTP 503/.test(w.message)), JSON.stringify(doc.warnings));
        assert.match(fs.readFileSync(path.join(out, 'cve-report.html'), 'utf8'), /incomplete-banner/);
      }
    });
  }
}

for (const strict of [false, true]) test(`CLI Packagist 503 cancels publication, strict=${strict}`, t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-packagist-outage-'));
  t.after(() => fs.rmSync(dir, {recursive:true,force:true}));
  const src = path.join(dir,'source'); fs.mkdirSync(src);
  fs.writeFileSync(path.join(src,'composer.json'), JSON.stringify({require:{'monolog/monolog':'1.0.0'}}));
  fs.writeFileSync(path.join(src,'composer.lock'), JSON.stringify({packages:[{name:'monolog/monolog',version:'1.0.0'}]}));
  const hook = path.join(dir,'fixture.cjs');
  fs.writeFileSync(hook, `require('node:os').homedir=()=>__dirname;
    globalThis.fetch=async()=>Response.json({error:'Unavailable'},{status:503});`);
  const out = path.join(dir,'report');
  const args = ['--require',hook,path.join(__dirname,'../vigievuln.js'),'scan',src,'--ecosystem','composer',
    '-d','osv,nvd,eol,epss,kev,euvd,certfr,retire,transitive,all-libs',
    '--retries','0','--report-html','--report-json','-o',out];
  if(strict) args.push('--fail-on-incomplete','sources');
  const run=spawnSync(process.execPath,args,{cwd:dir,env:{PATH:process.env.PATH,FORCE_COLOR:'0'},encoding:'utf8',timeout:30000});
  // OSV is disabled (-d osv) and every other source answers 503: no advisory source
  // assessed the only package, so the scan is still cancelled with or without the gate.
  assert.equal(run.status,2,run.stdout+run.stderr);
  assert.match(run.stderr,/Scan cancelled/);
  assert.match(run.stderr,/Advisory discovery is incomplete for 1 package\/version\(s\)[\s\S]*monolog\/monolog@1\.0\.0 — OSV \+ a second advisory source/);
  // The cancellation names the decisive gap first; the Packagist outage is named in the scan issues too.
  assert.match(run.stdout+run.stderr,/Packagist.*503/i);
  assert.deepEqual(fs.existsSync(out)?fs.readdirSync(out):[],[]);
});
