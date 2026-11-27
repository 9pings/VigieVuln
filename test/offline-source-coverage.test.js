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
 const args = ['--require', hook, path.join(__dirname, '../vigievuln.js'), 'scan', src, '--ecosystem', ecosystem, '--offline', '-d', 'nvd,eol,epss,kev,euvd,certfr,retire,transitive,all-libs,gcve', '--no-binaries', '--no-certs', '--report-json', '-o', output, '--fail-on-incomplete', 'sources'];
 if (ecosystem === 'maven') args.push('--no-osv');
 const run = spawnSync(process.execPath, args, {cwd:dir, env:{PATH:process.env.PATH, FORCE_COLOR:'0'}, encoding:'utf8', timeout:30000});
 assert.equal(run.status, 2, run.stdout + run.stderr);
 assert.match(run.stderr,/Scan cancelled/);
 assert.match(run.stderr,ecosystem==='maven'?/CVEProject/:/OSV/);
 assert.deepEqual(fs.existsSync(output)?fs.readdirSync(output):[],[]);
});

test('Packagist missing package evidence fails the sources gate online and offline', t => {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-packagist-coverage-'));
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const project=path.join(dir,'project');
 fs.mkdirSync(project);
 fs.writeFileSync(path.join(project,'composer.json'),JSON.stringify({require:{'example/widget':'1.0.0'}}));
 fs.writeFileSync(path.join(project,'composer.lock'),JSON.stringify({packages:[{name:'example/widget',version:'1.0.0'}]}));
 const hook=path.join(dir,'fetch.cjs');
 fs.writeFileSync(hook,`globalThis.fetch=async url=>{
   if(url.includes('security-advisories'))return Response.json({advisories:{}});
   return Response.json({package:{name:'example/widget',versions:{'1.0.0':{version:'1.0.0'}}}});
 };`);
 for(const mode of ['online','offline']){
  const home=path.join(dir,mode), out=path.join(home,'report');
  fs.mkdirSync(home);
  const args=['--require',hook,path.resolve(__dirname,'../vigievuln.js'),'scan',project,'--ecosystem','composer',
   '-d','osv,nvd,euvd,eol,epss,kev,certfr,retire,transitive,all-libs,gcve','--cve-offline','--no-binaries','--no-certs',
   '--report-json','-o',out,'--fail-on-incomplete','sources',...(mode==='offline'?['--offline']:[])];
  const run=spawnSync(process.execPath,args,{cwd:home,env:{HOME:home,USERPROFILE:home,PATH:process.env.PATH},encoding:'utf8',timeout:10000});
  assert.equal(run.status,2,run.stdout+run.stderr);
  assert.match(run.stderr,/Packagist.*example\/widget/i);
  assert.deepEqual(fs.existsSync(out)?fs.readdirSync(out):[],[]);
 }
});
