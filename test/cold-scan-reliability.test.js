'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

test('cold npm scans retain confirmed findings across a partial OSV outage and retry registry failures on the next scan', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(),'vv-cold-scan-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const project = path.join(root,'project'), hook = path.join(root,'hook.cjs');
  fs.mkdirSync(project);
  const dependencies = {widget:'1.0.0'};
  fs.writeFileSync(path.join(project,'package.json'), JSON.stringify({name:'fixture',dependencies}));
  fs.writeFileSync(path.join(project,'package-lock.json'), JSON.stringify({lockfileVersion:3,packages:{
    '':{name:'fixture',dependencies},'node_modules/widget':{version:'1.0.0'},
  }}));
  fs.writeFileSync(hook, `
    const mode=process.env.SCENARIO;
    const published=['CVE-2024-12345','CVE-2024-23456'];
    if(mode==='added') published.push('CVE-2024-34567');
    if(mode==='reverse') published.reverse();
    globalThis.fetch=async (url,init)=>{
      const u=new URL(url);
      if(u.hostname==='registry.npmjs.org') {
        if(mode==='limited') return new Response(null,{status:429,headers:{'retry-after':'3600'}});
        return Response.json({name:'widget',versions:{'1.0.0':{deprecated:'end of support'}},'dist-tags':{latest:'1.0.0'}});
      }
      if(u.hostname==='api.osv.dev') {
        if(u.pathname.endsWith('/querybatch')) return Response.json({results:JSON.parse(init.body).queries.map(()=>({vulns:published.map(id=>({id}))}))});
        const id=u.pathname.split('/').pop();
        if(mode==='partial' && id==='CVE-2024-23456') return new Response(null,{status:503});
        return Response.json({id,summary:'Example '+id,database_specific:{severity:'HIGH'}});
      }
      if(mode==='nvd-down' && u.hostname==='services.nvd.nist.gov'){
        console.error('NVD fixture returned HTTP 429');
        return new Response(null,{status:429});
      }
      throw Error('Unexpected URL '+u.hostname);
    };
  `);
  function run(mode, homeName=mode, extra=[]) {
    const home=path.join(root,homeName), out=path.join(home,'out');
    fs.mkdirSync(home,{recursive:true});
    // The offline native source has an authoritative, independently timestamped package lookup.
    const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir:path.join(home,'.vigie-vuln')});
    store.commit({queries:[{source:'cveproject',ecosystem:'npm',name:'widget',version:'*',ids:[],complete:true,fetchedAt:Date.now()}]});
    store.close();
    const flags=['--require',hook,path.resolve(__dirname,'../vigievuln.js'),'scan',project,'--ecosystem','npm',
      '-d',(mode==='nvd-down'?'':'nvd,')+'euvd,eol,epss,kev,certfr,retire,transitive,all-libs,gcve,nvd-mirror','--cve-offline','--no-osv-db',
      '--no-binaries','--no-certs','--retries',mode==='limited'?'1':'0','--report-json','-o',out,...extra];
    const proc=spawnSync(process.execPath,flags,{cwd:home,env:{HOME:home,USERPROFILE:home,PATH:process.env.PATH,SCENARIO:mode},encoding:'utf8',timeout:20000});
    assert.ifError(proc.error);
    const file=path.join(out,'findings.json');
    return {code:proc.status,log:proc.stdout+proc.stderr,report:fs.existsSync(file)?JSON.parse(fs.readFileSync(file)):null};
  }
  const strict=['--fail-on-incomplete','sources'];
  const first=run('ok','cold-a',strict), second=run('reverse','cold-b',strict);
  assert.equal(first.code,0,first.log);
  assert.equal(second.code,0,second.log);
  assert.deepEqual(first.report.cve,second.report.cve);
  assert.deepEqual(first.report.cve.map(c=>c.id),['CVE-2024-12345','CVE-2024-23456']);
  const oneRecord=run('nvd-down','single-record',strict);
  assert.match(oneRecord.log,/NVD fixture returned HTTP 429/);
  assert.equal(oneRecord.code,0,oneRecord.log);
  assert.deepEqual(oneRecord.report.cve.map(f=>f.id),first.report.cve.map(f=>f.id));
  const added=run('added');
  assert.deepEqual(added.report.cve.filter(c=>c.id!=='CVE-2024-34567'),first.report.cve);
  assert.equal(added.report.cve.length,3);
  const baseline = path.join(root,'cold-a','out','findings.json');
  const compared = run('added','baseline-check',['--baseline',baseline,'--fail-on-new',...strict]);
  assert.equal(compared.code,1,compared.log);
  assert.deepEqual(compared.report.diff.cve.added.map(c=>c.id),['CVE-2024-34567']);
  const partial=run('partial','partial',['--fail-on','high','--report-html','--report-xlsx','--report-doc','--report-sbom','--report-csaf','--report-sarif']);
  const rejected=path.join(root,'partial','out');
  assert.deepEqual(fs.existsSync(rejected)?fs.readdirSync(rejected):[],[]);
  assert.equal(partial.code,2,partial.log);
  assert.equal(partial.report,null);
  assert.match(partial.log,/Scan cancelled/);
  assert.doesNotMatch(partial.log,/▸ Results/);
  assert.equal(run('partial','partial-strict',strict).code,2);
  const limited=run('limited','retry',strict);
  assert.equal(limited.code,2,limited.log);
  assert.match(limited.log,/npm registry.*HTTP 429.*3600s.*budget/);
  assert.equal(limited.report,null);
  const recovered=run('ok','retry',strict);
  assert.equal(recovered.code,0,recovered.log);
  assert.deepEqual(recovered.report.obsolete,first.report.obsolete);
  assert.equal(recovered.report.obsolete.length,1);
});
