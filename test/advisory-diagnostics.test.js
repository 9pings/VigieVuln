'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {advisoryEvidenceDiagnostic}=require('../lib/diagnostics');
const {groupReportWarnings}=require('../lib/report-notices');

test('image acquisitions and advisory failures share one warning without swallowing code failures',()=>{
 const values=[{type:'image-scan-failed',message:'registry network request failed',items:[{id:'private.example/app:1',manifestPaths:['compose.yml']}]},
  {type:'source-unavailable',artifactTargetId:'nginx',source:'alpine-tracker',affectsCompleteness:false,message:'HTTP 404',items:[{id:'https://security.alpinelinux.org/srcpkg/demo'}]},
  {type:'source-unavailable',artifactTargetId:'nginx',source:'osv',message:'HTTP 503'},
  {type:'source-unavailable',source:'packagist',message:'HTTP 503'}];
 const groups=groupReportWarnings(values),images=groups.find(w=>w.type==='image-source-unavailable');
 assert.equal(groups.length,2);assert.equal(images.count,2);assert.equal(images.affectsCompleteness,true);
 assert.equal(images.items.length,2);assert.match(images.items[1].resources[0],/srcpkg\/demo/);
 assert.match(images.items[1].detail,/404/);assert.match(images.items[1].detail,/503/);
 assert.deepEqual(groupReportWarnings(groups),groups);assert.equal(values[1].items[0].artifactTargetId,undefined);
 assert.equal(groupReportWarnings([values[1]])[0].affectsCompleteness,false);
 const html=require('../lib/cve-report').generateHtmlReport({cveMatches:[],resolvedDeps:new Map(),projectInfo:{name:'fixture'},warnings:values,locale:'fr'});
 assert.equal((html.match(/class="warn-block warn-image-source-unavailable"/g)||[]).length,1);
 assert.match(html,/Indisponible sur les sources publiques/);
});

test('unknown comparisons deduplicate matching passes and cannot certify a resolved baseline',()=>{
 const diagnostic=advisoryEvidenceDiagnostic([{id:'CVE-2024-12345',package:'demo',version:'1.0.0'},{id:'CVE-2024-12345',name:'demo',version:'1.0.0'}]);
 assert.equal(diagnostic.count,1);assert.equal(diagnostic.affectsCompleteness,false);assert.equal(diagnostic.affectsAssessment,true);
 const before={cve:[{id:'CVE-2024-12345',dep:{ecosystem:'npm',coord:'demo',version:'1.0.0'}}]},after={cve:[],provenance:{notices:[diagnostic]}};
 const diff=require('../lib/diff').diffFindings(before,after);
 assert.equal(diff.cve.removed.length,0);assert.equal(diff.cve.unassessed.length,1);
});

test('an Alpine 404 is a published-entry absence, while HTTP 503 remains a failed consultation',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-alpine-absence-'));
 t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true});});
 const inventory={distribution:{id:'alpine',versionId:'3.20'},packages:[{manager:'apk',name:'demo',sourceName:'demo',sourceVersion:'1.0-r0'}]};
 const assess=()=>require('../lib/system-inventory/distribution-sources').assessDistributionSources;
 let result=await assess()(inventory,{cacheDir,fetcher:async()=>new Response('',{status:404})});
 assert.equal(result.coverage[0].execution,'completed');assert.equal(result.coverage[0].notListed,1);assert.equal(result.coverage[0].affectsCompleteness,false);
 assert.equal(result.warnings[0].code,'record-not-listed');assert.equal(result.warnings[0].affectsCompleteness,false);assert.deepEqual(result.matches,[]);
 result=await assess()(inventory,{cacheDir,fetcher:async()=>new Response('',{status:503})});
 assert.equal(result.coverage[0].execution,'partial');assert.notEqual(result.warnings[0].affectsCompleteness,false);
});

test('CLI reports undecidable npm evidence once without an unavailable-source or strict-source failure',t=>{
 const {spawnSync}=require('node:child_process'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-npm-evidence-'));
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const src=path.join(dir,'src');fs.mkdirSync(src);
 fs.writeFileSync(path.join(src,'package.json'),JSON.stringify({name:'fixture',dependencies:{demo:'1.0.0'}}));
 fs.writeFileSync(path.join(src,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{name:'fixture',dependencies:{demo:'1.0.0'}},'node_modules/demo':{version:'1.0.0'}}}));
 const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir:path.join(dir,'.vigie-vuln')});
 const affected=status=>({packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status}]});
 store.commit({records:[require('../lib/native-advisories').cveEnvelope({cveMetadata:{cveId:'CVE-2024-12345',state:'PUBLISHED'},containers:{cna:{affected:[affected('affected')]},adp:[{affected:[affected('unaffected')]}]}},{fetchedAt:Date.now()})]});store.close();
 const hook=path.join(dir,'hook.cjs');fs.writeFileSync(hook,"require('node:os').homedir=()=>__dirname;globalThis.fetch=()=>{throw Error('network forbidden')};");
 const out=path.join(dir,'report');
 const run=spawnSync(process.execPath,['--require',hook,path.resolve('vigievuln.js'),'scan',src,'--offline','--ecosystem','npm','-d','osv,nvd,eol,epss,kev,euvd,certfr,retire,transitive,all-libs,gcve','--no-binaries','--no-certs','--report-json','--fail-on-incomplete','sources','-o',out],{cwd:dir,encoding:'utf8',timeout:20000});
 assert.equal(run.status,2,run.stdout+run.stderr);
 const log=require('./helpers/cancelled-scan')(run,[path.join(out,'findings.json')]);
 assert.match(log,/OSV/);
});
