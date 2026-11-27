'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
const {zipSync,strToU8}=require('fflate');
test('classic scan accepts project ZIP and descriptors while retaining air-gapped options',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-scan-inputs-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const cli=path.resolve(__dirname,'../vigievuln.js'),source=path.join(root,'project.zip');
 fs.writeFileSync(source,zipSync({'package-lock.json':strToU8(JSON.stringify({name:'example',lockfileVersion:3,packages:{'':{name:'example',version:'1.0'}}}))}));
 const run=args=>spawnSync(process.execPath,[cli,...args],{cwd:root,env:{HOME:root,USERPROFILE:root,PATH:process.env.PATH},encoding:'utf8',timeout:20000});
 const output=path.join(root,'report');
 const r=run(['scan',source,'--no-gcve','--offline','--no-retire','--no-certs','--no-binaries','-o',output]);
 assert.equal(r.status,0,r.stdout+r.stderr);
 const doc=JSON.parse(fs.readFileSync(path.join(output,'findings.json')));
 assert.equal(doc.project.name,'project.zip');assert.equal(doc.project.src,'project.zip');
 const deps=path.join(root,'deps.json');
 assert.equal(run(['scan',source,'--export-anonymized',deps]).status,0);
 const replay=path.join(root,'descriptor-report');
 const d=run(['scan',deps,'--no-gcve','--offline','--no-retire','-o',replay]);assert.equal(d.status,0,d.stdout+d.stderr);
 assert.ok(fs.existsSync(path.join(replay,'cve-report.html')));
 assert.equal(run(['scan',deps,'--no-gcve','--offline','--export-cache',path.join(root,'cache.tar.gz')]).status,0);
 for(const args of [['image',source],['analyse',deps],['collect','/'],['-s',root],['--src',root],['--source',root]])
  assert.match(run(args).stderr,/removed/);
});
test('source ZIP rejects escaping paths and releases its temporary files',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-zip-input-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const file=path.join(root,'unsafe.zip');fs.writeFileSync(file,zipSync({'../escape':strToU8('x')}));
 await assert.rejects(require('../lib/source-input').prepareSource(file),/Unsafe/);
 assert.equal(fs.existsSync(path.join(root,'escape')),false);
});

test('system scan rejects project descriptors and source scan rejects system inventories',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-json-kind-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const cli=path.resolve(__dirname,'../vigievuln.js'),project=path.join(root,'deps.json'),system=path.join(root,'system.json');
 fs.writeFileSync(project,JSON.stringify({schema:'fad-deps/1',deps:[]}));
 fs.writeFileSync(system,JSON.stringify({schema:'vigievuln-artifact-inventory/1',targets:[]}));
 const run=args=>spawnSync(process.execPath,[cli,...args],{cwd:root,env:{HOME:root,USERPROFILE:root,PATH:process.env.PATH},encoding:'utf8'});
 assert.match(run(['scan',system]).stderr,/system scan/);
 assert.match(run(['system','scan',project]).stderr,/Dependency descriptors use vigievuln scan/);
});
