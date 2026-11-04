const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {proxyScope}=require('../lib/proxy-scope');

test('archive CLI uses the configured proxy scope and rejects unmarked or other-origin bundles', t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-scope-archive-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const hook=path.join(dir,'hook.cjs'); fs.writeFileSync(hook,`require('node:os').homedir=()=>${JSON.stringify(dir)};`);
 const origin='https://proxy.example'; const scope=proxyScope(origin,{homeDir:dir});
 const openStore=require('../lib/advisory-store').openAdvisoryStore;
 const record={source:'osv',document:{id:'GHSA-fixture',affected:[]},fetchedAt:Date.now()};
 const seeded=openStore({cacheDir:scope});seeded.commit({records:[record]});seeded.close();
 const global=path.join(dir,'.vigie-vuln'); fs.mkdirSync(global,{recursive:true});
 fs.writeFileSync(path.join(global,'config.json'),JSON.stringify({sourceProfile:'proxy',proxyCache:origin}));
 fs.writeFileSync(path.join(global,'global-only.json'),'{}');
 const run=(...args)=>spawnSync(process.execPath,['--require',hook,path.join(__dirname,'../vigievuln.js'),...args],{encoding:'utf8',env:{PATH:process.env.PATH,FORCE_COLOR:'0'}});
 const bundle=path.join(dir,'scoped.tar.gz'); let r=run('--export-cache',bundle); assert.equal(r.status,0,r.stderr);
 fs.rmSync(path.join(scope,'cache.sqlite'),{force:true}); r=run('--import-cache',bundle); assert.equal(r.status,0,r.stderr);
 {const store=openStore({cacheDir:scope});assert.equal(store.getRecord('osv','GHSA-fixture').document.id,'GHSA-fixture');store.close()}
 assert.equal(fs.existsSync(path.join(scope,'global-only.json')),false);
 if (process.platform !== 'win32') {
  const zip=path.join(dir,'scoped.zip'); r=run('--export-cache',zip); assert.equal(r.status,0,r.stderr);
  fs.rmSync(path.join(scope,'cache.sqlite'),{force:true}); r=run('--import-cache',zip); assert.equal(r.status,0,r.stderr);
  {const store=openStore({cacheDir:scope});assert.equal(store.getRecord('osv','GHSA-fixture').document.id,'GHSA-fixture');store.close()}
 }
 const plain=path.join(dir,'plain.tar.gz'); r=run('--source-profile','all','--export-cache',plain); assert.equal(r.status,0,r.stderr);
 r=run('--import-cache',plain); assert.notEqual(r.status,0); assert.match(r.stderr,/origin mismatch|origin marker|ENOENT/);
 r=run('--proxy-cache','https://other.example','--import-cache',bundle); assert.notEqual(r.status,0); assert.match(r.stderr,/origin mismatch/);
 const routed=path.join(dir,'routed.tar.gz');
 r=run('cache','export',routed,'--source-profile','proxy','--proxy-cache',origin); assert.equal(r.status,0,r.stderr);
 r=run('cache','import',routed,'--source-profile','proxy','--proxy-cache',origin); assert.equal(r.status,0,r.stderr);
 r=run('cache','import',routed,'--source-profile','proxy','--proxy-cache','https://other.example'); assert.notEqual(r.status,0); assert.match(r.stderr,/origin mismatch/);
 const explicitConfig=path.join(dir,'selected.json'); fs.writeFileSync(explicitConfig,JSON.stringify({sourceProfile:'proxy',proxyCache:origin}));
 r=run('cache','import',routed,'--config',explicitConfig); assert.equal(r.status,0,r.stderr);
});

test('removing the sole configured proxy fails closed until the source mode is changed explicitly', t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-unset-proxy-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const hook=path.join(dir,'hook.cjs'); fs.writeFileSync(hook,`require('node:os').homedir=()=>${JSON.stringify(dir)};`);
 const configDir=path.join(dir,'.vigie-vuln'); fs.mkdirSync(configDir);
 const file=path.join(configDir,'config.json'); const before={sourceProfile:'proxy',proxyCache:'https://proxy.example'};
 fs.writeFileSync(file,JSON.stringify(before));
 const run=(...args)=>spawnSync(process.execPath,['--require',hook,path.join(__dirname,'../vigievuln.js'),...args],{encoding:'utf8',env:{PATH:process.env.PATH,FORCE_COLOR:'0'}});
 let result=run('--unset-proxy-cache'); assert.equal(result.status,2); assert.match(result.stderr,/setup --mode direct/);
 assert.deepEqual(JSON.parse(fs.readFileSync(file,'utf8')),before);
 result=run('setup','--mode','direct','--sources','all'); assert.equal(result.status,0,result.stderr);
 const after=JSON.parse(fs.readFileSync(file,'utf8')); assert.equal(after.sourceProfile,'all'); assert.equal(after.proxyCache,undefined);
 result=run('--unset-proxy-cache'); assert.equal(result.status,0,result.stderr);
});

test('explicit --no-osv-db overrides a configured group even with the EU source profile', t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-group-layer-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const hook=path.join(dir,'hook.cjs'); fs.writeFileSync(hook,`require('node:os').homedir=()=>${JSON.stringify(dir)};globalThis.fetch=()=>{throw Error('network forbidden')};`);
 const config=path.join(dir,'selected.json'); fs.writeFileSync(config,JSON.stringify({activate:'osv-db'}));
 const project=path.join(dir,'project');fs.mkdirSync(project);
 fs.writeFileSync(path.join(project,'package.json'),JSON.stringify({name:'fixture',version:'1.0.0'}));
 const r=spawnSync(process.execPath,['--require',hook,path.join(__dirname,'../vigievuln.js'),'scan',project,'--config',config,'--offline','--source-profile','eu','--no-osv-db','-d','report'],{encoding:'utf8',env:{PATH:process.env.PATH,FORCE_COLOR:'0'},timeout:30000});
 assert.equal(r.status,0,r.stderr+r.stdout);
});
