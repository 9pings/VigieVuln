'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {getCacheDir,getProxyCacheDir} = require('../lib/cache-directory');

function home(t) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vigie-migration-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  return dir;
}
test('legacy cache and config move together and are visible to the CLI', t=>{
  const dir=home(t), old=path.join(dir,'.fad-checker'), dest=path.join(dir,'.vigie-vuln');
  fs.mkdirSync(old); fs.writeFileSync(path.join(old,'config.json'),JSON.stringify({proxyCache:'default'}));
  fs.writeFileSync(path.join(old,'kev-cache.json'),'legacy');
  const result=spawnSync(process.execPath,[path.join(__dirname,'../vigievuln.js'),'--show-config'],{
    env:{...process.env,HOME:dir,USERPROFILE:dir,FORCE_COLOR:'0'},encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/default/);
  assert.equal(fs.readFileSync(path.join(dest,'kev-cache.json'),'utf8'),'legacy');assert.equal(fs.existsSync(old),false);
});
test('existing new directory always wins and legacy data remains untouched',t=>{
  const dir=home(t),old=path.join(dir,'.fad-checker'),dest=path.join(dir,'.vigie-vuln');
  fs.mkdirSync(old);fs.mkdirSync(dest);fs.writeFileSync(path.join(old,'only-old'),'old');fs.writeFileSync(path.join(dest,'only-new'),'new');
  assert.equal(getCacheDir({homeDir:dir}),dest);
  assert.deepEqual(fs.readdirSync(old),['only-old']);assert.deepEqual(fs.readdirSync(dest),['only-new']);
});
test('failed rename preserves legacy and creates an empty new cache',t=>{
  const dir=home(t),old=path.join(dir,'.fad-checker'),dest=path.join(dir,'.vigie-vuln');
  fs.mkdirSync(old);fs.writeFileSync(path.join(old,'config.json'),'private');
  const impl={...fs,renameSync(){throw Object.assign(new Error('denied'),{code:'EACCES'});}};
  const warnings=[];
  assert.equal(getCacheDir({homeDir:dir,fsImpl:impl,platform:'win32',warn:m=>warnings.push(m)}),dest);
  assert.equal(fs.readFileSync(path.join(old,'config.json'),'utf8'),'private');assert.deepEqual(fs.readdirSync(dest),[]);
  assert.equal(warnings.length,1);assert.ok(warnings[0].includes(old));assert.ok(warnings[0].includes(dest));
  assert.match(warnings[0],/back up or move.*then rename/i);assert.doesNotMatch(warnings[0],/private/);
  const marker=path.join(dir,'.vigie-vuln.migration-pending');
  assert.equal(fs.readFileSync(marker,'utf8'),'');
  getCacheDir({homeDir:dir,warn:m=>warnings.push(m)});assert.equal(warnings.length,1);
  const child=spawnSync(process.execPath,['-e',`const {getCacheDir}=require(${JSON.stringify(path.join(__dirname,'../lib/cache-directory'))});getCacheDir({homeDir:process.argv[1]});getCacheDir({homeDir:process.argv[1]});`,dir],{encoding:'utf8'});
  assert.equal(child.status,0,child.stderr);assert.equal((child.stderr.match(/cache migration failed/g)||[]).length,1);
  assert.ok(child.stderr.includes(old));assert.ok(child.stderr.includes(marker));assert.doesNotMatch(child.stderr,/private/);
});
test('symbolic links are never migrated or followed as cache roots',t=>{
  const dir=home(t), outside=path.join(dir,'outside'),old=path.join(dir,'.fad-checker'),dest=path.join(dir,'.vigie-vuln');
  fs.mkdirSync(outside);fs.writeFileSync(path.join(outside,'keep'),'safe');
  try {fs.symlinkSync(outside,old,'dir');} catch(error) {if(['EPERM','EACCES','ENOSYS'].includes(error.code))return t.skip('symlink unavailable');throw error;}
  const warnings=[];
  assert.equal(getCacheDir({homeDir:dir,warn:m=>warnings.push(m)}),dest);assert.deepEqual(fs.readdirSync(dest),[]);
  assert.match(warnings[0],/not a regular directory.*manual recovery/);
  fs.rmdirSync(dest);fs.symlinkSync(outside,dest,'dir');
  assert.throws(()=>getCacheDir({homeDir:dir}),/symbolic link/);
  assert.equal(fs.readFileSync(path.join(outside,'keep'),'utf8'),'safe');
});
test('separate proxy cache migrates independently and never merges with an existing new cache',t=>{
  const dir=home(t), old=path.join(dir,'.fad-checker-proxy-cache'), dest=path.join(dir,'.vigie-vuln-proxy-cache');
  fs.mkdirSync(old);fs.writeFileSync(path.join(old,'data'),'proxy');
  assert.equal(getProxyCacheDir({homeDir:dir}),dest);
  if(process.platform==='linux' || process.platform==='win32' || process.platform==='darwin') {
    assert.equal(fs.readFileSync(path.join(dest,'data'),'utf8'),'proxy');
    fs.mkdirSync(old);fs.writeFileSync(path.join(old,'other'),'untouched');
  }
  assert.equal(getProxyCacheDir({homeDir:dir}),dest);
  assert.equal(fs.readFileSync(path.join(old,process.platform==='linux'||process.platform==='win32'||process.platform==='darwin'?'other':'data'),'utf8'),process.platform==='linux'||process.platform==='win32'||process.platform==='darwin'?'untouched':'proxy');
});
test('macOS invokes exclusive rename and preserves legacy on failure',t=>{
  const dir=home(t),old=path.join(dir,'.fad-checker'),dest=path.join(dir,'.vigie-vuln');
  fs.mkdirSync(old);fs.writeFileSync(path.join(old,'old'),'old');
  let invoked=false;
  const spawn=(exe,args)=>{invoked=true;assert.equal(exe,'/usr/bin/perl');assert.match(args[1],/syscall\(488, -2.*4\)/);assert.deepEqual(args.slice(2),[old,dest]);return {status:1};};
  assert.equal(getCacheDir({homeDir:dir,platform:'darwin',spawn}),dest);
  assert.equal(invoked,true);assert.equal(fs.readFileSync(path.join(old,'old'),'utf8'),'old');assert.deepEqual(fs.readdirSync(dest),[]);
});

test('a destination created during migration is never overwritten',t=>{
  const dir=home(t),old=path.join(dir,'.fad-checker'),dest=path.join(dir,'.vigie-vuln');
  fs.mkdirSync(old);fs.writeFileSync(path.join(old,'old'),'old');
  const spawn=(cmd,args,options)=>{fs.mkdirSync(dest);fs.writeFileSync(path.join(dest,'new'),'new');return spawnSync(cmd,args,options);};
  assert.equal(getCacheDir({homeDir:dir,platform:'linux',spawn}),dest);
  assert.equal(fs.readFileSync(path.join(dest,'new'),'utf8'),'new');
  assert.equal(fs.readFileSync(path.join(old,'old'),'utf8'),'old');
});

for(const platform of ['linux','win32']) test(`failed proxy migration warns and persists a marker (${platform})`,t=>{
  const dir=home(t),old=path.join(dir,'.fad-checker-proxy-cache'),dest=path.join(dir,'.vigie-vuln-proxy-cache');
  fs.mkdirSync(old);fs.writeFileSync(path.join(old,'secret'),'do-not-print');
  const warnings=[];
  const fsImpl={...fs,renameSync(){throw Error('not available');}};
  const spawn=()=>({status:1});
  assert.equal(getProxyCacheDir({homeDir:dir,platform,fsImpl,spawn,warn:m=>warnings.push(m)}),dest);
  assert.equal(warnings.length,1);assert.ok(warnings[0].includes(old));assert.ok(warnings[0].includes(dest));
  assert.doesNotMatch(warnings[0],/do-not-print/);
  assert.equal(fs.readFileSync(path.join(dir,'.vigie-vuln-proxy-cache.migration-pending'),'utf8'),'');
  assert.equal(fs.readFileSync(path.join(old,'secret'),'utf8'),'do-not-print');
});

test('marker creation failure still warns without blocking a fresh cache',t=>{
  const dir=home(t),old=path.join(dir,'.fad-checker');fs.mkdirSync(old);
  const warnings=[];
  const fsImpl={...fs,renameSync(){throw Error('rename failed');},writeFileSync(){throw Error('marker failed');}};
  assert.equal(getCacheDir({homeDir:dir,platform:'win32',fsImpl,warn:m=>warnings.push(m)}),path.join(dir,'.vigie-vuln'));
  assert.equal(warnings.length,1);assert.match(warnings[0],/cache migration failed/);
  assert.ok(fs.existsSync(old));
});

test('a reminder remains visible if the old cache cannot be inspected',t=>{
  const dir=home(t),old=path.join(dir,'.fad-checker'),dest=path.join(dir,'.vigie-vuln');
  fs.mkdirSync(dest);fs.writeFileSync(path.join(dir,'.vigie-vuln.migration-pending'),'');
  const fsImpl={...fs,lstatSync(file){if(file===old)throw Object.assign(new Error('denied'),{code:'EACCES'});return fs.lstatSync(file);}};
  const warnings=[];
  assert.equal(getCacheDir({homeDir:dir,fsImpl,warn:m=>warnings.push(m)}),dest);
  assert.equal(warnings.length,1);assert.match(warnings[0],/manual recovery/);
});
