'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {getCacheDir,getProxyCacheDir}=require('../lib/cache-directory');
const {prepareDirectCache,prepareServeCache}=require('../lib/cache-startup');

function home(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vigie-cache-location-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return dir}

test('cache directory lookup never migrates a legacy directory',t=>{
 const dir=home(t),old=path.join(dir,'.fad-checker'),current=path.join(dir,'.vigie-vuln');
 fs.mkdirSync(old);fs.writeFileSync(path.join(old,'cache.json'),'old');
 assert.equal(getCacheDir({homeDir:dir}),current);
 assert.equal(fs.existsSync(current),false);
 assert.equal(fs.readFileSync(path.join(old,'cache.json'),'utf8'),'old');
});

test('startup removes legacy cache files and copies only the old config when needed',t=>{
 const dir=home(t),old=path.join(dir,'.fad-checker'),current=path.join(dir,'.vigie-vuln');
 fs.mkdirSync(old);fs.writeFileSync(path.join(old,'config.json'),'private key');
 fs.writeFileSync(path.join(old,'cache.json'),'old');
 prepareDirectCache({homeDir:dir});
 assert.equal(fs.readFileSync(path.join(current,'config.json'),'utf8'),'private key');
 assert.equal(fs.existsSync(path.join(current,'cache.json')),false);
 assert.equal(fs.existsSync(old),false);
});

test('startup purges the separate proxy cache without migrating its old contents',t=>{
 const dir=home(t),old=path.join(dir,'.fad-checker-proxy-cache'),current=path.join(dir,'.vigie-vuln-proxy-cache');
 fs.mkdirSync(old);fs.mkdirSync(current);
 fs.writeFileSync(path.join(old,'old.json'),'old');fs.writeFileSync(path.join(current,'current.json'),'current');
 assert.equal(getProxyCacheDir({homeDir:dir}),current);
 prepareServeCache({homeDir:dir});
 assert.equal(fs.existsSync(old),false);assert.deepEqual(fs.readdirSync(current),[]);
});

test('symbolic links cannot be cache roots',t=>{
 const dir=home(t),outside=path.join(dir,'outside');fs.mkdirSync(outside);
 try{fs.symlinkSync(outside,path.join(dir,'.vigie-vuln'),'dir')}
 catch(error){if(['EPERM','EACCES','ENOSYS'].includes(error.code))return t.skip('symlink unavailable');throw error}
 assert.throws(()=>getCacheDir({homeDir:dir}),/unsafe VigieVuln cache directory/);
 assert.throws(()=>prepareDirectCache({homeDir:dir}),/unsafe cache directory/);
});
