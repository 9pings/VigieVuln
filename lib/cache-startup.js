'use strict';

const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
function statOrNull(file){try{return fs.lstatSync(file)}catch(error){if(error.code==='ENOENT')return null;throw error}}

function cleanRoot(root,{keepConfig=false}={}){
 let stat;try{stat=fs.lstatSync(root)}catch(error){if(error.code==='ENOENT')return;throw error}
 if(!stat.isDirectory()||stat.isSymbolicLink())throw Error('unsafe cache directory');
 const keep=new Set(['cache.sqlite','cache.sqlite-wal','cache.sqlite-shm',...(keepConfig?['config.json']:[])]);
 if(keepConfig&&statOrNull(path.join(root,'config.json'))){
  const item=fs.lstatSync(path.join(root,'config.json'));
  if(!item.isFile()||item.isSymbolicLink()||item.nlink!==1)throw Error('unsafe cache configuration');
 }
 for(const name of fs.readdirSync(root))if(!keep.has(name))fs.rmSync(path.join(root,name),{recursive:true,force:true});
}

function prepareDirectCache({homeDir=os.homedir()}={}){
 const current=path.join(homeDir,'.vigie-vuln'),legacy=path.join(homeDir,'.fad-checker');
 const existing=statOrNull(current),old=statOrNull(legacy);
 if(existing){
  const stat=existing;
  if(!stat.isDirectory()||stat.isSymbolicLink())throw Error('unsafe cache directory');
 }
 if(old&&(!old.isDirectory()||old.isSymbolicLink()))throw Error('unsafe legacy cache directory');
 fs.mkdirSync(current,{recursive:true,mode:0o700});
 const config=path.join(current,'config.json'),oldConfig=path.join(legacy,'config.json');
 if(!statOrNull(config)&&statOrNull(oldConfig)){
  const stat=fs.lstatSync(oldConfig);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1)throw Error('unsafe legacy cache configuration');
  fs.copyFileSync(oldConfig,config,fs.constants.COPYFILE_EXCL);fs.chmodSync(config,0o600);
 }
 cleanRoot(current,{keepConfig:true});
 if(old){
  fs.rmSync(legacy,{recursive:true,force:true});
 }
 return current;
}

function prepareScopedCache(root){cleanRoot(root);return root}

function prepareServeCache({homeDir=os.homedir()}={}){
 const current=path.join(homeDir,'.vigie-vuln-proxy-cache'),legacy=path.join(homeDir,'.fad-checker-proxy-cache');
 cleanRoot(current);
 if(fs.existsSync(legacy)){
  const stat=fs.lstatSync(legacy);
  if(!stat.isDirectory()||stat.isSymbolicLink())throw Error('unsafe legacy proxy cache directory');
  fs.rmSync(legacy,{recursive:true,force:true});
 }
 return current;
}

module.exports={cleanRoot,prepareDirectCache,prepareScopedCache,prepareServeCache};
