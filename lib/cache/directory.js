'use strict';

const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');

// Cache locations never migrate data from pre-1.2 directories. Startup disposes
// of legacy files while retaining configuration and account sessions.
let activeCacheDir=null;
function directory(name,{homeDir=os.homedir()}={}){
 const root=path.join(homeDir,name);
 try{
  const stat=fs.lstatSync(root);
  if(!stat.isDirectory()||stat.isSymbolicLink())throw Error('unsafe VigieVuln cache directory');
 }catch(error){if(error.code!=='ENOENT')throw error}
 return root;
}
const getCacheDir=options=>activeCacheDir||directory('.vigie-vuln',options);
const getProxyCacheDir=options=>directory('.vigie-vuln-proxy-cache',options);
const setActiveCacheDir=value=>{activeCacheDir=value};
module.exports={getCacheDir,getProxyCacheDir,setActiveCacheDir};
