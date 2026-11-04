'use strict';

const fs=require('node:fs');
const path=require('node:path');
const {createCacheRepository}=require('../cache-repository');

function slot(file){
 const dir=path.dirname(file);
 return {root:path.basename(dir)==='advisory-snapshots'?path.dirname(dir):dir,key:path.basename(file)};
}
function cached(file){
 const {root,key}=slot(file);
 try{return createCacheRepository(root).get('application-snapshot',key)}catch{return null}
}
function exists(file){return !!cached(file)||fs.existsSync(file)}
function read(file,{preferCache=false}={}){
 if(!preferCache&&fs.existsSync(file)){const stat=fs.statSync(file);return {bytes:fs.readFileSync(file),stat}}
 const entry=cached(file);
 if(entry){const bytes=Buffer.from(JSON.stringify(entry.value));return {bytes,stat:{size:bytes.length,mtimeMs:entry.fetchedAt,mtime:new Date(entry.fetchedAt),isFile:()=>true}}}
 if(fs.existsSync(file)){const stat=fs.statSync(file);return {bytes:fs.readFileSync(file),stat}}
 throw Object.assign(new Error(`ENOENT: no such advisory snapshot: ${file}`),{code:'ENOENT'});
}
function write(file,snapshot){
 const {root,key}=slot(file),stamp=Date.parse(snapshot?._fadSnapshot?.collectedAt);
 createCacheRepository(root).put('application-snapshot',key,snapshot,{fetchedAt:Number.isFinite(stamp)?stamp:Date.now()});
}
module.exports={exists,read,write};
