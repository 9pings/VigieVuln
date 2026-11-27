'use strict';

const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {Unzip,UnzipInflate}=require('fflate');

async function prepareSource(input) {
 const absolute=path.resolve(input),stat=await fs.promises.stat(absolute);
 if(stat.isDirectory())return {root:absolute,name:path.basename(absolute)||absolute,cleanup:async()=>{}};
 if(!stat.isFile() || !/\.zip$/i.test(absolute))throw Error('scan expects a source directory, project ZIP or dependency descriptor JSON');
 const root=await fs.promises.mkdtemp(path.join(os.tmpdir(),'vigievuln-source-'));
 const cleanup=()=>fs.promises.rm(root,{recursive:true,force:true});
 let entries=0,bytes=0,failure;
 const seen=new Set();
 const unzip=new Unzip(file=>{
  try {
   if(++entries>1000000)throw Error('Source ZIP contains too many entries');
   const name=file.name;
   if(name.includes('\0') || name.includes('\\') || name.startsWith('/') || /^[A-Za-z]:/.test(name) || name.split('/').includes('..'))
    throw Error('Unsafe source ZIP path');
   const parts=name.split('/').filter(p=>p && p!=='.');
   if(parts.length>256)throw Error('Source ZIP path is too deep');
   const relative=parts.join('/');
   if(!relative)return;
   if(seen.has(relative))throw Error('Duplicate source ZIP entry');
   seen.add(relative);
   const output=path.join(root,...parts);
   if(name.endsWith('/')){fs.mkdirSync(output,{recursive:true});file.ondata=error=>{if(error)failure=error;};file.start();return;}
   fs.mkdirSync(path.dirname(output),{recursive:true});
   fs.writeFileSync(output,'',{flag:'wx',mode:0o600});
   file.ondata=(error,data)=>{
    if(failure)return;
    try{
     if(error)throw error;
     bytes+=data.length;
     if(bytes>20*1024**3)throw Error('Source ZIP exceeds extracted size limit');
     fs.appendFileSync(output,data);
    }catch(error){failure=error;file.terminate();}
   };
   file.start();
  }catch(error){failure=error;file.terminate();}
 });
 unzip.register(UnzipInflate);
 try {
  for await(const chunk of fs.createReadStream(absolute)){
   unzip.push(chunk);
   if(failure)throw failure;
  }
  unzip.push(new Uint8Array(),true);
  if(failure)throw failure;
  if(!seen.size)throw Error('Source ZIP is empty');
  const children=await fs.promises.readdir(root,{withFileTypes:true});
  const source=children.length===1 && children[0].isDirectory()?path.join(root,children[0].name):root;
  return {root:source,name:path.basename(absolute),archive:absolute,cleanup};
 }catch(error){await cleanup();throw error;}
}
module.exports={prepareSource};
