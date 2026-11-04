'use strict';

const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');

const root=path.resolve(__dirname,'..');
const home=fs.mkdtempSync(path.join(os.tmpdir(),'vigievuln-test-home-'));
const files=fs.readdirSync(path.join(root,'test')).filter(name=>name.endsWith('.test.js')).sort().map(name=>path.join(root,'test',name));
try{
 const result=spawnSync(process.execPath,['--test','--test-concurrency=1',...files],{
  cwd:root,env:{...process.env,HOME:home,USERPROFILE:home},stdio:'inherit',
 });
 if(result.error)throw result.error;
 process.exitCode=result.status??1;
}finally{fs.rmSync(home,{recursive:true,force:true})}
