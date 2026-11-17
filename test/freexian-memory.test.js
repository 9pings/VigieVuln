'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process'),path=require('node:path');
test('one dense multi-megabyte input chunk parses under a 64 MiB V8 heap',()=>{
 const modulePath=path.resolve(__dirname,'../lib/system-inventory/freexian-tracker');
 const program=`const {parseTrackerBytes}=require(${JSON.stringify(modulePath)});(async()=>{const parts=[];for(let i=0;i<90000;i++)parts.push('"p'+i+'":{"CVE-2025-1234":{"releases":{"bullseye":{"status":"open"}}}}');const body=Buffer.from('{'+parts.join(',')+'}');parts.length=0;const r=await parseTrackerBytes(body,{packages:['p1']});if(!r.packages.p1||Object.keys(r.packages).length!==1)throw Error('bad projection');process.stdout.write(String(body.length));})().catch(e=>{console.error(e);process.exitCode=1});`;
 const child=spawnSync(process.execPath,['--max-old-space-size=64','-e',program],{encoding:'utf8',timeout:60000,maxBuffer:1024*1024});
 assert.equal(child.status,0,child.stderr);assert.ok(Number(child.stdout)>4*1024*1024);
});
