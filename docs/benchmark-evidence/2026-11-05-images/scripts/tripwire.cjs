'use strict';
// Preload in the scanner process. Fail the process if a prohibited call is
// attempted even when scanner error handling catches the exception.
const fs=require('node:fs');
const state={networkAttempts:0,subprocessAttempts:0};
function blocked(kind){state[kind]++;throw Error('benchmark tripwire: '+kind);}
const cp=require('node:child_process');
for(const method of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[method]=()=>blocked('subprocessAttempts');
if(process.env.VV_BENCH_OFFLINE==='1'){
 globalThis.fetch=()=>blocked('networkAttempts');
 for(const protocol of ['node:http','node:https'])for(const method of ['request','get'])require(protocol)[method]=()=>blocked('networkAttempts');
 require('node:net').Socket.prototype.connect=()=>blocked('networkAttempts');
}
process.on('exit',()=>{
 if(process.env.VV_BENCH_TRIPWIRE)fs.writeFileSync(process.env.VV_BENCH_TRIPWIRE,JSON.stringify(state));
 if(state.networkAttempts||state.subprocessAttempts)process.exitCode=99;
});
