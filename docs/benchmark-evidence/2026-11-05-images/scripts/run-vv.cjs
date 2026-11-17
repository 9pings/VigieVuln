'use strict';
// Run after run-comparators.sh. Isolated client homes, image archives unchanged.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../../../..');
const base=process.argv[2]||'/tmp/vv-image-benchmark-20261105';
const cli=path.join(root,'vigievuln.js'),guard=path.join(__dirname,'tripwire.cjs');
const commands=[];
function run(project,label,args,{home,offline=false}={}){
 const dir=path.join(base,project);fs.mkdirSync(home,{recursive:true});
 const wire=path.join(dir,label+'.tripwire.json'),log=path.join(dir,label+'.log');
 const start=Date.now();
 const env={...process.env,HOME:home,USERPROFILE:home,PATH:'/nonexistent',VV_BENCH_OFFLINE:offline?'1':'0',VV_BENCH_TRIPWIRE:wire};
 // These subprocesses intentionally use isolated config rather than inherited service credentials.
 for(const k of Object.keys(env))if(/^(?:FAD|VIGIEVULN)_/.test(k))delete env[k];
 const result=cp.spawnSync(process.execPath,['--require',guard,cli,...args],{cwd:root,env,encoding:'utf8',maxBuffer:16*1024*1024,timeout:300000});
 fs.writeFileSync(log,(result.stdout||'')+(result.stderr||''));
 const tripwire=fs.existsSync(wire)?JSON.parse(fs.readFileSync(wire)):null;
 commands.push({project,label,command:[process.execPath,'--require',guard,cli,...args],exitCode:result.status,durationMs:Date.now()-start,offline,tripwire,
  logSha256:crypto.createHash('sha256').update(fs.readFileSync(log)).digest('hex')});
 if(result.status!==0)throw Error(label+' failed: '+(result.stderr||result.error));
 assert.deepEqual(tripwire,{networkAttempts:0,subprocessAttempts:0});
}
function tuples(report){return report.cve.map(v=>JSON.stringify([v.dep.ecosystem,v.dep.coord,v.dep.version,v.id,[...(v.aliases||[])].sort(),[...(v.upstream||[])].sort(),v.severity,v.kev,v.epss,v.epssPercentile])).sort();}
const equality=[];
for(const project of ['traefik','nginx']){
 const dir=path.join(base,project),onlineHome=path.join(dir,'direct-home'),offlineHome=path.join(dir,'airgap-home');
 const cache=path.join(dir,'direct-cache'),offlineCache=path.join(dir,'airgap-cache'),bundle=path.join(dir,'airgap-cache.tar.gz');
 run(project,'vv-final',['image',path.join(dir,'oci'),'--cache-dir',cache,'--export-inventory',path.join(dir,'inventory.json'),'--report-output',path.join(dir,'vv-final'),'--lang','fr'],{home:onlineHome});
 run(project,'cache-export',['cache','export',bundle,'--cache-dir',cache],{home:onlineHome,offline:true});
 run(project,'cache-import',['cache','import',bundle,'--cache-dir',offlineCache],{home:offlineHome,offline:true});
 run(project,'vv-airgap',['image',path.join(dir,'inventory.json'),'--inventory','--offline','--cache-dir',offlineCache,'--report-output',path.join(dir,'vv-airgap'),'--lang','fr'],{home:offlineHome,offline:true});
 const a=JSON.parse(fs.readFileSync(path.join(dir,'vv-final/findings.json'))),b=JSON.parse(fs.readFileSync(path.join(dir,'vv-airgap/findings.json')));
 assert.deepEqual(tuples(a),tuples(b));
 equality.push({project,components:a.artifacts[0].componentCount,findings:a.cve.length,tupleCount:tuples(a).length,equal:true,
  networkAttempts:0,subprocessAttempts:0,tupleSha256:crypto.createHash('sha256').update(JSON.stringify(tuples(a))).digest('hex')});
}
fs.writeFileSync(path.resolve(__dirname,'../vv-pathways.json'),JSON.stringify({generatedAt:new Date().toISOString(),commands,equality},null,2)+'\n');
console.log(JSON.stringify(equality));
