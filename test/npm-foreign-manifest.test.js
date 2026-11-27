const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const {isClibManifest}=require('../lib/codecs/npm/manifest-kind');
const {parsePackageJson}=require('../lib/codecs/npm/parse');
const {collectNpmDeps}=require('../lib/codecs/npm/collect');
const {createDiscoveryCoverage}=require('../lib/scan-reliability');
const clib={name:'sha256',version:'0.0.2',repo:'jb55/sha256.c',src:['sha256.c','sha256.h'],
 dependencies:{'jb55/rotate-bits.h':'0.1.1'},development:{'thlorenz/tap.c':'*'}};
function tmp(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-clib-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return dir;}

test('legacy clib package.json is not an npm dependency or an npm no-lockfile failure',t=>{
 const dir=tmp(t),file=path.join(dir,'package.json');fs.writeFileSync(file,JSON.stringify(clib));
 assert.equal(parsePackageJson(file).manifestType,'clib');
 const deps=collectNpmDeps(dir);assert.equal(deps.size,0);assert.equal(deps.parsedManifests.length,0);
 assert.equal(deps.warnings.length,1);assert.equal(deps.warnings[0].type,'foreign-manifest');
 assert.equal(deps.warnings[0].severity,'info');assert.equal(deps.warnings[0].items[0].id,'jb55/rotate-bits.h');
 assert.equal(require('../lib/scan-reliability').isBlocking(deps.warnings[0]),false);
 const handler=require('../lib/artifacts/applications').handlers?.find(h=>h.id==='npm');
 assert.ok(handler);assert.deepEqual(handler.parse(JSON.stringify(clib)),[]);
});

test('C source fields alone do not exclude npm native addons, and conflicting lockfiles remain an error',t=>{
 for(const npm of [{...clib,main:'index.js'},{...clib,scripts:{install:'node-gyp rebuild'}},
   {...clib,dependencies:{'@scope/native':'1.2.3'}},{...clib,repo:undefined}])assert.equal(isClibManifest(npm),false);
 const dir=tmp(t);fs.writeFileSync(path.join(dir,'package.json'),JSON.stringify(clib));
 fs.writeFileSync(path.join(dir,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{}}));
 assert.ok(collectNpmDeps(dir).warnings.some(w=>require('../lib/scan-reliability').isBlocking(w)));
});

test('private classification is scoped to ecosystem, target and version; public versions retain required sources',()=>{
 const privateDep={ecosystem:'npm',name:'internal',artifactId:'internal',version:'1.0.0',versions:['1.0.0']};
 const dep={...privateDep,version:'2.0.0',versions:['1.0.0','2.0.0']},coverage=createDiscoveryCoverage(),deps=new Map([['internal',dep]]);
 const options={privateDeps:[privateDep]};
 assert.deepEqual(coverage.publicDependencies(deps,options).get('internal').versions,['2.0.0']);
 const gap=coverage.assess(deps,options);assert.equal(gap.count,1);assert.equal(gap.items[0].id,'internal@2.0.0');
 assert.equal(coverage.assess(new Map([['internal',privateDep]]),options),null);
 assert.ok(coverage.assess(new Map([['image',{...privateDep,artifactTargetId:'image'}]]),options));
 assert.ok(coverage.assess(new Map([['python',{...privateDep,ecosystem:'pypi'}]]),options));
 assert.deepEqual(dep.versions,['1.0.0','2.0.0']);
 const maven={ecosystem:'maven',groupId:'internal',artifactId:'library',version:'1.0',versions:['1.0','2.0']};
 assert.equal(coverage.assess(new Map([['maven',maven]]),{privateMavenIds:['internal:library']}),null);
 assert.equal(coverage.assess(new Map([['maven',maven]]),{privateMavenIds:['internal:library:1.0']}).items[0].id,'internal:library@2.0');
});

for(const status of [404,410,405,429])test(`CLI registry HTTP ${status}: only confirmed absence is private and nonblocking`,t=>{
 const dir=tmp(t),src=path.join(dir,'src'),out=path.join(dir,'out'),hook=path.join(dir,'hook.cjs');fs.mkdirSync(src);
 const name='@internal/fixture';fs.writeFileSync(path.join(src,'package.json'),JSON.stringify({name:'app',dependencies:{[name]:'1.0.0'}}));
 fs.writeFileSync(path.join(src,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{dependencies:{[name]:'1.0.0'}},['node_modules/'+name]:{version:'1.0.0'}}}));
 fs.writeFileSync(hook,`globalThis.fetch=async(url)=>{
   const u=new URL(url);require('node:fs').appendFileSync(__dirname+'/calls',u.hostname+'\\n');
   if(u.hostname==='registry.npmjs.org')return Response.json({}, {status:${status}});
   throw Error('Unexpected source lookup '+u.hostname);
 };`);
 const run=extra=>spawnSync(process.execPath,['--require',hook,path.resolve(__dirname,'../vigievuln.js'),'scan',src,
   '-d','eol,retire,certs','--no-osv-db','--retries','0','-o',out,...extra],
   {cwd:dir,env:{PATH:process.env.PATH,HOME:dir,USERPROFILE:dir,FORCE_COLOR:'0'},encoding:'utf8',timeout:30000});
 const result=run([]);
 if([404,410].includes(status)){
   assert.equal(result.status,0,result.stdout+'\n'+result.stderr);
   let doc=JSON.parse(fs.readFileSync(path.join(out,'findings.json')));
   assert.equal(doc.summary.scanReliable,true);assert.ok(doc.warnings.some(w=>w.type==='private-libs'));
   assert.deepEqual([...new Set(fs.readFileSync(path.join(dir,'calls'),'utf8').trim().split('\n'))],['registry.npmjs.org']);
   const replay=run(['--offline']);assert.equal(replay.status,0,replay.stdout+'\n'+replay.stderr);
   doc=JSON.parse(fs.readFileSync(path.join(out,'findings.json')));assert.ok(doc.warnings.some(w=>w.type==='private-libs'));
   if(status===404){
    const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir:path.join(dir,'.vigie-vuln')});
    store.commit({records:[{source:'osv',fetchedAt:Date.now(),document:{id:'CVE-2025-12345',summary:'Previously recorded advisory',database_specific:{severity:'HIGH'}}}],
      queries:[{source:'osv',ecosystem:'npm',name,version:'1.0.0',ids:['CVE-2025-12345'],complete:true,fetchedAt:Date.now()}]});store.close();
    const known=run(['--offline']);assert.equal(known.status,0,known.stdout+'\n'+known.stderr);
    doc=JSON.parse(fs.readFileSync(path.join(out,'findings.json')));
    assert.ok(doc.cve.some(c=>c.id==='CVE-2025-12345'),'private classification must retain available advisory evidence');
   }
 }else{
   assert.equal(result.status,2,result.stdout+'\n'+result.stderr);
   assert.match(result.stderr,/Scan cancelled/);assert.equal(fs.existsSync(path.join(out,'findings.json')),false);
 }
});
