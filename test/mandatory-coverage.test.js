'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createDiscoveryCoverage,isBlocking}=require('../lib/scan/reliability');
const {summarizeCveRecords}=require('../lib/findings/cve-record-coverage');
const dep={ecosystem:'npm',name:'fixture',artifactId:'fixture',version:'1.0.0',versions:['1.0.0','2.0.0']};
const deps=new Map([['fixture',dep]]);
test('each installed version requires two discovery sources, including OSV, even with zero findings',()=>{
 const coverage=createDiscoveryCoverage();
 coverage.consulted(dep,'osv','1.0.0');
 coverage.consulted(dep,'vigievuln','2.0.0');
 const gap=coverage.assess(deps);
 assert.equal(isBlocking(gap),true);
 assert.deepEqual(gap.items.map(i=>i.missing),[['a second advisory source'],['OSV']]);
 coverage.consulted(dep,'cveproject','1.0.0');
 coverage.consulted(dep,'osv','2.0.0');
 assert.equal(coverage.assess(deps),null);
});
test('a missing exact CVE record blocks by default even with both enrichment providers disabled',()=>{
 const id='CVE-2024-10001',row={source:'osv',cve:{id}};
 const missing=summarizeCveRecords([row],{nvd:false,euvd:false});
 assert.ok(isBlocking(missing.warning));
 assert.equal(missing.coverage.missing,1);
 row.cve.sourceAdvisoryId='GHSA-fixture';
 assert.equal(isBlocking(summarizeCveRecords([row],{nvd:false,euvd:false}).warning),false);
});

test('a required POM on a private Maven mirror retries a temporary 429 and keeps its timeout per attempt',async()=>{
 const {fetchPomFromRepos,createRepoHealth}=require('../lib/providers/maven/repo');
 const {guardedFetch,createSourceHealth}=require('../lib/scan/source-health');
 const waits=[],notices=[],signals=[];
 const fetcher=guardedFetch({health:createSourceHealth(),retries:1,sleep:async ms=>waits.push(ms),onRetry:n=>notices.push(n),
  fetch:async(url,options)=>{signals.push(options.signal);return signals.length===1?
   new Response('',{status:429,headers:{'retry-after':'8'}}):new Response('<project/>');}});
 const result=await fetchPomFromRepos([{url:'https://mirror.invalid/maven/'}],'org.example','lib','1',{fetcher,health:createRepoHealth()});
 assert.equal(result.body,'<project/>');assert.deepEqual(waits,[8000]);assert.equal(notices[0].code,'HTTP 429');
 assert.notEqual(signals[0],signals[1]);
});

test('analyse publishes a host summary with one CVE record; a strict rerun without OSV is cancelled and preserves the previous reports, a default rerun publishes an incomplete report',async t=>{
 const fs=require('node:fs'), os=require('node:os'), path=require('node:path'), {spawnSync}=require('node:child_process');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-publish-host-'));t.after(()=>{require('../lib/cache/db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const root=path.join(dir,'root'), cacheDir=path.join(dir,'cache'), out=path.join(dir,'out'), input=path.join(dir,'inventory.json');
 fs.mkdirSync(path.join(root,'etc'),{recursive:true});fs.writeFileSync(path.join(root,'etc/os-release'),'ID=debian\nVERSION_ID=12\n');
 fs.mkdirSync(path.join(root,'var/lib/dpkg'),{recursive:true});
 fs.writeFileSync(path.join(root,'var/lib/dpkg/status'),'Package: fixture\nStatus: install ok installed\nVersion: 1.0-1\nArchitecture: amd64\nSource: fixture (1.0-1)\n');
 const {acquireInventories,createSnapshot}=require('../lib/artifacts/scan');
 const targets=await acquireInventories(root,{offline:true});
 targets[0].metadata.systemApplications={applications:[],inventory:[],relations:[]};
 fs.writeFileSync(input,JSON.stringify(createSnapshot(targets)));
 const cve='CVE-2024-12345';
 await require('../lib/system-inventory').importSystemAdvisories([{id:cve,summary:'Example advisory',affected:[{package:{ecosystem:'Debian:12',name:'fixture'},versions:['1.0-1']}]}],
  {distribution:targets[0].distribution,cacheDir,complete:true});
 const store=require('../lib/advisories/store').openAdvisoryStore({cacheDir});
 store.commit({queries:['system:deb:debian:12','system:deb:debian:*'].map(ecosystem=>({source:'cveproject',ecosystem,name:'fixture',version:'*',ids:[],complete:true,fetchedAt:Date.now()}))});store.close();
 const run=(extra=[])=>spawnSync(process.execPath,[path.resolve(__dirname,'../vigievuln.js'),'system','scan',input,'--offline','--lang','fr','--cache-dir',cacheDir,'--report-output',out,'--no-distro-advisories','--no-gcve','--enrich','none',...extra],
  {cwd:dir,encoding:'utf8',env:{PATH:process.env.PATH,HOME:dir,USERPROFILE:dir}});
 const good=run();assert.equal(good.status,0,good.stderr+good.stdout);
 const files=fs.readdirSync(out);assert.deepEqual(files.sort(),['SHA256SUMS','cve-report.html','findings.json']);
 const before=new Map(files.map(file=>[file,fs.readFileSync(path.join(out,file))]));
 const doc=JSON.parse(before.get('findings.json'));assert.equal(doc.summary.scanReliable,true);assert.equal(doc.cve.length,1);
 const html=before.get('cve-report.html').toString();assert.match(html,/href="#chhost">CVE-2024-12345/);assert.match(html,/host-chart-priority/);
 // Without OSV the package lacks one of its two sources. Under --fail-on-incomplete the
 // scan is cancelled and the previous reports are left untouched.
 const cancelled=run(['--no-osv','--fail-on-incomplete','advisories']);
 assert.equal(cancelled.status,2,cancelled.stderr);assert.match(cancelled.stderr,/Scan annulé/);
 for(const [file,body] of before)assert.deepEqual(fs.readFileSync(path.join(out,file)),body,file);
 // By default the same gap is not fatal (the native source assessed the package): the
 // report is replaced by one marked incomplete that names the missing OSV consultation.
 const incomplete=run(['--no-osv']);
 const {doc:partial}=require('./helpers/incomplete-scan')(incomplete,path.join(out,'findings.json'));
 assert.match(incomplete.stderr,/Couverture incomplète/);
 assert.ok(partial.warnings.some(w=>w.code==='package-advisory-coverage'&&w.fatal===false&&w.items.some(i=>i.id==='fixture@1.0-1'&&i.detail==='OSV')),JSON.stringify(partial.warnings));
 assert.match(fs.readFileSync(path.join(out,'cve-report.html'),'utf8'),/incomplete-banner/);
});

test('unsupported package managers still block while raw binary identities do not require package advisory coverage',()=>{
 const library={ecosystem:'cargo',name:'example',version:'1.0',coordKey:'cargo:example'};
 const binary={ecosystem:'binary',provenance:'binary',name:'libexample.so',coordKey:'binary:libexample.so'};
 const gap=createDiscoveryCoverage().assess(new Map([[library.coordKey,library],[binary.coordKey,binary]]));
 assert.ok(isBlocking(gap));
 assert.deepEqual(new Set(gap.items.map(i=>i.id)),new Set(['example@1.0']));
 assert.equal(require('../lib/scan/reliability').incompleteCheck({capability:'advisories',execution:'not-applicable',reason:'No installed components in this ecosystem.'}),false);
});

test('binary product/version identification is nonblocking; extracted Go dependencies still require OSV and another source',()=>{
 const binaries=[{ecosystem:'binary',provenance:'binary',name:'unknown.so'},
  {ecosystem:'binary',provenance:'binary',name:'libc.so',identity:{name:'GNU C Library',version:'2.39',source:'circl:hashlookup'}},
  {ecosystem:'binary',provenance:'binary',name:'vendor.dll',identity:{ecosystem:'nuget',name:'Vendor.Library',version:'1.2.3',source:'deps.dev'}}];
 const deps=new Map(binaries.map((d,i)=>['binary:'+i,d]));
 const coverage=createDiscoveryCoverage();assert.equal(coverage.assess(deps),null);
 const module={ecosystem:'go',provenance:'binary-module',name:'example.org/library',version:'v1.2.3',coordKey:'binary-module:library'};
 deps.set(module.coordKey,module);
 let gap=coverage.assess(deps);assert.equal(gap.count,1);assert.deepEqual(gap.items[0].missing,['OSV','a second advisory source']);
 coverage.consulted(module,'osv');coverage.consulted(module,'cveproject');assert.equal(coverage.assess(deps),null);
});

test('CLI publishes raw binaries as inventory, with or without a cached product/version identity',t=>{
 const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
 const {spawnSync}=require('node:child_process');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-binary-advisory-'));
 t.after(()=>{require('../lib/cache/db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const src=path.join(dir,'source'),cacheDir=path.join(dir,'.vigie-vuln');fs.mkdirSync(src);
 const bytes=Buffer.concat([Buffer.from([0x4d,0x5a]),Buffer.alloc(62)]);
 fs.writeFileSync(path.join(src,'library.dll'),bytes);
 const hash=crypto.createHash('sha256').update(bytes).digest('hex');
 for(const identity of [null,{name:'Example native library',version:'1.2.3',ecosystem:null,source:'circl:hashlookup'}]){
  require('../lib/cache/json').save(cacheDir,'hash-id',{_fetchedAt:Date.now(),entries:{[hash]:identity}});
  const out=path.join(dir,identity?'identified':'unknown');
  const result=spawnSync(process.execPath,[path.resolve(__dirname,'../vigievuln.js'),'scan',src,'--offline',
   '--report-html','--report-json','-o',out],
   {cwd:dir,env:{PATH:process.env.PATH,HOME:dir,USERPROFILE:dir,FORCE_COLOR:'0'},encoding:'utf8',timeout:30000});
  assert.equal(result.status,0,result.stdout+'\n'+result.stderr);
  const doc=JSON.parse(fs.readFileSync(path.join(out,'findings.json'),'utf8'));
  assert.equal(doc.summary.scanReliable,true);assert.equal(doc.cve.length,0);
  assert.equal(doc.unmanaged.length,1);assert.deepEqual(doc.unmanaged[0].identity,identity);
  assert.doesNotMatch(result.stderr,/Scan cancelled|No verified package\/version assessment/);
  assert.match(fs.readFileSync(path.join(out,'cve-report.html'),'utf8'),/library.dll/);
 }
});

test('a Maven CVE detail is redundant only for versions already known to be affected',()=>{
 const {collectPackageNvdBindings}=require('../lib/providers/nvd/package-ranges');
 const dep={ecosystem:'maven',groupId:'org.example',artifactId:'library',version:'1.0',versions:['1.0','2.0']};
 const id='CVE-2024-10001',known={dep,cve:{id},source:'osv'};
 const store={getPackageRecords:()=>[{source:'osv',document:{id,affected:[{package:{ecosystem:'Maven',name:'org.example:library'}}]}}]};
 const deps=new Map([['library',dep]]);
 assert.equal(collectPackageNvdBindings(deps,store,[known]).length,1);
 assert.deepEqual(collectPackageNvdBindings(deps,store,[known,{...known,dep:{...dep,version:'2.0'}}]),[]);
});

test('publication(): a non-fatal blocker publishes an incomplete report; no blocker is neither',()=>{
 const {publication,coverageWarning}=require('../lib/scan/reliability');
 const gap=coverageWarning('Advisory discovery is incomplete for 1 package/version(s).',{code:'package-advisory-coverage',fatal:false});
 const p=publication([gap,{type:'suppressed',severity:'info',message:'note'}],{inventoryCount:3});
 assert.equal(p.cancel,false);assert.equal(p.incomplete,true);assert.deepEqual(p.blockers,[gap]);assert.deepEqual(p.reasons,[]);
 const clean=publication([{type:'suppressed',severity:'info',message:'note'}],{inventoryCount:3});
 assert.equal(clean.cancel,false);assert.equal(clean.incomplete,false);assert.deepEqual(clean.blockers,[]);
 assert.deepEqual(publication([],{inventoryCount:0}),{blockers:[],cancel:false,incomplete:false,reasons:[]});
});

test('publication(): a fatal blocker, or no inventory with an inventory blocker, cancels',()=>{
 const {publication,coverageWarning}=require('../lib/scan/reliability');
 const fatal=coverageWarning('No advisory source assessed any package.',{code:'package-advisory-coverage',fatal:true});
 const other={type:'osv-coverage',message:'OSV gap'};
 const p=publication([other,fatal],{inventoryCount:2});
 assert.equal(p.cancel,true);assert.equal(p.incomplete,false);assert.deepEqual(p.reasons,[fatal,other],'decisive gap first, then every other gap');
 const noLock={type:'no-lockfile',message:'package.json without lockfile'};
 const empty=publication([noLock,other],{inventoryCount:0});
 assert.equal(empty.cancel,true);assert.deepEqual(empty.reasons,[noLock,other]);
 // An empty inventory with only an advisory-type blocker is not an inventory failure.
 assert.equal(publication([other],{inventoryCount:0}).cancel,false);
 // The same inventory blocker with an inventory publishes.
 assert.equal(publication([noLock],{inventoryCount:1}).incomplete,true);
});

test('publication(): --fail-on-incomplete cancels only when a blocker capability is required',()=>{
 const {publication,warningCapability}=require('../lib/scan/reliability');
 const structural={type:'dependency-coverage',message:'1 Maven POM(s) could not be resolved'};
 const advisory={type:'osv-coverage',message:'OSV gap'};
 const declared={type:'scan-reliability',reliabilityFailure:true,capability:'sources',message:'source gap'};
 assert.equal(warningCapability(structural),'inventory');assert.equal(warningCapability(advisory),'advisories');assert.equal(warningCapability(declared),'advisories');
 const inv=publication([structural],{inventoryCount:1,strict:['inventory']});
 assert.equal(inv.cancel,true);assert.deepEqual(inv.reasons,[structural]);
 assert.deepEqual(publication([structural],{inventoryCount:1,strict:['advisories']}),{blockers:[structural],cancel:false,incomplete:true,reasons:[]});
 // 'sources' is treated as 'advisories', in the strict list and in a warning's capability.
 assert.deepEqual(publication([advisory],{inventoryCount:1,strict:['sources']}).reasons,[advisory]);
 assert.deepEqual(publication([declared],{inventoryCount:1,strict:['advisories']}).reasons,[declared]);
 assert.equal(publication([advisory],{inventoryCount:1,strict:['inventory']}).cancel,false);
 assert.equal(publication([advisory],{inventoryCount:1,strict:['recipes']}).cancel,false);
});

test('createDiscoveryCoverage().assess is fatal only when every assessed version lacks both sources',()=>{
 const coverage=createDiscoveryCoverage();
 const a={ecosystem:'npm',name:'first',artifactId:'first',version:'1.0.0'},b={ecosystem:'npm',name:'second',artifactId:'second',version:'2.0.0'};
 const both=new Map([['first',a],['second',b]]);
 let gap=coverage.assess(both);
 assert.equal(gap.assessed,2);assert.equal(gap.unassessed,2);assert.equal(gap.fatal,true);
 assert.deepEqual(gap.items.map(i=>i.missing),[['OSV','a second advisory source'],['OSV','a second advisory source']]);
 // One version consulted by OSV only: still a gap, no longer fatal.
 coverage.consulted(a,'osv');
 gap=coverage.assess(both);
 assert.equal(gap.unassessed,1);assert.equal(gap.fatal,false);assert.ok(isBlocking(gap));
 // Within a single package, one of two versions assessed by a second source is enough.
 const multi=createDiscoveryCoverage();
 multi.consulted(dep,'cveproject','1.0.0');
 gap=multi.assess(deps);assert.equal(gap.assessed,2);assert.equal(gap.unassessed,1);assert.equal(gap.fatal,false);
 assert.equal(createDiscoveryCoverage().assess(deps).fatal,true);
 // Nothing to assess: no warning at all.
 assert.equal(createDiscoveryCoverage().assess(new Map()),null);
});
