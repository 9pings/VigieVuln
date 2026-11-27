'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const {spawnSync}=require('node:child_process');const tar=require('tar-stream');
const cwd=path.resolve(__dirname,'..'),cli=path.join(cwd,'vigievuln.js');
function fixture(t){const d=fs.mkdtempSync(path.join(os.tmpdir(),'vv-cli-image-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));const root=path.join(d,'root');fs.mkdirSync(path.join(root,'etc'),{recursive:true});fs.mkdirSync(path.join(root,'var/lib/dpkg'),{recursive:true});fs.writeFileSync(path.join(root,'etc/os-release'),'ID=debian\nVERSION_ID=12\n');fs.writeFileSync(path.join(root,'var/lib/dpkg/status'),'Package: specimen\nStatus: install ok installed\nVersion: 1.0-1\nArchitecture: amd64\n\n');return {d,root,cache:path.join(d,'cache')};}
function run(args,d){return spawnSync(process.execPath,[cli,...args],{cwd,encoding:'utf8',timeout:30000,env:{...process.env,HOME:d,USERPROFILE:d,NO_COLOR:'1',FAD_CHECKER_ENV:'',HTTP_PROXY:'http://127.0.0.1:9',HTTPS_PROXY:'http://127.0.0.1:9'}});}
const cancelled=require('./helpers/cancelled-scan');
const incomplete=require('./helpers/incomplete-scan');
function seedNative(cacheDir){
 const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir});
 store.commit({coverages:[{source:'cveproject',ecosystem:'*',complete:true,fetchedAt:Date.now()}]});
 store.close();
}
async function seedSystem(cacheDir){
 seedNative(cacheDir);
 await require('../lib/system-inventory').importSystemAdvisories([{id:'DEBIAN-test',affected:[{package:{ecosystem:'Debian:12',name:'other'},versions:['1-1']}]}],{cacheDir,distribution:{id:'debian',versionId:'12'},complete:true});
}
function ok(p){assert.equal(p.status,0,p.stderr+'\n'+p.stdout);}
async function archive(file){const pack=tar.pack(),chunks=[];pack.on('data',c=>chunks.push(c));const done=new Promise((r,j)=>{pack.on('end',r);pack.on('error',j)});pack.entry({name:'etc/os-release'},'ID=debian\nVERSION_ID=12\n');pack.entry({name:'var/lib/dpkg/status'},'Package: specimen\nStatus: install ok installed\nVersion: 1.0-1\nArchitecture: amd64\n\n');pack.finalize();await done;fs.writeFileSync(file,Buffer.concat(chunks));}
test('image RetireJS is opt-in, can be disabled, and reports missing offline signatures',t=>{
 const {makeCommand}=require('../lib/cli-image');
 for(const [args,value] of [[[],false],[['--image-retire'],true],[['--image-retire','--no-image-retire'],false]]){const c=makeCommand();c.parse(args,{from:'user'});assert.equal(c.opts().imageRetire,value);}
 const {d,root,cache}=fixture(t),out=path.join(d,'retire');
 cancelled(run(['system','scan',root,'--image-retire','--offline','--cache-dir',cache,'--report-output',out],d));
 assert.equal(fs.existsSync(path.join(out,'findings.json')),false);
});
test('offline rootfs and archive create JSON and HTML, export and rescan inventory',async t=>{
 const {d,root,cache}=fixture(t),out=path.join(d,'out'),snap=path.join(d,'inventory.json');
 await seedSystem(cache);
 ok(run(['system','scan',root,'--offline','--no-distro-advisories','--no-gcve','--cache-dir',cache,'--report-output',out,'--export-inventory',snap],d));
 const report=JSON.parse(fs.readFileSync(path.join(out,'findings.json')));assert.equal(report.artifacts.length,1);assert.equal(report.artifacts[0].componentCount,1);const html=fs.readFileSync(path.join(out,'cve-report.html'),'utf8');assert.match(html,/id="chhost"/);assert.equal(report.summary.scanReliable,true);assert.equal(report.artifacts[0].components.length,0);
 const snapshot=JSON.parse(fs.readFileSync(snap));assert.equal(snapshot.targets[0].deps[0].name,'specimen');assert.ok(!JSON.stringify(snapshot).includes('/vigievuln-artifact-'));
 const again=path.join(d,'again');ok(run(['system','scan',snap,'--inventory','--offline','--no-distro-advisories','--no-gcve','--cache-dir',cache,'--report-output',again],d));assert.equal(JSON.parse(fs.readFileSync(path.join(again,'findings.json'))).artifacts[0].evidence,'cached-inventory');
 const file=path.join(d,'root.tar'),archiveOut=path.join(d,'archive');await archive(file);ok(run(['system','scan',file,'--offline','--no-distro-advisories','--no-gcve','--cache-dir',cache,'--report-output',archiveOut],d));assert.equal(JSON.parse(fs.readFileSync(path.join(archiveOut,'findings.json'))).artifacts[0].componentCount,1);
});
test('no-report, strict coverage, and invalid options return useful outcomes',t=>{
 const {d,root,cache}=fixture(t),out=path.join(d,'none'),snap=path.join(d,'snap.json');
 cancelled(run(['system','scan',root,'--offline','--cache-dir',cache,'--no-report','--report-output',out,'--export-inventory',snap],d),[snap]);assert.ok(!fs.existsSync(snap));assert.ok(!fs.existsSync(out));
 const strict=run(['system','scan',root,'--offline','--cache-dir',cache,'--no-report','--fail-on-incomplete','advisories'],d);assert.equal(strict.status,2,strict.stderr);assert.match(strict.stderr,/incomplete/i);
 for(const args of [['--fail-on','very-high'],['--registry','--inventory'],['--prefer-sbom'],['--fail-on-incomplete','nonsense']]) {const p=run(['system','scan',root,'--offline','--cache-dir',cache,...args],d);assert.notEqual(p.status,0,p.stdout);}
});
test('SBOM import is inventoried with explicit unverified evidence',t=>{
 const {d,cache}=fixture(t),file=path.join(d,'publisher.json'),out=path.join(d,'sbom-out');fs.writeFileSync(file,JSON.stringify({bomFormat:'CycloneDX',specVersion:'1.5',components:[{type:'library',name:'left-pad',version:'1.3.0',purl:'pkg:npm/left-pad@1.3.0'}]}));
 seedNative(cache);
 const journal=require('../lib/advisory-store').openAdvisoryStore({cacheDir:cache});
 journal.commit({queries:[{source:'osv',ecosystem:'npm',name:'left-pad',version:'1.3.0',ids:[],fetchedAt:Date.now(),complete:true}]});journal.close();
 const published=run(['system','scan',file,'--sbom','--offline','--no-gcve','--cache-dir',cache,'--report-output',out],d);
 // The unverified publisher inventory no longer cancels: the report is published and marked incomplete.
 const {log,doc}=incomplete(published,path.join(out,'findings.json'));
 assert.match(log,/SBOM.*unverified/i);
 assert.equal(doc.artifacts.length,1);assert.equal(doc.artifacts[0].componentCount,1);
 assert.ok(doc.warnings.some(w=>w.type==='dependency-coverage'&&w.capability==='inventory'&&/SBOM has no artifact subject digest.*unverified/.test(w.message)),JSON.stringify(doc.warnings));
 assert.ok(doc.warnings.some(w=>w.type==='dependency-coverage'&&/SBOM publisher identity and signatures were not verified/.test(w.message)),JSON.stringify(doc.warnings));
 assert.match(fs.readFileSync(path.join(out,'cve-report.html'),'utf8'),/incomplete-banner/);
});
test('source image references appear in reports and fail incomplete sources gate',t=>{
 const {d}=fixture(t),src=path.join(d,'src'),out=path.join(d,'source');fs.mkdirSync(src);fs.writeFileSync(path.join(src,'Dockerfile'),'FROM alpine:3.20\n');
 const p=run(['scan',src,'--images','--offline','--report-json',path.join(out,'findings.json'),'--report-html',path.join(out,'report.html'),'--fail-on-incomplete','sources'],d);assert.equal(p.status,2,p.stderr+'\n'+p.stdout);
 cancelled(p,[path.join(out,'findings.json'),path.join(out,'report.html')]);
});
test('custom advisory configuration imports and matches an exact offline distribution scope',t=>{
 const {d,root,cache}=fixture(t),config=path.join(d,'scope.json'),advisories=path.join(d,'advisories.json'),out=path.join(d,'custom');
 fs.writeFileSync(path.join(root,'etc/os-release'),'ID=custom\nVERSION_ID=9\n');fs.writeFileSync(config,JSON.stringify({distribution:{id:'custom',versionId:'9'},base:'Custom',ecosystem:'Custom:9',versionScheme:'debian'}));
 fs.writeFileSync(advisories,JSON.stringify([{id:'CUSTOM-1',aliases:['CVE-2024-12345'],affected:[{package:{ecosystem:'Custom:9',name:'specimen',purl:'pkg:deb/custom/specimen?arch=source'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0-1'}]}]}]}]));
 ok(run(['system','scan','--import-advisories',advisories,'--distribution','custom:9','--snapshot-complete','--advisory-config',config,'--cache-dir',cache,'--offline'],d));
 seedNative(cache);
 ok(run(['system','scan',root,'--offline','--no-gcve','--no-distro-advisories','--cache-dir',cache,'--report-output',out,'--advisory-config',config],d));
 const report=JSON.parse(fs.readFileSync(path.join(out,'findings.json')));assert.match(JSON.stringify(report),/CVE-2024-12345/);
});
test('inventory and report outputs cannot overwrite inputs or each other',t=>{const {d,root,cache}=fixture(t),file=path.join(d,'input.json');fs.writeFileSync(file,JSON.stringify({bomFormat:'CycloneDX',components:[]}));const original=fs.readFileSync(file,'utf8');const p=run(['system','scan',file,'--sbom','--offline','--cache-dir',cache,'--no-report','--export-inventory',file],d);assert.notEqual(p.status,0);assert.equal(fs.readFileSync(file,'utf8'),original);const alias=path.join(d,'alias');fs.symlinkSync(file,alias);const q=run(['system','scan',file,'--sbom','--offline','--cache-dir',cache,'--no-report','--export-inventory',alias],d);assert.notEqual(q.status,0);assert.equal(fs.readFileSync(file,'utf8'),original);const output=path.join(d,'out.json');const r=run(['system','scan',root,'--offline','--cache-dir',cache,'--export-inventory',output,'--report-json',output],d);assert.notEqual(r.status,0);assert.ok(!fs.existsSync(output));});
test('fleet proxy routes image advisories and isolates scoped offline cache',async t=>{
 const http=require('node:http'),{spawn}=require('node:child_process'),{d,cache}=fixture(t),sbom=path.join(d,'npm.cdx.json');
 fs.writeFileSync(sbom,JSON.stringify({bomFormat:'CycloneDX',specVersion:'1.5',components:[{type:'library',name:'left-pad',version:'1.3.0',purl:'pkg:npm/left-pad@1.3.0'}]}));
 const requests=[];const server=http.createServer((req,res)=>{let bytes='';req.on('data',c=>bytes+=c);req.on('end',()=>{let body;try{body=JSON.parse(bytes)}catch{res.writeHead(400).end();return;}requests.push(body);
  if(req.url!=='/v1/resource'||body.provider!=='osv'||body.type!=='packages'){res.writeHead(404).end();return;}
  res.writeHead(200,{'content-type':'application/json','x-fad-proxy-fetched-at':new Date().toISOString()});res.end(JSON.stringify({results:body.params.queries.map(()=>({}))}));});});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const url=`http://127.0.0.1:${server.address().port}`,cfg=path.join(d,'config.json');fs.writeFileSync(cfg,JSON.stringify({sourceProfile:'proxy',proxyCache:url}));
 const trace=path.join(d,'network.txt'),preload=path.join(d,'tripwire.js');
 fs.writeFileSync(preload,`const fs=require('node:fs'),real=globalThis.fetch,allowed=${JSON.stringify(url)},log=${JSON.stringify(trace)};globalThis.fetch=(u,o)=>{fs.appendFileSync(log,String(u)+'\\n');if(new URL(String(u)).origin!==allowed)throw Error('direct advisory network tripwire');return real(u,o)};`);
 const launch=args=>new Promise((resolve,reject)=>{const child=spawn(process.execPath,[cli,...args],{cwd,env:{...process.env,HOME:d,USERPROFILE:d,NO_COLOR:'1',FAD_CHECKER_ENV:'',VIGIEVULN_ENV:'',NODE_OPTIONS:`--require=${preload}`}});let output='';child.stdout.on('data',x=>output+=x);child.stderr.on('data',x=>output+=x);child.on('error',reject);child.on('close',status=>resolve({status,output}));});
 const args=['system','scan',sbom,'--sbom','--config',cfg,'--allow-insecure-http','--cache-dir',cache,'--no-report','--enrich','none'];
 // OSV answers through the fleet proxy; the other native sources 404 there, so the
 // package lacks a second advisory source: the scan publishes, marked incomplete.
 const osvOnly=/Advisory discovery is incomplete for 1 package\/version\(s\)[\s\S]*left-pad@1\.3\.0 — a second advisory source/;
 const online=await launch(args);assert.match(incomplete(online).log,osvOnly);assert.ok(requests.some(r=>r.provider==='osv'&&r.type==='packages'));
 const forward=await launch(['system','scan',sbom,'--sbom','--config',cfg,'--allow-insecure-http','--cache-dir',path.join(d,'forward-cache'),'--no-report','--enrich','none','--proxy','http://127.0.0.1:1']);assert.match(incomplete(forward).log,osvOnly);

 const snapshot=path.join(d,'sbom-inventory.json'),prepared=path.join(d,'prepared.tar.gz');
 const exported=await launch([...args,'--offline','--export-inventory',snapshot]);assert.match(incomplete(exported).log,osvOnly);assert.ok(fs.existsSync(snapshot),'an incomplete scan still exports its inventory');
 const inv=require('../lib/artifacts/scan');
 fs.writeFileSync(snapshot,JSON.stringify(inv.createSnapshot([inv.sbomTarget(sbom)])));
 const warm=await launch(['cache','prepare',snapshot,'--output',prepared,'--config',cfg,'--allow-insecure-http','--cache-dir',cache,'--enrich','none']);assert.equal(warm.status,0,warm.output);assert.ok(fs.existsSync(prepared));
 const doc=JSON.parse(fs.readFileSync(snapshot)),target=doc.targets[0];target.coverage.push({artifactTargetId:target.id,capability:'advisories',collector:'native-binaries',execution:'partial',result:'indeterminate',reason:'Binary identity unavailable'});
 fs.writeFileSync(snapshot,JSON.stringify(require('../lib/artifacts/scan').createSnapshot(doc.targets)));
 const partial=path.join(d,'partial.tar.gz'),partialRun=await launch(['cache','prepare',snapshot,'--output',partial,'--config',cfg,'--allow-insecure-http','--cache-dir',cache,'--enrich','none']);assert.equal(partialRun.status,0,partialRun.output);assert.ok(fs.existsSync(partial));assert.match(partialRun.output,/incomplete advisory or source coverage/);
 const strictFile=path.join(d,'partial-strict.tar.gz'),strictRun=await launch(['cache','prepare',snapshot,'--output',strictFile,'--config',cfg,'--allow-insecure-http','--cache-dir',cache,'--enrich','none','--fail-on-incomplete','advisories']);assert.equal(strictRun.status,2,strictRun.output);assert.equal(fs.existsSync(strictFile),false);
 const globalConfig=path.join(d,'.vigie-vuln','config.json');fs.mkdirSync(path.dirname(globalConfig),{recursive:true});fs.writeFileSync(globalConfig,JSON.stringify({sourceProfile:'proxy',proxyCache:url}));
 const saved=await launch(['system','scan',sbom,'--sbom','--offline','--cache-dir',cache,'--no-report','--enrich','none']);assert.match(incomplete(saved).log,osvOnly);
 const count=requests.length, offline=await launch([...args,'--offline']);assert.match(incomplete(offline).log,osvOnly);assert.equal(requests.length,count);assert.ok(fs.readFileSync(trace,'utf8').trim().split('\n').every(line=>new URL(line).origin===url));
 const denied=await launch(['system','scan',sbom,'--sbom','--config',cfg,'--cache-dir',cache,'--no-report']);assert.notEqual(denied.status,0);assert.match(denied.output,/not encrypted|allow-insecure-http/);
});
test('EU advisory profile excludes cached and imported OSV evidence',t=>{
 const {d,root,cache}=fixture(t),out=path.join(d,'eu');const result=run(['system','scan',root,'--offline','--source-profile','eu','--cache-dir',cache,'--report-output',out,'--enrich','none'],d);cancelled(result,[path.join(out,'findings.json')]);assert.match(result.stderr,/OSV/);
 const rejected=run(['system','scan','--offline','--source-profile','eu','--import-advisories','some.json','--distribution','debian:12','--cache-dir',cache],d);assert.notEqual(rejected.status,0);assert.match(rejected.stderr,/excluded/);
});
test('originless saved proxy keys are accepted only for official hosted proxies',t=>{
 const {d,root,cache}=fixture(t),dir=path.join(d,'.vigie-vuln'),config=path.join(dir,'config.json');fs.mkdirSync(dir,{recursive:true});
 const data={sourceProfile:'proxy',proxyCache:'https://api.vigievuln.fr',proxyCacheToken:'example-secret',proxyCacheTokenOrigin:null};
 fs.writeFileSync(config,JSON.stringify(data));let p=run(['system','scan',root,'--offline','--cache-dir',cache,'--no-report','--enrich','none'],d);assert.equal(p.status,2,p.stderr);assert.ok(!p.stderr.includes(data.proxyCacheToken));
 data.proxyCache='https://unrelated.example';fs.writeFileSync(config,JSON.stringify(data));p=run(['system','scan',root,'--offline','--cache-dir',cache,'--no-report','--enrich','none'],d);assert.notEqual(p.status,0);assert.match(p.stderr,/unbound custom proxy/);assert.ok(!p.stderr.includes(data.proxyCacheToken));
 data.proxyCacheTokenOrigin='https://different.example';fs.writeFileSync(config,JSON.stringify(data));p=run(['system','scan',root,'--offline','--cache-dir',cache,'--no-report','--enrich','none'],d);assert.notEqual(p.status,0);assert.match(p.stderr,/belongs to another server/);
});
test('explicit digest source definitions persist into inventory and report without tag guessing',async t=>{
 const {d,root,cache}=fixture(t),snapshot=path.join(d,'initial.json'),withDefs=path.join(d,'with-definitions.json'),src=path.join(d,'defs'),out=path.join(d,'defined-report');
 await seedSystem(cache);
 ok(run(['system','scan',root,'--offline','--no-distro-advisories','--no-gcve','--cache-dir',cache,'--no-report','--export-inventory',snapshot],d));const doc=JSON.parse(fs.readFileSync(snapshot)),digest='sha256:'+'a'.repeat(64);doc.targets[0].metadata.digest=digest;fs.writeFileSync(snapshot,JSON.stringify(require('../lib/artifacts/scan').createSnapshot(doc.targets)));
 fs.mkdirSync(src);fs.writeFileSync(path.join(src,'Dockerfile'),`FROM repo/app@${digest} AS base\nFROM repo/app:latest AS final\n`);
 ok(run(['system','scan',snapshot,'--inventory','--definitions',src,'--offline','--no-distro-advisories','--no-gcve','--cache-dir',cache,'--report-output',out,'--export-inventory',withDefs],d));
 const saved=JSON.parse(fs.readFileSync(withDefs)),def=saved.targets[0].metadata.definitions;assert.equal(def.length,1);assert.equal(def[0].path,'Dockerfile');assert.equal(def[0].line,1);assert.equal(def[0].binding,'manifest-digest');assert.equal(def[0].finalStage,false);
 const report=JSON.parse(fs.readFileSync(path.join(out,'findings.json')));assert.equal(report.artifacts[0].metadata.definitions[0].declared,`repo/app@${digest}`);assert.equal(report.imageReferences.length,2);assert.deepEqual(report.imageReferences[1].boundArtifactIds,[]);
 const replay=path.join(d,'replay');ok(run(['system','scan',withDefs,'--inventory','--offline','--no-distro-advisories','--no-gcve','--cache-dir',cache,'--report-output',replay],d));const restored=JSON.parse(fs.readFileSync(path.join(replay,'findings.json')));assert.equal(restored.imageReferences.length,2);assert.equal(restored.artifacts[0].metadata.definitions[0].line,1);
});

test('image advisory reuse defaults on and explicit flags override configuration',()=>{
 const {makeCommand}=require('../lib/cli-image'),{applyLayers}=require('../lib/options-env');
 for(const [args,config,expected] of [[[],{},true],[[],{reuseStableAdvisories:false},false],[['--no-reuse-stable-advisories'],{reuseStableAdvisories:true},false],[['--reuse-stable-advisories'],{reuseStableAdvisories:false},true]]){
  const command=makeCommand();command.parse(args,{from:'user'});
  assert.equal(applyLayers(command,{fileLayer:config}).reuseStableAdvisories,expected);
 }
});
