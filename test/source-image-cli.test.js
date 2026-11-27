'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),tar=require('tar-stream'),{spawnSync}=require('node:child_process');
const cli=path.resolve(__dirname,'../vigievuln.js'),cwd=path.dirname(cli),hash=b=>'sha256:'+crypto.createHash('sha256').update(b).digest('hex');
async function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-source-image-cli-'));t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true})});
 const src=path.join(dir,'source');fs.mkdirSync(src);fs.writeFileSync(path.join(src,'package-lock.json'),JSON.stringify({name:'fixture',version:'1.0.0',lockfileVersion:3,packages:{'':{name:'fixture',version:'1.0.0'}}}));
 fs.writeFileSync(path.join(src,'Dockerfile'),'FROM example.test/team/demo:1\n');fs.writeFileSync(path.join(src,'compose.yml'),'services:\n  web:\n    image: example.test/team/demo:1\n  build:\n    build: .\n    image: private-local:1\n');fs.writeFileSync(path.join(src,'.gitlab-ci.yml'),'job:\n  image: "$CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX/alpine:3"\n');
 const pack=tar.pack(),parts=[];pack.on('data',c=>parts.push(c));const done=new Promise((ok,bad)=>{pack.on('end',ok);pack.on('error',bad)});pack.entry({name:'etc/os-release'},'ID=debian\nVERSION_ID=12\n');pack.entry({name:'var/lib/dpkg/status'},'Package: libfoo\nStatus: install ok installed\nVersion: 1.0-1\nArchitecture: amd64\nSource: foo (1.0-1)\n\n');const elf=Buffer.alloc(64);elf.set([0x7f,0x45,0x4c,0x46,2,1,1]);elf.writeUInt16LE(3,16);elf.writeUInt16LE(62,18);elf.writeUInt32LE(1,20);elf.writeUInt16LE(64,52);pack.entry({name:'usr/lib/unaffected-os-helper.so',mode:0o755},elf);pack.finalize();await done;
 const layer=Buffer.concat(parts),config=Buffer.from(JSON.stringify({os:'linux',architecture:'amd64',rootfs:{type:'layers',diff_ids:[hash(layer)]}})),desc=b=>({digest:hash(b),size:b.length}),manifest=Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:desc(config),layers:[desc(layer)]}));
 const files={layer:layer.toString('base64'),config:config.toString('base64'),manifest:manifest.toString('base64'),layerDigest:hash(layer),configDigest:hash(config),manifestDigest:hash(manifest)};fs.writeFileSync(path.join(dir,'registry.json'),JSON.stringify(files));
 const preload=path.join(dir,'preload.cjs');fs.writeFileSync(preload,`const fs=require('node:fs');require('node:os').homedir=()=>process.env.VV_FIXTURE_HOME;for(const proto of ['node:http','node:https'])for(const method of ['request','get'])require(proto)[method]=()=>{fs.appendFileSync(process.env.VV_FIXTURE_CALLS,'BLOCKED-NETWORK\\n');throw Error('network tripwire')};require('node:net').Socket.prototype.connect=()=>{fs.appendFileSync(process.env.VV_FIXTURE_CALLS,'BLOCKED-NETWORK\\n');throw Error('network tripwire')};const f=JSON.parse(fs.readFileSync(process.env.VV_FIXTURE_OCI));globalThis.fetch=async(url)=>{fs.appendFileSync(process.env.VV_FIXTURE_CALLS,String(url)+'\\n');if(process.env.VV_FIXTURE_OFFLINE==='1')throw Error('offline network tripwire');const u=new URL(String(url));if(u.hostname!=='example.test')throw Error('unexpected external request '+u.hostname);if(!u.pathname.startsWith('/v2/team/demo/'))return new Response('',{status:404});const key=decodeURIComponent(u.pathname.split('/').pop());let b=key==='1'||key===f.manifestDigest?f.manifest:key===f.configDigest?f.config:key===f.layerDigest?f.layer:null;return b?new Response(Buffer.from(b,'base64'),{headers:{'content-type':'application/vnd.oci.image.manifest.v1+json','docker-content-digest':key==='1'?f.manifestDigest:key}}):new Response('',{status:404});};`);
 const run=(args,home,offline=false)=>{const calls=path.join(dir,'calls.txt');fs.rmSync(calls,{force:true});fs.mkdirSync(home,{recursive:true});const r=spawnSync(process.execPath,['--require',preload,cli,...args],{cwd,encoding:'utf8',timeout:60000,env:{...process.env,VV_FIXTURE_HOME:home,VV_FIXTURE_OCI:path.join(dir,'registry.json'),VV_FIXTURE_CALLS:calls,VV_FIXTURE_OFFLINE:offline?'1':'0',NO_COLOR:'1',FAD_CHECKER_ENV:'',VIGIEVULN_ENV:''}});assert.ifError(r.error);return {status:r.status,stdout:r.stdout,stderr:r.stderr,calls:fs.existsSync(calls)?fs.readFileSync(calls,'utf8').trim().split('\n'):[]};};
 return {dir,src,run,manifestDigest:hash(manifest)};
}
const flags=['--cve-offline','--no-gcve','--no-nvd','--no-euvd','--no-certfr','--no-epss','--no-kev','--no-eol','--no-retire','--no-binaries','--no-jars','--no-certs','--no-transitive','--no-all-libs','--retries','0'];
const imageFlags=[...flags,'--images'];
const cancelled=require('./helpers/cancelled-scan');
const incomplete=require('./helpers/incomplete-scan');
const ok=r=>assert.equal(r.status,0,r.stdout+'\n'+r.stderr);

test('source image descriptor prepares cache online and replays real project offline',async t=>{
 const {dir,src,run,manifestDigest}=await fixture(t),isolated=path.join(dir,'isolated'),online=path.join(dir,'online'),offline=path.join(dir,'offline'),descriptor=path.join(dir,'descriptor.json'),bundle=path.join(dir,'prepared.tar.gz'),report=path.join(dir,'live.json'),replay=path.join(dir,'replay.json');
 let result=run(['scan',src,'--export-anonymized',descriptor,...imageFlags],isolated,true);ok(result);assert.deepEqual(result.calls,[]);
 const doc=JSON.parse(fs.readFileSync(descriptor));assert.ok(doc.imageReferences.some(x=>x.reference==='example.test/team/demo:1'));assert.ok(doc.imageReferences.every(x=>!String(x.reference).includes('private-local')&&!String(x.reference).includes('$')));
 const cacheDir=path.join(online,'.vigie-vuln');fs.mkdirSync(cacheDir,{recursive:true});await require('../lib/system-inventory').importSystemAdvisories([{id:'DEBIAN-CVE-X',aliases:['CVE-2024-12345'],affected:[{package:{ecosystem:'Debian:12',name:'foo',purl:'pkg:deb/debian/foo?arch=source'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1.0-2'}]}]}]}],{distribution:{id:'debian',versionId:'12'},cacheDir,complete:true});require('../lib/cache-db').closeCacheDbs();
 // Only the distribution advisories are seeded, so both scans publish a report marked
 // incomplete (no second source for the image package); the offline replay must
 // reproduce the online image finding from the prepared cache.
 const gap=doc=>doc.warnings.some(w=>w.code==='package-advisory-coverage'&&w.fatal===false&&w.items.some(i=>i.id==='foo@1.0-1'&&i.detail==='a second advisory source'));
 result=run(['scan',src,'--report-json',report,...imageFlags],online);const live=incomplete(result,report).doc;assert.match(result.stdout,/Image inventories: 1 image/);assert.match(result.stdout,/Image vulnerability analysis: 1 image/);assert.ok(result.calls.some(x=>x.includes('example.test')));assert.ok(result.calls.every(x=>x.includes('example.test')));
 assert.deepEqual(live.cve.map(c=>c.id),['CVE-2024-12345']);assert.equal(live.artifacts.length,1);assert.ok(gap(live),JSON.stringify(live.warnings));
 result=run(['cache','prepare',descriptor,'--output',bundle,...imageFlags],online);ok(result);assert.ok(fs.existsSync(bundle));assert.ok(result.calls.some(url=>url.includes('/manifests/')));assert.ok(!result.calls.some(url=>url.includes('/blobs/')),'cache prepare reuses the unchanged image inventory');
 result=run(['--import-cache',bundle],offline,true);ok(result);assert.deepEqual(result.calls,[]);
 result=run(['scan',src,'--offline','--report-json',replay,...imageFlags],offline,true);const replayed=incomplete(result,replay).doc;assert.deepEqual(result.calls,[]);
 assert.deepEqual(replayed.cve.map(c=>c.id),live.cve.map(c=>c.id));assert.equal(replayed.artifacts.length,1);assert.ok(gap(replayed),JSON.stringify(replayed.warnings));
});

test('images are disabled by default and respect explicit flags, groups and configuration',async t=>{
 const {dir,src,run}=await fixture(t),home=path.join(dir,'home'),config=path.join(dir,'config.json');fs.writeFileSync(config,JSON.stringify({images:false}));
 for(const [i,args] of [['default',[]],['flag',['--no-images']],['group',['-d','images']],['config',['--config',config]]]){const out=path.join(dir,i+'.json'),html=path.join(dir,i+'.html'),r=run(['scan',src,'--offline','--report-json',out,'--report-html',html,...flags,...args],home,true);ok(r);assert.deepEqual(r.calls,[]);const doc=JSON.parse(fs.readFileSync(out));assert.equal((doc.artifacts||[]).length,0);assert.equal((doc.imageReferences||[]).length,0);assert.ok(!doc.warnings.some(w=>/image/i.test(w.reason||'')));assert.doesNotMatch(fs.readFileSync(html,'utf8'),/id="chimages"/);}
 const out=path.join(dir,'override.json'),r=run(['scan',src,'--config',config,'--images','--offline','--report-json',out,...flags],home,true);cancelled(r,[out]);assert.match(r.stderr,/image/i);
 const enabledConfig=path.join(dir,'enabled.json');fs.writeFileSync(enabledConfig,JSON.stringify({images:true}));
 for(const [name,args] of [['group',['-a','images']],['configured',['--config',enabledConfig]]]){
  const target=path.join(dir,'enabled-'+name+'.json'),enabled=run(['scan',src,'--offline','--report-json',target,...flags,...args],home,true);cancelled(enabled,[target]);assert.match(enabled.stderr,/image/i);
 }
 const disabled=path.join(dir,'config-overridden.json');ok(run(['scan',src,'--config',enabledConfig,'--no-images','--offline','--report-json',disabled,...flags],home,true));assert.equal((JSON.parse(fs.readFileSync(disabled)).imageReferences||[]).length,0);

});

test('anonymized image descriptor keeps only resolvable registry references and never source paths',async t=>{
 const {dir,src,run}=await fixture(t),out=path.join(dir,'descriptor-only.json'),r=run(['scan',src,'--export-anonymized',out,...imageFlags],path.join(dir,'phase-one'),true);ok(r);assert.deepEqual(r.calls,[]);const body=fs.readFileSync(out,'utf8'),doc=JSON.parse(body);assert.ok(doc.imageReferences.length>=1);assert.ok(doc.imageReferences.every(x=>x.reference==='example.test/team/demo:1'));assert.ok(!body.includes(src));assert.ok(!body.includes('private-local'));assert.ok(!body.includes('CI_DEPENDENCY_PROXY'));
});

test('cache prepare rejects an unavailable image and never writes an incomplete archive',async t=>{
 const {dir,src,run}=await fixture(t),desc=path.join(dir,'descriptor.json'),bundle=path.join(dir,'incomplete.tar.gz');ok(run(['scan',src,'--export-anonymized',desc,...imageFlags],path.join(dir,'phase-one'),true));
 const body=JSON.parse(fs.readFileSync(desc));body.imageReferences=body.imageReferences.map(x=>({...x,reference:'example.test/team/missing:1'}));fs.writeFileSync(desc,JSON.stringify(body));
 const defaultBundle=path.join(dir,'without-images.tar.gz'),withoutImages=run(['cache','prepare',desc,'--output',defaultBundle,...flags],path.join(dir,'default-prepare'));ok(withoutImages);assert.deepEqual(withoutImages.calls,[]);assert.equal(fs.existsSync(defaultBundle),false,'image-only descriptor has no enabled inventory to prepare');
 const result=run(['cache','prepare',desc,'--output',bundle,...imageFlags],path.join(dir,'phase-two'));assert.notEqual(result.status,0,result.stdout+'\n'+result.stderr);assert.equal(fs.existsSync(bundle),false);assert.ok(result.calls.some(url=>url.includes('/team/missing/')));
});

test('standalone registry CLI reports mutable references in JSON and French HTML, including offline replay',async t=>{
 const {dir,run}=await fixture(t),home=path.join(dir,'home'),cache=path.join(home,'.vigie-vuln'),out=path.join(dir,'registry-report');
 const args=['system','scan','example.test/team/demo:1','--registry','--retries','0','--platform','linux/amd64','--cache-dir',cache,'--no-osv','--no-distro-advisories','--no-gcve','--enrich','none','--lang','fr','--report-output',out];
 cancelled(run(args,home),[path.join(out,'findings.json')]);
 for(const offline of [false,true]){
  if(offline){const result=run([...args,'--offline'],home,true);cancelled(result);assert.deepEqual(result.calls,[]);}
  assert.equal(fs.existsSync(path.join(out,'findings.json')),false);
  assert.equal(fs.existsSync(path.join(out,'cve-report.html')),false);
 }
});
