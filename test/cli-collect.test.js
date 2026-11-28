'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const {execFile} = require('node:child_process');
const exec = require('node:util').promisify(execFile);
const tar = require('tar-stream');
const cli = path.resolve(__dirname, '../vigievuln.js');

async function archive(entries) {
  const pack = tar.pack(), chunks = [];
  const read = (async () => {for await (const chunk of pack) chunks.push(chunk);})();
  for (const [name, bytes] of entries) pack.entry({name}, bytes);
  pack.finalize();
  await read;
  return Buffer.concat(chunks);
}

test('collect preserves paths and replays CVEs on a separate auditor without initialising the client cache', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-collect-'));
  t.after(() => { require('../lib/cache/db').closeCacheDbs(); fs.rmSync(dir, {recursive:true,force:true}); });
  const root = path.join(dir, 'server'), home = path.join(dir, 'client-home'), output = path.join(dir, 'out.json');
  function put(rel, text) {
    const file = path.join(root, rel);
    fs.mkdirSync(path.dirname(file), {recursive:true});
    fs.writeFileSync(file, text);
  }
  put('etc/os-release', 'ID=debian\nVERSION_ID=12\n');
  put('var/lib/dpkg/status','Package: example\nVersion: 1.3-2\nStatus: install ok installed\nArchitecture: amd64\n');
  put('srv/web/composer.lock',JSON.stringify({packages:[{name:'demo/lib',version:'v2.3.4'}]}));
  put('srv/web/demo.key','-----BEGIN PRIVATE KEY-----\nSYNTHETIC_BODY_MUST_STAY_LOCAL\n-----END PRIVATE KEY-----');
  put('srv/web/front/package-lock.json',JSON.stringify({lockfileVersion:3,packages:{'node_modules/specimen':{version:'1.0.0'}}}));
  put('srv/web/compose.yaml','services:\n  web:\n    image: example:latest\n');
  put('srv/news/wp-includes/version.php', "<?php $wp_version = '6.6.2';");
  put('srv/news/wp-includes/sodium_compat/composer.json','{"name":"paragonie/sodium_compat","version":"2.0.0"}');
  put('srv/news/wp-admin/index.php', '<?php');
  put('srv/news/wp-load.php', '<?php');
  put('srv/news/wp-content/plugins/example/example.php','<?php /* Plugin Name: Example */');
  put('srv/news/wp-content/plugins/example/assets/package.json','{"name":"example-assets","version":"1.0.0"}');
  put('srv/news/wp-content/themes/unidentified/build/composer.json','{"name":"sample/styles","version":"1.0.0"}');
  put('srv/web/front/node_modules/lib/package.json','{"name":"lib","version":"3.0.0"}');
  put('usr/share/nodejs/pack/package.json','{"name":"distro-module","version":"1.3.0"}');
  put('srv/tools/Gemfile.lock','GEM\n  specs:\n    rack (1.2.3)\n');
  put('srv/dotnet/packages.lock.json',JSON.stringify({version:1,dependencies:{net8:{Example:{type:'Direct',resolved:'1.2.3'}}}}));
  put('srv/tools/uv.lock','[[package]]\nname="client"\nversion="1.2.3"\n');
  put('srv/web/broken/package.json','secret-sentinel-017 broken');
  put('srv/invalid.yml','host: !invalid secret-sentinel-017');
  put('usr/local/bundle/gems/demo/Dockerfile','FROM unrelated-example');
  put('proc/fake/package.json','{"name":"excluded","version":"1.0.0"}');
  fs.mkdirSync(path.join(home,'.fad-checker'),{recursive:true});
  fs.writeFileSync(path.join(home,'.fad-checker','sentinel'),'preserve');
  const tmp = path.join(dir,'no-tmp');
  fs.writeFileSync(tmp,'not a directory');
  const hook = path.join(dir,'no-network.cjs');
  fs.writeFileSync(hook,`globalThis.fetch=()=>{throw Error('unexpected network')};
    require('node:net').Socket.prototype.connect=()=>{throw Error('unexpected socket')};`);
  const env = {...process.env,HOME:home,USERPROFILE:home,TMPDIR:tmp,TEMP:tmp,TMP:tmp};
  const collected = await exec(process.execPath,['--require',hook,cli,'system','collect',root,'--output',output],{cwd:dir,env});
  assert.match(collected.stdout, /vigievuln system scan \.\/out\.json/);
  assert.deepEqual(fs.readdirSync(home),['.fad-checker']);
  assert.equal(fs.readFileSync(path.join(home,'.fad-checker','sentinel'),'utf8'),'preserve');
  const [target] = require('../lib/artifacts/scan').readSnapshot(output);
  assert.equal(target.distribution.id,'debian');
  const extensions = 'srv/news/wp-content/';
  assert.ok(!target.metadata.systemApplications.applications.some(a=>a.root.startsWith(extensions)));
  const assets = target.deps.find(d=>d.artifactPath===extensions+'plugins/example/assets/package.json');
  assert.deepEqual(assets.systemApplicationIds,[target.id+':wordpress:srv/news']);
  assert.equal(assets.imageRole,'transitive');
  const bundled = target.deps.find(d=>d.artifactPath==='srv/news/wp-includes/sodium_compat/composer.json');
  assert.deepEqual(bundled.systemApplicationIds,assets.systemApplicationIds);
  assert.equal(bundled.imageRole,'transitive');
  assert.ok(!target.metadata.systemApplications.applications.some(a=>a.root.endsWith('sodium_compat')));
  // Replaying an older snapshot repairs the spurious project and its references.
  const legacy = structuredClone(target);
  const oldId=target.id+':project:assets';
  legacy.metadata.systemApplications.applications.push({id:oldId,type:'project',root:extensions+'plugins/example/assets'});
  legacy.metadata.systemApplications.inventory.push({id:oldId+':project',applicationId:oldId,kind:'project'});
  legacy.deps.find(d=>d.coordKey===assets.coordKey).systemApplicationIds=[oldId];
  const replay=require('../lib/artifacts/inventory-scope').applyComponentScope(legacy);
  assert.ok(!replay.metadata.systemApplications.applications.some(a=>a.id===oldId));
  assert.deepEqual(replay.deps.find(d=>d.coordKey===assets.coordKey).systemApplicationIds,assets.systemApplicationIds);
  assert.equal(target.metadata.inspectLocalImages,false);
  assert.ok(target.metadata.projectCertificates.some(c=>c.kind==='private-key' && c.path==='srv/web/demo.key'));
  assert.ok(!fs.readFileSync(output,'utf8').includes('SYNTHETIC_BODY_MUST_STAY_LOCAL'));
  assert.ok(!fs.readFileSync(output,'utf8').includes('secret-sentinel-017'));
  const apps = target.metadata.systemApplications;
  assert.ok(apps.inventory.some(c=>c.kind==='core' && c.version==='6.6.2' && c.path==='srv/news'));
  assert.ok(apps.applications.some(a=>a.type==='project' && a.root==='srv/web/front'));
  assert.ok(!apps.applications.some(a=>a.root.includes('node_modules') || a.root.includes('usr/share/nodejs')));
  for (const ecosystem of ['ruby','pypi','nuget']) assert.ok(target.deps.some(d=>d.ecosystem===ecosystem &&
    d.version==='1.2.3' && d.provenance==='lockfile'),ecosystem);
  assert.ok(target.deps.some(d=>d.name==='distro-module' && d.imageRole==='transitive'));
  const lib = target.deps.find(d=>d.artifactPath==='srv/web/front/node_modules/lib/package.json');
  assert.equal(lib.systemSection,'dependency');
  assert.equal(lib.imageRole,'transitive');
  assert.deepEqual(lib.systemApplicationIds,[target.id+':project:srv/web/front']);
  assert.ok(target.deps.some(d=>d.name==='example' && d.version==='1.3-2' && d.artifactPath==='/var/lib/dpkg/status'));
  assert.ok(target.deps.some(d=>d.namespace==='demo' && d.name==='lib' && d.artifactPath==='srv/web/composer.lock' && d.provenance==='lockfile'));
  assert.ok(!target.deps.some(d=>d.name==='excluded'));
  assert.deepEqual(target.metadata.declarations.map(r=>r.path),['srv/web/compose.yaml']);
  assert.ok(!target.warnings.some(w=>w.manifestPath==='srv/invalid.yml'));
  // Destroy the test root. The auditor can now use only the collected evidence.
  fs.rmSync(root,{recursive:true});
  const auditor = path.join(dir,'auditor');
  const store = require('../lib/advisories/store').openAdvisoryStore({cacheDir:path.join(auditor,'.vigie-vuln')});
  const id = 'CVE-2025-10001', record = {cveMetadata:{cveId:id,state:'PUBLISHED'},containers:{cna:{affected:[
    {packageURL:'pkg:npm/specimen',versions:[{version:'1.0.0',status:'affected'}]},
  ]}}};
  store.commit({records:[require('../lib/advisories/native').cveEnvelope(record,{fetchedAt:Date.now()})]});
  store.close();
  require('../lib/cache/json').save(path.join(auditor,'.vigie-vuln'),'eol-cache.json',{
    entries:{wordpress:[{cycle:'6.6',eol:'2025-01-01',latest:'6.6.3'}]},
    meta:{fetchedAt:Date.now()},
  });
  const feed = path.join(dir,'wordfence.json');
  const uuid='123e4567-e89b-12d3-a456-426614174000';
  fs.writeFileSync(feed, JSON.stringify({[uuid]:{id:uuid,cve:'CVE-2025-19999',title:'Fixture',software:[{
    type:'core',slug:'wordpress',affected_versions:{exact:{from_version:'6.6.2',to_version:'6.6.2',from_inclusive:true,to_inclusive:true}},
    patched_versions:['6.6.3']}],references:[]}}));
  await assert.rejects(exec(process.execPath,[cli,'system','scan','--offline','--wordfence-feed',feed,'--lang','fr',output,'--report-output',path.join(dir,'reports')],
    {cwd:dir,env:{...process.env,HOME:auditor,USERPROFILE:auditor}}),{code:2});
  assert.equal(fs.existsSync(path.join(dir,'reports','findings.json')),false);
});

test('Docker cache and local archive are inspected locally, deduplicated and linked to the declaration', {skip:process.platform==='win32'}, async t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(),'vv-engine-'));
  t.after(()=>fs.rmSync(tmp,{recursive:true,force:true}));
  const root=path.join(tmp,'root'), scratch=path.join(tmp,'scratch'), socket=path.join(tmp,'engine.sock');
  fs.mkdirSync(root);fs.mkdirSync(scratch);
  fs.writeFileSync(path.join(root,'Dockerfile'),'FROM sample:local\n');
  const config=JSON.stringify({os:'linux',architecture:'amd64'});
  const id='sha256:'+require('node:crypto').createHash('sha256').update(config).digest('hex');
  const layer=await archive([['app/node_modules/present/package.json','{"name":"present","version":"3.2.1"}']]);
  const bytes=await archive([['manifest.json',JSON.stringify([{Config:'config.json',RepoTags:['sample:local'],Layers:['layer.tar']}])],['config.json',config],['layer.tar',layer]]);
  const image=path.join(tmp,'project-image.tar'), out=path.join(tmp,'inventory.json');
  fs.writeFileSync(image,bytes);
  const calls=[];
  let selective=false;
  const engine=require('node:http').createServer((req,res)=>{
    calls.push(req.method+' '+req.url);
    if(req.url==='/images/json?all=1') {
      const items=[{Id:id,RepoTags:['sample:local']}];
      if (selective) items.push({Id:'sha256:'+'c'.repeat(64),RepoTags:['unrelated:local']});
      return res.end(JSON.stringify(items));
    }
    if(req.url==='/images/'+encodeURIComponent(id)+'/get')return res.end(bytes);
    res.writeHead(404);res.end();
  });
  await new Promise((resolve,reject)=>engine.once('error',reject).listen(socket,resolve));
  t.after(()=>new Promise(resolve=>engine.close(resolve)));
  const env={...process.env,HOME:path.join(tmp,'unused-home'),TMPDIR:scratch};
  await exec(process.execPath,[cli,'system','collect',root,'--image',image,'--docker','--docker-socket',socket,'--output',out],{env});
  const [host, target]=require('../lib/artifacts/scan').readSnapshot(out);
  assert.equal(host.metadata.inspectLocalImages,true);
  assert.equal(host.metadata.declarations[0].path,'Dockerfile');
  assert.deepEqual(host.metadata.declarations[0].localImageCandidates,[target.id]);
  assert.ok(target.deps.some(d=>d.name==='present' && d.artifactPath==='app/node_modules/present/package.json'));
  assert.deepEqual(target.metadata.localSources,[image,id]);
  assert.deepEqual(calls,['GET /images/json?all=1','GET /images/'+encodeURIComponent(id)+'/get']);
  assert.equal(target.metadata.systemApplications,undefined);
  calls.length=0;
  selective=true;
  await exec(process.execPath,[cli,'system','collect',root,'--images','--docker-socket',socket,'--output',out],{env});
  assert.deepEqual(calls,['GET /images/json?all=1','GET /images/'+encodeURIComponent(id)+'/get']);
  assert.deepEqual(fs.readdirSync(scratch),[]);
  assert.equal(fs.existsSync(env.HOME),false);
  fs.writeFileSync(path.join(root,'Dockerfile'),'FROM unavailable:local\n');
  calls.length=0;
  await assert.rejects(exec(process.execPath,[cli,'system','collect',root,'--images','--docker-socket',socket,'--output',out],{env}),{code:2});
  assert.deepEqual(calls,['GET /images/json?all=1']);
  assert.ok(require('../lib/artifacts/scan').readSnapshot(out)[0].warnings.some(w=>w.message.includes('unavailable:local')));
  await assert.rejects(exec(process.execPath,[cli,'system','collect',root,'--docker','--docker-socket',socket+'.missing','--output',out],{env}),{code:2});
  const [partial]=require('../lib/artifacts/scan').readSnapshot(out);
  assert.ok(partial.coverage.some(c=>c.collector==='local-images' && c.execution==='partial'));
});

test('Ghost themes, Redmine core and installed Ruby libraries retain their identities on collection and replay', async t => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-gems-'));
  t.after(() => { require('../lib/cache/db').closeCacheDbs(); fs.rmSync(scratch, {recursive:true, force:true}); });
  const root = path.join(scratch,'host'), output = path.join(scratch,'inventory.json');
  function put(file, data) {
    const full = path.join(root,file);
    fs.mkdirSync(path.dirname(full),{recursive:true});
    fs.writeFileSync(full,data);
  }
  put('opt/ghost/package.json','{"name":"ghost","version":"6.79.0"}');
  put('opt/ghost/index.js','');
  put('opt/ghost/core/boot.js','');
  put('opt/ghost/content/themes/source/package.json','{"name":"source","version":"1.7.6","engines":{"ghost":">=5"}}');
  put('srv/redmine/Gemfile','');
  put('srv/redmine/config/application.rb','');
  put('srv/redmine/lib/redmine/version.rb','module Redmine\n module VERSION\n MAJOR = 6\n MINOR = 1\n TINY = 6\n end\nend\n');
  const store = 'usr/local/bundle/gems/sample-1.0.0';
  put(store+'/Gemfile','');
  put(store+'/Gemfile.lock','GEM\n  specs:\n    phantom (2.0.0)\n');
  put('usr/local/bundle/specifications/sample-1.0.0.gemspec','s.name = "sample"\ns.version = "1.0.0"');
  await exec(process.execPath,[cli,'system','collect',root,'--output',output]);
  const [target] = require('../lib/artifacts/scan').readSnapshot(output);
  const state = target.metadata.systemApplications;
  assert.deepEqual(state.applications.map(a=>a.type).sort(),['ghost','redmine']);
  const redmine = state.applications.find(a=>a.type==='redmine');
  assert.equal(state.inventory.find(c=>c.applicationId===redmine.id && c.kind==='core').version,'6.1.6');
  assert.equal(state.inventory.find(c=>c.kind==='theme').name,'source');
  const installed = target.deps.find(d=>d.name==='sample');
  assert.equal(installed.imageRole,'transitive');
  assert.equal(installed.version,'1.0.0');
  assert.ok(!target.deps.some(d=>d.name==='phantom'));
  const legacyId='old-project-in-store';
  state.applications.push({id:legacyId,type:'project',root:store});
  state.inventory.push({applicationId:legacyId,id:legacyId+':project',kind:'project'});
  target.deps.push({...installed,coordKey:'phantom',provenance:'lockfile',name:'phantom',artifactPath:store+'/Gemfile.lock',systemApplicationIds:[legacyId]});
  const replay = require('../lib/artifacts/inventory-scope').applyComponentScope(target);
  assert.ok(!replay.metadata.systemApplications.applications.some(a=>a.id===legacyId));
  assert.ok(!replay.deps.some(d=>d.name==='phantom'));
  assert.ok(replay.deps.some(d=>d.name==='sample'));
  const cacheDir=path.join(scratch,'cache');
  require('../lib/cache/repository').createCacheRepository(cacheDir).put('image-product-nvd/2',
    JSON.stringify(['redmine:redmine','6.1.6']),{records:[{id:'CVE-2099-1234'}],unknown:[]});
  const assessment=await require('../lib/artifacts/product-advisories').assessProductAdvisories(replay,{cacheDir,offline:true});
  assert.equal(assessment.matches.length,1);
  assert.deepEqual(assessment.matches[0].dep.systemApplicationIds,[redmine.id]);
  assert.match(assessment.matches[0].dep.artifactPath,/lib\/redmine\/version\.rb$/);
});

test('collect leaves out an excluded directory and never blocks on special files in the tree', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-collect-exclude-'));
  t.after(() => fs.rmSync(dir, {recursive:true,force:true}));
  const root = path.join(dir, 'server'), home = path.join(dir, 'home'), output = path.join(dir, 'out.json');
  const put = (rel, text) => { const file = path.join(root, rel); fs.mkdirSync(path.dirname(file), {recursive:true}); fs.writeFileSync(file, text); };
  put('etc/os-release', 'ID=debian\nVERSION_ID=12\n');
  put('var/lib/dpkg/status', 'Package: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:1.2.13.dfsg-1\n');
  const lock = name => JSON.stringify({name:'app',version:'1.0.0',lockfileVersion:3,packages:{'':{name:'app',version:'1.0.0',dependencies:{[name]:'1.0.0'}},[`node_modules/${name}`]:{version:'1.0.0'}}});
  put('srv/app/package.json', JSON.stringify({name:'app',version:'1.0.0',dependencies:{kept:'1.0.0'}}));
  put('srv/app/package-lock.json', lock('kept'));
  put('opt/kit/package.json', JSON.stringify({name:'kit',version:'1.0.0',dependencies:{'kit-only':'1.0.0'}}));
  put('opt/kit/package-lock.json', lock('kit-only'));
  // A named pipe with a manifest name: reading it would block forever.
  if (process.platform !== 'win32') require('node:child_process').execFileSync('mkfifo', [path.join(root, 'srv/app/Gemfile.lock'), path.join(root, 'srv/app/server.pem')]);
  const names = async extra => {
    await exec(process.execPath, [cli, 'system', 'collect', root, ...extra, '--output', output], {env:{...process.env, HOME:home, USERPROFILE:home}, timeout:30000});
    return [...new Set(JSON.parse(fs.readFileSync(output, 'utf8')).targets.flatMap(t => (t.deps || []).map(d => d.name)))].sort();
  };
  const all = await names([]);
  assert.ok(all.includes('kept') && all.includes('kit-only'), all.join());
  const without = await names(['--exclude-path', 'opt/kit']);
  assert.ok(without.includes('kept') && !without.includes('kit-only'), without.join());
  const absolute = await names(['--exclude-path', path.join(root, 'opt/kit')]);
  assert.deepEqual(absolute, without);
  assert.equal(fs.existsSync(path.join(home, '.vigie-vuln')), false, 'collection does not create the client cache directory');
});
