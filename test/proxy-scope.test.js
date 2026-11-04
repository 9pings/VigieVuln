const isolatedTestCache = require('./helpers/isolated-cache')('proxy-scope');
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {proxyScope} = require('../lib/proxy-scope');

test('proxy origins use isolated persistent scopes and refuse unmarked existing scopes', t => {
 const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-proxy-scope-'));
 t.after(()=>fs.rmSync(homeDir, {recursive:true, force:true}));
 const a = proxyScope('https://a.example', {homeDir});
 const b = proxyScope('https://b.example', {homeDir});
 assert.notEqual(a,b);
 assert.equal(proxyScope('https://a.example/', {homeDir}),a);
 fs.mkdirSync(a); fs.writeFileSync(path.join(a,'entry'),'a');
 assert.equal(fs.existsSync(path.join(b,'entry')),false);
 fs.rmSync(path.join(path.dirname(a),'origin.json'));
 assert.throws(()=>proxyScope('https://a.example',{homeDir}), /no origin marker/);
});

test('proxy offline scan reads an imported advisory from its isolated cache without fetch', async t => {
 const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-proxy-offline-'));
 t.after(()=>fs.rmSync(dir, {recursive:true, force:true}));
 const project = path.join(dir,'project'); fs.mkdirSync(project);
 fs.writeFileSync(path.join(project,'package.json'), JSON.stringify({name:'fixture',version:'1.0.0',dependencies:{lodash:'4.17.20'}}));
 const seedDir = path.join(dir,'seed','.vigie-vuln');
 const advisory = {id:'GHSA-test',aliases:['CVE-2024-12345'],affected:[{package:{ecosystem:'npm',name:'lodash'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'4.17.21'}]}]}]};
 const fetchedAt=Date.now();
 const seedStore = require('../lib/advisory-store').openAdvisoryStore({cacheDir:seedDir});
 try {
  seedStore.commit({
   records:[{source:'osv',document:advisory,fetchedAt,provenance:{transport:'seed'}}],
   coverages:[{source:'osv',ecosystem:'npm',fetchedAt,complete:true,provenance:{transport:'seed'}}],
  });
 } finally { seedStore.close(); }
 const archive = path.join(dir,'seed.tar.gz');
 const packed = spawnSync('tar',['-czf',archive,'-C',path.join(dir,'seed'),'.vigie-vuln'],{encoding:'utf8'});
 assert.equal(packed.status,0,packed.stderr);
 const scoped = proxyScope('https://proxy.example',{homeDir:dir});
 await require('../lib/cache-archive').importCache(archive,{targetDir:scoped});
 const hook = path.join(dir,'hook.js');
 fs.writeFileSync(hook, `require('node:os').homedir = () => ${JSON.stringify(dir)}; globalThis.fetch = () => { throw Error('NETWORK_ATTEMPT'); };`);
 const report = path.join(dir,'report.json');
 const child = spawnSync(process.execPath, [path.join(__dirname,'..','vigievuln.js'), '--src',project,'--offline','--source-profile','proxy','--proxy-cache','https://proxy.example','--report-json',report,'--no-retire','--no-gcve'], {
  encoding:'utf8', timeout:30000, env:{...process.env, NODE_OPTIONS:`--require=${hook}`}
 });
 assert.equal(child.status,0,child.stderr + child.stdout);
 assert.doesNotMatch(child.stderr + child.stdout,/NETWORK_ATTEMPT/);
 assert.match(fs.readFileSync(report,'utf8'),/CVE-2024-12345/);
});
