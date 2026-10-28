const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { resolveHostedProxy, checkHostedProxy, loginForProxy } = require('../lib/hosted-proxy');

test('hosted proxy selects only the two official origins and requires an account key online', () => {
  assert.equal(resolveHostedProxy({vigievulnProxy:true}, {VIGIEVULN_PROXY_CACHE_TOKEN:'secret'}).proxyCache, 'https://api.vigievuln.fr');
  assert.equal(resolveHostedProxy({vigievulnProxy:'com',proxyCacheToken:'explicit'}, {}).proxyCache, 'https://api.vigievuln.com');
  assert.throws(()=>resolveHostedProxy({vigievulnProxy:'https://evil.invalid'}, {}), /fr or com/);
  assert.throws(()=>resolveHostedProxy({vigievulnProxy:true}, {}), /requires a proxy key/);
  assert.throws(()=>resolveHostedProxy({vigievulnProxy:true,proxyCache:'http://localhost'}, {}), /not both/);
  assert.equal(resolveHostedProxy({vigievulnProxy:true,offline:true}, {}).proxyCacheToken, null);
  for (const proxyCache of ['default','vigievuln']) {
    const resolved=resolveHostedProxy({proxyCache}, {VIGIEVULN_PROXY_CACHE_TOKEN:'secret'});
    assert.equal(resolved.proxyCache,'https://api.vigievuln.fr');
    assert.equal(resolved.vigievulnProxy,'fr');
  }
  assert.equal(resolveHostedProxy({proxyCache:'https://api.vigievuln.com/'},{VIGIEVULN_PROXY_CACHE_TOKEN:'secret'}).vigievulnProxy,'com');
});

test('proxy cache setting persists across CLI invocations and can be removed', () => {
  const fs=require('node:fs'),os=require('node:os');
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'vigie-proxy-setting-'));
  const env={...process.env,HOME:home,USERPROFILE:home,FORCE_COLOR:'0',VIGIEVULN_PROXY_CACHE_TOKEN:'',FAD_PROXY_CACHE_TOKEN:'',VIGIEVULN_ENV:'',FAD_CHECKER_ENV:''};
  const cli=path.join(__dirname,'../vigievuln.js');
  const run=(...args)=>spawnSync(process.execPath,[cli,...args],{env,encoding:'utf8'});
  try {
    assert.equal(run('--set-proxy-cache','vigievuln').status,0);
    const config=JSON.parse(fs.readFileSync(path.join(home,'.fad-checker','config.json'),'utf8'));
    assert.equal(config.proxyCache,'vigievuln');
    assert.match(run('--show-config').stdout,/"proxyCache": "vigievuln"/);
    const scan=run('-s',home);
    assert.equal(scan.status,2);
    assert.match(scan.stderr,/requires a proxy key/);
    assert.equal(run('--set-proxy-cache-token','secret-token-example').status,0);
    const shown=run('--show-config').stdout;
    assert.match(shown,/"proxyCacheToken": "\*\*\*"/);
    assert.doesNotMatch(shown,/secret-token-example/);
    assert.equal(run('--unset-proxy-cache-token').status,0);
    assert.equal(run('--set-proxy-cache','not-a-proxy').status,1);
    assert.equal(run('--unset-proxy-cache').status,0);
    assert.equal(JSON.parse(fs.readFileSync(path.join(home,'.fad-checker','config.json'),'utf8')).proxyCache,undefined);
  } finally {fs.rmSync(home,{recursive:true,force:true})}
});

test('account login creates a dedicated proxy key and logs out the session', async () => {
  const calls=[];
  const fetcher=async (url,opts)=>{
    calls.push({url,opts});
    if(url.endsWith('/login')) return Response.json({token:'session'});
    if(url.endsWith('/proxy-keys')) return Response.json({key:{token:'proxy-key'}},{status:201});
    return Response.json({revoked:1});
  };
  assert.equal(await loginForProxy({origin:'https://api.vigievuln.fr',email:'a@example.test',password:'secret',fetcher}),'proxy-key');
  assert.deepEqual(calls.map(c=>new URL(c.url).pathname),['/v1/accounts/login','/v1/accounts/proxy-keys','/v1/accounts/logout']);
  assert.equal(calls[1].opts.headers.authorization,'Bearer session');
  assert.ok(calls.every(c=>c.opts.redirect==='error'));
});

test('anonymized export works offline even with the official proxy configured and no key', () => {
  const fs=require('node:fs'),os=require('node:os');
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'vigie-offline-export-'));
  const project=path.join(home,'project');fs.mkdirSync(project);
  fs.writeFileSync(path.join(project,'package.json'),JSON.stringify({name:'example',version:'1.0.0',dependencies:{'left-pad':'1.3.0'}}));
  const preload=path.join(home,'block-network.cjs');
  fs.writeFileSync(preload,'globalThis.fetch = () => { throw new Error("unexpected network access") };');
  const env={...process.env,HOME:home,USERPROFILE:home,VIGIEVULN_PROXY_CACHE_TOKEN:'',FAD_PROXY_CACHE_TOKEN:'',VIGIEVULN_ENV:'',FAD_CHECKER_ENV:'',NODE_OPTIONS:`--require=${preload}`,FORCE_COLOR:'0'};
  const cli=path.join(__dirname,'../vigievuln.js');
  const run=(...args)=>spawnSync(process.execPath,[cli,...args],{env,encoding:'utf8',timeout:15000});
  try {
    assert.equal(run('--set-proxy-cache','vigievuln').status,0);
    const output=path.join(home,'deps.json');const r=run('-s',project,'--export-anonymized',output);
    assert.equal(r.status,0,r.stderr);assert.ok(fs.existsSync(output));
    const projectFile=path.join(home,'project.json');const prepared=run('-s',project,'--prepare-project',projectFile);
    assert.equal(prepared.status,0,prepared.stderr);
    assert.equal(JSON.parse(fs.readFileSync(projectFile,'utf8')).schema,'fad-deps/2');
  } finally {fs.rmSync(home,{recursive:true,force:true})}
});

test('preflight authenticates without redirects and fails clearly on expired keys', async () => {
  await checkHostedProxy('https://api.vigievuln.fr', 'secret', async (url, options) => {
    assert.equal(url, 'https://api.vigievuln.fr/v1/proxy/status');
    assert.equal(options.headers.authorization, 'Bearer secret');
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal);
    return Response.json({ok:true,service:'vigievuln-proxy'});
  });
  for (const status of [401,403]) await assert.rejects(checkHostedProxy('https://api.vigievuln.fr', 'secret', async()=>new Response('',{status})), /invalid, expired or revoked/);
  await assert.rejects(checkHostedProxy('https://api.vigievuln.fr','secret',async()=>Response.json({ok:true})), /unexpected/);
});

test('CLI rejects missing hosted credentials before starting a scan', () => {
  const env = {...process.env, VIGIEVULN_PROXY_CACHE_TOKEN:'', FAD_PROXY_CACHE_TOKEN:'', VIGIEVULN_ENV:'', FAD_CHECKER_ENV:'', FORCE_COLOR:'0'};
  const result=spawnSync(process.execPath,[path.join(__dirname,'../vigievuln.js'),'-s',__dirname,'--vigievuln-proxy'],{env,encoding:'utf8'});
  assert.equal(result.status,2);assert.match(result.stderr,/requires a proxy key/);assert.doesNotMatch(result.stdout,/Collection/);
});

test('hosted mode refuses explicitly requested bulk OSV imports',()=>{
 const env={...process.env,VIGIEVULN_PROXY_CACHE_TOKEN:'test-key',VIGIEVULN_ENV:'',FAD_CHECKER_ENV:'',FORCE_COLOR:'0'};
 for(const flags of [['--osv-db'],['-a','osv-db'],['--osv-db-refresh']]){
  const r=spawnSync(process.execPath,[path.join(__dirname,'../vigievuln.js'),'-s',__dirname,'--proxy-cache','default',...flags],{env,encoding:'utf8'});
  assert.equal(r.status,2);assert.match(r.stderr,/bulk archive/);
 }
});

test('hosted online lookups cannot be bypassed by an explicitly supplied local store', async () => {
  const {configureResourceRoute,getResource}=require('../lib/providers');
  let calls=0;
  const store={get(){throw new Error('hosted lookup must not read local store')}};
  configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,token:'test',store:null,health:null,
    fetcher:async()=>{calls++;return Response.json({data:[]})}});
  try {
    const result=await getResource('epss','scores',{ids:['CVE-2021-44228']},{store});
    assert.equal(result.status,200);assert.equal(calls,1);
  } finally {configureResourceRoute({proxyUrl:null,hosted:false,token:null,fetcher:null});}
});

test('hosted stale responses record the source and oldest cache date', async () => {
  const {configureResourceRoute,getResource}=require('../lib/providers');
  const {createSourceHealth}=require('../lib/source-health');
  const health=createSourceHealth();
  configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,token:'test',store:null,health,
    fetcher:async()=>Response.json({data:[]},{headers:{'x-fad-proxy':'stale','x-fad-proxy-fetched-at':'2026-10-27T10:00:00.000Z'}})});
  try {
    assert.equal((await getResource('epss','scores',{ids:['CVE-2021-44228']},{streaming:true})).status,200);
    assert.deepEqual(health.stale(),[{id:'epss',at:Date.parse('2026-10-27T10:00:00.000Z')}]);
    assert.deepEqual(health.degraded(),[]);
  } finally {configureResourceRoute({proxyUrl:null,hosted:false,token:null,fetcher:null,health:null});}
});

test('hosted Maven scanner requests only dependency keys and matches the returned CVEs', async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const { extractMavenRelevantCve } = require('../lib/cve-download');
  const { configureResourceRoute } = require('../lib/providers');
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/cve-samples/cve-2021-44228-real.json'), 'utf8'));
  const cve = extractMavenRelevantCve(fixture);
  const calls = [];
  configureResourceRoute({proxyUrl: 'https://proxy.invalid', token: 'test', store: null, health: null,
    fetcher: async (url, init) => {
      const body = JSON.parse(init.body); calls.push(body);
      assert.equal(body.type, 'cve-maven');
      assert.ok(body.params.keys.includes('p:org.apache.logging.log4j:log4j-core'));
      return new Response(JSON.stringify({cves: [cve], builtAt: '2026-10-28'}), {status: 200});
    }});
  try {
    const dep = {groupId:'org.apache.logging.log4j', artifactId:'log4j-core', version:'2.14.1', ecosystem:'maven', coordKey:'org.apache.logging.log4j:log4j-core'};
    const scanner = require('../lib/codecs/maven.codec').nativeScanners[0];
    const result = await scanner.scan(new Map([['log4j', dep]]), {hostedProxy:true});
    assert.ok(result.matches.some(m => m.cve.id === 'CVE-2021-44228'));
    assert.equal(calls.length, 1);
  } finally { configureResourceRoute({proxyUrl:null, token:null, fetcher:null}); }
});

test('a hosted scan writes stale source warnings in HTML and JSON and supports a strict gate', () => {
  const fs=require('node:fs'),os=require('node:os');const home=fs.mkdtempSync(path.join(os.tmpdir(),'vigie-stale-report-'));
  const project=path.join(home,'project');fs.mkdirSync(project);
  fs.writeFileSync(path.join(project,'pom.xml'),'<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>demo</artifactId><version>1</version><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>1.0</version></dependency></dependencies></project>');
  const hook=path.join(home,'hook.cjs');
  fs.writeFileSync(hook,`globalThis.fetch=async (url,init={})=>{if(String(url).endsWith('/v1/proxy/status'))return Response.json({ok:true,service:'vigievuln-proxy'});if(String(url).endsWith('/v1/resource'))return process.env.VV_MISSING ? new Response('',{status:503}) : Response.json({cves:[],builtAt:'2026-10-27'},{headers:{'x-fad-proxy':'stale','x-fad-proxy-fetched-at':'2026-10-27T10:00:00.000Z'}});throw Error('unexpected network')}`);
  const env={...process.env,HOME:home,USERPROFILE:home,VIGIEVULN_PROXY_CACHE_TOKEN:'test-key',VIGIEVULN_ENV:'',FAD_CHECKER_ENV:'',NODE_OPTIONS:`--require=${hook}`,FORCE_COLOR:'0'};
  const out=path.join(home,'out');
  try {
    const args=[path.join(__dirname,'../vigievuln.js'),'-s',project,'--proxy-cache','default','--retries','0','--no-transitive','--no-all-libs','--no-osv','--no-nvd','--no-epss','--no-kev','--no-euvd','--no-certfr','--no-eol','--no-binaries','--no-jars','--no-certs','--report-html','--report-json','-o',out,'--fail-on-incomplete','sources'];
    const r=spawnSync(process.execPath,args,{env,encoding:'utf8',timeout:20000});
    assert.equal(r.status,2,r.stderr+'\n'+r.stdout);
    const html=fs.readFileSync(path.join(out,'cve-report.html'),'utf8');
    const files=fs.readdirSync(out).filter(x=>x.endsWith('.json'));assert.ok(files.length);
    const report=JSON.parse(fs.readFileSync(path.join(out,files[0]),'utf8'));
    assert.match(html,/2026-10-27T10:00:00/);
    assert.ok(report.warnings.some(w=>w.type==='source-stale' && w.message.includes('2026-10-27T10:00:00')));
    const missingOut=path.join(home,'missing');
    const missingArgs=args.slice(0,-2);missingArgs[missingArgs.indexOf('-o')+1]=missingOut;
    const missing=spawnSync(process.execPath,missingArgs,{env:{...env,VV_MISSING:'1'},encoding:'utf8',timeout:20000});
    assert.equal(missing.status,0,missing.stderr+'\n'+missing.stdout);
    const missingFile=fs.readdirSync(missingOut).find(x=>x.endsWith('.json'));
    const missingReport=JSON.parse(fs.readFileSync(path.join(missingOut,missingFile),'utf8'));
    assert.ok(missingReport.warnings.some(w=>w.type==='source-unavailable'));
  } finally {fs.rmSync(home,{recursive:true,force:true})}
});

test('hosted EUVD uses only matching CVE identifiers and no bulk catalogue', async () => {
  const { configureResourceRoute } = require('../lib/providers');
  const { enrichEuvd } = require('../lib/euvd');
  const calls = [];
  const fetcher=async (url,init)=>{
    const body=JSON.parse(init.body); calls.push(body); assert.equal(body.type,'cves');
    return new Response(JSON.stringify({items:[{cve:'CVE-2021-44228',id:'EUVD-2021-34768',exploitedSince:'2021-12-10'}]}),{status:200});
  };
  configureResourceRoute({proxyUrl:'https://proxy.invalid',token:'test',store:null,health:null,fetcher});
  try {
    const matches=[{cve:{id:'CVE-2021-44228'}}];
    await enrichEuvd(matches,{hostedProxy:true,fetcher});
    assert.deepEqual(matches[0].cve.euvd,{id:'EUVD-2021-34768',exploitedSince:'2021-12-10'});
    assert.equal(calls.length,1);
  } finally { configureResourceRoute({proxyUrl:null,token:null,fetcher:null}); }
});

test('hosted CERT-FR uses only relevant CVE identifiers, not the advisory catalogue', async () => {
  const { configureResourceRoute } = require('../lib/providers');
  const { enrichCertFr } = require('../lib/certfr');
  const calls = [];
  const fetcher=async (url,init)=>{
    const body=JSON.parse(init.body); calls.push(body); assert.equal(body.type,'cves');
    return new Response(JSON.stringify({items:[{cve:'CVE-2021-44228',advisories:[{ref:'CERTFR-2021-ALE-022',kind:'alerte',title:'Log4j'}]}]}),{status:200});
  };
  configureResourceRoute({proxyUrl:'https://proxy.invalid',token:'test',store:null,health:null,fetcher});
  try {
    const matches=[{cve:{id:'CVE-2021-44228'}}];
    await enrichCertFr(matches,{hostedProxy:true,fetcher});
    assert.equal(matches[0].cve.certfr[0].ref,'CERTFR-2021-ALE-022');
    assert.equal(calls.length,1);
  } finally { configureResourceRoute({proxyUrl:null,token:null,fetcher:null}); }
});

test('hosted KEV uses targeted CVE identifiers and preserves exploitation details', async () => {
  const { configureResourceRoute } = require('../lib/providers');
  const { enrichKev } = require('../lib/kev');
  const calls=[];
  const fetcher=async (url,init)=>{const body=JSON.parse(init.body);calls.push(body);assert.equal(body.type,'cves');return new Response(JSON.stringify({items:[{cve:'CVE-2021-44228',kev:{dateAdded:'2021-12-10',dueDate:'2021-12-24',ransomware:true}}]}),{status:200});};
  configureResourceRoute({proxyUrl:'https://proxy.invalid',token:'test',store:null,health:null,fetcher});
  try { const matches=[{cve:{id:'CVE-2021-44228'}}]; await enrichKev(matches,{hostedProxy:true,fetcher});assert.equal(matches[0].cve.kev,true);assert.equal(matches[0].cve.kevRansomware,true);assert.equal(calls.length,1); }
  finally { configureResourceRoute({proxyUrl:null,token:null,fetcher:null}); }
});
