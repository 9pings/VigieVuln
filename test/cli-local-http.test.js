'use strict';
require('./helpers/isolated-cache')('local-http');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const {spawn,spawnSync}=require('node:child_process');
const cli=path.resolve(__dirname,'../vigievuln.js');
function run(args,root,env={}) {
 return new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,[cli,...args],{env:{...process.env,...env,NODE_OPTIONS:`--require=${path.join(root,'hook.cjs')}`},stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);
  child.on('error',reject);child.on('close',status=>resolve({status,stdout,stderr}));
 });
}
test('anonymous HTTP setup, seed and online scan require consent and never send an inherited key',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-http-flow-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.writeFileSync(path.join(root,'hook.cjs'),`require('node:os').homedir=()=>${JSON.stringify(root)};`);
 const seed=path.join(root,'seed','.vigie-vuln'),fetchedAt=Date.now();
 const document={id:'GHSA-http-flow',aliases:['CVE-2024-12345'],affected:[{package:{ecosystem:'npm',name:'lodash'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'4.17.21'}]}]}]};
 const seeded=require('../lib/advisory-store').openAdvisoryStore({cacheDir:seed});
 seeded.commit({records:[{source:'osv',document,fetchedAt}],coverages:[{source:'osv',ecosystem:'npm',fetchedAt,complete:true}]});seeded.close();
 const tar=path.join(root,'seed.tar.gz');
 const hits=[];
 const server=http.createServer((req,res)=>{hits.push({path:req.url,method:req.method,range:req.headers.range,authorization:req.headers.authorization,token:req.headers['x-fad-proxy-token']});
  if(req.url==='/v1/proxy/capabilities'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({service:'vigievuln-proxy',schema:1,authenticationRequired:false}));}
  if(req.url==='/dumps/vigievuln-cli-cache.tar.gz'){
   const data=fs.readFileSync(tar),headers={'content-type':'application/gzip','content-length':data.length};
   if(req.method==='HEAD'){res.writeHead(200,headers);return res.end();}
   if(req.headers.range==='bytes=0-16383'){
    const prefix=data.subarray(0,16384);res.writeHead(206,{...headers,'content-length':prefix.length,'content-range':`bytes 0-${prefix.length-1}/${data.length}`});return res.end(prefix);
   }
   res.writeHead(200,headers);return res.end(data);
  }
  if(req.url==='/v1/resource'){let input='';req.on('data',c=>input+=c);req.on('end',()=>{const p=JSON.parse(input);let data={};
    if(p.provider==='osv' && p.type==='packages')data={results:(p.params.queries||[p.params]).map(()=>({vulns:[{id:document.id}]}))};
    else if(p.provider==='osv' && p.type==='vuln')data=document;
    else if(p.provider==='npm')data={name:'lodash','dist-tags':{latest:'4.17.21'},versions:{'4.17.20':{version:'4.17.20'},'4.17.21':{version:'4.17.21'}}};
    res.writeHead(200,{'content-type':'application/json','x-fad-proxy-fetched-at':new Date().toISOString()});res.end(JSON.stringify(data));});return;}
  res.writeHead(404);res.end();
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const origin=`http://127.0.0.1:${server.address().port}`;
 await require('../lib/cache-archive-sqlite').exportCache(tar,{sourceDir:seed,proxyOrigin:origin});
 fs.mkdirSync(path.join(root,'.vigie-vuln'));fs.writeFileSync(path.join(root,'.vigie-vuln','config.json'),JSON.stringify({proxyCacheToken:'old-secret',proxyCacheTokenOrigin:'https://old.example'}));
 const setup=['setup','--mode','server','--server-url',origin,'--seed'];
 const denied=await run(setup,root);assert.notEqual(denied.status,0);assert.match(denied.stderr,/--allow-insecure-http/);assert.equal(hits.length,0);
 const done=await run([...setup,'--allow-insecure-http'],root);assert.equal(done.status,0,done.stderr);assert.match(done.stderr,/not encrypt/i);
 assert.deepEqual(hits.map(({path,method,range})=>({path,method,...(range?{range}:{})})),[
  {path:'/v1/proxy/capabilities',method:'GET'},
  {path:'/dumps/vigievuln-cli-cache.tar.gz',method:'HEAD'},
  {path:'/dumps/vigievuln-cli-cache.tar.gz',method:'GET',range:'bytes=0-16383'},
  {path:'/dumps/vigievuln-cli-cache.tar.gz',method:'GET'},
 ]);
 const config=JSON.parse(fs.readFileSync(path.join(root,'.vigie-vuln','config.json')));assert.equal(config.insecureHttpOrigin,origin);assert.equal(config.proxyAnonymousOrigin,origin);
 const identity=await run(['whoami'],root);assert.equal(identity.status,0,identity.stdout+identity.stderr);assert.match(identity.stdout,/anonymous access; login is not required/i);
 const project=path.join(root,'project');fs.mkdirSync(project);fs.writeFileSync(path.join(project,'package.json'),JSON.stringify({name:'fixture',version:'1.0.0',dependencies:{lodash:'4.17.20'}}));
 const report=path.join(root,'report.json');
 const scan=await run(['scan',project,'--advisory-query-ttl','0','--no-gcve','--no-euvd','--no-certfr','--no-nvd','--no-epss','--no-eol','--no-kev','--no-retire','--no-all-libs','--no-transitive','--report-json',report],root);
 assert.equal(scan.status,0,scan.stdout+scan.stderr);assert.ok(hits.some(x=>x.path==='/v1/resource'));assert.match(fs.readFileSync(report,'utf8'),/CVE-2024-12345/);
 assert.ok(hits.every(x=>!x.authorization && !x.token),'no stored credential is transmitted to anonymous server');
 const before=hits.length;
 const other=await run(['scan',project,'--proxy-cache',`http://localhost:${server.address().port}`],root);
 assert.equal(other.status,2);assert.match(other.stderr,/--allow-insecure-http/);assert.equal(hits.length,before,'consent is not transferred to another origin');
});

test('HTTP authenticated setup and subsequent login use the saved origin consent',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-http-auth-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.writeFileSync(path.join(root,'hook.cjs'),`require('node:os').homedir=()=>${JSON.stringify(root)};`);
 const account={id:'account-id',email:'user@example.test',terms:{version:'v1',documentUrl:'/terms/v1',accepted:true}};
 const hits=[];const server=http.createServer((req,res)=>{hits.push(req.url);res.setHeader('content-type','application/json');
  if(req.url==='/v1/proxy/capabilities')return res.end(JSON.stringify({service:'vigievuln-proxy',schema:1,authenticationRequired:true}));
  if(req.url==='/v1/accounts/login')return res.end(JSON.stringify({token:'account_token',tokenType:'Bearer',expiresAt:Date.now()+3600000,account}));
  if(req.url==='/v1/accounts/proxy-keys'){assert.equal(req.headers.authorization,'Bearer account_token');return res.end(JSON.stringify({key:{token:'proxy_token'}}));}
  if(req.url==='/v1/accounts/me'){assert.equal(req.headers.authorization,'Bearer account_token');return res.end(JSON.stringify({account}));}
  res.statusCode=404;res.end('{}');
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const origin=`http://127.0.0.1:${server.address().port}`,env={VIGIEVULN_EMAIL:'user@example.test',VIGIEVULN_PASSWORD:'test-only'};
 const result=await run(['setup','--mode','server','--server-url',origin,'--allow-insecure-http'],root,env);
 assert.equal(result.status,0,result.stdout+result.stderr);assert.deepEqual(hits,['/v1/proxy/capabilities','/v1/accounts/login','/v1/accounts/proxy-keys']);
 const file=path.join(root,'.vigie-vuln','config.json'),config=JSON.parse(fs.readFileSync(file));config.proxyAnonymousOrigin=origin;fs.writeFileSync(file,JSON.stringify(config));
 const status=await run(['whoami'],root);assert.equal(status.status,0,status.stdout+status.stderr);assert.equal(hits.at(-1),'/v1/accounts/me');assert.match(status.stderr,/not encrypt/i);
 assert.equal(JSON.parse(fs.readFileSync(file)).proxyAnonymousOrigin,origin,'status does not change mode');
 const login=await run(['login'],root);assert.equal(login.status,0,login.stdout+login.stderr);assert.equal(JSON.parse(fs.readFileSync(file)).proxyAnonymousOrigin,undefined,'successful explicit login restores authenticated mode');
});

test('explicit login records anonymous mode without changing the saved key; status remains read-only',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-http-anon-transition-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.writeFileSync(path.join(root,'hook.cjs'),`require('node:os').homedir=()=>${JSON.stringify(root)};`);
 const hits=[];const server=http.createServer((req,res)=>{
  hits.push({url:req.url,authorization:req.headers.authorization,token:req.headers['x-fad-proxy-token']});
  if(req.url==='/v1/proxy/capabilities'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({service:'vigievuln-proxy',schema:1,authenticationRequired:false}));}
  if(req.url==='/v1/resource'){let input='';req.on('data',c=>input+=c);req.on('end',()=>{const p=JSON.parse(input);let body={};
   if(p.provider==='osv' && p.type==='packages')body={results:(p.params.queries||[p.params]).map(()=>({vulns:[]}))};
   res.writeHead(200,{'content-type':'application/json','x-fad-proxy-fetched-at':new Date().toISOString()});res.end(JSON.stringify(body));});return;}
  res.writeHead(404);res.end();
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const origin=`http://127.0.0.1:${server.address().port}`, configDir=path.join(root,'.vigie-vuln'),configPath=path.join(configDir,'config.json');
 fs.mkdirSync(configDir);fs.writeFileSync(configPath,JSON.stringify({proxyCacheToken:'old-secret',proxyCacheTokenOrigin:'https://old.example',insecureHttpOrigin:origin}));
 const selected=await run(['--set-proxy-cache',origin],root);assert.equal(selected.status,0,selected.stdout+selected.stderr);
 const before=fs.readFileSync(configPath,'utf8');
 const status=await run(['whoami'],root);assert.equal(status.status,0,status.stdout+status.stderr);assert.equal(fs.readFileSync(configPath,'utf8'),before);
 const login=await run(['login'],root);assert.equal(login.status,0,login.stdout+login.stderr);assert.match(login.stdout,/anonymous access; login is not required/i);
 const config=JSON.parse(fs.readFileSync(configPath));assert.equal(config.proxyAnonymousOrigin,origin);assert.equal(config.proxyCacheToken,'old-secret');assert.equal(config.proxyCacheTokenOrigin,'https://old.example');
 const project=path.join(root,'project');fs.mkdirSync(project);fs.writeFileSync(path.join(project,'package.json'),JSON.stringify({name:'fixture',version:'1.0.0',dependencies:{lodash:'4.17.20'}}));
 const report=path.join(root,'report.json');
 const scan=await run(['scan',project,'--advisory-query-ttl','0','--no-gcve','--no-euvd','--no-certfr','--no-nvd','--no-epss','--no-eol','--no-kev','--no-retire','--no-all-libs','--no-transitive','--report-json',report],root);
 assert.equal(scan.status,0,scan.stdout+scan.stderr);assert.ok(hits.some(x=>x.url==='/v1/resource'));assert.ok(hits.every(x=>!x.authorization && !x.token));
});
