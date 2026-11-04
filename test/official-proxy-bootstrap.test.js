'use strict';
require('./helpers/isolated-cache')('official-proxy-bootstrap');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const cli=path.resolve(__dirname,'../vigievuln.js');
test('proxy-only scan creates an official proxy key from an existing account session',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-bootstrap-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 // Use the real storage boundary: POSIX private mode, Windows DPAPI + ACLs.
 // A manually written plaintext fixture is intentionally rejected on Windows.
 require('../lib/account-session').createAccountSessionStore({homeDir:root}).write({token:'session_token',expiresAt:Date.now()+3600000});
 const configDir=path.join(root,'.vigie-vuln');fs.mkdirSync(configDir);
 fs.writeFileSync(path.join(configDir,'config.json'),JSON.stringify({sourceProfile:'proxy',proxyCache:'vigievuln'}));
 const project=path.join(root,'project');fs.mkdirSync(project);fs.writeFileSync(path.join(project,'package.json'),JSON.stringify({name:'fixture',version:'1.0.0',dependencies:{lodash:'4.17.20'}}));
 const calls=path.join(root,'calls.jsonl'),hook=path.join(root,'hook.cjs');
 fs.writeFileSync(hook,`const fs=require('node:fs');require('node:os').homedir=()=>${JSON.stringify(root)};\nglobalThis.fetch=async (url,init={})=>{fs.appendFileSync(${JSON.stringify(calls)},JSON.stringify({url:String(url),method:init.method||'GET',auth:init.headers?.authorization||null,proxyToken:init.headers?.['x-fad-proxy-token']||null,redirect:init.redirect})+'\\n');\nconst account={id:'account-id',email:'a@example.test',terms:{version:'v1',documentUrl:'/terms/v1',accepted:true}};\nif(url==='https://www.vigievuln.fr/v1/accounts/me')return Response.json({account});\nif(url==='https://www.vigievuln.fr/v1/accounts/proxy-keys')return Response.json({key:{token:'new_proxy_key'}});\nif(url==='https://api.vigievuln.fr/v1/proxy/status')return Response.json({ok:true,service:'vigievuln-proxy'});\nif(url==='https://api.vigievuln.fr/v1/resource'){const p=JSON.parse(init.body);const d=p.provider==='osv'&&p.type==='packages'?{results:(p.params.queries||[p.params]).map(()=>({vulns:[]}))}:{};return Response.json(d,{headers:{'x-fad-proxy-fetched-at':new Date().toISOString()}});}\nthrow Error('unexpected direct request '+url);};`);
 const env={...process.env,NODE_OPTIONS:`--require=${hook}`};delete env.VIGIEVULN_PROXY_CACHE_TOKEN;delete env.FAD_PROXY_CACHE_TOKEN;
 const report=path.join(root,'findings.json');
 const result=spawnSync(process.execPath,[cli,'scan',project,'--no-gcve','--no-euvd','--no-certfr','--no-nvd','--no-epss','--no-eol','--no-kev','--no-retire','--no-all-libs','--no-transitive','--report-json',report],{env,encoding:'utf8',timeout:30000});
 assert.equal(result.status,0,result.stdout+result.stderr);assert.match(result.stderr,/Proxy key created/);
 const records=fs.readFileSync(calls,'utf8').trim().split('\n').map(JSON.parse);
 assert.ok(records.some(x=>x.url==='https://www.vigievuln.fr/v1/accounts/me' && x.auth==='Bearer session_token'));
 assert.ok(records.some(x=>x.url==='https://www.vigievuln.fr/v1/accounts/proxy-keys' && x.method==='POST'));
 assert.ok(records.some(x=>x.url==='https://api.vigievuln.fr/v1/resource' && x.proxyToken==='new_proxy_key'));
 assert.ok(records.every(x=>x.url.startsWith('https://api.vigievuln.fr/') || ['https://www.vigievuln.fr/v1/accounts/me','https://www.vigievuln.fr/v1/accounts/proxy-keys'].includes(x.url)));
 assert.ok(records.every(x=>x.redirect==='error'));
});
