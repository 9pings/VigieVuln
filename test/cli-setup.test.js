const isolatedTestCache = require('./helpers/isolated-cache')('setup-http');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { run, proxyOrigin, downloadSeed, authenticationRequired } = require('../lib/cli-setup');

function setupDeps(answers, cfg = {}) {
  const output = [], saved = [], sessions = [];
  const config = { load:()=>structuredClone(cfg), save:value=>saved.push(value) };
  const ask = async () => { if (!answers.length) throw Error('unexpected prompt'); return answers.shift(); };
  const select = async (_message, choices) => { if (!answers.length) throw Error('unexpected selection'); const value=answers.shift() || choices[0].name; assert.ok(choices.some(c=>c.name===value)); return value; };
  const createSessionStore = () => ({ read:()=>null, write:s=>sessions.push(s) });
  const createAccountClient = ({sessionStore, accountOrigin}) => ({
    me:async()=>{throw Error('no session');},
    createProxyKey:async()=>({token:'proxy-secret'}),
    accountOrigin, sessionStore,
  });
  const ensureSignedIn = async ({store, account}) => { store.write({token:'session-secret',origin:account.accountOrigin}); return {}; };
  return { interactive:true, ask, select, banner:()=>output.push('banner'), config, createSessionStore, createAccountClient, ensureSignedIn,
    authenticationRequired:async()=>true, proxyScope:()=>'/scope/.vigie-vuln', out:s=>output.push(s), warn:s=>output.push(s), saved, sessions, output };
}

test('setup defaults to all sources and retains other settings', async () => {
 const d = setupDeps(['','',''], { nvd_api_key:'old', proxyCache:'vigievuln' });
 await run([], d);
 assert.equal(d.saved[0].sourceProfile, 'all');
 assert.equal(d.saved[0].nvd_api_key, 'old');
 assert.equal(d.saved[0].proxyCache, undefined);
 assert.equal(d.sessions.length, 0);
 assert.equal(d.output[0], 'banner');
});

test('official server asks for seed before login and does not ask for source region', async () => {
 const d=setupDeps(['official','no']); const steps=[];
 const choose=d.select; d.select=async (message,choices)=>{steps.push(message);return choose(message,choices);};
 d.ensureSignedIn=async ({store})=>{steps.push('login');store.write({token:'session'});};
 await run([],d);
 assert.deepEqual(steps.map(s=>s==='login' ? s : s.startsWith('How') ? 'mode' : 'seed'),['mode','seed','login']);
 assert.equal(d.saved[0].sourceProfile,'proxy');
});

test('autonomous EU choice skips login when no seed is selected', async () => {
 const d=setupDeps(['direct','eu','no']);
 await run([],d);
 assert.equal(d.saved[0].sourceProfile,'eu');
 assert.equal(d.sessions.length,0);
});

test('flags configure an autonomous profile without any terminal or prompt', async () => {
 const d=setupDeps([]); d.interactive=false; d.env={};
 d.ask=d.select=()=>{throw Error('unexpected prompt');};
 await run(['--mode','direct','--sources','eu'],d);
 assert.equal(d.saved[0].sourceProfile,'eu');
});

test('flags authenticate a server from environment, then seed without a prompt', async () => {
 const d=setupDeps([]);d.interactive=false;d.env={VIGIEVULN_EMAIL:'person@example.test',VIGIEVULN_PASSWORD:'secret'};
 d.ask=d.select=()=>{throw Error('unexpected prompt');};
 d.createAccountClient=({sessionStore})=>({login:async credentials=>{assert.equal(credentials.password,'secret');sessionStore.write({token:'session'});return {terms:{accepted:true}};},createProxyKey:async()=>({token:'proxy-secret'})});
 let seed;d.downloadSeed=async v=>{seed=v;};
 await run(['--mode','server','--server-url','https://proxy.example','--seed'],d);
 assert.equal(seed.origin,'https://proxy.example');assert.equal(d.saved[0].sourceProfile,'proxy');
 assert.ok(!JSON.stringify(d.saved).includes('secret') || d.saved[0].proxyCacheToken==='proxy-secret');
});

test('flags reject ambiguous configuration and unaccepted terms without saving', async () => {
 const d=setupDeps([]);d.interactive=false;d.env={VIGIEVULN_EMAIL:'x',VIGIEVULN_PASSWORD:'y'};
 await assert.rejects(run(['--mode','official','--sources','eu'],d),/--sources/);
 d.createAccountClient=()=>({login:async()=>({terms:{accepted:false,version:'1',url:'https://example.test/terms/1'}})});
 await assert.rejects(run(['--mode','official'],d),/terms acceptance required/);
 assert.deepEqual(d.saved,[]);
});

test('unattended terms acceptance requires an exact explicitly selected version', async () => {
 const d=setupDeps([]);d.interactive=false;d.env={VIGIEVULN_EMAIL:'x',VIGIEVULN_PASSWORD:'y'};
 let accepted=[];
 d.createAccountClient=({sessionStore})=>({login:async()=>{sessionStore.write({token:'session'});return {terms:{accepted:false,version:'2',url:'https://example.test/terms/2'}};},acceptTerms:async v=>accepted.push(v),createProxyKey:async()=>({token:'proxy-secret'})});
 await assert.rejects(run(['--mode','official','--accept-terms','1'],d),/version does not match/);
 assert.deepEqual(accepted,[]);
 await run(['--mode','official','--accept-terms','2'],d);
 assert.deepEqual(accepted,['2']);
});

test('proxy setup signs in, imports only after sign-in, and persists origin-bound token', async () => {
 const d = setupDeps(['custom','https://proxy.example','yes'], {someSetting:true});
 const calls = [];
 d.downloadSeed = async v => {calls.push(v);assert.equal(d.saved.length,0);};
 await run([], d);
 assert.deepEqual(calls, [{origin:'https://proxy.example',token:'session-secret',targetDir:'/scope/.vigie-vuln'}]);
 assert.equal(d.saved[0].proxyCache,'https://proxy.example');
 assert.equal(d.saved[0].proxyCacheTokenOrigin,'https://proxy.example');
 assert.equal(d.saved[0].sourceProfile,'proxy');
 assert.equal(d.sessions[0].origin,'https://proxy.example');
 assert.ok(d.output.some(s=>s.includes('https://proxy.example/account')));
 assert.ok(!d.output.join(' ').includes('proxy-secret'));
});

test('a failed seed leaves old config and session untouched', async () => {
 const d = setupDeps(['official','yes'], {someSetting:true});
 let issued=0;
 const original=d.createAccountClient;
 d.createAccountClient=opts=>({...original(opts),createProxyKey:async()=>{issued++;return {token:'proxy-secret'};}});
 d.downloadSeed = async ()=>{throw Error('seed unavailable');};
 await assert.rejects(run([], d), /seed unavailable/);
 assert.deepEqual(d.saved, []);
 assert.deepEqual(d.sessions, []);
 assert.equal(issued,0,'failed or interrupted seed must not create an orphaned proxy key');
});

test('proxy key is created only after successful authenticated seed import', async () => {
 const d=setupDeps(['official','yes']);const order=[];
 const original=d.createAccountClient;
 d.createAccountClient=opts=>({...original(opts),createProxyKey:async()=>{order.push('key');return {token:'proxy-secret'};}});
 d.downloadSeed=async args=>{assert.equal(args.token,'session-secret');order.push('seed');};
 await run([],d);
 assert.deepEqual(order,['seed','key']);assert.equal(d.saved[0].proxyCacheToken,'proxy-secret');
});

test('direct profile can seed from a chosen custom proxy using that account', async () => {
 const d = setupDeps(['direct','all','yes','custom','https://custom.example'], {proxyCache:'https://old.example'});
 const original=d.createAccountClient;let issued=0;
 d.createAccountClient=opts=>({...original(opts),createProxyKey:async()=>{issued++;return {token:'proxy-secret'};}});
 let call; d.downloadSeed = async value => {call=value;};
 await run([],d);
 assert.equal(call.origin,'https://custom.example');
 assert.equal(call.targetDir,undefined);
 assert.equal(d.sessions[0].origin,'https://custom.example');
 assert.equal(d.saved[0].sourceProfile,'all');
 assert.equal(d.saved[0].proxyCache,undefined);
 assert.equal(issued,0,'direct mode needs no proxy key after seeding');
});

test('proxy origins accept explicit HTTP and forbid credentials, paths, and fragments', () => {
 for (const value of ['https://user:pass@example.test','https://example.test/path','https://example.test/#x'])
  assert.throws(()=>proxyOrigin(value));
 assert.equal(proxyOrigin('http://127.0.0.1:8000'), 'http://127.0.0.1:8000');
 assert.equal(proxyOrigin('http://192.168.1.10:8000'), 'http://192.168.1.10:8000');
 assert.equal(proxyOrigin('http://vigie.internal:8000'), 'http://vigie.internal:8000');
});

test('HTTP setup refuses before login or seed without explicit consent', async () => {
 const d=setupDeps([]); d.interactive=false; d.env={};let calls=0;
 d.ensureSignedIn=async()=>{calls++;};d.downloadSeed=async()=>{calls++;};
 await assert.rejects(run(['--mode','server','--server-url','http://192.168.1.10:8000','--seed'],d),/--allow-insecure-http/);
 assert.equal(calls,0);assert.deepEqual(d.saved,[]);
 assert.ok(d.output.some(x=>/passwords.*exposed/i.test(x)));
});

test('HTTP interactive consent is specific to the origin and can be declined', async () => {
 const d=setupDeps(['custom','http://vigie.internal:8000','no','no']);let calls=0;
 d.ensureSignedIn=async()=>{calls++;};
 await assert.rejects(run([],d),/not approved/);assert.equal(calls,0);assert.deepEqual(d.saved,[]);
 const accepted=setupDeps(['custom','http://vigie.internal:8000','no','yes']);
 await run([],accepted);assert.equal(accepted.saved[0].insecureHttpOrigin,'http://vigie.internal:8000');
 const repeat=setupDeps([],{insecureHttpOrigin:'http://vigie.internal:8000'});repeat.interactive=false;repeat.env={};
 await run(['--mode','server','--server-url','http://vigie.internal:8000'],repeat);
 assert.equal(repeat.saved[0].insecureHttpOrigin,'http://vigie.internal:8000');
 const other=setupDeps([],{insecureHttpOrigin:'http://vigie.internal:8000'});other.interactive=false;other.env={};
 await assert.rejects(run(['--mode','server','--server-url','http://other.internal:8000'],other),/--allow-insecure-http/);
});

test('HTTP non-interactive setup explicitly authorizes seed and preserves origin', async () => {
 const d=setupDeps([]);d.interactive=false;d.env={};let seed;
 d.downloadSeed=async value=>{seed=value;};
 await run(['--mode','server','--server-url','http://192.168.1.10:8000','--seed','--allow-insecure-http'],d);
 assert.equal(seed.origin,'http://192.168.1.10:8000');
 assert.equal(d.saved[0].insecureHttpOrigin,seed.origin);
 assert.equal(d.saved[0].proxyCacheTokenOrigin,seed.origin);
});

test('regional setup warns about incomplete coverage and disabled features', async () => {
 const d=setupDeps(['direct','eu','no']);await run([],d);
 assert.ok(d.output.some(s=>/limits advisory coverage.*CMS.*binary/i.test(s)));
});

test('only a valid explicit capability permits anonymous setup and seed', async () => {
 const d=setupDeps([],{proxyCacheToken:'old-key',proxyCacheTokenOrigin:'https://old.example'});d.interactive=false;d.env={};
 d.authenticationRequired=async()=>false;d.ensureSignedIn=()=>{throw Error('unexpected authentication');};
 let seed;d.downloadSeed=async args=>{seed=args;};
 await run(['--mode','server','--server-url','http://vigie.internal:8000','--allow-insecure-http','--seed'],d);
 assert.deepEqual(seed,{origin:'http://vigie.internal:8000',anonymous:true,targetDir:'/scope/.vigie-vuln'});
 assert.equal(d.saved[0].proxyAnonymousOrigin,seed.origin);assert.equal(d.saved[0].insecureHttpOrigin,seed.origin);
 assert.equal(d.saved[0].proxyCacheToken,'old-key');assert.equal(d.sessions.length,0);
});

test('capability probe defaults to authentication for all failures and invalid responses', async () => {
 const origin='http://127.0.0.1:12345';let called;
 assert.equal(await authenticationRequired(origin,async (url,init)=>{called={url,init};return Response.json({service:'vigievuln-proxy',schema:1,authenticationRequired:false});}),false);
 assert.equal(called.url,origin+'/v1/proxy/capabilities');assert.equal(called.init.redirect,'error');assert.equal(called.init.credentials,'omit');assert.equal(called.init.headers,undefined);
 for (const fetcher of [async()=>{throw Error('offline');},async()=>new Response('',{status:404}),async()=>Response.json({authenticationRequired:false}),async()=>Response.json({service:'vigievuln-proxy',schema:1,authenticationRequired:'false'}),async()=>new Response('x'.repeat(9000),{headers:{'content-type':'application/json'}})])
  assert.equal(await authenticationRequired(origin,fetcher),true);
});

test('anonymous seed omits authorization and keeps redirect protection', async () => {
 let request;
 await downloadSeed({origin:'http://127.0.0.1:12345',anonymous:true,fetcher:async (url,options)=>{request={url,options};return new Response(Buffer.from('seed'),{headers:{'content-type':'application/gzip'}});},importFn:async()=>{}});
 assert.equal(request.options.headers.authorization,undefined);assert.equal(request.options.redirect,'error');
 await assert.rejects(downloadSeed({origin:'http://127.0.0.1:12345',fetcher:()=>{throw Error('must not fetch');}}),/Sign in/);
});

test('seed reports connection, downloaded bytes and archive import progress', async () => {
 const events=[];
 const bytes=Buffer.from('seed data');
 await downloadSeed({origin:'https://proxy.example',token:'test-token',onProgress:e=>events.push(e),
  fetcher:async()=>new Response(bytes,{headers:{'content-type':'application/gzip','content-length':String(bytes.length)}}),
  importFn:async (_file,opts)=>{opts.onProgress({phase:'extracting'});opts.onProgress({phase:'merging'});return {stats:{skipped:[]}};}});
 assert.equal(events[0].phase,'connecting');
 assert.ok(events.some(e=>e.phase==='downloading' && e.bytes===bytes.length && e.total===bytes.length));
 assert.ok(events.some(e=>e.phase==='downloaded' && e.bytes===bytes.length));
 assert.deepEqual(events.slice(-2).map(e=>e.phase),['extracting','merging']);
 assert.ok(!JSON.stringify(events).includes('test-token'));
});

test('seed download authenticates, refuses redirects and merges without replacing', async () => {
 let request, bytes;
 const fakeFetch = async (url, options) => {request={url,options};return new Response(Buffer.from('seed'),{headers:{'content-type':'application/gzip'}});};
 await downloadSeed({origin:'https://proxy.example',token:'secret',fetcher:fakeFetch,importFn:async (file,opts)=>{bytes=fs.readFileSync(file,'utf8');assert.deepEqual(opts,{replace:false,force:false});}});
 assert.equal(bytes,'seed');
 assert.equal(request.options.headers.authorization,'Bearer secret');
 assert.equal(request.options.redirect,'error');
 assert.equal(request.url,'https://proxy.example/dumps/vigievuln-cli-cache.tar.gz');
 await assert.rejects(downloadSeed({origin:'https://proxy.example',token:'secret',fetcher:async()=>new Response('',{status:302,headers:{location:'https://evil.test'}})}));
});

test('official proxy seed is fetched from the canonical website without redirects', async () => {
 let request;
 await downloadSeed({origin:'https://api.vigievuln.fr',token:'secret',fetcher:async (url,options)=>{request={url,options};return new Response(Buffer.from('seed'),{headers:{'content-type':'application/gzip'}});},importFn:async()=>{}});
 assert.equal(request.url,'https://www.vigievuln.fr/dumps/vigievuln-cli-cache.tar.gz');
 assert.equal(request.options.redirect,'error');
 assert.equal(request.options.headers.authorization,'Bearer secret');
});
