const {test}=require('node:test');
const assert=require('node:assert/strict');
const {sanitizeDescriptor,createProject,updateProject,projectRequest,MAX_RESPONSE_BYTES}=require('../lib/project-client');
const sample={schema:'fad-deps/2',privatePath:'/secret',deps:[{ecosystem:'npm',ecosystemType:'npm',name:'demo',namespace:'',version:'1.0.0',scope:'prod',relation:'direct',manifestPath:'/secret'}]};
test('project uploads rebuild a path-free descriptor and reject redirects',async()=>{
 let got;
 const fetcher=async(url,opts)=>{got={url,opts};return Response.json({project:{id:'ok'}})};
 await createProject({session:'session',name:'demo',descriptor:sample,fetcher});
 assert.equal(got.url,'https://www.vigievuln.fr/v1/projects');assert.equal(got.opts.redirect,'error');
 assert.ok(!got.opts.body.includes('/secret'));assert.equal(JSON.parse(got.opts.body).descriptor.deps[0].relation,'direct');
 assert.throws(()=>sanitizeDescriptor({...sample,deps:[{...sample.deps[0],relation:'maybe'}]}),/invalid dependency/);
});
test('updates require explicit project id and revision and preserve conflict errors',async()=>{
 await assert.rejects(updateProject({session:'s',id:'bad',revision:1,descriptor:sample}),/id and current revision/);
 await assert.rejects(updateProject({session:'s',id:'12345678-1234-1234-1234-123456789abc',revision:2,descriptor:sample,
  fetcher:async()=>new Response('',{status:409})}),/HTTP 409/);
});

test('local paths and malformed coordinates are refused before create or update sends data', async () => {
 let calls=0;
 const fetcher=async()=>{calls++;return Response.json({project:{id:'ok'}})};
 for(const field of ['name','namespace']) {
  for(const value of ['/home/alice/private','//server/share','C:\\Users\\alice','C:/Users/alice','../private','./private',
   'name/../private','name//private','name/','https://registry/private',123,{},['private']]) {
   const descriptor={...sample,deps:[{...sample.deps[0],[field]:value}]};
   await assert.rejects(createProject({session:'s',name:'test',descriptor,fetcher}),/invalid dependency/);
   await assert.rejects(updateProject({session:'s',id:'12345678-1234-1234-1234-123456789abc',revision:1,descriptor,fetcher}),/invalid dependency/);
  }
 }
 assert.equal(calls,0);
 for(const [name,namespace] of [['@scope/package',''],['module','github.com/org'],['artifact','org.example'],['vendor/package',''],['package~variant','']]) {
  const result=sanitizeDescriptor({...sample,deps:[{...sample.deps[0],name,namespace}]});
  assert.equal(result.deps[0].name,name);
  assert.equal(result.deps[0].namespace,namespace);
 }
});

test('project transport reports safe typed errors, never response or transport secrets', async () => {
 const secret='SENTINEL';
 const request=fetcher=>projectRequest('/v1/projects',{session:'synthetic_session',fetcher});
 for(const fetcher of [
  async()=>new Response(secret,{headers:{'content-type':'application/json'}}),
  async()=>new Response(secret,{headers:{'content-type':'text/html'}}),
  ...[null,[],7].map(value=>async()=>Response.json(value)),
 ]) {
  await assert.rejects(request(fetcher),error=>error.code==='INVALID_RESPONSE' && !JSON.stringify(error).includes(secret) && !error.stack.includes(secret));
 }
 for(const fetcher of [async()=>{throw new Error(secret)},async()=>new Response(new ReadableStream({start(controller){controller.error(new Error(secret))}}),
  {headers:{'content-type':'application/json'}})]) {
  await assert.rejects(request(fetcher),error=>error.code==='NETWORK_ERROR' && !error.stack.includes(secret));
 }
 for(const [status,code] of [[401,'UNAUTHORIZED'],[403,'FORBIDDEN'],[409,'REVISION_CONFLICT'],[429,'RATE_LIMITED'],[502,'HTTP_ERROR']]) {
  await assert.rejects(request(async()=>new Response(secret,{status})),error=>error.code===code && error.status===status && !error.stack.includes(secret));
 }
 for(const fetcher of [async()=>new Response(null,{status:302}),async()=>({ok:true,status:200,redirected:true}),
  async()=>({ok:true,status:200,url:'https://other.invalid/v1/projects'})]) {
  await assert.rejects(request(fetcher),{code:'REDIRECT_REFUSED'});
 }
});

test('project responses are bounded by actual bytes, including chunked data and false lengths', async () => {
 const headers={'content-type':'application/json'};
 const exact='{"data":"'+'x'.repeat(MAX_RESPONSE_BYTES-11)+'"}';
 assert.equal(Buffer.byteLength(exact),MAX_RESPONSE_BYTES);
 assert.equal((await projectRequest('/v1/projects',{session:'s',fetcher:async()=>new Response(exact,{headers})})).data.length,MAX_RESPONSE_BYTES-11);
 for(const declared of [undefined,'1',String(MAX_RESPONSE_BYTES+1)]) {
  let cancelled=false;
  const stream=new ReadableStream({start(controller){
   controller.enqueue(Buffer.alloc(MAX_RESPONSE_BYTES,32));
   controller.enqueue(Buffer.from('é'));
  },cancel(){cancelled=true}});
  await assert.rejects(projectRequest('/v1/projects',{session:'s',fetcher:async()=>new Response(stream,
   {headers:{...headers,...(declared===undefined?{}:{'content-length':declared})}})}),{code:'RESPONSE_TOO_LARGE'});
  assert.equal(cancelled,true);
 }
});

test('project timeout covers a stalled body and a transport that ignores abort', async () => {
 let cancelled=false;
 await assert.rejects(projectRequest('/v1/projects',{session:'s',timeoutMs:20,fetcher:async()=>new Response(
  new ReadableStream({cancel(){cancelled=true}}),{headers:{'content-type':'application/json'}})}),{code:'TIMEOUT'});
 assert.equal(cancelled,true);
 await assert.rejects(projectRequest('/v1/projects',{session:'s',timeoutMs:20,fetcher:()=>new Promise(()=>{})}),{code:'TIMEOUT'});
});

test('CLI project push uses the saved account session and never forwards descriptor paths',()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'vigie-project-cli-'));
 try {
  fs.mkdirSync(path.join(home,'.vigievuln'),{mode:0o700});
  fs.writeFileSync(path.join(home,'.vigievuln','account-session.json'),JSON.stringify({token:'test_session_123',expiresAt:Date.now()+3600000}),{mode:0o600});
  const descriptor=path.join(home,'deps.json'),preload=path.join(home,'fake.cjs'),capture=path.join(home,'request.json');
  fs.writeFileSync(descriptor,JSON.stringify(sample));
  fs.writeFileSync(preload,`globalThis.fetch=async (url,opts)=>{ if(url.endsWith('/v1/accounts/me'))return Response.json({account:{id:'account',email:'test@example.test'}}); require('node:fs').writeFileSync(process.env.VV_CAPTURE,JSON.stringify({url,method:opts.method,body:opts.body})); return Response.json({project:{id:'12345678-1234-1234-1234-123456789abc',revision:1}}) }`);
  const r=spawnSync(process.execPath,[path.join(__dirname,'../vigievuln.js'),'project','push','--file',descriptor,'--name','demo'],
   {env:{...process.env,HOME:home,USERPROFILE:home,NODE_OPTIONS:`--require=${preload}`,VV_CAPTURE:capture},encoding:'utf8',timeout:15000});
  assert.equal(r.status,0,r.stderr);const req=JSON.parse(fs.readFileSync(capture,'utf8'));
  assert.equal(req.url,'https://www.vigievuln.fr/v1/projects');assert.ok(!req.body.includes('/secret'));
 } finally {fs.rmSync(home,{recursive:true,force:true})}
});
