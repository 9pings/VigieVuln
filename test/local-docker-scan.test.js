'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),tar=require('tar-stream');
test('a named local Docker image is collected without registry access and retains its requested identity',{skip:process.platform==='win32'},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-docker-input-')),socket=path.join(root,'docker.sock');
 const pack=tar.pack(),parts=[];pack.on('data',p=>parts.push(p));
 const ended=new Promise(r=>pack.on('end',r));pack.entry({name:'etc/os-release'},'ID=debian\nVERSION_ID=12\n');
 pack.entry({name:'var/lib/dpkg/status'},'Package: demo\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n');pack.finalize();await ended;
 const requests=[],id='sha256:'+'a'.repeat(64);
 const server=http.createServer((req,res)=>{
  requests.push(req.url);
  if(req.url==='/images/local%3Afixture/json'){res.setHeader('content-type','application/json');res.end(JSON.stringify({Id:id,RepoTags:['local:fixture']}));}
  else if(req.url==='/images/'+encodeURIComponent(id)+'/get'){res.end(Buffer.concat(parts));}
  else res.writeHead(404).end();
 });
 await new Promise(r=>server.listen(socket,r));
 t.after(async()=>{await new Promise(r=>server.close(r));fs.rmSync(root,{recursive:true,force:true});});
 const inventories=await require('../lib/artifacts/scan').acquireInventories('local:fixture',{system:true,localDockerReference:'local:fixture',dockerSocket:socket,fetcher:()=>assert.fail('registry bypass')});
 assert.equal(inventories.length,1);
 assert.equal(inventories[0].metadata.acquisition.reference,'local:fixture');
 assert.equal(inventories[0].metadata.localDocker.id,id);
 assert.ok(inventories[0].metadata.systemApplications);
 assert.ok(inventories[0].packages.some(p=>p.name==='demo'));
 assert.equal(requests.length,2);
});
test('an absent Docker image permits the normal registry fallback',{skip:process.platform==='win32'},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-docker-miss-')),socket=path.join(root,'docker.sock');
 const server=http.createServer((req,res)=>res.writeHead(404).end());await new Promise(r=>server.listen(socket,r));
 t.after(async()=>{await new Promise(r=>server.close(r));fs.rmSync(root,{recursive:true,force:true});});
 assert.equal(await require('../lib/local-docker').openImage('absent:tag',socket),null);
 assert.equal(await require('../lib/local-docker').openImage('absent:tag',socket+'.missing'),null);
});
