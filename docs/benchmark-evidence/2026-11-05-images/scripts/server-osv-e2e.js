'use strict';
// Real local server APIs, with this checkout's CLI library injected in memory.
// OSV replies are verbatim recordings; the mock changes transport only.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict');
const cli=path.resolve(__dirname,'../../../..'),fixtures=path.join(__dirname,'../server-fixtures');
const batch=JSON.parse(fs.readFileSync(path.join(fixtures,'querybatch.json'),'utf8'));
const docs=new Map((batch.results[0].vulns||[]).map(v=>[v.id,JSON.parse(fs.readFileSync(path.join(fixtures,v.id+'.json'),'utf8'))]));
const query={package:{ecosystem:'Debian:12',name:'apt'},version:'2.6.1'};
const inventory={distribution:{id:'debian',versionId:'12'},packages:[{manager:'dpkg',name:'apt',sourceName:'apt',sourceVersion:'2.6.1',version:'2.6.1',architecture:'amd64'}]};
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'vv-server-osv-e2e-'));
const routing=require(path.join(cli,'lib/providers')),system=require(path.join(cli,'lib/system-inventory'));
async function run(name){
 const repo=path.resolve(cli,'..',name),fad=require(path.join(repo,'lib/fad'));
 // No installation or mutation of the sibling repository: bind its official
 // shared-module hook to the code under test before loading server modules.
 fad.fad=rel=>require(path.join(cli,'lib',rel));fad.fadData=file=>require(path.join(cli,'data',file));
 const {driver,store,tokens,assets}=await require(path.join(repo,'test/helpers/db')).open(':memory:');
 const token=(await tokens.add({role:'client',label:'local-e2e'})).token;let upstream=0,requests=[];
 const fetcher=async(url,init={})=>{
  upstream++;const u=String(url);requests.push(u);
  if(u==='https://api.osv.dev/v1/querybatch'){
   const body=JSON.parse(init.body);assert.deepEqual(body.queries,[query]);return Response.json(batch);
  }
  const prefix='https://api.osv.dev/v1/vulns/';if(u.startsWith(prefix)){
   const id=decodeURIComponent(u.slice(prefix.length));assert.ok(docs.has(id));return Response.json(docs.get(id));
  }
  throw Error('Unexpected upstream');
 };
 const server=require(path.join(repo,'lib/server')).createServiceServer({store,tokens,assets,fetcher,localAnswers:true,log:()=>{}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const origin=`http://127.0.0.1:${server.address().port}`,cacheDir=path.join(temp,name);
 try{
  routing.configureResourceRoute({proxyUrl:origin,hosted:true,token,fetcher:null,store:null,hostedStore:null});
  const online=await system.assessTargetedSystemInventory(inventory,{cacheDir});
  assert.equal(online.coverage[0].status,'complete');assert.ok(online.matches.length>0);assert.equal(upstream,docs.size+1);
  let hostedBulkStatus=null;if(name==='server-main'){const r=await fetch(origin+'/v1/resource',{method:'POST',headers:{'content-type':'application/json','x-fad-proxy-token':token},body:JSON.stringify({provider:'osvdb',type:'ecosystem-archive',params:{ecosystem:'Debian'}})});hostedBulkStatus=r.status;assert.equal(hostedBulkStatus,410);}
  await new Promise(resolve=>server.close(resolve));routing.configureResourceRoute({proxyUrl:null,hosted:false,token:null});
  const offline=await system.assessTargetedSystemInventory(inventory,{cacheDir,offline:true,fetcher:()=>{throw Error('network access during offline replay')}});
  assert.equal(offline.coverage[0].status,'complete');assert.deepEqual(offline.matches.map(x=>x.cve.id).sort(),online.matches.map(x=>x.cve.id).sort());
  const unseen=await system.assessTargetedSystemInventory({...inventory,packages:[{...inventory.packages[0],version:'2.6.2',sourceVersion:'2.6.2'}]},{cacheDir,offline:true,fetcher:()=>{throw Error('network access during offline replay')}});assert.equal(unseen.coverage[0].status,'incomplete');
  return {server:name,clientLibrary:'checkout injected via fad.fad',ecosystem:query.package.ecosystem,package:query.package.name,version:query.version,upstreamCalls:upstream,queryRoutedToUpstream:requests.includes('https://api.osv.dev/v1/querybatch'),advisoryIds:online.matches.map(x=>x.cve.id).sort(),onlineCoverage:online.coverage[0],offlineCoverage:offline.coverage[0],offlineMatches:offline.matches.length,unseenVersionCoverage:unseen.coverage[0].status,...(hostedBulkStatus?{hostedBulkStatus}:{})};
 }finally{if(server.listening)await new Promise(resolve=>server.close(resolve));routing.configureResourceRoute({proxyUrl:null,hosted:false,token:null});await driver.close();}
}
(async()=>{try{const results=[];for(const name of ['server','server-main'])results.push(await run(name));console.log(JSON.stringify({schema:'vigievuln-server-osv-e2e/1',evidence:'actual localhost service APIs; recorded OSV upstream',recordedAt:'2026-11-05',results},null,2));}finally{require(path.join(cli,'lib/cache-db')).closeCacheDbs();fs.rmSync(temp,{recursive:true,force:true});}})().catch(e=>{console.error(e.stack);process.exitCode=1});
