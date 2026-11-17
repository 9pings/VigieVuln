'use strict';
// Local preview only; reads the saved Debian OSV cache and frozen NVD metadata.
const fs=require('node:fs'),path=require('node:path'),zlib=require('node:zlib'),{spawn}=require('node:child_process');
const cli=path.resolve(__dirname,'../../../..'),serverRepo=path.resolve(cli,'../server-main'),dir=path.resolve(__dirname,'..');
(async()=>{
 const repo=require(path.join(cli,'lib/cache-repository')).createCacheRepository('/tmp/vv-image-benchmark-20261105/nginx/direct-cache');
 const record=repo.get('system-osv:Debian:11','openssl').value.find(r=>r.id==='DLA-3942-1');
 const metadata=JSON.parse(zlib.gunzipSync(fs.readFileSync(path.join(dir,'metadata-refresh/nginx-nvd-records.json.gz'))));
 const {driver,assets,store,tokens}=await require(path.join(serverRepo,'test/helpers/db')).open(':memory:');
 let server;
 try{
  await assets.upsert(require(path.join(serverRepo,'lib/jobs/osv')).osvAsset(record).asset);
  for(const id of record.upstream.filter(v=>/^CVE-/.test(v))){
   const body=metadata.records.find(r=>r.id===id)?.body;if(!body)continue;
   await assets.upsert({type:'cve',key:id,title:id,published:true,data:{id,description:body.description||''}});
   await assets.setNvd([{id,published:body.published,metrics:body.score==null?[]:[{source:'NVD',score:body.score,severity:body.severity,vector:body.cvssVector,version:String(body.cvssVersion||'').replace(/^CVSS:/,'')}]}]);
  }
  server=require(path.join(serverRepo,'lib/server')).createServiceServer({assets,store,tokens,log:()=>{}});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const url=`http://127.0.0.1:${server.address().port}/advisory/osv/DLA-3942-1?lang=en`,response=await fetch(url);if(!response.ok)throw Error(`local page HTTP ${response.status}`);
  fs.writeFileSync(path.join(dir,'dla-site-local-preview.html'),await response.text());
  const chrome=spawn('chromium',['--headless','--no-sandbox','--disable-gpu','--hide-scrollbars','--window-size=1440,1800',`--screenshot=${path.join(dir,'dla-site-local-preview.png')}`,url],{stdio:'ignore'});
  const code=await new Promise(resolve=>chrome.on('exit',resolve));if(code!==0)throw Error(`Chromium exited ${code}`);
  console.log('Saved local DLA HTML and screenshot with Debian OSV and frozen NVD metadata.');
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await driver.close();require(path.join(cli,'lib/cache-db')).closeCacheDbs();}
})().catch(e=>{console.error(e.stack);process.exitCode=1});
