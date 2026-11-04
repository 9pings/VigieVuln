'use strict';
require('./helpers/isolated-cache')('nvd-package-cli');
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');

for(const native of [false,true,'legacy']) test(`CLI finds an isolated release from stored identity and NVD ${native==='legacy'?'legacy split':native?'native affected':'CPE'} ranges online and offline`,t=>{
 const coord=native==='legacy'?'com.fasterxml.jackson.dataformat:jackson-dataformat-cbor':native?'ch.qos.logback:logback-core':'com.fasterxml.jackson.core:jackson-databind',version=native==='legacy'?'2.6.7':native?'1.2.2':'2.5.2';
 const [group,artifact]=coord.split(':');
 const nvd=native?require('../lib/nvd').extractFromNvdRecord(require(native==='legacy'?'./fixtures/cve-maven-matching/nvd-cbor-28491.json':'./fixtures/cve-maven-matching/nvd-logback-13006.json')):require('./fixtures/cve-maven-matching/nvd-jackson-11113.json');
 const osv=native?{id:'GHSA-aaaa-bbbb-cccc',aliases:[nvd.id],affected:[{package:{ecosystem:'Maven',name:coord},ranges:[{type:'ECOSYSTEM',events:[{introduced:'999.0'},{fixed:'1000.0'}]}]}]}:require('./fixtures/cve-maven-matching/osv-jackson-11113.json');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-nvd-package-cli-'));

 const home=path.join(root,'home'),cache=path.join(home,'.vigie-vuln'),src=path.join(root,'project');
 fs.mkdirSync(src,{recursive:true});
 fs.writeFileSync(path.join(src,'pom.xml'),`<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>fixture</artifactId><version>1.0</version><dependencies><dependency><groupId>${group}</groupId><artifactId>${artifact}</artifactId><version>${version}</version></dependency></dependencies></project>`);
 const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir:cache});
 t.after(()=>{store.close();require('../lib/cache-db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});
 store.commit({records:[{source:'osv',document:osv,fetchedAt:Date.now()}]});
 const db=require('../lib/cache-db').getCacheDb(cache),nvdBytes=Buffer.from(JSON.stringify(nvd));
 const savedNvd=[nvd.id,'live',Date.now(),null,require('../lib/advisory-compression').compress(nvdBytes),nvdBytes.length,
  JSON.stringify({schema:require('../lib/nvd').NVD_CACHE_SCHEMA})];
 db.prepare('INSERT INTO nvd_records(cve,kind,fetched_at,revision_ms,body_deflate,body_bytes,metadata_json) VALUES (?,?,?,?,?,?,?)').run(...savedNvd);
 const preload=path.join(root,'preload.cjs'),calls=path.join(root,'calls.jsonl'),report=path.join(root,'report.json');
 fs.writeFileSync(preload,`
 require('node:os').homedir=()=>process.env.VV_NVD_TEST_HOME;
 globalThis.fetch=async(url,init={})=>{
  require('node:fs').appendFileSync(process.env.VV_NVD_TEST_CALLS,String(url)+'\\n');
  if(process.env.VV_NVD_TEST_OFFLINE==='1')throw Error('unexpected offline request');
  if(String(url)==='https://api.osv.dev/v1/querybatch')return Response.json({results:JSON.parse(init.body).queries.map(()=>({}))});
  if(init.method==='HEAD')return new Response(null,{status:200});
  throw Error('unexpected request '+url);
 };
 `);
 const flags=['--cve-offline','--no-gcve','--no-transitive','--no-all-libs','--no-euvd','--no-certfr','--no-epss','--no-kev','--no-eol','--no-retire','--no-binaries','--no-jars','--no-certs','--retries','0'];
 function scan(offline,extra=[]) {
  fs.rmSync(calls,{force:true});fs.rmSync(report,{force:true});
  const result=spawnSync(process.execPath,['--require',preload,path.join(__dirname,'../vigievuln.js'),'scan',src,...flags,...(offline?['--offline']:['--advisory-query-ttl','0']),'--report-json',report,...extra],{cwd:root,encoding:'utf8',timeout:15000,env:{...process.env,VV_NVD_TEST_HOME:home,VV_NVD_TEST_CALLS:calls,VV_NVD_TEST_OFFLINE:offline?'1':'0',VIGIEVULN_ENV:'',FAD_CHECKER_ENV:''}});
  assert.ifError(result.error);assert.equal(result.status,0,result.stdout+result.stderr);
  if(offline)assert.equal(fs.existsSync(calls),false,'offline performed no network requests');
  else assert.match(fs.readFileSync(calls,'utf8'),/api\.osv\.dev\/v1\/querybatch/);
  return JSON.parse(fs.readFileSync(report)).cve.filter(c=>!c.suppressed&&!c.cpeFiltered);
 }
 for(const offline of [false,true]) {
  const matches=scan(offline);
  assert.deepEqual(matches.map(m=>[m.dep.coord,m.dep.version,m.id]),[[coord,version,nvd.id]]);
  assert.equal(matches[0].source,'nvd');
 }
 assert.deepEqual(scan(true,['--no-nvd']),[],'disabled sources cannot be used through the binding stage');
 db.prepare('DELETE FROM nvd_records WHERE cve=?').run(nvd.id);
 assert.deepEqual(scan(true),[]);
 assert.ok(JSON.parse(fs.readFileSync(report)).warnings.some(w=>w.type==='source-unavailable' && /NVD:.*package-bound/.test(w.message)),'missing NVD coverage is visible');
 db.prepare('INSERT INTO nvd_records(cve,kind,fetched_at,revision_ms,body_deflate,body_bytes,metadata_json) VALUES (?,?,?,?,?,?,?)').run(...savedNvd);
 store.commit({records:[{source:'osv',document:{...osv,withdrawn:new Date().toISOString()},fetchedAt:Date.now()}]});
 assert.deepEqual(scan(true),[],'withdrawn OSV identity cannot be revived by an NVD cache entry');
});
