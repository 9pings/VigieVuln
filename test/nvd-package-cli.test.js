'use strict';
require('./helpers/isolated-cache')('nvd-package-cli');
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');

for(const native of [false,true,'legacy']) test(`CLI finds an isolated release from stored identity and NVD ${native==='legacy'?'legacy split':native?'native affected':'CPE'} ranges online and offline`,t=>{
 const coord=native==='legacy'?'com.fasterxml.jackson.dataformat:jackson-dataformat-cbor':native?'ch.qos.logback:logback-core':'com.fasterxml.jackson.core:jackson-databind',version=native==='legacy'?'2.6.7':native?'1.2.2':'2.5.2';
 const [group,artifact]=coord.split(':');
 const nvd=native?require('../lib/providers/nvd/enrich').extractFromNvdRecord(require(native==='legacy'?'./fixtures/cve-maven-matching/nvd-cbor-28491.json':'./fixtures/cve-maven-matching/nvd-logback-13006.json')):require('./fixtures/cve-maven-matching/nvd-jackson-11113.json');
 const osv=native?{id:'GHSA-aaaa-bbbb-cccc',aliases:[nvd.id],affected:[{package:{ecosystem:'Maven',name:coord},ranges:[{type:'ECOSYSTEM',events:[{introduced:'999.0'},{fixed:'1000.0'}]}]}]}:require('./fixtures/cve-maven-matching/osv-jackson-11113.json');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-nvd-package-cli-'));

 const home=path.join(root,'home'),cache=path.join(home,'.vigie-vuln'),src=path.join(root,'project');
 fs.mkdirSync(src,{recursive:true});
 fs.writeFileSync(path.join(src,'pom.xml'),`<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>fixture</artifactId><version>1.0</version><dependencies><dependency><groupId>${group}</groupId><artifactId>${artifact}</artifactId><version>${version}</version></dependency></dependencies></project>`);
 const store=require('../lib/advisories/store').openAdvisoryStore({cacheDir:cache});
 t.after(()=>{store.close();require('../lib/cache/db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true});});
 store.commit({records:[{source:'osv',document:osv,fetchedAt:Date.now()}]});
 const db=require('../lib/cache/db').getCacheDb(cache),nvdBytes=Buffer.from(JSON.stringify(nvd));
 const index=require('../lib/providers/cveproject/download').newIndex();
 Object.assign(index.meta,{builtAt:new Date().toISOString(),cveCount:0});
 db.prepare('INSERT INTO cache_snapshots VALUES(?,?,?,?,?,?)').run('cve_lookup',Date.now(),1,0,0,JSON.stringify(index.meta));
 const savedNvd=[nvd.id,'live',Date.now(),null,require('../lib/cache/advisory-compression').compress(nvdBytes),nvdBytes.length,
  JSON.stringify({schema:require('../lib/providers/nvd/enrich').NVD_CACHE_SCHEMA})];
 db.prepare('INSERT OR REPLACE INTO nvd_records(cve,kind,fetched_at,revision_ms,body_deflate,body_bytes,metadata_json) VALUES (?,?,?,?,?,?,?)').run(...savedNvd);
 const preload=path.join(root,'preload.cjs'),calls=path.join(root,'calls.jsonl'),report=path.join(root,'report.json');
 fs.writeFileSync(preload,`
 require('node:os').homedir=()=>process.env.VV_NVD_TEST_HOME;
 globalThis.fetch=async(url,init={})=>{
  require('node:fs').appendFileSync(process.env.VV_NVD_TEST_CALLS,String(url)+'\\n');
  if(process.env.VV_NVD_TEST_OFFLINE==='1')throw Error('unexpected offline request');
  if(String(url)==='https://api.osv.dev/v1/querybatch')return Response.json({results:JSON.parse(init.body).queries.map(()=>({}))});
  if(process.env.VV_NVD_TEST_ABSENT==='1' && String(url).includes('services.nvd.nist.gov'))return new Response(null,{status:404,headers:{'x-fad-proxy-fetched-at':'2020-01-01T00:00:00Z'}});
  if(init.method==='HEAD')return new Response(null,{status:200});
  throw Error('unexpected request '+url);
 };
 `);
 const flags=['--cve-offline','--no-gcve','--no-transitive','--no-all-libs','--no-euvd','--no-certfr','--no-epss','--no-kev','--no-eol','--no-retire','--no-binaries','--no-jars','--no-certs','--retries','0'];
 function scan(offline,extra=[],absent=false,missing=false) {
  fs.rmSync(calls,{force:true});fs.rmSync(report,{force:true});
  const result=spawnSync(process.execPath,['--require',preload,path.join(__dirname,'../vigievuln.js'),'scan',src,...flags,...(offline?['--offline']:['--advisory-query-ttl','0']),'--report-json',report,...extra],{cwd:root,encoding:'utf8',timeout:15000,env:{...process.env,VV_NVD_TEST_HOME:home,VV_NVD_TEST_CALLS:calls,VV_NVD_TEST_OFFLINE:offline?'1':'0',VV_NVD_TEST_ABSENT:absent?'1':'0',VIGIEVULN_ENV:'',FAD_CHECKER_ENV:''}});
  assert.ifError(result.error);
  if(missing){
   // The package-bound NVD record is gone from the offline cache: the report is published
   // marked incomplete and names the unavailable record instead of reporting a clean result.
   const {log,doc}=require('./helpers/incomplete-scan')(result,report);
   assert.match(log,/NVD:.*package-bound/);
   assert.ok(doc.warnings.some(w=>w.type==='source-unavailable'&&/NVD: 1 package-bound CVE record\(s\) unavailable/.test(w.message)),JSON.stringify(doc.warnings));
   return;
  }
  assert.equal(result.status,0,result.stdout+result.stderr);
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
 scan(true,[],false,true);
 assert.deepEqual(scan(false,['--no-nvd-mirror'],true),[]);
 const absentReport=JSON.parse(fs.readFileSync(report));
 assert.ok(!absentReport.warnings.some(w=>/NVD:.*package-bound/.test(w.message)),'an answered NVD absence is not an outage');
 assert.ok(absentReport.provenance.sourceLimitations.some(n=>n.source==='NVD'&&/returned no record/.test(n.message)),'absence remains visible in coverage context');
 db.prepare('INSERT OR REPLACE INTO nvd_records(cve,kind,fetched_at,revision_ms,body_deflate,body_bytes,metadata_json) VALUES (?,?,?,?,?,?,?)').run(...savedNvd);
 store.commit({records:[{source:'osv',document:{...osv,withdrawn:new Date().toISOString()},fetchedAt:Date.now()}]});
 assert.deepEqual(scan(true),[],'withdrawn OSV identity cannot be revived by an NVD cache entry');
});
