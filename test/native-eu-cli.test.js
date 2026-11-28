'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');

test('source CLI finds and enriches a native GCVE with US sources excluded and no network',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-native-eu-cli-')),home=path.join(root,'home'),cache=path.join(home,'.vigie-vuln'),src=path.join(root,'src');
 fs.mkdirSync(src,{recursive:true});
 fs.writeFileSync(path.join(src,'package.json'),JSON.stringify({name:'fixture',version:'1.0.0',dependencies:{demo:'1.0.0'}}));
 fs.writeFileSync(path.join(src,'package-lock.json'),JSON.stringify({name:'fixture',version:'1.0.0',lockfileVersion:3,packages:{'':{name:'fixture',version:'1.0.0',dependencies:{demo:'1.0.0'}},'node_modules/demo':{version:'1.0.0'}}}));
 const store=require('../lib/advisories/store').openAdvisoryStore({cacheDir:cache}),now=Date.now(),cve='CVE-2025-12345';
 t.after(()=>{store.close();require('../lib/cache/db').closeCacheDbs();fs.rmSync(root,{recursive:true,force:true})});
 const raw={cveMetadata:{vulnId:'GCVE-1-fixture',cveId:cve,state:'PUBLISHED'},containers:{cna:{descriptions:[{lang:'en',value:'Native fixture'}],affected:[{packageURL:'pkg:npm/demo',versions:[{version:'1.0.0',status:'affected'}]}],x_gcve:[{vulnId:'GCVE-1-fixture',recordType:'advisory'}]}}};
 store.commit({records:[require('../lib/advisories/native').gcveEnvelope({raw,gna:1,collectedAt:new Date(now).toISOString(),sourceUrl:'https://example.test/feed'})]});
 const repo=require('../lib/cache/repository').createCacheRepository(cache);
 repo.put('catalogue','euvd',{_fetchedAt:now,body:{byCve:{[cve]:'EUVD-2025-12345'},exploited:{}}});
 repo.put('catalogue','euvd-targeted',{entries:{[cve]:{item:{id:'EUVD-2025-12345',exploitedSince:null},fetchedAt:now,stale:false,details:{id:'EUVD-2025-12345',source:'euvd',score:6.5,severity:'MEDIUM',description:'EUVD fixture metadata',cvssVersion:'CVSS:3.1',cvssVector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',references:[]},detailsFetchedAt:now,detailsStale:false}}});
 repo.put('catalogue','certfr',{meta:{fetchedAt:now},entries:{'CERTFR-2025-AVI-001':{kind:'avis',title:'Fixture',cves:[cve]}}});
 const preload=path.join(root,'preload.cjs'),calls=path.join(root,'network'),report=path.join(root,'findings.json');
 fs.writeFileSync(preload,`require('node:os').homedir=()=>process.env.VV_EU_TEST_HOME;globalThis.fetch=async()=>{require('node:fs').writeFileSync(process.env.VV_EU_TEST_CALLS,'unexpected');throw Error('network forbidden')};`);
 const result=spawnSync(process.execPath,['--require',preload,path.join(__dirname,'../vigievuln.js'),'scan',src,'--offline','--source-profile','eu','--no-eol','--no-retire','--no-all-libs','--no-binaries','--no-certs','--report-json',report],{cwd:root,encoding:'utf8',timeout:20000,env:{PATH:process.env.PATH,HOME:home,USERPROFILE:home,FORCE_COLOR:'0',VV_EU_TEST_HOME:home,VV_EU_TEST_CALLS:calls}});
 assert.ifError(result.error);assert.equal(result.status,2,result.stdout+result.stderr);assert.equal(fs.existsSync(calls),false);
 const log=require('./helpers/cancelled-scan')(result,[report]);assert.match(log,/OSV/);
});
