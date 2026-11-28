'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const hist=require('../lib/providers/debian/historical'),current=require('../lib/providers/debian/current'),{closeCacheDbs}=require('../lib/cache/db');
const d={id:'debian',versionId:'11',codename:'bullseye'},at=Date.parse('2026-11-05T12:00:00Z'),commit='b'.repeat(40);
const old={CVE:'CVE-2024-2511 [known before end of support]\n\t- openssl 3.2.2-1\n\t[bullseye] - openssl 1.1.1w-0+deb11u2\n',DSA:'',DLA:''};
const newest=`CVE-2026-76642 [New util-linux issue]\n\t- util-linux 2.42.3-1\n\t[bookworm] - util-linux <not-affected> (Vulnerable code introduced later)\nCVE-2026-102473 [Another issue]\n\t- util-linux <unfixed>\nCVE-2026-102474 [Already confirmed]\n\t- util-linux 2.42.3-1\nCVE-2026-102475 [Package version too new]\n\t- util-linux 2.0-1\nCVE-2026-102476 [Explicit release exception]\n\t- util-linux 2.42.3-1\n\t[bullseye] - util-linux <not-affected> (Code not present)\nCVE-2024-2511 [known before end of support]\n\t- openssl 3.2.2-1\n\t[bullseye] - openssl 1.1.1w-0+deb11u2\nCVE-2026-999999 [unrelated]\n\t- unrelated 9.0-1\n`;
const dep={name:'bsdutils',sourceName:'util-linux',sourceVersion:'2.36.1-8+deb11u2',version:'1:2.36.1-8+deb11u2',manager:'dpkg'};
const openssl={name:'libssl1.1',sourceName:'openssl',sourceVersion:'1.1.1w-0+deb11u1',version:'1.1.1w-0+deb11u1',manager:'dpkg'};
const setup=async dir=>hist.importHistoricalDebian(old,{distribution:d,commit:'a'.repeat(40),cutoff:'2026-08-31',packages:['util-linux','openssl'],cacheDir:dir});
const mock=(calls)=>async(kind,params)=>{calls.push([kind,params]);if(kind==='history')return new Response(JSON.stringify([{id:commit,committed_date:'2026-11-05T10:00:00Z'}]));return new Response(newest,{headers:{'x-fad-proxy-fetched-at':'2026-11-05T11:00:00Z','x-vigievuln-source-sha256':'f'.repeat(64)}})};
test('current tracker creates only possible observations with exact rule and other-release context',async()=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-current-deb-'));try{
 await setup(dir);const calls=[],inventory={distribution:d,packages:[dep,openssl]},confirmedMatches=[{dep:{name:'bsdutils'},cve:{id:'CVE-2026-102474'}}];
 const result=await current.assessCurrentDebianCandidates(inventory,{cacheDir:dir,now:at,fetchResource:mock(calls),confirmedMatches});
 assert.deepEqual(calls.map(x=>x[0]),['history','list']);assert.equal(result.matches,undefined);assert.deepEqual(result.observations.map(o=>o.cveId).sort(),['CVE-2026-102473','CVE-2026-76642']);
 const o=result.observations.find(x=>x.cveId==='CVE-2026-76642');assert.equal(o.status,'possible');assert.equal(o.evidence.releaseApplicability,'unknown');assert.equal(o.evidence.comparison.threshold,'2.42.3-1');assert.equal(o.evidence.comparison.installedVersion,dep.sourceVersion);assert.deepEqual(o.evidence.contextReleases[0].releases,['bookworm']);assert.equal(o.evidence.currentCommit,commit);assert.equal(o.evidence.packageFixVerified,false);assert.match(o.reason,/bookworm/);
 const offline=await current.assessCurrentDebianCandidates(inventory,{cacheDir:dir,now:at,offline:true,fetchResource:()=>{throw Error('network forbidden')},confirmedMatches});assert.deepEqual(offline.observations,result.observations);assert.equal(offline.coverage[0].completeness,'candidate-only');
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});
test('historical scope is required and prevents attributing old data to unconsulted packages',async()=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-current-deb-'));try{
 let calls=[];const inventory={distribution:d,packages:[dep]},none=await current.assessCurrentDebianCandidates(inventory,{cacheDir:dir,fetchResource:mock(calls),now:at});assert.equal(none.observations.length,0);assert.equal(calls.length,0);assert.equal(none.coverage[0].execution,'not-applicable');
 await hist.importHistoricalDebian(old,{distribution:d,commit:'a'.repeat(40),cutoff:'2026-08-31',packages:['openssl'],cacheDir:dir});
 const partial=await current.assessCurrentDebianCandidates(inventory,{cacheDir:dir,fetchResource:mock(calls),now:at});assert.equal(partial.observations.length,0);assert.equal(partial.coverage[0].execution,'partial');assert.equal(partial.coverage[0].unknown,1);
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});
test('fresh cached observation is reused, stale offline use remains dated, and earlier commits are rejected',async()=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-current-deb-'));try{
 await setup(dir);const calls=[],inv={distribution:d,packages:[dep]};await current.assessCurrentDebianCandidates(inv,{cacheDir:dir,fetchResource:mock(calls),now:at});
 await current.assessCurrentDebianCandidates(inv,{cacheDir:dir,fetchResource:mock(calls),now:at+1000});assert.equal(calls.length,2);
 const stale=await current.assessCurrentDebianCandidates(inv,{cacheDir:dir,offline:true,now:at+5*3600000});assert.equal(stale.coverage[0].stale,true);assert.equal(stale.coverage[0].fetchedAt,Date.parse('2026-11-05T11:00:00Z'));
 await assert.rejects(current.syncCurrentDebianCandidates(inv,{cacheDir:dir,now:at,fetchResource:async()=>new Response(JSON.stringify([{id:commit,committed_date:'2026-08-31T20:00:00Z'}]))}),/postdate/);
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});
