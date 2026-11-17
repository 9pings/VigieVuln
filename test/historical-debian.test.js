'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const h=require('../lib/system-inventory/historical-debian');const {closeCacheDbs}=require('../lib/cache-db');
const d={id:'debian',versionId:'11',codename:'bullseye'};
// Shape taken from Debian security-tracker data/CVE/list and data/DLA/list.
const lists={CVE:`CVE-2024-2511 (Some non-default TLS server configurations)\n\t{DLA-3942-1}\n\t- openssl 3.2.2-1 (bug #1068658)\n\t[bookworm] - openssl 3.0.14-1~deb12u1\nCVE-2026-53612 [Local privilege escalation]\n\t- util-linux 2.42.2-1\n\t[bullseye] - util-linux <not-affected> (Vulnerable code introduced later)\nCVE-2026-53613 [Local privilege escalation]\n\t- util-linux 2.42.2-1\nCVE-2025-10000 [Unbounded status]\n\t[bullseye] - openssl <no-dsa> (Minor issue)\nCVE-2025-10001 [Version specific fix]\n\t[bullseye] - openssl 1:1.1.1w-0+deb11u3\n`,DLA:`[01 Sep 2024] DLA-3942-1 openssl - security update\n\t{CVE-2024-2511}\n\t[bullseye] - openssl 1:1.1.1w-0+deb11u2\n`,DSA:`[01 Sep 2024] DSA-1234-1 nginx - security update\n\t{CVE-2024-4000}\n\t[bookworm] - nginx 1.22.1-9\n`};
const tempfile=()=>fs.mkdtempSync(path.join(os.tmpdir(),'vv-history-'));
function package_(sourceName,sourceVersion){return {name:sourceName,sourceName,sourceVersion,version:sourceVersion,manager:'dpkg'};}
test('historical distro decisions use explicit release evidence and preserve unbounded uncertainty',async()=>{const dir=tempfile();try{
 await h.importHistoricalDebian(lists,{distribution:d,commit:'a'.repeat(40),cutoff:'2026-08-31',cacheDir:dir});
 const r=h.assessHistoricalDebian({distribution:d,packages:[package_('openssl','1:1.1.1w-0+deb11u1'),package_('util-linux','2.36.1-8')]},{cacheDir:dir});
 assert.deepEqual(r.matches.map(m=>m.cve.id).sort(),['CVE-2024-2511','CVE-2025-10001','CVE-2026-53613']);assert.equal(r.matches.find(x=>x.cve.id==='CVE-2024-2511').cve.fixVersion,'1:1.1.1w-0+deb11u2');
 assert.equal(r.coverage[0].status,'complete');assert.equal(r.coverage[0].completeness,'historical-only');assert.equal(r.observations[0].status,'unknown');assert.ok(r.coverage[0].unknown>=1);assert.equal(r.coverage[0].historicalCutoff,'2026-08-31');
 assert.equal(h.assessHistoricalDebian({distribution:d,packages:[package_('openssl','1:1.1.1w-0+deb11u3')]},{cacheDir:dir}).matches.length,0);
 assert.equal(h.assessHistoricalDebian({distribution:{...d,codename:'bookworm'},packages:[package_('openssl','1')]},{cacheDir:dir}).coverage[0].status,'missing');
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});
test('package projection preserves relevant whole blocks and empty subsets stay explicitly scoped',async()=>{const dir=tempfile();try{
 const cv=h.projectDebianList(lists.CVE,{list:'CVE',packages:['openssl']});assert.match(cv,/CVE-2024-2511/);assert.match(cv,/\[bookworm\] - openssl/);assert.doesNotMatch(cv,/CVE-2026-53612/);
 const projected=Object.fromEntries(['CVE','DSA','DLA'].map(list=>[list,h.projectDebianList(lists[list],{list,packages:['openssl']})]));
 await h.importHistoricalDebian(projected,{distribution:d,commit:'b'.repeat(40),cutoff:'2026-08-31',packages:['openssl','other'],cacheDir:dir});
 const r=h.assessHistoricalDebian({distribution:d,packages:[package_('openssl','1:1.1.1w-0+deb11u1'),package_('not-requested','1')]},{cacheDir:dir});
 assert.equal(r.matches.length,2);assert.ok(r.coverage[0].unknown>=2);
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});
test('online discovery validates lifecycle and immutable commit; offline assessment makes no requests',async()=>{const dir=tempfile();try{
 const calls=[];const fetchResource=async(kind,p)=>{calls.push([kind,p]);if(kind==='lifecycle')return new Response(JSON.stringify([{cycle:'11',codename:'Bullseye',eol:'2026-08-31'}]));if(kind==='history')return new Response(JSON.stringify([{id:'c'.repeat(40),committed_date:'2026-08-31T12:00:00Z'}]));return new Response(lists[p.list]);};
 const out=await h.syncHistoricalDebian(d,{cacheDir:dir,fetchResource,packages:['openssl']});assert.equal(out.commit,'c'.repeat(40));assert.deepEqual(calls.map(c=>c[0]),['lifecycle','history','list','list','list']);assert.deepEqual(calls[2][1].packages,['openssl']);
 const r=h.assessHistoricalDebian({distribution:d,packages:[package_('openssl','1:1.1.1w-0+deb11u1')]},{cacheDir:dir,offline:true,fetchResource:()=>{throw Error('unexpected network')}});assert.equal(r.matches.length,2);
 await assert.rejects(h.syncHistoricalDebian(d,{cacheDir:dir,offline:true}),/offline/);
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});

test('explicit third-party package origin produces possible evidence and no Debian affected verdict',async()=>{const dir=tempfile();try{await h.importHistoricalDebian(lists,{distribution:d,commit:'a'.repeat(40),cutoff:'2026-08-31',cacheDir:dir});const r=h.assessHistoricalDebian({distribution:d,packages:[package_('openssl','1:1.1.1w-0+deb11u1')]},{cacheDir:dir,packageOrigin:()=>({status:'third-party'})});assert.equal(r.matches.length,0);assert.ok(r.observations.some(x=>x.cveId==='CVE-2024-2511'&&x.status==='possible'));}finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});

test('source archive corroboration is cached; absence and origin uncertainty do not claim third-party status',async()=>{const dir=tempfile();try{
 await h.importHistoricalDebian(lists,{distribution:d,commit:'a'.repeat(40),cutoff:'2026-08-31',cacheDir:dir});
 const queries=[{name:'openssl',version:'1:1.1.1w-0+deb11u1'},{name:'nginx',version:'1.24.0-1~bullseye'}];
 const checks=await h.syncDebianPackageOrigins(queries,{cacheDir:dir,fetchResource:async(kind,p)=>new Response(JSON.stringify(p.name==='openssl'?{package:p.name,version:p.version,pkg_infos:{suites:['bullseye']}}:{error:404}))});
 assert.deepEqual(checks.map(x=>x.status),['corroborated','unknown']);
 const r=h.assessHistoricalDebian({distribution:d,packages:[package_('openssl',queries[0].version)]},{cacheDir:dir,offline:true});
 assert.equal(r.matches[0].cve.historicalEvidence.originStatus,'corroborated');
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});
test('an active release is not historical, and explicit future cutoffs fail',async()=>{
 const fetchResource=async()=>new Response(JSON.stringify([{cycle:'11',codename:'Bullseye',eol:'2999-01-01'}]));
 assert.deepEqual(await h.syncHistoricalDebian(d,{fetchResource}),{notApplicable:true,reason:'release-not-historical'});
 await assert.rejects(h.syncHistoricalDebian(d,{cutoff:'2999-01-01',fetchResource}),/future/);
});

test('source acquisition retains actual proxy evidence time and immutable source hashes',async()=>{const dir=tempfile();try{
 const time='2026-08-31T10:00:00Z',headers={'x-fad-proxy-fetched-at':time,'x-vigievuln-source-sha256':'d'.repeat(64)};
 const fetchResource=async(kind,p)=>new Response(kind==='history'?JSON.stringify([{id:'e'.repeat(40),committed_date:'2026-08-31T09:00:00Z'}]):lists[p.list],{headers});
 await h.syncHistoricalDebian(d,{cutoff:'2026-08-31',packages:['openssl'],cacheDir:dir,fetchResource});
 const cache=require('../lib/cache-repository').createCacheRepository(dir),s=cache.getSnapshot(h.namespace(d));
 assert.equal(s.fetchedAt,Date.parse(time));assert.equal(s.metadata.sourceHashes.CVE,'d'.repeat(64));
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});

test('large package scope is batched without changing source identity or dropping queried packages',async()=>{const dir=tempfile();try{
 const packages=Array.from({length:1001},(_,i)=>`pkg${i}`),calls=[];
 const fetchResource=async(kind,p)=>{calls.push([kind,p]);if(kind==='history')return new Response(JSON.stringify([{id:'f'.repeat(40),committed_date:'2026-08-31T09:00:00Z'}]));return new Response('',{headers:{'x-vigievuln-source-sha256':'d'.repeat(64)}})};
 await h.syncHistoricalDebian(d,{cutoff:'2026-08-31',packages,cacheDir:dir,fetchResource});
 assert.equal(calls.filter(x=>x[0]==='list').length,6);assert.deepEqual(calls.filter(x=>x[0]==='list').map(x=>x[1].packages.length),[1000,1,1000,1,1000,1]);
 const s=require('../lib/cache-repository').createCacheRepository(dir).getSnapshot(h.namespace(d));assert.equal(s.metadata.queriedPackages.length,1001);
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});

test('explicit non-Debian dpkg Origin is treated as a candidate, while Maintainer alone is not used as an origin classifier',async()=>{const dir=tempfile();try{
 await h.importHistoricalDebian(lists,{distribution:d,commit:'a'.repeat(40),cutoff:'2026-08-31',cacheDir:dir});
 const base=package_('openssl','1:1.1.1w-0+deb11u1');
 const third=h.assessHistoricalDebian({distribution:d,packages:[{...base,packageMetadata:{origin:'Other Vendor'}}]},{cacheDir:dir});
 assert.equal(third.matches.length,0);assert.ok(third.observations.some(x=>x.status==='possible'));
 const unknown=h.assessHistoricalDebian({distribution:d,packages:[{...base,packageMetadata:{maintainer:'example@example.test'}}]},{cacheDir:dir});
 assert.equal(unknown.matches.length,2);assert.equal(unknown.matches[0].cve.historicalEvidence.originStatus,'distribution-context');
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});

test('Debian inherited source notes are overridden only by release version notes, not no-DSA triage',async()=>{const dir=tempfile();try{
 const input={CVE:`CVE-2022-3715 [Bash issue]\n\t- bash 5.2-1 (medium)\n\t[bullseye] - bash <no-dsa> (Minor issue)\nCVE-2024-1111 [Earlier code absent]\n\t- bash 5.2-1\n\t[bullseye] - bash <not-affected> (Code introduced later)\nCVE-2024-2222 [Release explicitly unfixed]\n\t- bash 4.0-1\n\t[bullseye] - bash <unfixed>\nCVE-2024-3333 [Not security relevant in Debian]\n\t- bash <unfixed> (unimportant)\nCVE-2024-4444 [Uncertain analysis]\n\t- bash 6.0-1\n\t[bullseye] - bash <undetermined>\n`,DSA:`[01 Sep 2024] DSA-1234-1 unrelated - update\n\t{CVE-2024-9999}\n\t[bullseye] - unrelated 2-1\n`,DLA:`[01 Sep 2024] DLA-3942-1 bash - update\n\t{CVE-2022-3715}\n\t[bookworm] - bash 5.2-2\n`};
 await h.importHistoricalDebian(input,{distribution:d,commit:'d'.repeat(40),cutoff:'2026-08-31',cacheDir:dir});
 const r=h.assessHistoricalDebian({distribution:d,packages:[package_('bash','5.1-2')]},{cacheDir:dir});
 assert.deepEqual(r.matches.map(x=>x.cve.id).sort(),['CVE-2022-3715','CVE-2024-2222','CVE-2024-3333']);
 const inherited=r.matches.find(x=>x.cve.id==='CVE-2022-3715').cve;assert.equal(inherited.fixVersion,null);assert.equal(inherited.historicalEvidence.comparisonThreshold,'5.2-1');assert.equal(inherited.historicalEvidence.annotations[0].kind,'no-dsa');
 assert.equal(r.matches.find(x=>x.cve.id==='CVE-2024-3333').cve.historicalEvidence.trackerUrgency,'unimportant');assert.ok(r.observations.some(x=>x.cveId==='CVE-2024-4444'&&x.status==='unknown'));
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});

test('multiple release fixes use the latest Debian threshold; unfixed release overrides a fix',async()=>{const dir=tempfile();try{
 const input={CVE:`CVE-2024-5555 [Issue]\n\t- curl 8.0-1\n\t[bullseye] - curl 7.1-1\nCVE-2024-6666 [Issue]\n\t- curl 8.0-1\n\t[bullseye] - curl <unfixed>\n`,DSA:`[01 Sep 2024] DSA-1234-1 curl - update\n\t{CVE-2024-5555 CVE-2024-6666}\n\t[bullseye] - curl 7.3-1\n`,DLA:`[01 Sep 2024] DLA-3942-1 curl - update\n\t{CVE-2024-5555}\n\t[bullseye] - curl 7.2-1\n`};
 await h.importHistoricalDebian(input,{distribution:d,commit:'e'.repeat(40),cutoff:'2026-08-31',cacheDir:dir});
 const r=h.assessHistoricalDebian({distribution:d,packages:[package_('curl','7.2-1')]},{cacheDir:dir});
 assert.equal(r.matches.find(x=>x.cve.id==='CVE-2024-5555').cve.fixVersion,'7.3-1');assert.equal(r.matches.find(x=>x.cve.id==='CVE-2024-6666').cve.fixVersion,null);
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});

test('legacy historical cache remains usable but visibly incomplete until reimported',async()=>{const dir=tempfile();try{
 const cache=require('../lib/cache-repository').createCacheRepository(dir),ns=h.namespace(d),time=Date.now();
 cache.put(ns,'openssl',[{id:'CVE-2024-2511',description:'historical',statuses:[],fixes:[{version:'1:1.1.1w-0+deb11u2',source:'DLA/list'}]}],{fetchedAt:time});
 cache.putSnapshot(ns,{fetchedAt:time,complete:true,metadata:{commit:'a'.repeat(40),cutoff:'2026-08-31',distribution:d}});
 const inventory={distribution:d,packages:[package_('openssl','1:1.1.1w-0+deb11u1')]};
 let r=h.assessHistoricalDebian(inventory,{cacheDir:dir,offline:true});assert.equal(r.matches.length,1);assert.equal(r.coverage[0].execution,'partial');assert.equal(r.coverage[0].parserVersion,1);
 await h.importHistoricalDebian(lists,{distribution:d,commit:'a'.repeat(40),cutoff:'2026-08-31',packages:['openssl'],cacheDir:dir});
 r=h.assessHistoricalDebian(inventory,{cacheDir:dir,offline:true});assert.equal(r.coverage[0].parserVersion,2);assert.equal(r.coverage[0].execution,'completed');
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});

test('a Debian REJECTED CVE is not resurrected by an inherited package note or advisory',async()=>{const dir=tempfile();try{
 const input={CVE:'CVE-2018-10886\n\tREJECTED\n\t{DSA-4255-1 DLA-1431-1}\n\t- ant 1.10.4-1\n',DSA:'[01 Sep 2018] DSA-4255-1 ant - update\n\t{CVE-2018-10886}\n\t[bullseye] - ant 1.9.12-1\n',DLA:'[01 Sep 2018] DLA-1431-1 ant - update\n\t{CVE-2018-10886}\n\t[bullseye] - ant 1.9.12-1\n'};
 await h.importHistoricalDebian(input,{distribution:d,commit:'a'.repeat(40),cutoff:'2026-08-31',packages:['ant'],cacheDir:dir});
 assert.equal(h.assessHistoricalDebian({distribution:d,packages:[package_('ant','1.9-1')]},{cacheDir:dir}).matches.length,0);
 }finally{closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});}});
