'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {resolveImageUpdate}=require('../lib/images/update');
test('registry tag pagination selects same patch branch and variant, then replays offline',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-tags-'));t.after(()=>{require('../lib/cache/db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const crypto=require('node:crypto'),hash=b=>'sha256:'+crypto.createHash('sha256').update(b).digest('hex'),config=Buffer.from(JSON.stringify({os:'linux',architecture:'amd64'})),manifest={schemaVersion:2,config:{digest:hash(config),size:config.length},layers:[]};
 const calls=[],fetcher=async url=>{calls.push(url);if(url.includes('/manifests/'))return Response.json(manifest);if(url.includes('/blobs/'))return new Response(config);return url.includes('last=')?Response.json({name:'app',tags:['1.2.8-alpine','1.2.11-alpine']}):Response.json({name:'app',tags:['1.2.3-alpine','1.2.7','1.3.9-alpine']},{headers:{link:'</v2/team/app/tags/list?n=2&last=1.2.3-alpine>; rel="next"'}});};
 const metadata={platform:{os:'linux',architecture:'amd64'},acquisition:{kind:'registry',reference:'registry.example/team/app:1.2.3-alpine'}};
 const result=await resolveImageUpdate(metadata,{cacheDir,fetcher});assert.equal(result.status,'available');assert.equal(result.targetReference,'registry.example/team/app:1.2.11-alpine');assert.equal(result.verifiedFix,false);assert.equal(calls.length,4);
 const offline=await resolveImageUpdate(metadata,{cacheDir,offline:true,fetcher:()=>{throw Error('network')}});assert.deepEqual(offline,result);
});
test('ambiguous tags, archives and unsafe pagination never invent an update',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-tags-'));t.after(()=>{require('../lib/cache/db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 assert.equal((await resolveImageUpdate({acquisition:{kind:'archive'}},{cacheDir})).status,'unknown');
 assert.equal((await resolveImageUpdate({acquisition:{kind:'registry',reference:'registry.example/a:latest'}},{cacheDir,fetcher:()=>assert.fail('network')})).status,'unknown');
 const r=await resolveImageUpdate({platform:{os:'linux',architecture:'amd64'},acquisition:{kind:'registry',reference:'registry.example/a:1.2.3'}},{cacheDir,fetcher:async()=>Response.json({tags:['1.2.3']},{headers:{link:'<https://evil.example/v2/a/tags/list>; rel="next"'}})});assert.equal(r.status,'unknown');assert.match(r.reason,/unsafe/);
});
test('branch tags and tag plus digest require a compatible platform',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-tags-'));t.after(()=>{require('../lib/cache/db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const crypto=require('node:crypto'),hash=b=>'sha256:'+crypto.createHash('sha256').update(b).digest('hex'),config=Buffer.from(JSON.stringify({os:'linux',architecture:'amd64'})),manifest={schemaVersion:2,config:{digest:hash(config),size:config.length},layers:[]};let calls=0;
 const fetcher=async url=>{calls++;if(url.includes('/manifests/'))return Response.json(manifest);if(url.includes('/blobs/'))return new Response(config);return Response.json({tags:['1.24.0','1.24.9']});};
 const run=(tag,arch)=>resolveImageUpdate({platform:{os:'linux',architecture:arch},acquisition:{kind:'registry',reference:`registry.example/a:${tag}`}},{cacheDir,fetcher});
 assert.equal((await run('1.24','amd64')).targetTag,'1.24.9');assert.equal((await run('1.24.0@sha256:'+ 'a'.repeat(64),'amd64')).targetTag,'1.24.9');assert.equal(calls,3);
 assert.equal((await run('1.24','arm64')).status,'unknown');
});
test('archive registry association requires exact platform digest and detects rebuilt mutable tags',async t=>{
 const cacheDir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-tags-'));t.after(()=>{require('../lib/cache/db').closeCacheDbs();fs.rmSync(cacheDir,{recursive:true,force:true})});
 const crypto=require('node:crypto'),hash=b=>'sha256:'+crypto.createHash('sha256').update(b).digest('hex'),config=Buffer.from(JSON.stringify({os:'linux',architecture:'amd64'})),manifest={schemaVersion:2,config:{digest:hash(config),size:config.length},layers:[]};let calls=0;
 const fetcher=async url=>{calls++;if(url.includes('/manifests/'))return Response.json(manifest);if(url.includes('/blobs/'))return new Response(config);return Response.json({tags:['1.24.0']});};
 const digest='sha256:'+'a'.repeat(64),metadata={digest,platform:{os:'linux',architecture:'amd64'},acquisition:{kind:'archive',source:'image.tar'},registryReference:{reference:'registry.example/a:1.24.0',platformDigest:'sha256:'+'b'.repeat(64),indexDigest:'sha256:'+'c'.repeat(64),verifiedAt:new Date().toISOString()}};
 assert.equal((await resolveImageUpdate(metadata,{cacheDir,fetcher})).reasonCode,'no-reference');assert.equal(calls,0);
 metadata.registryReference.platformDigest=digest;const result=await resolveImageUpdate(metadata,{cacheDir,fetcher});assert.equal(result.status,'available');assert.equal(result.reasonCode,'rebuilt-tag');assert.equal(metadata.acquisition.kind,'archive');
 await assert.rejects(resolveImageUpdate(metadata,{cacheDir,imageUpdateTtlMs:0}),/TTL/);
 const key='image-tags-'+crypto.createHash('sha256').update('registry.example/a').digest('hex'),repo=require('../lib/cache/repository').createCacheRepository(cacheDir),saved=repo.get('catalogue',key).value;saved.observedAt=new Date(Date.now()+3600000).toISOString();repo.put('catalogue',key,saved);
 const offline=await resolveImageUpdate(metadata,{cacheDir,offline:true});assert.equal(offline.reasonCode,'cache-miss');const before=calls;await resolveImageUpdate(metadata,{cacheDir,fetcher});assert.ok(calls>before);
});
test('ARM variant may come from index descriptor and conflicting config is rejected',async()=>{
 const crypto=require('node:crypto'),hash=b=>'sha256:'+crypto.createHash('sha256').update(b).digest('hex');
 const config=Buffer.from(JSON.stringify({os:'linux',architecture:'arm'})),manifest=Buffer.from(JSON.stringify({schemaVersion:2,config:{digest:hash(config),size:config.length},layers:[]})),index={schemaVersion:2,manifests:[{digest:hash(manifest),size:manifest.length,platform:{os:'linux',architecture:'arm',variant:'v7'}}]};
 const fetcher=async url=>url.endsWith('/manifests/1.0.1')?Response.json(index):url.includes('/manifests/')?new Response(manifest):new Response(config);
 const proof=await require('../lib/images/registry').fetchRegistryTagPlatform('registry.example/a:1.0.1',{os:'linux',architecture:'arm',variant:'v7'},{fetcher});assert.equal(proof.platformDigest,hash(manifest));
 const tags=require('../lib/images/registry').fetchRegistryTags;
 await assert.rejects(tags('registry.example/a:1.0.1',{limits:{maxTagPages:0}}),/invalid registry tag limits/);
 await assert.rejects(tags('registry.example/a:1.0.1',{limits:{maxTags:1},fetcher:async()=>Response.json({tags:['1.0.0','1.0.1']})}),/count exceeds/);
});
