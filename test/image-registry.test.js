'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {fetchRegistryImage,fetchRegistrySboms,parseReference}=require('../lib/image-registry');
const {openArtifact}=require('../lib/artifacts');
const tar=require('tar-stream');
function encode(value) {return Buffer.from(JSON.stringify(value));}
function desc(body,extra={}) {return {digest:`sha256:${crypto.createHash('sha256').update(body).digest('hex')}`,size:body.length,...extra};}
async function layer() {const pack=tar.pack(),chunks=[]; pack.on('data',x=>chunks.push(x)); const done=new Promise((resolve,reject)=>{pack.on('end',resolve);pack.on('error',reject);}); pack.entry({name:'etc/os-release'},'ID=example');pack.finalize();await done;return Buffer.concat(chunks);}
async function registryFixture() {
 const objects=new Map(), platforms=[];
 const blob=body=>{const d=desc(body);objects.set(d.digest,body);return d;};
 const l=blob(await layer());
 for (const arch of ['amd64','arm64']) {const c=blob(encode({os:'linux',architecture:arch})); const m=encode({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:c,layers:[l]}); const md=blob(m);platforms.push({...md,platform:{os:'linux',architecture:arch}});}
 const nested=encode({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:platforms});const nestedDesc=blob(nested);
 const root=encode({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[nestedDesc]}); objects.set('latest',root);
 const requests=[];
 const fetcher=async (url,options)=>{requests.push({url,options}); const id=decodeURIComponent(new URL(url).pathname.split('/').pop()); const body=objects.get(id);return body ? new Response(body,{status:200,headers:{'content-type':'application/vnd.oci.image.manifest.v1+json'}}) : new Response('missing',{status:404});};
 return {objects,platforms,requests,fetcher};
}
async function temp(t) {const d=fs.mkdtempSync(path.join(os.tmpdir(),'registry-test-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));return d;}
test('nested multi-platform indexes acquire OCI layouts and select a platform',async t=>{
 const f=await registryFixture(),dir=await temp(t), acquired=await fetchRegistryImage('example.org/team/image:latest',{fetcher:f.fetcher,tmpDir:dir,platform:'linux/arm64'});t.after(acquired.cleanup);
 assert.equal(acquired.metadata.platforms.length,1);assert.equal(acquired.metadata.platforms[0].architecture,'arm64');
 const opened=await openArtifact(acquired.path);t.after(opened.cleanup);assert.equal(opened.targets.length,1);assert.equal(await fs.promises.readFile(path.join(opened.targets[0].root,'etc/os-release'),'utf8'),'ID=example');
 await assert.rejects(fetchRegistryImage('example.org/team/image',{fetcher:f.fetcher,tmpDir:dir,platform:'linux/s390x'}),/platform/);
});
test('digest and size mismatches fail and remove temporary downloads',async t=>{
 const dir=await temp(t), f=await registryFixture();f.objects.set(f.platforms[0].digest,Buffer.from('tampered'));
 await assert.rejects(fetchRegistryImage('example.org/a',{fetcher:f.fetcher,tmpDir:dir}),/mismatch/);assert.deepEqual(await fs.promises.readdir(dir),[]);
 const g=await registryFixture(), old=JSON.parse(g.objects.get('latest'));old.manifests[0].size++;g.objects.set('latest',encode(old));
 await assert.rejects(fetchRegistryImage('example.org/a',{fetcher:g.fetcher,tmpDir:dir}),/size mismatch/);assert.deepEqual(await fs.promises.readdir(dir),[]);
});
test('offline prevents every request',async()=>{let called=false;await assert.rejects(fetchRegistryImage('example.org/a',{offline:true,fetcher:()=>{called=true;throw Error('tripwire');}}),/offline/);assert.equal(called,false);});
test('authentication respects trusted origins and strips credentials on redirect',async t=>{
 const dir=await temp(t),f=await registryFixture(), requests=[];let challenged=false;
 const fetcher=async(url,opts)=>{requests.push({url,authorization:opts.headers.Authorization});const u=new URL(url);
   if(u.host==='auth.example.org') return new Response(JSON.stringify({token:'secret-token'}),{status:200});
   if(u.host==='cdn.example.org') return f.fetcher(url,opts);
   if(!challenged){challenged=true;return new Response('',{status:401,headers:{'www-authenticate':'Bearer realm="https://auth.example.org/token",service="registry"'}});}
   if(u.pathname.includes('/blobs/')) return new Response(null,{status:307,headers:{location:`https://cdn.example.org${u.pathname}`}});
   return f.fetcher(url,opts);
 };
 const options={fetcher,tmpDir:dir,credentials:{username:'u',password:'password'},authOrigins:['https://auth.example.org']};
 const acquired=await fetchRegistryImage('example.org/a',options);await acquired.cleanup();
 assert.match(requests.find(r=>r.url.startsWith('https://auth.')).authorization,/^Basic /);
 assert.ok(requests.some(r=>r.url.startsWith('https://cdn.')));assert.ok(requests.filter(r=>r.url.startsWith('https://cdn.')).every(r=>!r.authorization));
 challenged=false;await assert.rejects(fetchRegistryImage('example.org/a',{...options,authOrigins:[]}),/explicitly trusted/);
});
test('reference parsing rejects malformed forms',()=>{
 for(const s of ['', 'example.org/a@','example.org/a@@sha256:abc','example.org//a','https://example.org/a','a?password=x','example.org/a:','example.org:bad/a']) assert.throws(()=>parseReference(s),undefined,s);
 assert.deepEqual(parseReference('alpine').repository,'library/alpine');
});
test('attestations in indexes are classified and not scanned as images',async t=>{
 const f=await registryFixture(),dir=await temp(t),index=JSON.parse(f.objects.get('latest'));
 const fake=encode({schemaVersion:2,config:{mediaType:'application/vnd.oci.empty.v1+json'},layers:[]});const a=desc(fake,{platform:{os:'unknown',architecture:'unknown'},annotations:{'vnd.docker.reference.type':'attestation-manifest'}});index.manifests.push(a);f.objects.set(a.digest,fake);f.objects.set('latest',encode(index));
 const acquired=await fetchRegistryImage('example.org/a',{fetcher:f.fetcher,tmpDir:dir});t.after(acquired.cleanup);
 assert.equal(acquired.metadata.platforms.length,2);assert.equal(acquired.metadata.diagnostics[0].kind,'non-image-artifact');assert.ok(!f.requests.some(x=>x.url.includes(a.digest)));
});
test('network and authentication errors do not reveal supplied credentials',async t=>{
 const dir=await temp(t), secret='dont-print-this-secret';
 await assert.rejects(fetchRegistryImage('example.org/a',{tmpDir:dir,credentials:{token:secret},fetcher:async()=>{throw Error(`network rejected ${secret}`);}}),e=>!e.message.includes(secret));
 let count=0;await assert.rejects(fetchRegistryImage('example.org/a',{tmpDir:dir,fetcher:async()=>++count===1?new Response('',{status:401,headers:{'www-authenticate':'Bearer realm="https://auth.example.org/token"'}}):new Response(`bad-json-${secret}`)}),e=>!e.message.includes(secret));
 assert.deepEqual(await fs.promises.readdir(dir),[]);
});
test('publisher SBOMs are bound by OCI referrer subject and fetched without image layers',async()=>{
 const f=await registryFixture(), leaf=f.platforms[0], sbom=encode({spdxVersion:'SPDX-2.3',SPDXID:'SPDXRef-DOCUMENT',packages:[]}), sbomDesc=desc(sbom,{mediaType:'application/spdx+json'});
 const artifact=encode({schemaVersion:2,subject:{digest:leaf.digest},layers:[sbomDesc]}), artifactDesc=desc(artifact);f.objects.set(artifactDesc.digest,artifact);f.objects.set(sbomDesc.digest,sbom);
 const fetcher=async(url,options)=>{const u=new URL(url);if(u.pathname.includes('/referrers/')) return new Response(encode({schemaVersion:2,manifests:u.pathname.endsWith(leaf.digest)?[artifactDesc]:[]}));return f.fetcher(url,options);};
 const result=await fetchRegistrySboms('example.org/a',{fetcher,platform:'linux/amd64'});
 assert.equal(result.documents.length,1);assert.equal(result.documents[0].expectedDigest,leaf.digest);assert.equal(result.documents[0].document.spdxVersion,'SPDX-2.3');assert.equal(result.documents[0].source.signatureVerified,false);
 const image=JSON.parse(f.objects.get(leaf.digest));assert.ok(!f.requests.some(x=>x.url.includes(image.layers[0].digest)));
 const mismatched=encode({schemaVersion:2,subject:{digest:'sha256:'+ '0'.repeat(64)},layers:[sbomDesc]}), bad=desc(mismatched);f.objects.set(bad.digest,mismatched);
 const other=await fetchRegistrySboms('example.org/a',{platform:'linux/amd64',fetcher:async(url,opts)=>url.includes('/referrers/')?new Response(encode({schemaVersion:2,manifests:[bad]})):f.fetcher(url,opts)});
 assert.equal(other.documents.length,0);assert.equal(other.diagnostics[0].kind,'artifact-subject-mismatch');
});
test('BuildKit SBOM attestation requires matching in-toto subject and digest checks',async()=>{
 const f=await registryFixture(), leaf=f.platforms[0], root=JSON.parse(f.objects.get('latest'));
 const statement=encode({_type:'https://in-toto.io/Statement/v1',subject:[{digest:{sha256:leaf.digest.slice(7)}}],predicateType:'https://spdx.dev/Document',predicate:{spdxVersion:'SPDX-2.3',packages:[]}});
 const layer=desc(statement,{mediaType:'application/vnd.in-toto+json'}), artifact=encode({schemaVersion:2,layers:[layer]}), ad=desc(artifact,{annotations:{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':leaf.digest},platform:{os:'unknown',architecture:'unknown'}});
 root.manifests.push(ad);f.objects.set('latest',encode(root));f.objects.set(ad.digest,artifact);f.objects.set(layer.digest,statement);
 const fetcher=async(url,opts)=>url.includes('/referrers/')?new Response('missing',{status:404}):f.fetcher(url,opts);
 const got=await fetchRegistrySboms('example.org/a',{fetcher,platform:'linux/amd64'});assert.equal(got.documents.length,1);assert.equal(got.documents[0].source.kind,'buildkit-index');assert.equal(got.documents[0].document.subject[0].digest.sha256,leaf.digest.slice(7));assert.equal(got.diagnostics[0].kind,'referrers-unavailable');
 f.objects.set(layer.digest,Buffer.from('corrupt'));await assert.rejects(fetchRegistrySboms('example.org/a',{fetcher,platform:'linux/amd64'}),/mismatch/);
});
test('publisher SBOM discovery is offline-safe',async()=>{let called=false;await assert.rejects(fetchRegistrySboms('example.org/a',{offline:true,fetcher:()=>{called=true;}}),/offline/);assert.equal(called,false);});

test('online inventory cache verifies mutable tags and reuses content without downloading layers',async t=>{
 const {acquireInventories}=require('../lib/artifacts/scan');
 const f=await registryFixture(),dir=await temp(t),cacheDir=path.join(dir,'cache');
 t.after(()=>require('../lib/cache-db').closeCacheDbs());
 const options={cacheDir,registry:true,fetcher:f.fetcher,tmpDir:dir,platform:'linux/amd64'};
 const ref='example.org/team/image:latest';
 const first=await acquireInventories(ref,options);
 assert.ok(f.requests.some(r=>r.url.includes('/blobs/')));
 f.requests.length=0;
 const reused=await acquireInventories(ref,options);
 assert.equal(f.requests.length,1);
 assert.match(f.requests[0].url,/\/manifests\/latest$/);
 assert.equal(reused[0].evidence,'cached-inventory');
 assert.equal(reused[0].inventoryAt,first[0].inventoryAt);
 assert.deepEqual(reused[0].deps,first[0].deps);
 f.requests.length=0;
 await acquireInventories(ref,{...options,platform:'linux/arm64'});
 assert.ok(f.requests.some(r=>r.url.includes('/blobs/')),'platforms have distinct inventories');
 const changed=JSON.parse(f.objects.get('latest'));
 changed.annotations={'test.revision':'next'};
 f.objects.set('latest',encode(changed));
 f.requests.length=0;
 const updated=await acquireInventories(ref,options);
 assert.ok(f.requests.some(r=>r.url.includes('/blobs/')),'changed tag rebuilds inventory');
 assert.notEqual(updated[0].metadata.acquisition.indexDigest,first[0].metadata.acquisition.indexDigest);
 f.requests.length=0;
 await acquireInventories(ref,{...options,forceUpdate:true});
 assert.ok(f.requests.some(r=>r.url.includes('/blobs/')),'force update rebuilds inventory');
 f.requests.length=0;
 const offline=await acquireInventories(ref,{...options,offline:true});
 assert.equal(offline[0].evidence,'cached-inventory');assert.equal(f.requests.length,0);
 const originalFetcher=f.fetcher;
 await assert.rejects(acquireInventories(ref,{...options,fetcher:async()=>new Response('',{status:503})}),/HTTP 503/,'failed tag verification cannot silently claim current inventory');
 const digest=desc(f.objects.get('latest')).digest;
 f.objects.set(digest,f.objects.get('latest'));
 const pinned='example.org/team/image@'+digest;
 await acquireInventories(pinned,{...options,fetcher:originalFetcher});
 f.requests.length=0;
 assert.equal((await acquireInventories(pinned,options))[0].evidence,'cached-inventory');
 assert.equal(f.requests.length,0,'immutable digest needs no registry request');
});

test('manifest digest resolution rejects substituted content before trusting cached inventories',async()=>{
 const {fetchRegistryDigest}=require('../lib/image-registry'),f=await registryFixture();
 await assert.rejects(fetchRegistryDigest('example.org/team/image:latest',{fetcher:async()=>new Response(f.objects.get('latest'),{headers:{'docker-content-digest':'sha256:'+'a'.repeat(64)}})}),/digest mismatch/);
});
