'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = fs.promises;
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const tar = require('tar-stream');
const zlib = require('node:zlib');
const { openArtifact } = require('../lib/artifacts');

async function archive(entries) {
  const pack = tar.pack(); const chunks = []; pack.on('data', b => chunks.push(b));
  const ended = new Promise((resolve, reject) => { pack.on('end', resolve); pack.on('error', reject); });
  for (const [name, body, type, linkname] of entries) await new Promise((resolve, reject) => pack.entry({ name, type: type || 'file', linkname }, body || '', e => e ? reject(e) : resolve()));
  pack.finalize(); await ended; return Buffer.concat(chunks);
}
async function fixture(t) { const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'artifact-test-')); t.after(() => fsp.rm(d, { recursive: true, force: true })); return d; }
async function docker(t) {
  const d = await fixture(t), l1 = await archive([['etc/old','old'],['etc/keep','keep'],['opt/a','a'],['opt/b','b']]);
  const l2 = await archive([['etc/new','new'],['etc/.wh.old',''],['opt/c','c'],['opt/.wh..wh..opq',''],['alias','', 'symlink','etc'],['hard','', 'link','etc/new']]);
  const manifest = [{Config:'one.json',RepoTags:['sample:one'],Layers:['l1.tar','l2.tar']},{Config:'two.json',RepoTags:['sample:two'],Layers:['l1.tar']}];
  const file = path.join(d,'image'); await fsp.writeFile(file, zlib.gzipSync(await archive([['manifest.json', JSON.stringify(manifest)],['one.json', '{"os":"linux","architecture":"amd64"}'],['two.json','{"os":"linux","architecture":"arm64"}'],['l1.tar', l1],['l2.tar',l2]]))); return {d,file};
}
test('Docker save separates images, applies whiteouts before additions and cleans roots', async t => {
  const {file} = await docker(t), opened = await openArtifact(file); t.after(opened.cleanup);
  assert.equal(opened.targets.length, 2); const [a,b] = opened.targets;
  assert.equal(a.metadata.platform.architecture,'amd64'); assert.equal(b.metadata.platform.architecture,'arm64');
  assert.equal(await fsp.readFile(path.join(a.root,'etc/new'),'utf8'),'new');
  assert.equal(await fsp.readFile(path.join(a.root,'alias/new'),'utf8'),'new');
  assert.equal(await fsp.readFile(path.join(a.root,'hard'),'utf8'),'new');
  await assert.rejects(fsp.stat(path.join(a.root,'etc/old')), {code:'ENOENT'});
  assert.deepEqual(await fsp.readdir(path.join(a.root,'opt')), ['c']);
  assert.equal(await fsp.readFile(path.join(b.root,'etc/old'),'utf8'),'old');
  await opened.cleanup(); assert.equal(fs.existsSync(a.root),false);
});
test('OCI layout verifies descriptors and preserves each platform', async t => {
  const d = await fixture(t), dir = path.join(d,'layout'); await fsp.mkdir(path.join(dir,'blobs','sha256'), {recursive:true});
  async function blob(data, mediaType, platform) { const b = Buffer.isBuffer(data) ? data : Buffer.from(JSON.stringify(data)), hash=crypto.createHash('sha256').update(b).digest('hex'); await fsp.writeFile(path.join(dir,'blobs','sha256',hash), b); return {mediaType,digest:`sha256:${hash}`,size:b.length,...(platform ? {platform} : {})}; }
  const layer=await blob(zlib.gzipSync(await archive([['etc/os-release','ID=alpine']])),'application/vnd.oci.image.layer.v1.tar+gzip');
  const manifests=[]; for(const arch of ['amd64','arm64']) { const config=await blob({os:'linux',architecture:arch},'application/vnd.oci.image.config.v1+json'); manifests.push(await blob({schemaVersion:2,config,layers:[layer]},'application/vnd.oci.image.manifest.v1+json',{os:'linux',architecture:arch})); }
  await fsp.writeFile(path.join(dir,'oci-layout'), JSON.stringify({imageLayoutVersion:'1.0.0'})); await fsp.writeFile(path.join(dir,'index.json'),JSON.stringify({schemaVersion:2,manifests}));
  const tarEntries = [['oci-layout',await fsp.readFile(path.join(dir,'oci-layout'))],['index.json',await fsp.readFile(path.join(dir,'index.json'))]];
  for (const name of await fsp.readdir(path.join(dir,'blobs','sha256'))) tarEntries.push([`blobs/sha256/${name}`,await fsp.readFile(path.join(dir,'blobs','sha256',name))]);
  const archiveFile=path.join(d,'oci.tar'); await fsp.writeFile(archiveFile,await archive(tarEntries));
  const packed=await openArtifact(archiveFile); assert.equal(packed.targets.length,2); await packed.cleanup();
  const opened=await openArtifact(dir); t.after(opened.cleanup); assert.deepEqual(opened.targets.map(x => x.metadata.platform.architecture),['amd64','arm64']);
  assert.equal(await fsp.readFile(path.join(opened.targets[0].root,'etc/os-release'),'utf8'),'ID=alpine');
  await fsp.writeFile(path.join(dir,'blobs','sha256',layer.digest.slice(7)),'bad'); await assert.rejects(openArtifact(dir),/integrity mismatch/);
});
test('rootfs tar, traversal, links and limits', async t => {
  const d=await fixture(t), file=path.join(d,'archive'); await fsp.writeFile(file,await archive([['etc/a','ok']]));
  const opened=await openArtifact(file); assert.equal(opened.targets[0].kind,'rootfs'); await opened.cleanup();
  await assert.rejects(openArtifact(file,{limits:{maxFileBytes:1}}),/limit exceeded/);
  await fsp.writeFile(file,await archive([['../escape','bad']])); await assert.rejects(openArtifact(file),/Unsafe archive path/);
  await fsp.writeFile(file,await archive([['bad','','symlink','../../etc']])); await assert.rejects(openArtifact(file),/Link escapes/);
  const tmp=path.join(d,'temp'); await fsp.mkdir(tmp); await assert.rejects(openArtifact(file,{tmpdir:tmp}),/Link escapes/); assert.deepEqual(await fsp.readdir(tmp),[]);
});
test('source and compression adapters can extend input handling', async t => {
  const d=await fixture(t), file=path.join(d,'custom'); await fsp.writeFile(file,'test'); let cleaned=false;
  const opened=await openArtifact(file,{sources:[{probe: async () => true, open: async () => ({targets:[{id:'custom:1',kind:'custom',root:d,metadata:{}}],cleanup:async()=>{cleaned=true;}})}]});
  assert.equal(opened.targets[0].id,'custom:1'); await opened.cleanup(); assert.equal(cleaned,true);
  await assert.rejects(openArtifact(file,{sources:[{}]}),/Invalid artifact source adapter/);
});
test('zstd rootfs and hardlinks preserve entry ordering', async t => {
  if (typeof zlib.zstdCompressSync !== 'function') return t.skip('native zstd encoder unavailable');
  const d=await fixture(t), file=path.join(d,'root.zst');
  const content=await archive([['a','first'],['b','','link','a'],['a','second'],['late','','link','later'],['later','future']]);
  await fsp.writeFile(file,zlib.zstdCompressSync(content)); const opened=await openArtifact(file); t.after(opened.cleanup);
  assert.equal(await fsp.readFile(path.join(opened.targets[0].root,'b'),'utf8'),'first');
  assert.equal(await fsp.readFile(path.join(opened.targets[0].root,'late'),'utf8'),'future');
});

test('portable zstd decoder works without Node zstd support', async t => {
  if (typeof zlib.zstdCompressSync !== 'function') return t.skip('native zstd encoder unavailable');
  const d=await fixture(t), file=path.join(d,'root.zst'); await fsp.writeFile(file,zlib.zstdCompressSync(await archive([['a','zstd']])));
  const opened=await openArtifact(file,{preferPortableZstd:true}); try { assert.equal(await fsp.readFile(path.join(opened.targets[0].root,'a'),'utf8'),'zstd'); } finally { await opened.cleanup(); }
});
test('PAX long paths and symlink pivots stay within the root',async t=>{
 const d=await fixture(t), file=path.join(d,'root.tar'), long='nested/'.repeat(20)+'long-file';
 await fsp.writeFile(file,await archive([[long,'long'],['abs','','symlink','/nested'],['abs/via','inside']]));
 const opened=await openArtifact(file);t.after(opened.cleanup);assert.equal(await fsp.readFile(path.join(opened.targets[0].root,long),'utf8'),'long');assert.equal(await fsp.readFile(path.join(opened.targets[0].root,'nested/via'),'utf8'),'inside');
 await fsp.writeFile(file,await archive([['pivot','','symlink','../outside'],['pivot/escape','bad']]));await assert.rejects(openArtifact(file),/Link escapes/);assert.equal(fs.existsSync(path.join(d,'outside','escape')),false);
 await fsp.writeFile(file,await archive([['..\\escape','bad']]));await assert.rejects(openArtifact(file),/Unsafe archive path/);
});
test('OCI attestations are skipped with explicit warning',async t=>{
 const d=await fixture(t),dir=path.join(d,'oci'),blobs=path.join(dir,'blobs','sha256');await fsp.mkdir(blobs,{recursive:true});
 const blob=async x=>{const body=Buffer.isBuffer(x)?x:Buffer.from(JSON.stringify(x)), hash=crypto.createHash('sha256').update(body).digest('hex');await fsp.writeFile(path.join(blobs,hash),body);return {digest:`sha256:${hash}`,size:body.length};};
 const config=await blob({os:'linux',architecture:'amd64'}), layer=await blob(await archive([['a','x']])), image=await blob({config,layers:[layer]});
 const attest={digest:'sha256:'+ '1'.repeat(64),size:0,platform:{os:'unknown',architecture:'unknown'}};
 await fsp.writeFile(path.join(dir,'oci-layout'),'{"imageLayoutVersion":"1.0.0"}');await fsp.writeFile(path.join(dir,'index.json'),JSON.stringify({manifests:[image,attest]}));
 const opened=await openArtifact(dir);t.after(opened.cleanup);assert.equal(opened.targets.length,1);assert.ok(opened.targets[0].metadata.warnings.some(w => /non-image artifact/.test(w)));
});
test('Docker diff_ids bind uncompressed layer bytes to configuration identity',async t=>{
 const d=await fixture(t),file=path.join(d,'image.tar'),layer=await archive([['file','good']]);
 const diff='sha256:'+crypto.createHash('sha256').update(layer).digest('hex');
 const make=async(cfg,body=layer)=>fsp.writeFile(file,await archive([['manifest.json',JSON.stringify([{Config:'config.json',Layers:['layer.tar']}])],['config.json',JSON.stringify(cfg)],['layer.tar',body]]));
 await make({rootfs:{type:'layers',diff_ids:[diff]}},zlib.gzipSync(layer));const valid=await openArtifact(file);await valid.cleanup();
 await make({rootfs:{type:'layers',diff_ids:[diff]}},await archive([['file','evil']]));await assert.rejects(openArtifact(file),/diff_id mismatch/);
 await make({rootfs:{type:'layers',diff_ids:[]}});await assert.rejects(openArtifact(file),/diff_ids count/);
 await make({});const unknown=await openArtifact(file);assert.ok(unknown.targets[0].metadata.warnings.some(w=>w.includes('does not declare layer diff_ids')));await unknown.cleanup();
});
test('OCI descriptors support registered digest algorithms with verification',async t=>{
 const d=await fixture(t),dir=path.join(d,'layout'),blobs=path.join(dir,'blobs','sha512');await fsp.mkdir(blobs,{recursive:true});
 const blob=async data=>{const b=Buffer.isBuffer(data)?data:Buffer.from(JSON.stringify(data)),hex=crypto.createHash('sha512').update(b).digest('hex');await fsp.writeFile(path.join(blobs,hex),b);return{digest:'sha512:'+hex,size:b.length};};
 const layerBytes=await archive([['x','ok']]),layer=await blob(layerBytes),config=await blob({rootfs:{type:'layers',diff_ids:['sha256:'+crypto.createHash('sha256').update(layerBytes).digest('hex')]}}),manifest=await blob({config,layers:[layer]});
 await fsp.writeFile(path.join(dir,'index.json'),JSON.stringify({manifests:[manifest]}));await fsp.writeFile(path.join(dir,'oci-layout'),'{"imageLayoutVersion":"1.0.0"}');
 const opened=await openArtifact(dir);assert.equal(await fsp.readFile(path.join(opened.targets[0].root,'x'),'utf8'),'ok');await opened.cleanup();
});
