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
  for (const [name, body, type, linkname, pax] of entries) await new Promise((resolve, reject) => pack.entry({ name, type: type || 'file', linkname, ...(pax ? { pax } : {}) }, body || '', e => e ? reject(e) : resolve()));
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
  await fsp.writeFile(file,await archive([['bad','','symlink','../../etc']])); const clamped=await openArtifact(file);
  assert.equal(path.resolve(path.dirname(path.join(clamped.targets[0].root,'bad')),await fsp.readlink(path.join(clamped.targets[0].root,'bad'))),path.join(clamped.targets[0].root,'etc')); await clamped.cleanup();
  await fsp.writeFile(file,await archive([['ok','x'],['../escape','bad']]));
  const tmp=path.join(d,'temp'); await fsp.mkdir(tmp); await assert.rejects(openArtifact(file,{tmpdir:tmp}),/Unsafe archive path/); assert.deepEqual(await fsp.readdir(tmp),[]);
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
 await fsp.writeFile(file,await archive([['pivot','','symlink','../outside'],['pivot/escape','bad']]));const pivot=await openArtifact(file);
 assert.equal(await fsp.readFile(path.join(pivot.targets[0].root,'outside','escape'),'utf8'),'bad');await pivot.cleanup();assert.equal(fs.existsSync(path.join(d,'outside','escape')),false);
 await fsp.writeFile(file,await archive([['..\\escape','bad']]));const slash=await openArtifact(file);t.after(slash.cleanup);
 if(path.sep==='/')assert.deepEqual(await fsp.readdir(slash.targets[0].root),['..\\escape']);
 else {assert.deepEqual(await fsp.readdir(slash.targets[0].root),[]);assert.ok(slash.targets[0].metadata.warnings.some(w=>w.includes('cannot be represented')));}
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
async function walk(dir, out=[]) { for (const e of await fsp.readdir(dir,{withFileTypes:true})) { const p=path.join(dir,e.name); out.push(p); if (e.isDirectory()) await walk(p,out); } return out; }
test('POSIX backslash and drive-like names are ordinary file names; Windows skips them with a warning',async t=>{
 const d=await fixture(t),file=path.join(d,'root.tar'),slice='usr/lib/systemd/system/system-systemd\\x2dcryptsetup.slice';
 await fsp.writeFile(file,await archive([[slice,'[Unit]'],['usr/lib/systemd/system/sockets.target.wants/a\\x2db.socket','','symlink','../a\\x2db.socket'],['usr/lib/systemd/system/a\\x2db.socket','sock'],['C:drive','c'],['hard\\link','','link',slice],['keep','k']]));
 const opened=await openArtifact(file);t.after(opened.cleanup);const root=opened.targets[0].root;
 if(path.sep==='/'){
  assert.equal(await fsp.readFile(path.join(root,...slice.split('/')),'utf8'),'[Unit]');
  assert.equal(await fsp.readFile(path.join(root,'usr/lib/systemd/system/sockets.target.wants/a\\x2db.socket'),'utf8'),'sock');
  assert.equal(await fsp.readFile(path.join(root,'C:drive'),'utf8'),'c');assert.equal(await fsp.readFile(path.join(root,'hard\\link'),'utf8'),'[Unit]');
  assert.deepEqual(opened.targets[0].metadata.warnings,[]);
 } else {
  assert.equal(await fsp.readFile(path.join(root,'keep'),'utf8'),'k');assert.equal(fs.existsSync(path.join(root,'C:drive')),false);
  assert.equal(opened.targets[0].metadata.warnings.filter(w=>w.includes('cannot be represented')).length,5);
 }
});
test('NUL, absolute names, dot-dot components and depth overflow are still rejected',async t=>{
 const d=await fixture(t),file=path.join(d,'root.tar');
 for(const entries of [[['a','x','file',undefined,{path:'a\0b'}]],[['/etc/x','x']],[['a/../../x','x']],[['a\\..\\..\\b/../x','x']],[['h','','link','../outside']],[['h','','link','a/../../outside']]]){
  await fsp.writeFile(file,await archive(entries));await assert.rejects(openArtifact(file),/Unsafe archive path/,JSON.stringify(entries));
 }
 await fsp.writeFile(file,await archive([['a/b/c','x']]));await assert.rejects(openArtifact(file,{limits:{maxDepth:2}}),/Unsafe archive path/);
});
test('relative symlinks climbing above the root clamp at the root and never resolve outside it',async t=>{
 const d=await fixture(t),file=path.join(d,'root.tar'),outside=path.join(d,'etc');await fsp.mkdir(outside);
 // e1.js E1: Linux resolves ../../../../etc/os-release from /usr/lib to /etc/os-release.
 await fsp.writeFile(file,await archive([['etc/os-release','ID=debian\n'],['usr/lib/x','','symlink','../../../../etc/os-release'],['up','','symlink','../../../..'],['up/etc/written','in'],['usr/lib/x2','','symlink','../../../../etc/os-release'],['usr/lib/x2','overwrite']]));
 const opened=await openArtifact(file);t.after(opened.cleanup);const root=opened.targets[0].root;
 assert.equal(await fsp.readFile(path.join(root,'usr/lib/x'),'utf8'),'ID=debian\n');
 assert.equal(path.resolve(path.join(root,'usr/lib'),await fsp.readlink(path.join(root,'usr/lib/x'))),path.join(root,'etc/os-release'));
 assert.equal(await fsp.readFile(path.join(root,'etc/written'),'utf8'),'in');assert.deepEqual(await fsp.readdir(outside),[]);
 assert.equal(await fsp.readFile(path.join(root,'etc/os-release'),'utf8'),'ID=debian\n');
 for(const p of await walk(root)){const real=await fsp.realpath(p).catch(()=>null);if(real)assert.ok(real===root||real.startsWith(root+path.sep),p);}
});
test('opaque whiteout over a lower-layer symlink replaces the link and keeps its target',async t=>{
 const d=await fixture(t),file=path.join(d,'image.tar');
 // e1.js E8: lib -> usr/lib in layer 1, then lib/ + lib/.wh..wh..opq + lib/new in layer 2.
 const l1=await archive([['usr/lib/libz.so','Z'],['lib','','symlink','usr/lib'],['opt/data/old','o'],['link2','','symlink','opt/data']]);
 const l2=await archive([['lib/','','directory'],['lib/.wh..wh..opq',''],['lib/new','N'],['link2/.wh..wh..opq',''],['opt/data/.wh..wh..opq',''],['opt/data/fresh','f']]);
 await fsp.writeFile(file,await archive([['manifest.json',JSON.stringify([{Config:'c.json',Layers:['l1.tar','l2.tar']}])],['c.json','{"os":"linux","architecture":"amd64"}'],['l1.tar',l1],['l2.tar',l2]]));
 const opened=await openArtifact(file);t.after(opened.cleanup);const root=opened.targets[0].root;
 assert.equal(await fsp.readFile(path.join(root,'usr/lib/libz.so'),'utf8'),'Z');
 assert.ok((await fsp.lstat(path.join(root,'lib'))).isDirectory());assert.deepEqual(await fsp.readdir(path.join(root,'lib')),['new']);
 assert.ok((await fsp.lstat(path.join(root,'link2'))).isDirectory());assert.deepEqual(await fsp.readdir(path.join(root,'link2')),[]);
 assert.deepEqual(await fsp.readdir(path.join(root,'opt/data')),['fresh']);
});
