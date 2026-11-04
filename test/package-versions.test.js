'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const versions=require('../lib/package-versions');
const {setActiveCacheDir}=require('../lib/cache-directory');
const {fetchPom,pomCachePath}=require('../lib/transitive');
const pom=extra=>`<project><groupId>org.example</groupId><artifactId>app</artifactId><version>1.2.3</version>${extra || ''}</project>`;
function record(body, overrides={}) {return {_schema:1,origin:'https://repo1.maven.org',ecosystem:'maven',name:'org.example:app',version:'1.2.3',body,sha256:crypto.createHash('sha256').update(body).digest('hex'),collectedAt:Date.now(),sourceUrl:'https://repo1.maven.org/maven2/org/example/app/1.2.3/app-1.2.3.pom',format:'maven-pom',...overrides};}
function write(dir,r) {
 const db=require('../lib/cache-db').openCacheDb({cacheDir:dir});
 try { db.prepare('INSERT OR IGNORE INTO package_versions(origin,ecosystem,name,version,sha256,collected_at,source_url,format,body) VALUES (?,?,?,?,?,?,?,?,?)')
  .run(r.origin,r.ecosystem,r.name,r.version,r.sha256,r.collectedAt,r.sourceUrl,r.format,Buffer.from(r.body)); }
 finally {db.close()}
}
test('offline Maven reads exact seed, rejects conflicts and honors private repositories',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-durable-'));setActiveCacheDir(dir);
 try {
  const xml='<project><groupId>org.example</groupId><artifactId>app</artifactId><version>1.2.3</version></project>',r=record(xml);write(dir,r);
  assert.equal(await fetchPom('org.example','app','1.2.3',{offline:true,cacheDir:path.join(dir,'poms-cache')}),xml);
  require('../lib/maven-cache').write(pomCachePath('org.example','app','1.2.3',path.join(dir,'poms-cache')),'__NOT_FOUND__');
  assert.equal(await fetchPom('org.example','app','1.2.3',{offline:true,cacheDir:path.join(dir,'poms-cache')}),xml);
  assert.equal(await fetchPom('org.example','app','1.2.3',{offline:true,cacheDir:path.join(dir,'poms-cache'),repos:[{url:'https://private.test/'}]}),null);
  write(dir,record(xml.replace('</project>','<name>conflict</name></project>')));
  assert.equal(await fetchPom('org.example','app','1.2.3',{offline:true,cacheDir:path.join(dir,'poms-cache')}),null);
 } finally {setActiveCacheDir(null);require('../lib/cache-db').closeCacheDbs(); fs.rmSync(dir,{recursive:true,force:true});}
});
test('reject altered bytes and mutable npm metadata',()=>{
 const r=record(pom());assert.equal(versions.valid(r),true);assert.equal(versions.valid({...r,body:'tampered'}),false);
 const clean=JSON.stringify({name:'example',version:'1.2.3',dependencies:{child:'^1.0.0'}});
 const npm=record(clean,{origin:'https://registry.npmjs.org',ecosystem:'npm',name:'example',format:'npm-manifest',sourceUrl:'https://registry.npmjs.org/example',sha256:crypto.createHash('sha256').update(clean).digest('hex')});
 assert.equal(versions.valid(npm),true);assert.equal(versions.valid({...npm,sourceUrl:'https://registry.npmjs.org/other'}),false);
 const body=JSON.stringify({name:'example',version:'1.2.3',deprecated:'mutable'});
 assert.equal(versions.valid(record(body,{origin:'https://registry.npmjs.org',ecosystem:'npm',name:'example',format:'npm-manifest',sha256:crypto.createHash('sha256').update(body).digest('hex')})),false);
});

test('SQLite cache import preserves separate observations',async()=>{
 const {importCache,exportCache}=require('../lib/cache-archive-sqlite');
 const work=fs.mkdtempSync(path.join(os.tmpdir(),'vv-version-archive-')),src=path.join(work,'src','.vigie-vuln'),dst=path.join(work,'dst'),archive=path.join(work,'seed.tar.gz');
 try {
  const first=record(pom('<name>first</name>')), second=record(pom('<name>second</name>'));
  write(dst,first);write(src,second);
  await exportCache(archive,{sourceDir:src});
  await importCache(archive,{targetDir:dst});
  assert.equal(versions.getVersion('maven',first.name,first.version,{cacheDir:dst}),null);
  assert.ok(versions.drainIssues().some(x=>x.reason==='conflicting observations'));
 } finally {require('../lib/cache-db').closeCacheDbs(); fs.rmSync(work,{recursive:true,force:true});}
});
