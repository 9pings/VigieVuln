'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {gzipSync}=require('node:zlib');
const {createHash}=require('node:crypto');
const {attachReleaseVersions}=require('../lib/artifacts/release-versions');
const {renderLatestVersions}=require('../lib/artifacts/report');

function image() {
  const bash={name:'bash',sourceName:'bash',version:'1-1',manager:'dpkg',architecture:'amd64',ecosystem:'system',coordKey:'bash-deb',imageProduct:{id:'bash'}};
  const binary={name:'bash',version:'1',ecosystem:'binary',coordKey:'bin',imageProduct:{id:'bash'},osPackageOwners:[bash]};
  return {distribution:{id:'ubuntu',codename:'noble',versionId:'24.04'},components:[bash,binary],
    productInventory:{entries:[{componentKey:'bash-deb'},{componentKey:'bin'}]}};
}
function repository(){
  const entries=new Map();
  return {get:(ns,key)=>entries.get(ns+key),put:(ns,key,value,meta)=>entries.set(ns+key,{value,...meta})};
}
function indexFor(path) {
  const version=path.includes('noble-security')?'1:1.2-2':path.includes('noble-updates')?'1:1.2-1':'1-9';
  const stanza=(source,arch,v)=>`Package: bash\nSource: ${source}\nArchitecture: ${arch}\nVersion: ${v}\n\n`;
  return gzipSync(stanza('bash','amd64',version)+stanza('bash','arm64','9:9')+stanza('another-project','amd64','8:8'));
}
test('release references follow package source, architecture, security pocket and owner; offline replay makes zero requests',async()=>{
  const repo=repository(), online=image(), requests=[];
  const fetcher=async url=>{
    requests.push(url);
    if(url.includes('release-monitoring.org'))return Response.json({latest_version:'3.0-rc1',stable_versions:['2.0','1.0']});
    const buffer=indexFor(url);
    if(url.endsWith('/Release'))return new Response('SHA256:\n '+createHash('sha256').update(buffer).digest('hex')+' '+buffer.length+' main/binary-amd64/Packages.gz\n');
    return new Response(buffer);
  };
  await attachReleaseVersions(online,online.components,{cacheRepository:repo,fetcher});
  assert.equal(requests.length,7);
  const refs=online.components[0].releaseVersions;
  assert.equal(refs.distribution.version,'1:1.2-2');
  assert.match(refs.distribution.url,/security\.ubuntu\.com.*noble-security/);
  assert.equal(refs.upstream.version,'2.0');
  for(const item of [...online.components,...online.productInventory.entries])assert.deepEqual(item.releaseVersions,refs);
  const offline=image();let offlineCalls=0;
  await attachReleaseVersions(offline,offline.components,{offline:true,cacheRepository:repo,fetcher:()=>{offlineCalls++;throw Error('network')}});
  assert.equal(offlineCalls,0);
  assert.deepEqual(offline,online);
  assert.match(renderLatestVersions(refs,'fr'),/Distribution.*1:1.2-2.*Amont.*2.0.*Anitya/);
});
test('a failed archive checksum cannot yield a latest distribution version',async()=>{
  const a=image();
  await attachReleaseVersions(a,a.components,{cacheRepository:repository(),fetcher:async url=>{
    if(url.includes('release-monitoring.org'))return new Response('',{status:503});
    if(url.endsWith('/Release'))return new Response('SHA256:\n '+'a'.repeat(64)+' 3 main/binary-amd64/Packages.gz\n');
    return new Response('bad');
  }});
  assert.ok(a.components.every(c=>!c.releaseVersions));
  assert.equal(renderLatestVersions(undefined,'fr'),'—');
});
